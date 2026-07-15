from __future__ import annotations

import os
import re
import logging
from dataclasses import dataclass
from typing import Any

from nemoguardrails.library.gliner.request import gliner_request


logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)


DEFAULT_LANGUAGE = "en"
DEFAULT_NEMO_LANGUAGE = "auto"
DEFAULT_OPENAI_GUARDRAILS_LANGUAGE = "en"
DEFAULT_SCORE_THRESHOLD = 0.5
DEFAULT_PROVIDER = "nemo"
NEMO_PROVIDER = "nemo"
OPENAI_GUARDRAILS_PROVIDER = "openai-guardrails"
DEFAULT_GLINER_ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
DEFAULT_GLINER_MODEL = "nvidia/gliner-pii"
NEMO_LANGUAGE_ALIASES = {
    "auto": "auto",
    "en": "en",
    "zh": "zh",
    "zh-cn": "zh-Hans",
    "zh-hans": "zh-Hans",
    "zh-tw": "zh-Hant",
    "zh-hant": "zh-Hant",
}
OPENAI_GUARDRAILS_LANGUAGE_ALIASES = {
    "en": "en",
}

# GLiNER-PII accepts custom labels; this list provides useful defaults for the UI.
DEFAULT_SUPPORTED_ENTITIES = [
    "first_name",
    "last_name",
    "full_name",
    "person",
    "chinese_name",
    "email",
    "email_address",
    "phone_number",
    "mobile_phone",
    "telephone",
    "ssn",
    "national_id",
    "identity_document",
    "taiwan_id",
    "china_id",
    "street_address",
    "address",
    "location",
    "city",
    "state",
    "postcode",
    "country",
    "date",
    "date_of_birth",
    "birthdate",
    "time",
    "age",
    "gender",
    "occupation",
    "organization",
    "account_number",
    "credit_card_number",
    "swift_bic",
    "iban",
    "ip_address",
    "mac_address",
    "url",
    "username",
    "messaging_id",
    "password",
    "api_key",
    "passport_number",
    "driver_license",
    "tax_id",
    "medical_record_number",
    "health_insurance_id",
]

OPENAI_GUARDRAILS_SUPPORTED_ENTITIES = [
    "CREDIT_CARD",
    "CRYPTO",
    "DATE_TIME",
    "EMAIL_ADDRESS",
    "IBAN_CODE",
    "IP_ADDRESS",
    "NRP",
    "LOCATION",
    "PERSON",
    "PHONE_NUMBER",
    "MEDICAL_LICENSE",
    "URL",
    "CVV",
    "BIC_SWIFT",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "US_ITIN",
    "US_PASSPORT",
    "US_SSN",
    "UK_NHS",
    "UK_NINO",
    "ES_NIF",
    "ES_NIE",
    "IT_FISCAL_CODE",
    "IT_DRIVER_LICENSE",
    "IT_VAT_CODE",
    "IT_PASSPORT",
    "IT_IDENTITY_CARD",
    "PL_PESEL",
    "SG_NRIC_FIN",
    "SG_UEN",
    "AU_ABN",
    "AU_ACN",
    "AU_TFN",
    "AU_MEDICARE",
    "IN_PAN",
    "IN_AADHAAR",
    "IN_VEHICLE_REGISTRATION",
    "IN_VOTER",
    "IN_PASSPORT",
    "FI_PERSONAL_IDENTITY_CODE",
    "KR_RRN",
]

OPENAI_ENTITY_ALIASES = {
    "account_number": "US_BANK_NUMBER",
    "address": "LOCATION",
    "api_key": "CRYPTO",
    "city": "LOCATION",
    "country": "LOCATION",
    "credit_card_number": "CREDIT_CARD",
    "date": "DATE_TIME",
    "driver_license": "US_DRIVER_LICENSE",
    "email": "EMAIL_ADDRESS",
    "first_name": "PERSON",
    "iban": "IBAN_CODE",
    "ip_address": "IP_ADDRESS",
    "last_name": "PERSON",
    "location": "LOCATION",
    "passport_number": "US_PASSPORT",
    "person": "PERSON",
    "phone": "PHONE_NUMBER",
    "phone_number": "PHONE_NUMBER",
    "postcode": "LOCATION",
    "ssn": "US_SSN",
    "state": "LOCATION",
    "street_address": "LOCATION",
    "swift_bic": "BIC_SWIFT",
    "time": "DATE_TIME",
    "url": "URL",
}


class PiiConfigurationError(RuntimeError):
    pass


class PiiProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class PiiEntity:
    type: str
    start: int
    end: int
    score: float
    text: str
    replacement: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "start": self.start,
            "end": self.end,
            "score": self.score,
            "text": self.text,
            "replacement": self.replacement,
        }


class PiiDetector:
    def __init__(
        self,
        server_endpoint: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        chunk_length: int | None = None,
        overlap: int | None = None,
        flat_ner: bool | None = None,
    ):
        self.server_endpoint = (
            server_endpoint
            or os.getenv("NEMO_PII_SERVER_ENDPOINT")
            or os.getenv("GLINER_SERVER_ENDPOINT")
            or DEFAULT_GLINER_ENDPOINT
        )
        self.api_key = api_key if api_key is not None else (
            os.getenv("NEMO_PII_API_KEY") or os.getenv("NVIDIA_API_KEY")
        )
        self.model = model or os.getenv("NEMO_PII_MODEL") or DEFAULT_GLINER_MODEL
        self.chunk_length = (
            chunk_length
            if chunk_length is not None
            else _int_env("NEMO_PII_CHUNK_LENGTH")
        )
        self.overlap = overlap if overlap is not None else _int_env("NEMO_PII_OVERLAP")
        self.flat_ner = (
            flat_ner
            if flat_ner is not None
            else _bool_env("NEMO_PII_FLAT_NER")
        )

    def supported_entities(self, provider: str | None = None) -> list[str]:
        provider_name = _normalize_provider(provider)
        if provider_name == OPENAI_GUARDRAILS_PROVIDER:
            return OPENAI_GUARDRAILS_SUPPORTED_ENTITIES.copy()
        return DEFAULT_SUPPORTED_ENTITIES.copy()

    async def preview(
        self,
        text: str,
        language: str | None = None,
        score_threshold: float = DEFAULT_SCORE_THRESHOLD,
        entities: list[str] | None = None,
        provider: str | None = None,
        detect_encoded_pii: bool = False,
    ) -> dict[str, Any]:
        provider_name = _normalize_provider(provider)
        if provider_name == OPENAI_GUARDRAILS_PROVIDER:
            return await _openai_guardrails_preview(
                text=text,
                language=language,
                score_threshold=score_threshold,
                entities=entities,
                detect_encoded_pii=detect_encoded_pii,
            )

        normalized_language = _normalize_language(
            language or DEFAULT_NEMO_LANGUAGE,
            NEMO_LANGUAGE_ALIASES,
        )
        if normalized_language is None:
            raise ValueError(
                "NeMo GLiNER-PII preview language must be one of: "
                + ", ".join(sorted(set(NEMO_LANGUAGE_ALIASES.values())))
            )

        if not 0 < score_threshold <= 1:
            raise ValueError(
                "score_threshold must be greater than 0 and less than or equal to 1."
            )

        if _is_hosted_nvidia_endpoint(self.server_endpoint) and not self.api_key:
            raise PiiConfigurationError(
                "NVIDIA_API_KEY or NEMO_PII_API_KEY is required for the hosted GLiNER-PII endpoint."
            )

        try:
            response = await gliner_request(
                text=text,
                server_endpoint=self.server_endpoint,
                enabled_entities=entities or None,
                threshold=score_threshold,
                chunk_length=self.chunk_length,
                overlap=self.overlap,
                flat_ner=self.flat_ner,
                api_key=self.api_key,
                model=self.model,
            )
        except ValueError as exc:
            raise PiiProviderError(str(exc)) from exc

        pii_entities = _filter_overlaps(
            _normalize_entities(text, response.get("entities", []))
        )
        return {
            "enabled": True,
            "provider": NEMO_PROVIDER,
            "engine": "nemo-gliner-pii",
            "model": self.model,
            "server_endpoint": self.server_endpoint,
            "language": normalized_language,
            "score_threshold": score_threshold,
            "detect_encoded_pii": detect_encoded_pii,
            "masked": _mask_text(text, pii_entities),
            "entities": [entity.to_dict() for entity in pii_entities],
            "supported_entities": self.supported_entities(provider_name),
            "tagged_text": response.get("tagged_text", ""),
        }


async def _openai_guardrails_preview(
    text: str,
    language: str | None,
    score_threshold: float,
    entities: list[str] | None,
    detect_encoded_pii: bool,
) -> dict[str, Any]:
    normalized_language = _normalize_language(
        language or DEFAULT_OPENAI_GUARDRAILS_LANGUAGE,
        OPENAI_GUARDRAILS_LANGUAGE_ALIASES,
    )
    if normalized_language is None:
        raise ValueError(
            "Only English ('en') is supported by OpenAI Guardrails PII."
        )

    if not 0 < score_threshold <= 1:
        raise ValueError(
            "score_threshold must be greater than 0 and less than or equal to 1."
        )

    if not isinstance(detect_encoded_pii, bool):
        raise ValueError("detect_encoded_pii must be a boolean.")

    try:
        from guardrails.checks.text.pii import PIIConfig, PIIEntity, pii
    except ImportError as exc:
        raise PiiConfigurationError(
            "openai-guardrails is not installed. Run `uv add openai-guardrails`."
        ) from exc

    try:
        selected_entities = _openai_guardrails_entities(entities, PIIEntity)
        result = await pii(
            None,
            text,
            PIIConfig(
                entities=selected_entities,
                block=False,
                detect_encoded_pii=detect_encoded_pii,
            ),
        )
    except ValueError:
        raise
    except Exception as exc:
        raise PiiProviderError(str(exc)) from exc

    info = dict(result.info)
    detected = {
        str(entity_type): [str(value) for value in values]
        for entity_type, values in dict(info.get("detected_entities", {})).items()
    }
    masked = _angle_placeholders_to_brackets(str(info.get("checked_text", text)))

    return {
        "enabled": True,
        "provider": OPENAI_GUARDRAILS_PROVIDER,
        "engine": "OpenAI Guardrails Contains PII",
        "model": "Microsoft Presidio",
        "language": normalized_language,
        "score_threshold": score_threshold,
        "detect_encoded_pii": detect_encoded_pii,
        "masked": masked,
        "entities": _entities_from_detected_values(text, detected),
        "detected_entities": detected,
        "supported_entities": OPENAI_GUARDRAILS_SUPPORTED_ENTITIES.copy(),
        "pii_detected": bool(info.get("pii_detected", False)),
    }


def _openai_guardrails_entities(entities: list[str] | None, pii_entity_type: Any) -> list[Any]:
    if not entities:
        return list(pii_entity_type)

    selected: list[Any] = []
    unsupported: list[str] = []
    for entity in entities:
        normalized = _normalize_openai_entity(entity)
        try:
            selected.append(pii_entity_type(normalized))
        except ValueError:
            unsupported.append(entity)

    if unsupported:
        raise ValueError(
            "Unsupported OpenAI Guardrails PII entities: "
            + ", ".join(unsupported)
            + ". Supported entities: "
            + ", ".join(OPENAI_GUARDRAILS_SUPPORTED_ENTITIES)
        )

    deduped: list[Any] = []
    seen: set[str] = set()
    for entity in selected:
        if entity.value not in seen:
            deduped.append(entity)
            seen.add(entity.value)
    return deduped


def _normalize_openai_entity(entity: str) -> str:
    raw = str(entity).strip()
    alias = OPENAI_ENTITY_ALIASES.get(raw.lower())
    if alias:
        return alias
    return re.sub(r"[^A-Z0-9]+", "_", raw.upper()).strip("_")


def _angle_placeholders_to_brackets(text: str) -> str:
    return re.sub(r"<([A-Z0-9_]+)>", r"[\1]", text)


def _entities_from_detected_values(text: str, detected: dict[str, list[str]]) -> list[dict[str, Any]]:
    entities: list[dict[str, Any]] = []
    cursor_by_value: dict[str, int] = {}

    for entity_type, values in detected.items():
        for value in values:
            start_at = cursor_by_value.get(value, 0)
            start = text.find(value, start_at)
            if start == -1:
                start = text.find(value)
            end = start + len(value) if start != -1 else -1
            cursor_by_value[value] = max(end, start_at)
            entities.append(
                {
                    "type": entity_type,
                    "start": start,
                    "end": end,
                    "score": 0.0,
                    "text": value,
                    "replacement": f"[{_placeholder_label(entity_type)}]",
                }
            )

    return sorted(entities, key=lambda item: (item["start"] if item["start"] >= 0 else 10**9, item["type"]))


def _normalize_entities(text: str, entities: list[dict[str, Any]]) -> list[PiiEntity]:
    normalized: list[PiiEntity] = []

    for entity in entities:
        label = str(entity.get("suggested_label") or entity.get("label") or "").strip()
        if not label:
            continue

        start = _coerce_int(entity.get("start_position", entity.get("start")))
        end = _coerce_int(entity.get("end_position", entity.get("end")))
        if start is None or end is None or start < 0 or end <= start or end > len(text):
            continue

        score = _coerce_float(entity.get("score")) or 0.0
        normalized.append(
            PiiEntity(
                type=label,
                start=start,
                end=end,
                score=round(score, 4),
                text=text[start:end],
                replacement=f"[{_placeholder_label(label)}]",
            )
        )

    return normalized


def _filter_overlaps(entities: list[PiiEntity]) -> list[PiiEntity]:
    selected: list[PiiEntity] = []
    occupied: list[range] = []

    for entity in sorted(
        entities,
        key=lambda item: (item.score, item.end - item.start),
        reverse=True,
    ):
        entity_range = range(entity.start, entity.end)
        if any(_ranges_overlap(entity_range, existing) for existing in occupied):
            continue
        selected.append(entity)
        occupied.append(entity_range)

    return sorted(selected, key=lambda item: item.start)


def _ranges_overlap(left: range, right: range) -> bool:
    return left.start < right.stop and right.start < left.stop


def _mask_text(text: str, entities: list[PiiEntity]) -> str:
    masked = text
    for entity in sorted(entities, key=lambda item: item.start, reverse=True):
        masked = masked[: entity.start] + entity.replacement + masked[entity.end :]
    return masked


def _placeholder_label(label: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", label.upper()).strip("_")


def _is_hosted_nvidia_endpoint(server_endpoint: str) -> bool:
    return "integrate.api.nvidia.com" in server_endpoint


def _normalize_provider(provider: str | None) -> str:
    raw = (provider or os.getenv("PII_PROVIDER") or DEFAULT_PROVIDER).strip().lower()
    normalized = raw.replace("_", "-")
    if normalized in {"nemo", "nemo-gliner", "nemo-gliner-pii", "gliner"}:
        return NEMO_PROVIDER
    if normalized in {"openai", "openai-guardrails", "openai-guardrails-pii", "presidio"}:
        return OPENAI_GUARDRAILS_PROVIDER
    raise ValueError(
        "provider must be one of: "
        f"{NEMO_PROVIDER}, {OPENAI_GUARDRAILS_PROVIDER}"
    )


def default_language_for_provider(provider: str | None) -> str:
    provider_name = _normalize_provider(provider)
    if provider_name == OPENAI_GUARDRAILS_PROVIDER:
        return DEFAULT_OPENAI_GUARDRAILS_LANGUAGE
    return DEFAULT_NEMO_LANGUAGE


def _normalize_language(language: str, aliases: dict[str, str]) -> str | None:
    raw = language.strip().lower().replace("_", "-")
    return aliases.get(raw)


def _coerce_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int_env(name: str) -> int | None:
    value = os.getenv(name)
    return _coerce_int(value) if value else None


def _bool_env(name: str) -> bool | None:
    value = os.getenv(name)
    if value is None:
        return None
    return value.strip().lower() in {"1", "true", "yes", "on"}
