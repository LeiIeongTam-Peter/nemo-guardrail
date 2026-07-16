from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from nemoguardrails.library.gliner.request import gliner_request


DEFAULT_NEMO_LANGUAGE = "auto"
DEFAULT_SCORE_THRESHOLD = 0.5
DEFAULT_PROVIDER = "nemo"
NEMO_PROVIDER = "nemo"
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

    async def preview(
        self,
        text: str,
        language: str | None = None,
        score_threshold: float = DEFAULT_SCORE_THRESHOLD,
        provider: str | None = None,
    ) -> dict[str, Any]:
        _normalize_provider(provider)
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
                enabled_entities=None,
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
            "masked": _mask_text(text, pii_entities),
            "entities": [entity.to_dict() for entity in pii_entities],
            "tagged_text": response.get("tagged_text", ""),
        }


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
    raw = (provider or DEFAULT_PROVIDER).strip().lower()
    normalized = raw.replace("_", "-")
    if normalized in {"nemo", "nemo-gliner", "nemo-gliner-pii", "gliner"}:
        return NEMO_PROVIDER
    raise ValueError("provider must be 'nemo'.")


def default_language_for_provider(provider: str | None) -> str:
    _normalize_provider(provider)
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
