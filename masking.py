import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Pattern

import yaml
from pii import (
    DEFAULT_SCORE_THRESHOLD,
    PiiConfigurationError,
    PiiProviderError,
    default_language_for_provider,
)
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


@dataclass(frozen=True)
class MaskRule:
    name: str
    pattern: Pattern[str]
    replacement: str


@dataclass(frozen=True)
class PiiMaskOptions:
    language: str
    score_threshold: float
    entities: list[str] | None
    provider: str | None = None
    detect_encoded_pii: bool = False


class Masker:
    def __init__(self, enabled: bool, rules: list[MaskRule], collapse_blank_lines: bool = True):
        self.enabled = enabled
        self.rules = rules
        self.collapse_blank_lines = collapse_blank_lines

    @property
    def rule_names(self) -> list[str]:
        return [rule.name for rule in self.rules]

    @classmethod
    def from_path(cls, path: str) -> "Masker":
        config_path = Path(path)
        data: dict[str, Any] = {}

        if config_path.exists():
            with config_path.open("r", encoding="utf-8") as file:
                data = yaml.safe_load(file) or {}

        enabled = _env_bool("MASKING_ENABLED", data.get("enabled", True))
        collapse_blank_lines = _env_bool(
            "MASKING_COLLAPSE_BLANK_LINES",
            data.get("collapse_blank_lines", True),
        )
        rules = [_build_rule(item) for item in data.get("rules", [])]

        env_keywords = _split_csv(os.getenv("MASK_KEYWORDS", ""))
        env_replacement = os.getenv("MASK_REPLACEMENT", "[REDACTED]")
        for keyword in env_keywords:
            rules.append(
                _build_rule(
                    {
                        "name": f"env:{keyword}",
                        "type": "literal",
                        "pattern": keyword,
                        "replacement": env_replacement,
                        "case_sensitive": False,
                    }
                )
            )

        return cls(enabled=enabled, rules=rules, collapse_blank_lines=collapse_blank_lines)

    def mask_text(self, text: str) -> str:
        if not self.enabled:
            return text

        masked = text
        for rule in self.rules:
            masked = rule.pattern.sub(rule.replacement, masked)
        if self.collapse_blank_lines:
            masked = re.sub(r"\n{3,}", "\n\n", masked)
        return masked

    def mask_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.mask_text(value)
        if isinstance(value, list):
            return [self.mask_value(item) for item in value]
        if isinstance(value, dict):
            return {key: self.mask_value(item) for key, item in value.items()}
        return value

    def mask_body(self, body: bytes, content_type: str) -> bytes:
        if not self.enabled or not body:
            return body

        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return body

        if "application/json" in content_type:
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                return self.mask_text(text).encode("utf-8")

            masked_payload = self.mask_value(payload)
            return json.dumps(masked_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

        if content_type.startswith("text/") or "event-stream" in content_type:
            return self.mask_text(text).encode("utf-8")

        return body


class MaskingMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        masker: Masker,
        path_prefixes: list[str],
        pii_detector: Any | None = None,
    ):
        self.app = app
        self.masker = masker
        self.path_prefixes = path_prefixes
        self.pii_detector = pii_detector

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self._should_mask(str(scope.get("path", ""))):
            await self.app(scope, receive, send)
            return

        body = await _read_body(receive)
        request_headers = _headers_to_dict(scope.get("headers", []))
        content_type = request_headers.get("content-type", "")

        legacy_policy_error = self._reject_unsupported_policy_id(body, content_type)
        if legacy_policy_error is not None:
            await legacy_policy_error(scope, _empty_receive, send)
            return

        pii_result = self._resolve_pii_options(body, content_type)
        if isinstance(pii_result, JSONResponse):
            await pii_result(scope, _empty_receive, send)
            return

        pii_options = None
        if pii_result is not None:
            pii_options, body = pii_result

        masked_body = self.masker.mask_body(body, content_type)
        if pii_options is not None:
            try:
                masked_body = await mask_pii_body(
                    masked_body,
                    content_type,
                    self.pii_detector,
                    pii_options,
                )
            except Exception as exc:
                await _pii_error_response(exc)(scope, _empty_receive, send)
                return

        response_started: Message | None = None
        response_body = b""
        request_body_sent = False

        async def masked_receive() -> Message:
            nonlocal request_body_sent
            if request_body_sent:
                return {
                    "type": "http.request",
                    "body": b"",
                    "more_body": False,
                }
            request_body_sent = True
            return {
                "type": "http.request",
                "body": masked_body,
                "more_body": False,
            }

        async def send_wrapper(message: Message) -> None:
            nonlocal response_body, response_started

            if message["type"] == "http.response.start":
                response_started = message
                return

            if message["type"] != "http.response.body":
                await send(message)
                return

            response_body += message.get("body", b"")
            if message.get("more_body", False):
                return

            if response_started is None:
                response_started = {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [],
                }

            response_headers = _headers_to_dict(response_started.get("headers", []))
            masked_response_body = self.masker.mask_body(
                response_body,
                response_headers.get("content-type", ""),
            )
            if pii_options is not None:
                try:
                    masked_response_body = await mask_pii_body(
                        masked_response_body,
                        response_headers.get("content-type", ""),
                        self.pii_detector,
                        pii_options,
                    )
                except Exception as exc:
                    await _pii_error_response(exc)(scope, _empty_receive, send)
                    return

            headers = [
                (key, value)
                for key, value in response_started.get("headers", [])
                if key.lower() != b"content-length"
            ]

            await send(
                {
                    **response_started,
                    "headers": headers,
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": masked_response_body,
                    "more_body": False,
                }
            )

        await self.app(scope, masked_receive, send_wrapper)

    def _should_mask(self, path: str) -> bool:
        return any(path.startswith(prefix) for prefix in self.path_prefixes)

    def _reject_unsupported_policy_id(self, body: bytes, content_type: str) -> JSONResponse | None:
        if not body or "application/json" not in content_type:
            return None

        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

        if not isinstance(payload, dict):
            return None

        guardrails = payload.get("guardrails")
        if not isinstance(guardrails, dict) or "policy_id" not in guardrails:
            return None

        return _json_error(
            400,
            "guardrails.policy_id is no longer supported. Use masking.yml rules or guardrails.enable_pii.",
        )

    def _resolve_pii_options(
        self, body: bytes, content_type: str
    ) -> tuple[PiiMaskOptions | None, bytes] | JSONResponse | None:
        if not body or "application/json" not in content_type:
            return None

        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

        if not isinstance(payload, dict):
            return None

        guardrails = payload.get("guardrails")
        if not isinstance(guardrails, dict) or "enable_pii" not in guardrails:
            return None

        enable_pii = guardrails.pop("enable_pii", False)
        provider = guardrails.pop("pii_provider", None)
        language = guardrails.pop("pii_language", None)
        score_threshold = guardrails.pop("pii_score_threshold", DEFAULT_SCORE_THRESHOLD)
        entities = guardrails.pop("pii_entities", None)
        detect_encoded_pii = guardrails.pop("pii_detect_encoded", False)

        if not isinstance(enable_pii, bool):
            return _json_error(400, "guardrails.enable_pii must be a boolean.")

        sanitized_body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if not enable_pii:
            return None, sanitized_body

        if self.pii_detector is None:
            return _json_error(503, "PII detector is not configured.")
        if provider is not None and not isinstance(provider, str):
            return _json_error(400, "guardrails.pii_provider must be a string.")
        if language is not None and not isinstance(language, str):
            return _json_error(400, "guardrails.pii_language must be a string.")
        if language is None:
            try:
                language = default_language_for_provider(provider)
            except ValueError as exc:
                return _json_error(400, str(exc))
        if not isinstance(score_threshold, int | float):
            return _json_error(400, "guardrails.pii_score_threshold must be a number.")
        if entities is not None and not (
            isinstance(entities, list) and all(isinstance(item, str) for item in entities)
        ):
            return _json_error(400, "guardrails.pii_entities must be a list of strings.")
        if not isinstance(detect_encoded_pii, bool):
            return _json_error(400, "guardrails.pii_detect_encoded must be a boolean.")

        return (
            PiiMaskOptions(
                language=language,
                score_threshold=float(score_threshold),
                entities=entities,
                provider=provider,
                detect_encoded_pii=detect_encoded_pii,
            ),
            sanitized_body,
        )


def _build_rule(data: dict[str, Any]) -> MaskRule:
    rule_type = data.get("type", "literal")
    pattern = str(data["pattern"])
    replacement = str(data.get("replacement", "[REDACTED]"))
    case_sensitive = bool(data.get("case_sensitive", True))
    flags = 0 if case_sensitive else re.IGNORECASE

    if rule_type == "literal":
        compiled = re.compile(re.escape(pattern), flags)
    elif rule_type == "regex":
        compiled = re.compile(pattern, flags)
    else:
        raise ValueError(f"Unsupported masking rule type: {rule_type}")

    return MaskRule(
        name=str(data.get("name", pattern)),
        pattern=compiled,
        replacement=replacement,
    )


async def mask_pii_body(
    body: bytes,
    content_type: str,
    pii_detector: Any,
    options: PiiMaskOptions,
) -> bytes:
    if not body:
        return body

    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return body

    if "application/json" in content_type:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            masked = await _mask_pii_text(text, pii_detector, options)
            return masked.encode("utf-8")

        masked_payload = await mask_pii_value(payload, pii_detector, options)
        return json.dumps(masked_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    if content_type.startswith("text/") or "event-stream" in content_type:
        masked = await _mask_pii_text(text, pii_detector, options)
        return masked.encode("utf-8")

    return body


async def mask_pii_value(
    value: Any,
    pii_detector: Any,
    options: PiiMaskOptions,
    key: str | None = None,
) -> Any:
    if isinstance(value, str):
        if _should_pii_mask_key(key):
            return await _mask_pii_text(value, pii_detector, options)
        return value
    if isinstance(value, list):
        return [await mask_pii_value(item, pii_detector, options, key=key) for item in value]
    if isinstance(value, dict):
        return {
            item_key: await mask_pii_value(item, pii_detector, options, key=str(item_key))
            for item_key, item in value.items()
        }
    return value


async def _mask_pii_text(text: str, pii_detector: Any, options: PiiMaskOptions) -> str:
    if not text.strip():
        return text

    result = await pii_detector.preview(
        text=text,
        language=options.language,
        score_threshold=options.score_threshold,
        entities=options.entities,
        provider=options.provider,
        detect_encoded_pii=options.detect_encoded_pii,
    )
    return str(result.get("masked", text))


def _should_pii_mask_key(key: str | None) -> bool:
    return key in {"content", "text"}


def _pii_error_response(exc: Exception) -> JSONResponse:
    if isinstance(exc, PiiConfigurationError):
        return _json_error(503, str(exc))
    if isinstance(exc, PiiProviderError):
        return _json_error(502, str(exc))
    if isinstance(exc, ValueError):
        return _json_error(400, str(exc))
    return _json_error(500, f"PII masking failed: {exc}")


def _json_error(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": message})


async def _read_body(receive: Receive) -> bytes:
    body = b""
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return body
        if message["type"] != "http.request":
            continue
        body += message.get("body", b"")
        if not message.get("more_body", False):
            return body


async def _empty_receive() -> Message:
    return {"type": "http.request", "body": b"", "more_body": False}


def _headers_to_dict(headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
    return {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in headers
    }


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return bool(default)
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]
