import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Pattern

import yaml
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


@dataclass(frozen=True)
class MaskRule:
    name: str
    pattern: Pattern[str]
    replacement: str


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


class MaskingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, masker: Masker, path_prefixes: list[str]):
        super().__init__(app)
        self.masker = masker
        self.path_prefixes = path_prefixes

    async def dispatch(self, request: Request, call_next):
        if not self._should_mask(request.url.path):
            return await call_next(request)

        body = await request.body()
        masked_body = self.masker.mask_body(body, request.headers.get("content-type", ""))

        async def receive():
            return {
                "type": "http.request",
                "body": masked_body,
                "more_body": False,
            }

        masked_request = Request(request.scope, receive)
        response = await call_next(masked_request)

        response_body = b""
        async for chunk in response.body_iterator:
            response_body += chunk

        headers = dict(response.headers)
        headers.pop("content-length", None)
        masked_response_body = self.masker.mask_body(response_body, headers.get("content-type", ""))

        return Response(
            content=masked_response_body,
            status_code=response.status_code,
            headers=headers,
            media_type=response.media_type,
            background=response.background,
        )

    def _should_mask(self, path: str) -> bool:
        return self.masker.enabled and any(path.startswith(prefix) for prefix in self.path_prefixes)


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


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return bool(default)
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]
