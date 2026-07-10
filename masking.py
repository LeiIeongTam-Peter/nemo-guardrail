import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Pattern

import yaml
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


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

    def with_rules(self, rules: list[MaskRule], prepend: bool = False) -> "Masker":
        if not rules:
            return self
        combined_rules = [*rules, *self.rules] if prepend else [*self.rules, *rules]
        return Masker(
            enabled=self.enabled,
            rules=combined_rules,
            collapse_blank_lines=self.collapse_blank_lines,
        )

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
        policy_loader: Callable[[str], Any | None] | None = None,
    ):
        self.app = app
        self.masker = masker
        self.path_prefixes = path_prefixes
        self.policy_loader = policy_loader

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self._should_mask(str(scope.get("path", ""))):
            await self.app(scope, receive, send)
            return

        body = await _read_body(receive)
        request_headers = _headers_to_dict(scope.get("headers", []))
        content_type = request_headers.get("content-type", "")
        active_masker = self.masker

        policy_result = self._resolve_policy_masker(body, content_type)
        if isinstance(policy_result, JSONResponse):
            await policy_result(scope, _empty_receive, send)
            return
        if policy_result is not None:
            active_masker, body = policy_result

        masked_body = active_masker.mask_body(body, content_type)
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
            masked_response_body = active_masker.mask_body(
                response_body,
                response_headers.get("content-type", ""),
            )
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

    def _resolve_policy_masker(
        self, body: bytes, content_type: str
    ) -> tuple[Masker, bytes] | JSONResponse | None:
        if self.policy_loader is None or not body or "application/json" not in content_type:
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

        policy_id = guardrails.get("policy_id")
        if not isinstance(policy_id, str) or not policy_id.strip():
            return _policy_error(400, "guardrails.policy_id must be a non-empty string.")

        policy = self.policy_loader(policy_id.strip())
        if policy is None:
            return _policy_error(404, f"Policy not found: {policy_id.strip()}")
        if not bool(getattr(policy, "enabled", False)):
            return _policy_error(400, f"Policy is disabled: {policy_id.strip()}")

        guardrails.pop("policy_id", None)
        policy_rules = build_keyword_rules(
            policy_id=str(getattr(policy, "id")),
            keywords=list(getattr(policy, "keywords")),
            replacement=str(getattr(policy, "replacement")),
            case_sensitive=bool(getattr(policy, "case_sensitive")),
        )
        policy_body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return self.masker.with_rules(policy_rules, prepend=True), policy_body


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


def build_keyword_rules(
    policy_id: str,
    keywords: list[str],
    replacement: str = "[REDACTED]",
    case_sensitive: bool = False,
) -> list[MaskRule]:
    rules: list[MaskRule] = []
    normalized_keywords = {keyword.strip().lower() for keyword in keywords}

    if normalized_keywords.intersection({"name", "姓名", "名字"}):
        rules.extend(_build_name_value_rules(policy_id, replacement, case_sensitive))

    rules.extend(
        [
            _build_rule(
                {
                    "name": f"policy:{policy_id}:{index}",
                    "type": "regex",
                    "pattern": _placeholder_safe_literal_pattern(keyword),
                    "replacement": replacement,
                    "case_sensitive": case_sensitive,
                }
            )
            for index, keyword in enumerate(keywords, start=1)
        ]
    )
    return rules


def _build_name_value_rules(policy_id: str, replacement: str, case_sensitive: bool) -> list[MaskRule]:
    return [
        _build_rule(
            {
                "name": f"policy:{policy_id}:english-name-phrase",
                "type": "regex",
                "pattern": (
                    r"\bmy\s+n?ame\s+is\s+"
                    r"[A-Za-z][A-Za-z'-]*(?:\s+[A-Za-z][A-Za-z'-]*){0,3}"
                    r"(?=\s*(?:[,.;!?]|$|\bmy\b|\band\b))"
                ),
                "replacement": f"my {replacement} is {replacement}",
                "case_sensitive": case_sensitive,
            }
        ),
        _build_rule(
            {
                "name": f"policy:{policy_id}:i-am-name-phrase",
                "type": "regex",
                "pattern": (
                    r"\b((?i:i)(?:\s+(?i:am)|['’](?i:m)))\s+"
                    r"[A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,3}"
                    r"(?=\s*(?:[,.;!?]|$|\b(?i:my)\b|\b(?i:and)\b|\b(?i:do)\b|\b(?i:what)\b))"
                ),
                "replacement": rf"\1 {replacement}",
                "case_sensitive": True,
            }
        ),
        _build_rule(
            {
                "name": f"policy:{policy_id}:assistant-greeting-name",
                "type": "regex",
                "pattern": (
                    r"\b((?i:hi|hello|hey))\s+"
                    r"[A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,3}"
                    r"(?=\s*[!,.?])"
                ),
                "replacement": rf"\1 {replacement}",
                "case_sensitive": True,
            }
        ),
        _build_rule(
            {
                "name": f"policy:{policy_id}:redacted-label-name-value",
                "type": "regex",
                "pattern": (
                    r"\b((?i:your|my)\s+\[REDACTED\]\s+(?i:is)\s+)"
                    r"[A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,3}"
                    r"(?=\s*(?:[,.;!?]|$))"
                ),
                "replacement": rf"\1{replacement}",
                "case_sensitive": True,
            }
        ),
        _build_rule(
            {
                "name": f"policy:{policy_id}:chinese-name-phrase",
                "type": "regex",
                "pattern": r"(?:我叫|我的名字是|我的姓名是|名字是|姓名是)[\u4e00-\u9fff]{2,4}",
                "replacement": replacement,
                "case_sensitive": case_sensitive,
            }
        )
    ]


def _placeholder_safe_literal_pattern(keyword: str) -> str:
    return rf"(?<!\[){re.escape(keyword)}(?!\])"


def _policy_error(status_code: int, message: str) -> JSONResponse:
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
