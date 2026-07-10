from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


DEFAULT_REPLACEMENT = "[REDACTED]"
MAX_KEYWORDS = 500
MAX_KEYWORD_LENGTH = 256
POLICY_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class PolicyError(Exception):
    pass


class PolicyValidationError(PolicyError):
    pass


class PolicyConflictError(PolicyError):
    pass


@dataclass(frozen=True)
class Policy:
    id: str
    name: str
    description: str
    enabled: bool
    replacement: str
    case_sensitive: bool
    keywords: list[str]
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "replacement": self.replacement,
            "case_sensitive": self.case_sensitive,
            "keywords": self.keywords,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class PolicyStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def list_policies(self) -> list[Policy]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, name, description, enabled, replacement, case_sensitive,
                       keywords_json, created_at, updated_at
                FROM policies
                ORDER BY updated_at DESC, id ASC
                """
            ).fetchall()
        return [_row_to_policy(row) for row in rows]

    def get_policy(self, policy_id: str) -> Policy | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, name, description, enabled, replacement, case_sensitive,
                       keywords_json, created_at, updated_at
                FROM policies
                WHERE id = ?
                """,
                (policy_id,),
            ).fetchone()
        return _row_to_policy(row) if row else None

    def create_policy(self, data: dict[str, Any]) -> Policy:
        now = _utc_now()
        policy = _validate_policy_data(data, created_at=now, updated_at=now)

        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO policies (
                        id, name, description, enabled, replacement, case_sensitive,
                        keywords_json, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    _policy_params(policy),
                )
        except sqlite3.IntegrityError as exc:
            raise PolicyConflictError(f"Policy already exists: {policy.id}") from exc

        return policy

    def update_policy(self, policy_id: str, data: dict[str, Any]) -> Policy | None:
        existing = self.get_policy(policy_id)
        if existing is None:
            return None
        if "id" in data and data["id"] != policy_id:
            raise PolicyValidationError("body id must match path id.")

        now = _utc_now()
        merged = existing.to_dict()
        merged.update(data)
        merged["id"] = policy_id
        policy = _validate_policy_data(merged, created_at=existing.created_at, updated_at=now)

        with self._connect() as connection:
            connection.execute(
                """
                UPDATE policies
                SET name = ?,
                    description = ?,
                    enabled = ?,
                    replacement = ?,
                    case_sensitive = ?,
                    keywords_json = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    policy.name,
                    policy.description,
                    int(policy.enabled),
                    policy.replacement,
                    int(policy.case_sensitive),
                    json.dumps(policy.keywords, ensure_ascii=False),
                    policy.updated_at,
                    policy.id,
                ),
            )

        return policy

    def delete_policy(self, policy_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM policies WHERE id = ?", (policy_id,))
        return cursor.rowcount > 0

    def _init_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS policies (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    replacement TEXT NOT NULL,
                    case_sensitive INTEGER NOT NULL,
                    keywords_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection


def _validate_policy_data(data: dict[str, Any], created_at: str, updated_at: str) -> Policy:
    if not isinstance(data, dict):
        raise PolicyValidationError("Policy payload must be an object.")

    policy_id = _validate_policy_id(data.get("id"))
    name = _validate_string(data.get("name", policy_id), "name", allow_empty=False, max_length=128)
    description = _validate_string(data.get("description", ""), "description", allow_empty=True, max_length=500)
    enabled = _validate_bool(data.get("enabled", True), "enabled")
    replacement = _validate_string(
        data.get("replacement", DEFAULT_REPLACEMENT),
        "replacement",
        allow_empty=False,
        max_length=128,
    )
    case_sensitive = _validate_bool(data.get("case_sensitive", False), "case_sensitive")
    keywords = _validate_keywords(data.get("keywords"))

    return Policy(
        id=policy_id,
        name=name,
        description=description,
        enabled=enabled,
        replacement=replacement,
        case_sensitive=case_sensitive,
        keywords=keywords,
        created_at=created_at,
        updated_at=updated_at,
    )


def _validate_policy_id(value: Any) -> str:
    if not isinstance(value, str) or not POLICY_ID_PATTERN.fullmatch(value):
        raise PolicyValidationError("id must be 1-64 characters using letters, numbers, '_' or '-'.")
    return value


def _validate_string(value: Any, field: str, allow_empty: bool, max_length: int) -> str:
    if not isinstance(value, str):
        raise PolicyValidationError(f"{field} must be a string.")

    normalized = value.strip()
    if not allow_empty and not normalized:
        raise PolicyValidationError(f"{field} must not be empty.")
    if len(normalized) > max_length:
        raise PolicyValidationError(f"{field} must be at most {max_length} characters.")
    return normalized


def _validate_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyValidationError(f"{field} must be a boolean.")
    return value


def _validate_keywords(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise PolicyValidationError("keywords must be a list of strings.")
    if len(value) > MAX_KEYWORDS:
        raise PolicyValidationError(f"keywords must contain at most {MAX_KEYWORDS} items.")

    keywords: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise PolicyValidationError("keywords must contain only strings.")

        keyword = item.strip()
        if not keyword:
            raise PolicyValidationError("keywords must not contain empty strings.")
        if len(keyword) > MAX_KEYWORD_LENGTH:
            raise PolicyValidationError(
                f"keywords must be at most {MAX_KEYWORD_LENGTH} characters each."
            )
        if keyword not in seen:
            keywords.append(keyword)
            seen.add(keyword)

    if not keywords:
        raise PolicyValidationError("keywords must contain at least one item.")
    return keywords


def _row_to_policy(row: sqlite3.Row) -> Policy:
    return Policy(
        id=str(row["id"]),
        name=str(row["name"]),
        description=str(row["description"]),
        enabled=bool(row["enabled"]),
        replacement=str(row["replacement"]),
        case_sensitive=bool(row["case_sensitive"]),
        keywords=list(json.loads(row["keywords_json"])),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _policy_params(policy: Policy) -> tuple[Any, ...]:
    return (
        policy.id,
        policy.name,
        policy.description,
        int(policy.enabled),
        policy.replacement,
        int(policy.case_sensitive),
        json.dumps(policy.keywords, ensure_ascii=False),
        policy.created_at,
        policy.updated_at,
    )


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
