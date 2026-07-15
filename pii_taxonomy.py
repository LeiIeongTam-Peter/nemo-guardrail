from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


DEFAULT_TAXONOMY_PATH = Path(__file__).parent / "pii_taxonomy.yml"


def load_pii_taxonomy(path: str | Path = DEFAULT_TAXONOMY_PATH) -> dict[str, Any]:
    taxonomy_path = Path(path)
    if not taxonomy_path.exists():
        return {
            "version": 1,
            "description": "No PII taxonomy file was found.",
            "providers": {},
            "entities": [],
        }

    with taxonomy_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    if not isinstance(data, dict):
        raise ValueError("PII taxonomy must be a YAML mapping.")
    if "entities" in data and not isinstance(data["entities"], list):
        raise ValueError("PII taxonomy entities must be a list.")

    data.setdefault("version", 1)
    data.setdefault("providers", {})
    data.setdefault("entities", [])
    return data
