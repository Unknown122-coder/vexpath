"""Loads configuration, importing the vulnerable module as a side effect."""

from pathlib import Path
from typing import Any

import yaml


def load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data: dict[str, Any] = yaml.safe_load(handle) or {}
    return data
