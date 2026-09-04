"""Helpers for loading sanitized external API contract fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

_CONTRACTS = Path(__file__).parent / "fixtures" / "contracts"


def load_contract(name: str) -> object:
    """Load one decoded JSON contract fixture.

    Returns:
        The decoded fixture value.
    """
    return cast("object", json.loads((_CONTRACTS / name).read_text()))
