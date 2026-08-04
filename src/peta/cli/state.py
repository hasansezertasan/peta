"""Shared CLI state resolved once by the root callback."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["CliState"]


@dataclass(frozen=True)
class CliState:
    """Options resolved once at the root callback and shared by commands."""

    color: bool
