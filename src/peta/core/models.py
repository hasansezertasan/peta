"""Core data models for peta."""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["PackageInfo", "Vulnerability"]


@dataclass
class Vulnerability:
    """A known security vulnerability for a package."""

    id: str
    aliases: list[str]
    summary: str
    fixed_in: list[str]
    severity: str | None = None


@dataclass
class PackageInfo:
    """Package metadata from a local installation or PyPI."""

    name: str
    version: str
    source: str  # "local" or "remote"

    summary: str | None = None
    author: str | None = None
    author_email: str | None = None
    maintainer: str | None = None
    license: str | None = None
    python_requires: str | None = None
    homepage: str | None = None
    project_urls: dict[str, str] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    classifiers: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    files: list[str] | None = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
