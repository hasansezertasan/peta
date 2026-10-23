"""Shared Core Metadata parsing for locally installed and PyPI packages."""

from __future__ import annotations

from email.utils import getaddresses
from typing import TYPE_CHECKING, Literal, Protocol

from peta.core.models import CoreMetadata, EntryPointDeclaration, Person

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

__all__ = [
    "MODELED_HEADERS",
    "HeaderSource",
    "core_metadata_from_headers",
    "parse_people",
]

MODELED_HEADERS = frozenset(
    header.casefold()
    for header in (
        "Metadata-Version",
        "Name",
        "Version",
        "Summary",
        "Keywords",
        "Home-page",
        "Author",
        "Author-email",
        "Maintainer",
        "Maintainer-email",
        "License",
        "License-Expression",
        "License-File",
        "Classifier",
        "Requires-Dist",
        "Requires-Python",
        "Project-URL",
        "Provides-Extra",
        "Import-Name",
        "Import-Namespace",
        "Dynamic",
    )
)
"""Headers :class:`peta.core.models.CoreMetadata` has a typed field for.

Compared case-insensitively, as email headers are. Any other header an
installed distribution carries is kept verbatim in ``unrecognized``.
"""


def parse_people(names: str | None, emails: str | None) -> list[Person]:
    """Combine a legacy name field and an email field into people.

    ``Author-email`` is the only field that holds several people in a form
    that can be split reliably (``Name <addr>, Name <addr>``). ``Author`` is
    free text, so it is never split: it names the person when the email field
    carries one bare address, and otherwise is kept as its own name-only
    entry unless the email field already names it.

    Returns:
        The declared people, in declaration order.
    """
    parsed = [
        Person(name or None, address or None)
        for name, address in getaddresses([emails] if emails else [])
        if name or address
    ]
    if not names:
        return parsed
    if not parsed:
        return [Person(names, None)]
    if len(parsed) == 1 and parsed[0].name is None:
        return [Person(names, parsed[0].email)]
    if names in {person.name for person in parsed}:
        return parsed
    return [Person(names, None), *parsed]


class HeaderSource(Protocol):
    """The part of an email message Core Metadata is read through."""

    def get_all(self, name: str) -> list[str] | None:
        """Return every value of a header, or ``None`` when it is absent."""
        raise NotImplementedError

    def __iter__(self) -> Iterator[str]:
        """Iterate the header names, repeated once per occurrence."""
        raise NotImplementedError


def _all_headers(meta: HeaderSource, field: str) -> list[str]:
    return meta.get_all(field) or []


def _first_header(meta: HeaderSource, field: str) -> str | None:
    values = _all_headers(meta, field)
    return values[0] if values else None


def _joined_emails(meta: HeaderSource, field: str) -> str:
    return ", ".join(value for value in _all_headers(meta, field) if value)


def _unrecognized_headers(meta: HeaderSource) -> dict[str, list[str]]:
    # Header names are case-insensitive and ``get_all`` matches them so, so
    # each unknown header is keyed once, under its first spelling.
    names = {
        key.casefold(): key
        for key in reversed(list(meta))
        if key.casefold() not in MODELED_HEADERS
    }
    return {name: _all_headers(meta, name) for name in sorted(names.values())}


def core_metadata_from_headers(
    meta: HeaderSource,
    *,
    source: Literal["installed", "release_metadata"],
    entry_points: Iterable[EntryPointDeclaration] = (),
) -> CoreMetadata:
    """Map the headers of a ``METADATA`` file onto the Core Metadata model.

    Shared by the installed and the release readers so the two models stay
    aligned. Entry points are not headers, so the caller supplies them.

    Returns:
        The declared metadata, sourced as ``source`` says.
    """
    return CoreMetadata(
        source=source,
        metadata_version=_first_header(meta, "Metadata-Version"),
        license_files=_all_headers(meta, "License-File"),
        provides_extra=_all_headers(meta, "Provides-Extra"),
        import_names=_all_headers(meta, "Import-Name"),
        import_namespaces=_all_headers(meta, "Import-Namespace"),
        entry_points=list(entry_points),
        authors=parse_people(
            _first_header(meta, "Author"), _joined_emails(meta, "Author-email")
        ),
        maintainers=parse_people(
            _first_header(meta, "Maintainer"), _joined_emails(meta, "Maintainer-email")
        ),
        dynamic=_all_headers(meta, "Dynamic"),
        unrecognized=_unrecognized_headers(meta),
    )
