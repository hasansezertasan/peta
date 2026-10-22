"""Shared Core Metadata parsing for locally installed and PyPI packages."""

from __future__ import annotations

from email.utils import getaddresses

from peta.core.models import Person

__all__ = ["MODELED_HEADERS", "parse_people"]

MODELED_HEADERS = frozenset(
    header.casefold()
    for header in (
        "Metadata-Version",
        "Name",
        "Version",
        "Summary",
        "Description",
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
    carries one bare address, and stands alone when there is no email field.

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
    return parsed
