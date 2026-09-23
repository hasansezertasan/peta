"""Removing credentials from URLs before anything retains them.

Separate from :mod:`peta.core.cache` because nearly every layer needs it — the
transport, the validators, the output models, the CLI — and because the
validators must not depend on the cache: the cache itself reads its entries
through the validators' pre-decode scan.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

__all__ = ["redacted", "redacted_text"]

_CREDENTIAL_PARAMS = frozenset({
    "access_token",
    "api_key",
    "apikey",
    "key",
    "password",
    "secret",
    "token",
})
"""Query parameters redacted before a URL is hashed, stored, or reported.

Libraries.io takes its API key in the query string, so the URL peta requests
contains a credential. It must never reach the cache — neither in a file name
derived from it nor in the stored entry — because the cache outlives the
process and is world-readable in the user's home directory.

Redacting rather than including is also correct for the key: the response
depends on which package was asked about, not on who asked, so two users with
different keys should share one entry.
"""

_URL_IN_TEXT = re.compile(r"https?://[^\s'\"]+")
"""URLs that can appear inside an error message or other diagnostic string."""


def redacted(url: str) -> str:
    """Rewrite a URL with credential-bearing query parameters removed.

    Public because the cache is not the only place a request URL is retained:
    an error that names the URL it could not answer would otherwise carry the
    credential into a message, a log, or a traceback.

    Args:
        url: A request URL, possibly carrying a credential.

    Returns:
        The URL with any parameter named in :data:`_CREDENTIAL_PARAMS` dropped.
    """
    parts = urlsplit(url)
    if not parts.query:
        return url
    kept = [
        (name, value)
        for name, value in parse_qsl(parts.query, keep_blank_values=True)
        if name.lower() not in _CREDENTIAL_PARAMS
    ]
    return urlunsplit(parts._replace(query=urlencode(kept)))


def _redacted_match(url: str) -> str:
    """Redact one URL found inside free text, however malformed it is.

    :func:`redacted` parses, and a URL lifted out of untrusted metadata need
    not parse — ``https://[`` alone raises. Dropping the query outright is the
    safe answer for one of those: the credential cannot survive, and text that
    was never a real URL loses nothing that mattered.

    Returns:
        The URL with credential-bearing parameters removed.
    """
    try:
        return redacted(url)
    except ValueError:
        return url.split("?", 1)[0]


def redacted_text(value: str) -> str:
    """Redact credentials from every URL embedded in an arbitrary string.

    Returns:
        The original text with credentials removed from each HTTP(S) URL.
    """
    return _URL_IN_TEXT.sub(lambda match: _redacted_match(match.group()), value)
