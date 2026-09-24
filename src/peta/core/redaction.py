"""Removing credentials from URLs before anything retains them.

Separate from :mod:`peta.core.cache` because nearly every layer needs it — the
transport, the validators, the output models, the CLI — and because the
validators must not depend on the cache: the cache itself reads its entries
through the validators' pre-decode scan.
"""

from __future__ import annotations

import re
from urllib.parse import unquote_plus, urlsplit, urlunsplit

__all__ = ["redacted", "redacted_text"]

_CREDENTIAL_PARAMS = frozenset({
    "access_token",
    "api_key",
    "apikey",
    "key",
    "password",
    "secret",
    "token",
    # Signed URLs, which an index can use for provenance or file links: the
    # signature authorizes the request on its own, and the credential and
    # session-token parameters beside it identify the signer.
    "sig",
    "signature",
    "x-amz-credential",
    "x-amz-security-token",
    "x-amz-signature",
    "x-goog-credential",
    "x-goog-signature",
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

_QUERY_SEPARATOR = re.compile(r"[&;]")

_MAX_QUERY_FIELDS = 1000
"""Most query fields a URL may have before its query is dropped unparsed."""

_USERINFO = re.compile(r"^(https?://)[^/@]*@")
"""The ``user:password@`` part of a URL too malformed for ``urlsplit``."""

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
        The URL without userinfo, and with any parameter named in
        :data:`_CREDENTIAL_PARAMS` dropped.
    """
    parts = urlsplit(url)
    if "@" in parts.netloc:
        # ``https://{user}:{token}@index/`` is how a private index is usually
        # configured, and the userinfo is the credential itself.
        parts = parts._replace(netloc=parts.netloc.rpartition("@")[2])
        url = urlunsplit(parts)
    if not parts.query:
        return url
    if parts.query.count("&") + parts.query.count(";") >= _MAX_QUERY_FIELDS:
        # Dropped whole, unread. A diagnostic can quote a URL an index chose,
        # and parsing millions of empty fields would allocate a tuple for
        # each before anything was reported; no real URL has this many.
        return urlunsplit(parts._replace(query=""))
    # Split on ``;`` as well as ``&`` rather than through ``parse_qsl``, which
    # only splits on ``&``: ``?ok=1;token=s3cret`` read as one field named
    # ``ok`` and kept the token. Each field is judged by its decoded name, so
    # ``%74oken`` is caught too, and a kept field passes through verbatim.
    kept = [
        field
        for field in _QUERY_SEPARATOR.split(parts.query)
        if unquote_plus(field.partition("=")[0]).lower() not in _CREDENTIAL_PARAMS
    ]
    return urlunsplit(parts._replace(query="&".join(kept)))


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
        return _USERINFO.sub(r"\1", url.split("?", 1)[0])


def redacted_text(value: str) -> str:
    """Redact credentials from every URL embedded in an arbitrary string.

    Returns:
        The original text with credentials removed from each HTTP(S) URL.
    """
    return _URL_IN_TEXT.sub(lambda match: _redacted_match(match.group()), value)
