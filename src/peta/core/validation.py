"""Small runtime validators for decoded external API responses."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, cast

from peta.core.cache import redacted_text

if TYPE_CHECKING:
    import httpx

__all__ = [
    "EnrichmentError",
    "ResponseLimitError",
    "ResponseValidationError",
    "expect_int",
    "expect_list",
    "expect_mapping",
    "expect_string",
    "json_body",
    "optional_string",
    "optional_string_list",
    "optional_string_mapping",
]

MAX_COLLECTION_ITEMS = 1_000_000
"""Largest JSON object or array accepted from an untrusted response.

The response-size limit is what bounds realistic entries: ``grpcio``, the
densest package measured, lists 10,641 files at about 630 bytes each, so the
body cap stops it near 100,000. This limit is for the cheap case the body cap
cannot see — ``[0,0,0,...]`` packs 32 million items into 64 MiB, each of which
costs far more to hold as a Python object than it did as two bytes of JSON.
The previous value of 10,000 rejected ``grpcio`` outright.
"""

MAX_STRING_LENGTH = 8 * 1024 * 1024
"""Largest individual metadata string accepted from an untrusted response.

Descriptions are the long ones. The largest measured is a few kilobytes, but a
README with base64-embedded images can reach megabytes, so the ceiling is set
well above anything ordinary rather than at what was seen.
"""

MAX_JSON_DEPTH = 100
"""Deepest nesting accepted from an untrusted response.

Checked before decoding rather than after. ``json.loads`` recurses, so a
payload nested past the interpreter's stack raises ``RecursionError`` while
parsing — long before any validator could measure it — and ``RecursionError``
is a ``RuntimeError``, so the ``except ValueError`` each decoder wraps its
``.json()`` call in does not catch it. 120 KB of nested brackets is enough,
which the response-size limit is far too coarse to stop.
"""

_JSON_STRING = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"', re.DOTALL)
"""One complete JSON string literal.

Written as an unrolled loop rather than ``(?:[^"\\]|\\.)*`` so that it runs in
linear time: the alternation form backtracks catastrophically on a long run of
escapes, which would hand an attacker the denial of service this scan exists
to prevent.
"""

_OPENING = frozenset("[{")
_CLOSING = frozenset("]}")
_STRUCTURAL = re.compile(r"[\[\]{},]")
"""The only characters that change a document's shape once strings are gone.

Matching them with a regex lets the scan skip every other byte in C rather
than visiting each one in a Python loop.
"""


class EnrichmentError(Exception):
    """A source-specific failure from an optional external API."""

    def __init__(self, source: str, reason: str, *, contacted: bool = True) -> None:
        """Store the failed source, safe diagnostic reason, and whether it ran.

        Args:
            source: The source that failed.
            reason: A diagnostic to show a user. Credentials are stripped from
                any URL it names, here rather than at each call site: most of
                these reasons are ``str(exc)`` on a transport error, which
                quotes the request URL, and Libraries.io carries its API key
                in the query string.
            contacted: Whether a request was actually made. ``False`` for a
                refusal that never reached the network — being offline — so
                the resulting record can omit a retrieval time instead of
                claiming one for a source nothing was sent to.
        """
        self.source: str = source
        self.reason: str = redacted_text(reason)
        self.contacted: bool = contacted
        super().__init__(f"{source}: {self.reason}")


class ResponseValidationError(ValueError):
    """Raised when an external response does not match its consumed contract."""

    def __init__(self, source: str, path: str, expected: str) -> None:
        """Describe the source, JSON path, and expected value type."""
        super().__init__(f"{source} field {path} must be {expected}")


class ResponseLimitError(ResponseValidationError):
    """Raised when a response is well formed but past one of peta's limits.

    Separate from its parent so that a refusal on size does not claim the
    value had the wrong type. An array of 10,001 items *is* an array, and
    reporting it as "must be an array" sends whoever debugs it to check the
    response shape, find it correct, and lose the trail.
    """

    def __init__(self, source: str, path: str, limit: str) -> None:
        """Describe the source, JSON path, and the limit that was exceeded."""
        super().__init__(source, path, f"at most {limit}")


def _step(open_counts: list[int], token: str) -> str | None:
    """Apply one structural token to the scan, reporting any limit it breaks.

    ``open_counts`` holds an item count per container still open, over a
    sentinel for the top level so that malformed input — a stray ``,`` or
    ``]`` — cannot underflow it; the decoder rejects such input afterwards.
    Counting commas plus one overstates an empty container by one item, which
    is harmless for an upper bound.

    Returns:
        A description of the limit broken, or ``None``.
    """
    if token in _OPENING:
        open_counts.append(1)
        too_deep = len(open_counts) - 1 > MAX_JSON_DEPTH
        return f"{MAX_JSON_DEPTH} levels deep" if too_deep else None
    if token in _CLOSING:
        if len(open_counts) > 1:
            _ = open_counts.pop()
        return None
    open_counts[-1] += 1
    too_many = open_counts[-1] > MAX_COLLECTION_ITEMS
    return f"{MAX_COLLECTION_ITEMS:,} items" if too_many else None


def _structural_breach(text: str) -> str | None:
    """Measure nesting and per-container size before anything is decoded.

    Both have to be measured here rather than by the validators. Nesting,
    because ``json.loads`` recurses and fails while parsing. Size, because the
    validators only visit fields peta consumes: an ignored ``"padding"`` array
    of tens of millions of zeros would be fully allocated by ``json.loads``
    and never measured at all.

    Returns:
        A description of the first limit the document breaks, or ``None``.
    """
    open_counts = [0]
    for match in _STRUCTURAL.finditer(_JSON_STRING.sub("", text)):
        breach = _step(open_counts, match.group())
        if breach is not None:
            return breach
    return None


def json_body(response: httpx.Response, *, source: str) -> object:
    """Decode a JSON response, refusing one shaped to exhaust the process.

    Returns:
        The decoded body.

    Raises:
        ResponseLimitError: If the body nests past :data:`MAX_JSON_DEPTH`, or
            any one array or object holds more than
            :data:`MAX_COLLECTION_ITEMS` items.
    """
    breach = _structural_breach(response.text)
    if breach is not None:
        raise ResponseLimitError(source, "$", breach)
    return cast("object", response.json())


def expect_mapping(value: object, *, source: str, path: str) -> dict[str, object]:
    """Require a JSON object with string keys.

    Returns:
        The validated mapping.

    Raises:
        ResponseValidationError: If the value is not a string-keyed mapping.
        ResponseLimitError: If the object holds more than the item limit.
    """
    if not isinstance(value, dict):
        raise ResponseValidationError(source, path, "an object")
    raw = cast("dict[object, object]", value)
    if len(raw) > MAX_COLLECTION_ITEMS:
        raise ResponseLimitError(source, path, f"{MAX_COLLECTION_ITEMS:,} entries")
    if not all(isinstance(key, str) for key in raw):
        raise ResponseValidationError(source, path, "an object")
    return cast("dict[str, object]", value)


def expect_list(value: object, *, source: str, path: str) -> list[object]:
    """Require a JSON array.

    Returns:
        The validated list.

    Raises:
        ResponseValidationError: If the value is not a list.
        ResponseLimitError: If the array holds more than the item limit.
    """
    if not isinstance(value, list):
        raise ResponseValidationError(source, path, "an array")
    values = cast("list[object]", value)
    if len(values) > MAX_COLLECTION_ITEMS:
        raise ResponseLimitError(source, path, f"{MAX_COLLECTION_ITEMS:,} items")
    return values


def expect_string(value: object, *, source: str, path: str) -> str:
    """Require a string value.

    Returns:
        The validated string.

    Raises:
        ResponseValidationError: If the value is not a string.
        ResponseLimitError: If the string is longer than the length limit.
    """
    if not isinstance(value, str):
        raise ResponseValidationError(source, path, "a string")
    if len(value) > MAX_STRING_LENGTH:
        raise ResponseLimitError(source, path, f"{MAX_STRING_LENGTH:,} characters")
    return value


def optional_string(
    mapping: dict[str, object], key: str, *, source: str, path: str
) -> str | None:
    """Validate an optional nullable string field.

    Returns:
        The string, or ``None`` when the field is absent or null.
    """
    value = mapping.get(key)
    if value is None:
        return None
    return expect_string(value, source=source, path=f"{path}.{key}")


def optional_string_list(
    mapping: dict[str, object], key: str, *, source: str, path: str
) -> list[str] | None:
    """Validate an optional nullable array of strings.

    Returns:
        The string list, or ``None`` when the field is absent or null.

    Raises:
        ResponseValidationError: If a present value is not a list of strings.
    """
    value = mapping.get(key)
    if value is None:
        return None
    values = expect_list(value, source=source, path=f"{path}.{key}")
    if not all(isinstance(item, str) for item in values):
        raise ResponseValidationError(source, f"{path}.{key}[]", "a string")
    return cast("list[str]", values)


def optional_string_mapping(
    mapping: dict[str, object], key: str, *, source: str, path: str
) -> dict[str, str] | None:
    """Validate an optional nullable string-to-string object.

    Returns:
        The validated mapping, or ``None`` when the field is absent or null.

    Raises:
        ResponseValidationError: If a present value is not a string mapping.
    """
    value = mapping.get(key)
    if value is None:
        return None
    values = expect_mapping(value, source=source, path=f"{path}.{key}")
    if not all(isinstance(item, str) for item in values.values()):
        raise ResponseValidationError(source, f"{path}.{key}.*", "a string")
    return cast("dict[str, str]", values)


def expect_int(value: object, *, source: str, path: str) -> int:
    """Require an integer while rejecting JSON booleans.

    Returns:
        The validated integer.

    Raises:
        ResponseValidationError: If the value is not a genuine integer.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ResponseValidationError(source, path, "an integer")
    return value
