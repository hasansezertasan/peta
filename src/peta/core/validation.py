"""Small runtime validators for decoded external API responses."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, cast

from peta.core.redaction import redacted_text

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

_JSON_STRING = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*(?:"|\\?\Z)', re.DOTALL)
"""One JSON string literal, or an unterminated one running to the end.

Two properties keep this linear, and both are needed. The body is an unrolled
loop rather than ``(?:[^"\\]|\\.)*``, whose alternation backtracks
catastrophically on a long run of escapes. And a literal with no closing quote
is allowed to end at the end of the input: without that, the match fails, the
engine restarts from the next ``"`` — every escaped quote is one — and scans to
the end again, so ``"\\"\\"\\"...`` costs quadratic time. 32 KB of it took
nearly two seconds; a full-size body would take hours. An unterminated string
is invalid JSON anyway, and the decoder rejects it once the scan is done.
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


def _without_strings(text: str, limit: int) -> tuple[str, bool]:
    """Remove every string literal, noting whether any was over the limit.

    The raw literal counts its quotes and escapes, so it can only overstate the
    decoded length: a string under the limit here is under it once decoded,
    which is the direction that matters.

    Returns:
        The text with string literals removed, and whether one was too long.
    """
    too_long = False

    def blank(match: re.Match[str]) -> str:
        nonlocal too_long
        too_long = too_long or len(match.group()) - 2 > limit
        return ""

    return _JSON_STRING.sub(blank, text), too_long


def structural_breach(text: str, *, string_limit: int | None = None) -> str | None:
    """Measure nesting and per-container size before anything is decoded.

    All three have to be measured here rather than by the validators.
    Nesting, because ``json.loads`` recurses and fails while parsing. Sizes,
    because the validators only visit fields peta consumes, and not every
    string they consume goes through :func:`expect_string`: an ignored
    ``"padding"`` array, or a long string inside a list, would be fully
    allocated by ``json.loads`` and never measured at all.

    Public because the cache reads JSON back from disk, which it treats as
    untrusted too, and needs the same bound before it decodes an entry. It
    passes its own ``string_limit``: an entry carries a whole response body as
    one string, which may rightly be far longer than any metadata field.
    ``None`` means :data:`MAX_STRING_LENGTH`, read at call time.

    Returns:
        A description of the first limit the document breaks, or ``None``.
    """
    limit = MAX_STRING_LENGTH if string_limit is None else string_limit
    stripped, too_long = _without_strings(text, limit)
    if too_long:
        return f"{limit:,} characters"
    open_counts = [0]
    for match in _STRUCTURAL.finditer(stripped):
        breach = _step(open_counts, match.group())
        if breach is not None:
            return breach
    return None


def json_body(response: httpx.Response, *, source: str) -> object:
    """Decode a JSON response, refusing one shaped to exhaust the process.

    Returns:
        The decoded body.

    Raises:
        ResponseLimitError: If the body nests past :data:`MAX_JSON_DEPTH`,
            any one array or object holds more than
            :data:`MAX_COLLECTION_ITEMS` items, or any string is longer than
            :data:`MAX_STRING_LENGTH`.
    """
    # Decoded here, once, exactly as ``json.loads`` would decode bytes, and
    # both the scan and the parser read this same text. ``response.text``
    # would follow the declared charset while ``response.json()`` sniffs the
    # bytes, so a response declaring ``charset=utf-16-le`` over a UTF-8 body
    # showed the scan harmless CJK text and the parser a bracket bomb.
    content = response.content
    text = content.decode(json.detect_encoding(content), "surrogatepass")
    breach = structural_breach(text)
    if breach is not None:
        raise ResponseLimitError(source, "$", breach)
    return cast("object", json.loads(text))


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
