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


def _nesting_depth(text: str) -> int:
    """Measure how deeply a JSON document nests, ignoring string contents.

    Returns:
        The greatest nesting depth the document reaches.
    """
    depth = deepest = 0
    for character in _JSON_STRING.sub("", text):
        if character in _OPENING:
            depth += 1
            deepest = max(deepest, depth)
        elif character in _CLOSING:
            depth -= 1
    return deepest


def json_body(response: httpx.Response, *, source: str) -> object:
    """Decode a JSON response, refusing one nested deeply enough to crash.

    Returns:
        The decoded body.

    Raises:
        ResponseLimitError: If the body nests past :data:`MAX_JSON_DEPTH`.
    """
    if _nesting_depth(response.text) > MAX_JSON_DEPTH:
        raise ResponseLimitError(source, "$", f"{MAX_JSON_DEPTH} levels deep")
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
