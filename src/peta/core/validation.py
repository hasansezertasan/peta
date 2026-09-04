"""Small runtime validators for decoded external API responses."""

from __future__ import annotations

from typing import cast

__all__ = [
    "EnrichmentError",
    "ResponseValidationError",
    "expect_int",
    "expect_list",
    "expect_mapping",
    "expect_string",
    "optional_string",
    "optional_string_list",
    "optional_string_mapping",
]


class EnrichmentError(Exception):
    """A source-specific failure from an optional external API."""

    def __init__(self, source: str, reason: str) -> None:
        """Store the failed source and safe diagnostic reason."""
        self.source: str = source
        self.reason: str = reason
        super().__init__(f"{source}: {reason}")


class ResponseValidationError(ValueError):
    """Raised when an external response does not match its consumed contract."""

    def __init__(self, source: str, path: str, expected: str) -> None:
        """Describe the source, JSON path, and expected value type."""
        super().__init__(f"{source} field {path} must be {expected}")


def expect_mapping(value: object, *, source: str, path: str) -> dict[str, object]:
    """Require a JSON object with string keys.

    Returns:
        The validated mapping.

    Raises:
        ResponseValidationError: If the value is not a string-keyed mapping.
    """
    if not isinstance(value, dict):
        raise ResponseValidationError(source, path, "an object")
    raw = cast("dict[object, object]", value)
    if not all(isinstance(key, str) for key in raw):
        raise ResponseValidationError(source, path, "an object")
    return cast("dict[str, object]", value)


def expect_list(value: object, *, source: str, path: str) -> list[object]:
    """Require a JSON array.

    Returns:
        The validated list.

    Raises:
        ResponseValidationError: If the value is not a list.
    """
    if not isinstance(value, list):
        raise ResponseValidationError(source, path, "an array")
    return cast("list[object]", value)


def expect_string(value: object, *, source: str, path: str) -> str:
    """Require a string value.

    Returns:
        The validated string.

    Raises:
        ResponseValidationError: If the value is not a string.
    """
    if not isinstance(value, str):
        raise ResponseValidationError(source, path, "a string")
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
