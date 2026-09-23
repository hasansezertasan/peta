"""Security limits for decoded untrusted API responses."""

import json

import httpx
import pytest

from peta.core import validation

pytestmark = pytest.mark.unit


def _response(body: bytes) -> httpx.Response:
    """Build a JSON response carrying exactly these bytes.

    Returns:
        A response the decoder can be pointed at.
    """
    return httpx.Response(
        200, content=body, headers={"content-type": "application/json"}
    )


class TestLimitsAreReportedHonestly:
    """A refusal on size must not claim the value had the wrong type.

    An array of 10,001 items is still an array. Reporting it as "must be an
    array" sends whoever debugs it to check the response shape, find it
    correct, and lose the trail.
    """

    # The real limits are large enough that building a value past them is slow
    # and memory-hungry, so these tests shrink them; what is under test is the
    # comparison and the wording, not the particular number.

    def test_an_excessive_array_is_refused_as_a_limit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(validation, "MAX_COLLECTION_ITEMS", 3)

        with pytest.raises(validation.ResponseLimitError, match="at most 3 items"):
            _ = validation.expect_list([None] * 4, source="test", path="$")

    def test_an_excessive_string_is_refused_as_a_limit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(validation, "MAX_STRING_LENGTH", 3)

        with pytest.raises(validation.ResponseLimitError, match="at most 3 characters"):
            _ = validation.expect_string("abcd", source="test", path="$.name")

    def test_an_excessive_mapping_is_refused_as_a_limit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(validation, "MAX_COLLECTION_ITEMS", 3)
        value = {str(index): 1 for index in range(4)}

        with pytest.raises(validation.ResponseLimitError, match="at most 3 entries"):
            _ = validation.expect_mapping(value, source="test", path="$")

    def test_the_largest_real_package_fits(self) -> None:
        # grpcio's Simple API page lists 10,641 files. The first version of
        # this limit was 10,000, which broke ``peta versions grpcio`` outright.
        files = [{"filename": "x"}] * 10_641

        assert validation.expect_list(files, source="test", path="$.files") is files

    @pytest.mark.parametrize(
        ("value", "expected"), [(42, "must be an array"), ("x", "must be an array")]
    )
    def test_a_wrong_type_still_reports_the_type(
        self, value: object, expected: str
    ) -> None:
        with pytest.raises(validation.ResponseValidationError, match=expected):
            _ = validation.expect_list(value, source="test", path="$")

    def test_a_limit_error_is_still_a_validation_error(self) -> None:
        # Every decoder already maps ResponseValidationError onto its own
        # error type; a limit breach must keep travelling that same path.
        assert issubclass(
            validation.ResponseLimitError, validation.ResponseValidationError
        )


class TestNestingDepth:
    """Depth has to be checked before decoding, not after.

    ``json.loads`` recurses, so an over-nested payload raises ``RecursionError``
    while parsing, before any validator can see a decoded value — and
    ``RecursionError`` is a ``RuntimeError``, which the ``except ValueError``
    around each decode does not catch.
    """

    def test_a_deeply_nested_body_is_refused_before_decoding(self) -> None:
        depth = validation.MAX_JSON_DEPTH + 1
        body = ("[" * depth + "]" * depth).encode()

        with pytest.raises(validation.ResponseLimitError, match="100 levels deep"):
            _ = validation.json_body(_response(body), source="test")

    def test_a_body_that_would_overflow_the_stack_is_refused(self) -> None:
        # 120 KB, far under the 10 MiB response limit: the size cap is much
        # too coarse to stop this one.
        body = ("[" * 60000 + "]" * 60000).encode()

        with pytest.raises(validation.ResponseLimitError):
            _ = validation.json_body(_response(body), source="test")

    def test_an_ordinary_body_decodes(self) -> None:
        body = b'{"name": "requests", "releases": {"1.0": []}}'

        assert validation.json_body(_response(body), source="test") == {
            "name": "requests",
            "releases": {"1.0": []},
        }

    def test_brackets_inside_strings_do_not_count_as_nesting(self) -> None:
        # A summary full of brackets is data, not structure; counting it would
        # reject ordinary packages.
        body = ('{"summary": "' + "[" * 500 + '"}').encode()

        assert validation.json_body(_response(body), source="test") == {
            "summary": "[" * 500
        }

    def test_escaped_quotes_do_not_end_the_string_early(self) -> None:
        # The scanner has to skip a \\" without treating it as the closing
        # quote; if it does, the brackets after it look like real structure.
        summary = 'a " [[[ b'
        body = json.dumps({"summary": summary}).encode()

        assert validation.json_body(_response(body), source="test") == {
            "summary": summary
        }
