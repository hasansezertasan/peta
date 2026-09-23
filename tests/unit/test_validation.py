"""Security limits for decoded untrusted API responses."""

import json
import time

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


class TestCollectionSizeBeforeDecoding:
    """Collections have to be measured before ``json.loads`` builds them.

    The validators only visit fields peta consumes, so an array peta ignores
    is never measured afterwards — yet ``json.loads`` has already allocated
    every element of it. Measuring in the pre-decode scan covers the fields
    no validator will ever look at.
    """

    def test_an_ignored_padding_array_is_refused_before_decoding(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(validation, "MAX_COLLECTION_ITEMS", 3)
        body = b'{"name": "x", "padding": [0, 0, 0, 0]}'

        with pytest.raises(validation.ResponseLimitError, match="at most 3 items"):
            _ = validation.json_body(_response(body), source="test")

    def test_many_collections_under_the_limit_still_meet_a_document_budget(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Each array is under the per-collection limit, which resets for every
        # collection; without a document-wide budget, enough of them fill the
        # response-size limit with millions of values.
        monkeypatch.setattr(validation, "MAX_COLLECTION_ITEMS", 5)
        monkeypatch.setattr(validation, "MAX_JSON_VALUES", 10)
        body = json.dumps({key: [1, 2, 3, 4] for key in "abc"}).encode()

        with pytest.raises(validation.ResponseLimitError, match="10 values in total"):
            _ = validation.json_body(_response(body), source="test")

    def test_the_limit_is_per_collection_not_per_document(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Two collections each under the limit are fine however many items
        # the document holds in total; a document-wide count would reject
        # large but ordinary index pages.
        monkeypatch.setattr(validation, "MAX_COLLECTION_ITEMS", 3)
        body = b'{"a": [1, 2, 3], "b": [4, 5, 6]}'

        assert validation.json_body(_response(body), source="test") == {
            "a": [1, 2, 3],
            "b": [4, 5, 6],
        }

    def test_commas_inside_strings_are_not_items(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(validation, "MAX_COLLECTION_ITEMS", 3)
        summary = "a, b, c, d, e, f"
        body = json.dumps({"summary": summary}).encode()

        assert validation.json_body(_response(body), source="test") == {
            "summary": summary
        }


class TestStringsBeforeDecoding:
    """String literals are measured by the same pre-decode scan.

    Not every consumed string reaches :func:`validation.expect_string` —
    list elements, mapping values, and several hand-written checks only test
    the type — so the scan is the one place every string is seen.
    """

    def test_a_long_string_inside_a_list_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(validation, "MAX_STRING_LENGTH", 3)
        body = b'{"aliases": ["ok", "far too long"]}'

        with pytest.raises(validation.ResponseLimitError, match="at most 3 characters"):
            _ = validation.json_body(_response(body), source="test")

    def test_a_long_mapping_key_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(validation, "MAX_STRING_LENGTH", 3)
        body = b'{"far too long": 1}'

        with pytest.raises(validation.ResponseLimitError, match="characters"):
            _ = validation.json_body(_response(body), source="test")

    def test_a_string_at_the_limit_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(validation, "MAX_STRING_LENGTH", 3)
        body = b'{"abc": ["xyz"]}'

        assert validation.json_body(_response(body), source="test") == {"abc": ["xyz"]}


class TestScanStaysLinear:
    """The scan exists to stop a denial of service, so it must not be one."""

    def test_a_flood_of_short_strings_is_refused_before_the_string_scan(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The string scan calls back into Python once per literal, so a body
        # of millions of empty strings made the guard itself slow and
        # memory-hungry. Counting quotes in C first stops it before that.
        monkeypatch.setattr(validation, "MAX_JSON_VALUES", 10)
        body = json.dumps({"k": [""] * 20}).encode()
        calls: list[str] = []
        scan = validation._without_strings

        def recording(text: str, limit: int) -> tuple[str, bool]:
            calls.append(text)
            return scan(text, limit)

        monkeypatch.setattr(validation, "_without_strings", recording)

        with pytest.raises(validation.ResponseLimitError, match="values in total"):
            _ = validation.json_body(_response(body), source="test")

        assert calls == []

    def test_an_unterminated_run_of_escaped_quotes_is_fast(self) -> None:
        # With no closing quote, a literal pattern that insists on one fails,
        # restarts at the next quote — every escaped quote is one — and
        # rescans to the end: quadratic. 32 KB took nearly two seconds.
        body = ('"' + '\\"' * 200_000).encode()

        started = time.perf_counter()
        with pytest.raises(ValueError, match="Unterminated string"):
            _ = validation.json_body(_response(body), source="test")

        assert time.perf_counter() - started < 1.0


class TestScanAndParserReadTheSameText:
    def test_a_misleading_charset_cannot_hide_nesting(self) -> None:
        # ``response.text`` follows the declared charset while ``json.loads``
        # sniffs the bytes. Declaring UTF-16-LE over a UTF-8 body used to
        # show the scan harmless CJK text and the parser a bracket bomb.
        depth = validation.MAX_JSON_DEPTH + 1
        body = ("[" * depth + "]" * depth).encode("utf-8")
        response = httpx.Response(
            200,
            content=body,
            headers={"content-type": "application/json; charset=utf-16-le"},
        )

        with pytest.raises(validation.ResponseLimitError, match="levels deep"):
            _ = validation.json_body(response, source="test")

    @pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-32"])
    def test_every_json_encoding_still_decodes(self, encoding: str) -> None:
        body = json.dumps({"name": "requests"}).encode(encoding)

        assert validation.json_body(_response(body), source="test") == {
            "name": "requests"
        }
