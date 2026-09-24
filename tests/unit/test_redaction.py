"""Where peta's own credentials are stripped, and where they must not be.

Two rules pull in opposite directions and are easy to collapse into one:

* a URL peta *requested* can carry peta's API key, so any diagnostic quoting
  it has to be redacted before a user, a log, or a bug report sees it;
* a URL a package *declared* is metadata peta exists to report, and rewriting
  it would corrupt the output contract.

Redaction therefore happens where a diagnostic is built, never over rendered
output or over the envelope as a whole.
"""

from __future__ import annotations

import json

import pytest

from peta.cli.output.json import format_error, format_info
from peta.cli.output.render import render_info
from peta.cli.output.selection import OutputFormat
from peta.core.artifacts import PublisherFailure
from peta.core.models import (
    DependencyResolutionFailure,
    EnrichmentFailure,
    PackageInfo,
    ProviderWarning,
)
from peta.core.output import OutputMessage, SourceRecord
from peta.core.validation import EnrichmentError

pytestmark = pytest.mark.unit

CREDENTIALED = "https://libraries.io/api/pypi/x?api_key=s3cret&per_page=2"
DECLARED = "https://example.invalid/docs?key=install&token=guide"


def _declaring(homepage: str) -> PackageInfo:
    """Build a package whose homepage is the given declared URL.

    Returns:
        A package carrying that homepage.
    """
    return PackageInfo(name="x", version="1", source="remote", homepage=homepage)


class TestDiagnosticsAreRedacted:
    def test_an_enrichment_reason_loses_its_credential(self) -> None:
        # Most of these reasons are ``str(exc)`` on a transport error, which
        # quotes the request URL verbatim.
        error = EnrichmentError("libraries.io", f"GET {CREDENTIALED} failed")

        assert "s3cret" not in error.reason
        assert "s3cret" not in str(error)
        assert "per_page=2" in error.reason

    def test_an_output_message_loses_its_credential(self) -> None:
        message = OutputMessage(code="network_error", message=f"GET {CREDENTIALED}")

        # An exact comparison, not ``"libraries.io" in ...``: it pins that the
        # credential went and everything else in the URL stayed.
        assert message.message == "GET https://libraries.io/api/pypi/x?per_page=2"

    def test_a_json_error_envelope_carries_no_credential(self) -> None:
        rendered = format_error(
            "info", arguments={}, code="network_error", message=f"GET {CREDENTIALED}"
        )

        assert "s3cret" not in rendered
        assert json.loads(rendered)["errors"][0]["code"] == "network_error"

    def test_a_publisher_failure_loses_its_credential(self) -> None:
        # Provenance failures never pass through OutputMessage on their way
        # to human output: they become a source record and are rendered
        # directly, so they need their own boundary.
        failure = PublisherFailure("pkg-1.0.whl", f"GET {CREDENTIALED} failed")

        assert failure.reason == "GET https://libraries.io/api/pypi/x?per_page=2 failed"
        assert "s3cret" not in failure.description

    def test_a_source_record_loses_its_credential(self) -> None:
        record = SourceRecord(name="provenance", state="failed", reason=CREDENTIALED)

        assert record.reason == "https://libraries.io/api/pypi/x?per_page=2"

    def test_a_source_record_without_a_reason_is_left_alone(self) -> None:
        assert SourceRecord(name="pypi", state="success").reason is None

    @pytest.mark.parametrize(
        ("template", "expected"),
        [
            (
                "GET https://{userinfo}@index.example/simple/ failed",
                "GET https://index.example/simple/ failed",
            ),
            # Too malformed for urlsplit, so the fallback has to drop it too.
            ("see https://{userinfo}@[bad/x now", "see https://[bad/x now"),
        ],
    )
    def test_userinfo_credentials_are_removed(
        self, template: str, expected: str
    ) -> None:
        # ``https://{user}:{token}@index/`` is how a private index is usually
        # configured; the userinfo is the credential itself. Assembled at run
        # time so the source holds no literal credential for secret scanners.
        message = template.format(userinfo="user:s3cret")

        assert OutputMessage(code="network_error", message=message).message == expected

    def test_redaction_survives_text_around_the_url(self) -> None:
        message = OutputMessage(
            code="network_error", message=f"tried {CREDENTIALED} twice, gave up"
        )

        assert "s3cret" not in message.message
        assert message.message.startswith("tried ")
        assert message.message.endswith(" twice, gave up")


class TestDeclaredMetadataIsNotRewritten:
    @pytest.mark.parametrize("parameter", ["key=install", "token=guide"])
    def test_a_declared_query_parameter_survives(self, parameter: str) -> None:
        # ``key`` and ``token`` are among the names peta strips from its own
        # request URLs; they are also ordinary query parameters in the wild.
        package = _declaring(DECLARED)

        result = json.loads(format_info(package, arguments={}))["result"]

        assert parameter in result["homepage"]

    def test_the_declared_url_is_reported_byte_for_byte(self) -> None:
        package = _declaring(DECLARED)

        result = json.loads(format_info(package, arguments={}))["result"]

        assert result["homepage"] == DECLARED


class TestDiagnosticModelsRedactThemselves:
    """Every model that carries a diagnostic redacts it where it is built.

    Relying on ``EnrichmentError`` left gaps: a provider can report failure as
    a result rather than an exception, warnings never passed through it, and
    the human formatters render these models directly rather than through a
    redacted ``OutputMessage``.
    """

    def test_an_enrichment_failure_built_directly(self) -> None:
        failure = EnrichmentFailure(source="future", reason=CREDENTIALED, field=None)

        assert "s3cret" not in failure.reason

    def test_a_provider_warning(self) -> None:
        warning = ProviderWarning(source="future", code="note", message=CREDENTIALED)

        assert "s3cret" not in warning.message

    def test_a_dependency_resolution_failure(self) -> None:
        failure = DependencyResolutionFailure(
            source="pypi", state="failed", reason=CREDENTIALED, retrieved_at=None
        )

        assert "s3cret" not in failure.reason

    @pytest.mark.parametrize(
        "output_format", [OutputFormat.RICH, OutputFormat.TEXT, OutputFormat.MARKDOWN]
    )
    def test_no_human_format_shows_a_provider_credential(
        self, output_format: OutputFormat
    ) -> None:
        package = PackageInfo(
            name="x",
            version="1",
            source="remote",
            enrichment_failures=[
                EnrichmentFailure(source="future", reason=CREDENTIALED, field=None)
            ],
            provider_warnings=[
                ProviderWarning(source="future", code="note", message=CREDENTIALED)
            ],
        )

        out = render_info(output_format, package, arguments={}, color=False)

        assert "s3cret" not in out
        # The non-secret parameter survives, so the URL was redacted rather
        # than dropped; asserting on it avoids a host-substring check.
        assert "per_page=2" in out


class TestRedactionCoversSignedAndHostileUrls:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            (
                "https://files.example/p?X-Amz-Credential=a&X-Amz-Signature=b&X-Amz-Expires=60",
                "https://files.example/p?X-Amz-Expires=60",
            ),
            (
                "https://storage.example/o?X-Goog-Signature=b&alt=media",
                "https://storage.example/o?alt=media",
            ),
            (
                "https://cdn.example/f?Signature=b&Expires=1",
                "https://cdn.example/f?Expires=1",
            ),
        ],
    )
    def test_signed_url_credentials_are_removed(self, url: str, expected: str) -> None:
        # A failed provenance fetch quotes its URL, and a signature authorizes
        # the request on its own.
        assert OutputMessage(code="network_error", message=url).message == expected

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            # parse_qsl splits only on "&", so this read as one field "ok".
            ("https://x.example/?ok=1;token=s3cret", "https://x.example/?ok=1"),
            # A percent-encoded name is judged by what it decodes to.
            ("https://x.example/?%74oken=s3cret&q=a%20b", "https://x.example/?q=a%20b"),
        ],
    )
    def test_every_field_is_judged_whatever_its_spelling(
        self, url: str, expected: str
    ) -> None:
        assert OutputMessage(code="network_error", message=url).message == expected

    @pytest.mark.parametrize(
        ("message", "expected"),
        [
            # urlsplit normalizes the scheme to lowercase, an equivalent URL.
            ("see HTTPS://x.example/?token=s3cret", "see https://x.example/"),
            ("see HtTp://{userinfo}@[bad/x now", "see HtTp://[bad/x now"),
        ],
    )
    def test_the_scheme_is_matched_in_any_case(
        self, message: str, expected: str
    ) -> None:
        # URL schemes are case-insensitive, and a lowercase-only pattern let an
        # uppercase URL skip redaction entirely.
        text = message.format(userinfo="user:s3cret")

        assert OutputMessage(code="network_error", message=text).message == expected

    def test_a_query_with_absurdly_many_fields_is_dropped_unparsed(self) -> None:
        # A diagnostic can quote a URL an index chose; parsing millions of
        # empty fields would allocate a tuple for each before reporting.
        url = "https://x.example/?" + "a=&" * 5000

        assert OutputMessage(code="network_error", message=url).message == (
            "https://x.example/"
        )

    def test_an_ordinary_query_is_still_parsed_field_by_field(self) -> None:
        url = (
            "https://x.example/?" + "&".join(f"f{i}=1" for i in range(50)) + "&token=t"
        )

        message = OutputMessage(code="network_error", message=url).message

        assert "token" not in message
        assert "f49=1" in message
