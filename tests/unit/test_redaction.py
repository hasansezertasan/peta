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
from peta.core.models import PackageInfo
from peta.core.output import OutputMessage
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

        assert "s3cret" not in message.message
        assert "libraries.io" in message.message

    def test_a_json_error_envelope_carries_no_credential(self) -> None:
        rendered = format_error(
            "info", arguments={}, code="network_error", message=f"GET {CREDENTIALED}"
        )

        assert "s3cret" not in rendered
        assert json.loads(rendered)["errors"][0]["code"] == "network_error"

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
