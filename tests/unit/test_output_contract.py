"""Contract tests for versioned machine-readable output."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import cast

import pytest

from peta.cli.output.json import (
    format_compare,
    format_dep_tree,
    format_error,
    format_files,
    format_info,
    format_versions,
    format_why,
)
from peta.core.models import (
    VULNERABILITY_FIELD,
    DependencyNode,
    EnrichmentFailure,
    PackageInfo,
)
from peta.core.output import SCHEMA_VERSION, SourceRecord

pytestmark = pytest.mark.unit

GENERATED_AT = "2026-09-04T12:00:00Z"


def _pkg(**over: object) -> PackageInfo:
    base = PackageInfo(
        name="requests", version="2.31.0", source="local", dependencies=["urllib3"]
    )
    return replace(base, **over)


def _assert_envelope(raw: str, command: str) -> dict[str, object]:
    data = json.loads(raw)
    assert data["schema_version"] == SCHEMA_VERSION
    assert isinstance(data["peta_version"], str)
    assert data["generated_at"] == GENERATED_AT
    assert data["query"]["command"] == command
    assert data["query"]["target_environment"]["python_version"]
    assert data["errors"] == []
    return data


def test_info_envelope_and_partial_failure() -> None:
    pkg = _pkg(
        enrichment_failures=[
            EnrichmentFailure(
                source="osv", reason="HTTP 503", field=VULNERABILITY_FIELD
            )
        ]
    )
    data = _assert_envelope(
        format_info(
            pkg,
            arguments={"package": "requests", "no_osv": False},
            generated_at=GENERATED_AT,
        ),
        "info",
    )
    assert data["status"] == "partial"
    result = cast("dict[str, object]", data["result"])
    assert result["name"] == "requests"
    assert data["warnings"] == [
        {"code": "enrichment_failed", "message": "HTTP 503", "source": "osv"}
    ]
    sources = cast("list[dict[str, object]]", data["sources"])
    states = {source["state"] for source in sources}
    assert {"success", "failed"} <= states


def test_all_success_envelopes() -> None:
    pkg = _pkg(files=["requests/__init__.py"])
    node = DependencyNode(name="requests", version_spec="")
    outputs = [
        (format_compare(pkg, pkg, generated_at=GENERATED_AT), "compare"),
        (format_dep_tree(node, generated_at=GENERATED_AT), "deps"),
        (
            format_why("urllib3", [["requests", "urllib3"]], generated_at=GENERATED_AT),
            "deps",
        ),
        (format_files(pkg, generated_at=GENERATED_AT), "files"),
        (
            format_versions(
                "requests",
                [{"version": "2.31.0", "upload_time": "2023-05-22"}],
                generated_at=GENERATED_AT,
            ),
            "versions",
        ),
    ]
    for raw, command in outputs:
        assert _assert_envelope(raw, command)["status"] == "success"


def test_empty_result_is_not_a_failure() -> None:
    data = _assert_envelope(
        format_files(_pkg(files=[]), generated_at=GENERATED_AT), "files"
    )
    assert data["status"] == "empty"


def test_error_envelope_is_structured() -> None:
    data = json.loads(
        format_error(
            "info",
            arguments={"package": "missing"},
            code="package_not_found",
            message="Package 'missing' not found.",
            generated_at=GENERATED_AT,
        )
    )
    assert data["status"] == "failed"
    assert data["result"] is None
    assert data["errors"] == [
        {"code": "package_not_found", "message": "Package 'missing' not found."}
    ]


def test_skipped_sources_are_explicit() -> None:
    data = json.loads(
        format_info(
            _pkg(),
            arguments={"package": "requests", "no_osv": True, "no_stats": True},
            generated_at=GENERATED_AT,
        )
    )
    sources = {(source["name"], source["state"]) for source in data["sources"]}
    assert ("osv", "skipped") in sources
    assert ("pypistats", "skipped") in sources
    assert ("libraries.io", "skipped") in sources


def test_compare_sources_reference_indexed_result_paths() -> None:
    first = _pkg(
        retrieved_at=GENERATED_AT,
        enrichment_sources=[
            SourceRecord(
                name="osv",
                state="empty",
                target="requests",
                retrieved_at=GENERATED_AT,
                fields=["result.vulnerabilities"],
            )
        ],
    )
    second = _pkg(name="urllib3", version="2.2.0", retrieved_at=GENERATED_AT)
    data = json.loads(format_compare(first, second, generated_at=GENERATED_AT))
    fields = [field for source in data["sources"] for field in source["fields"]]
    assert fields == [
        "result.packages[0]",
        "result.packages[0].vulnerabilities",
        "result.packages[1]",
    ]
