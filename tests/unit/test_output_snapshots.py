"""Inline snapshots for the versioned JSON contract."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import cast

import pytest
from inline_snapshot import snapshot

from peta.cli.output.json import (
    format_compare,
    format_dep_tree,
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
from peta.core.output import SourceRecord

pytestmark = pytest.mark.unit

GENERATED_AT = "2026-09-04T12:00:00Z"


def _pkg(**over: object) -> PackageInfo:
    base = PackageInfo(
        name="requests",
        version="2.31.0",
        source="local",
        dependencies=["urllib3"],
        files=["requests/__init__.py"],
    )
    return replace(base, **over)


def _stable(raw: str) -> dict[str, object]:
    data = cast("dict[str, object]", json.loads(raw))
    data["peta_version"] = "<peta-version>"
    query = cast("dict[str, object]", data["query"])
    query["target_environment"] = "<target-environment>"
    sources = cast("list[dict[str, object]]", data["sources"])
    for source in sources:
        if "retrieved_at" in source:
            source["retrieved_at"] = "<retrieved-at>"
    return data


def test_each_command_envelope_snapshot() -> None:
    pkg = _pkg()
    enriched_pkg = _pkg(
        enrichment_sources=[
            SourceRecord(
                name="osv",
                state="empty",
                target="requests",
                retrieved_at=GENERATED_AT,
                fields=["result.vulnerabilities"],
            )
        ]
    )
    tree = DependencyNode(
        name="requests",
        version_spec="",
        installed_version="2.31.0",
        children=[DependencyNode(name="urllib3", version_spec=">=2")],
    )
    envelopes = {
        "info": _stable(format_info(pkg, generated_at=GENERATED_AT)),
        "compare": _stable(
            format_compare(enriched_pkg, pkg, generated_at=GENERATED_AT)
        ),
        "deps": _stable(format_dep_tree(tree, generated_at=GENERATED_AT)),
        "why": _stable(
            format_why("urllib3", [["requests", "urllib3"]], generated_at=GENERATED_AT)
        ),
        "files": _stable(format_files(pkg, generated_at=GENERATED_AT)),
        "versions": _stable(
            format_versions(
                "requests",
                [{"version": "2.31.0", "upload_time": "2023-05-22"}],
                generated_at=GENERATED_AT,
            )
        ),
    }
    assert envelopes == snapshot({
        "info": {
            "schema_version": "1",
            "peta_version": "<peta-version>",
            "generated_at": "2026-09-04T12:00:00Z",
            "query": {
                "command": "info",
                "arguments": {},
                "target_environment": "<target-environment>",
            },
            "status": "success",
            "sources": [
                {
                    "name": "local",
                    "state": "success",
                    "target": "requests",
                    "retrieved_at": "<retrieved-at>",
                    "fields": ["result"],
                }
            ],
            "warnings": [],
            "errors": [],
            "result": {
                "name": "requests",
                "version": "2.31.0",
                "summary": None,
                "author": None,
                "author_email": None,
                "maintainer": None,
                "license": None,
                "license_source": None,
                "python_requires": None,
                "homepage": None,
                "project_urls": {},
                "classifiers": [],
                "keywords": [],
                "dependencies": ["urllib3"],
                "vulnerabilities": [],
                "download_count": None,
                "dependent_count": None,
                "source": "local",
            },
        },
        "compare": {
            "schema_version": "1",
            "peta_version": "<peta-version>",
            "generated_at": "2026-09-04T12:00:00Z",
            "query": {
                "command": "compare",
                "arguments": {},
                "target_environment": "<target-environment>",
            },
            "status": "success",
            "sources": [
                {
                    "name": "local",
                    "state": "success",
                    "target": "requests",
                    "retrieved_at": "<retrieved-at>",
                    "fields": ["result.packages[0]"],
                },
                {
                    "name": "osv",
                    "state": "empty",
                    "target": "requests",
                    "retrieved_at": "<retrieved-at>",
                    "fields": ["result.packages[0].vulnerabilities"],
                },
                {
                    "name": "local",
                    "state": "success",
                    "target": "requests",
                    "retrieved_at": "<retrieved-at>",
                    "fields": ["result.packages[1]"],
                },
            ],
            "warnings": [],
            "errors": [],
            "result": {
                "packages": [
                    {
                        "name": "requests",
                        "version": "2.31.0",
                        "summary": None,
                        "author": None,
                        "author_email": None,
                        "maintainer": None,
                        "license": None,
                        "license_source": None,
                        "python_requires": None,
                        "homepage": None,
                        "project_urls": {},
                        "classifiers": [],
                        "keywords": [],
                        "dependencies": ["urllib3"],
                        "vulnerabilities": [],
                        "download_count": None,
                        "dependent_count": None,
                        "source": "local",
                    },
                    {
                        "name": "requests",
                        "version": "2.31.0",
                        "summary": None,
                        "author": None,
                        "author_email": None,
                        "maintainer": None,
                        "license": None,
                        "license_source": None,
                        "python_requires": None,
                        "homepage": None,
                        "project_urls": {},
                        "classifiers": [],
                        "keywords": [],
                        "dependencies": ["urllib3"],
                        "vulnerabilities": [],
                        "download_count": None,
                        "dependent_count": None,
                        "source": "local",
                    },
                ]
            },
        },
        "deps": {
            "schema_version": "1",
            "peta_version": "<peta-version>",
            "generated_at": "2026-09-04T12:00:00Z",
            "query": {
                "command": "deps",
                "arguments": {},
                "target_environment": "<target-environment>",
            },
            "status": "success",
            "sources": [],
            "warnings": [],
            "errors": [],
            "result": {
                "name": "requests",
                "version_spec": "",
                "installed_version": "2.31.0",
                "circular": False,
                "source": None,
                "resolution": None,
                "children": [
                    {
                        "name": "urllib3",
                        "version_spec": ">=2",
                        "installed_version": None,
                        "circular": False,
                        "source": None,
                        "resolution": None,
                        "children": [],
                    }
                ],
            },
        },
        "why": {
            "schema_version": "1",
            "peta_version": "<peta-version>",
            "generated_at": "2026-09-04T12:00:00Z",
            "query": {
                "command": "deps",
                "arguments": {},
                "target_environment": "<target-environment>",
            },
            "status": "success",
            "sources": [],
            "warnings": [],
            "errors": [],
            "result": {"target": "urllib3", "paths": [["requests", "urllib3"]]},
        },
        "files": {
            "schema_version": "1",
            "peta_version": "<peta-version>",
            "generated_at": "2026-09-04T12:00:00Z",
            "query": {
                "command": "files",
                "arguments": {},
                "target_environment": "<target-environment>",
            },
            "status": "success",
            "sources": [
                {
                    "name": "local",
                    "state": "success",
                    "target": "requests",
                    "retrieved_at": "<retrieved-at>",
                    "fields": ["result"],
                }
            ],
            "warnings": [],
            "errors": [],
            "result": {
                "name": "requests",
                "version": "2.31.0",
                "files": ["requests/__init__.py"],
            },
        },
        "versions": {
            "schema_version": "1",
            "peta_version": "<peta-version>",
            "generated_at": "2026-09-04T12:00:00Z",
            "query": {
                "command": "versions",
                "arguments": {},
                "target_environment": "<target-environment>",
            },
            "status": "success",
            "sources": [
                {
                    "name": "pypi",
                    "state": "success",
                    "target": "requests",
                    "retrieved_at": "<retrieved-at>",
                    "fields": ["result.versions"],
                }
            ],
            "warnings": [],
            "errors": [],
            "result": {
                "name": "requests",
                "versions": [{"version": "2.31.0", "upload_time": "2023-05-22"}],
            },
        },
    })


def test_partial_failure_envelope_snapshot() -> None:
    failures = [
        EnrichmentFailure(source="osv", reason="HTTP 503", field=VULNERABILITY_FIELD),
        EnrichmentFailure(
            source="pypistats", reason="invalid JSON", field="result.download_count"
        ),
        EnrichmentFailure(
            source="libraries.io", reason="HTTP 429", field="result.dependent_count"
        ),
    ]
    envelope = _stable(
        format_info(_pkg(enrichment_failures=failures), generated_at=GENERATED_AT)
    )
    assert envelope == snapshot({
        "schema_version": "1",
        "peta_version": "<peta-version>",
        "generated_at": "2026-09-04T12:00:00Z",
        "query": {
            "command": "info",
            "arguments": {},
            "target_environment": "<target-environment>",
        },
        "status": "partial",
        "sources": [
            {
                "name": "local",
                "state": "success",
                "target": "requests",
                "retrieved_at": "<retrieved-at>",
                "fields": ["result"],
            },
            {
                "name": "osv",
                "state": "failed",
                "target": "requests",
                "retrieved_at": "<retrieved-at>",
                "reason": "HTTP 503",
                "fields": ["result.vulnerabilities"],
            },
            {
                "name": "pypistats",
                "state": "failed",
                "target": "requests",
                "retrieved_at": "<retrieved-at>",
                "reason": "invalid JSON",
                "fields": ["result.download_count"],
            },
            {
                "name": "libraries.io",
                "state": "failed",
                "target": "requests",
                "retrieved_at": "<retrieved-at>",
                "reason": "HTTP 429",
                "fields": ["result.dependent_count"],
            },
        ],
        "warnings": [
            {"code": "enrichment_failed", "message": "HTTP 503", "source": "osv"},
            {
                "code": "enrichment_failed",
                "message": "invalid JSON",
                "source": "pypistats",
            },
            {
                "code": "enrichment_failed",
                "message": "HTTP 429",
                "source": "libraries.io",
            },
        ],
        "errors": [],
        "result": {
            "name": "requests",
            "version": "2.31.0",
            "summary": None,
            "author": None,
            "author_email": None,
            "maintainer": None,
            "license": None,
            "license_source": None,
            "python_requires": None,
            "homepage": None,
            "project_urls": {},
            "classifiers": [],
            "keywords": [],
            "dependencies": ["urllib3"],
            "vulnerabilities": [],
            "download_count": None,
            "dependent_count": None,
            "source": "local",
        },
    })
