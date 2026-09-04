"""Versioned JSON output formatters."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING

from peta.core.output import (
    EnvelopeStatus,
    OutputMessage,
    SourceRecord,
    SourceState,
    make_envelope,
    utc_now,
)

if TYPE_CHECKING:
    from peta.core.models import DependencyNode, PackageInfo
    from peta.core.output import CommandName, MessageCode

__all__ = [
    "format_compare",
    "format_dep_tree",
    "format_error",
    "format_files",
    "format_info",
    "format_versions",
    "format_why",
]


def _package_dict(pkg: PackageInfo) -> dict[str, object]:
    return {
        "name": pkg.name,
        "version": pkg.version,
        "summary": pkg.summary,
        "author": pkg.author,
        "author_email": pkg.author_email,
        "maintainer": pkg.maintainer,
        "license": pkg.license,
        "license_source": pkg.license_source,
        "python_requires": pkg.python_requires,
        "homepage": pkg.homepage,
        "project_urls": pkg.project_urls,
        "classifiers": pkg.classifiers,
        "keywords": pkg.keywords,
        "dependencies": pkg.dependencies,
        "vulnerabilities": [
            {
                "id": vulnerability.id,
                "aliases": vulnerability.aliases,
                "summary": vulnerability.summary,
                "fixed_in": vulnerability.fixed_in,
                "severity": vulnerability.severity,
            }
            for vulnerability in pkg.vulnerabilities
        ],
        "download_count": pkg.download_count,
        "dependent_count": pkg.dependent_count,
        "source": pkg.source,
    }


def _source(
    name: str, state: SourceState, target: str, timestamp: str, *, fields: list[str]
) -> SourceRecord:
    retrieved_at = timestamp if state in {"success", "empty"} else None
    return SourceRecord(
        name=name, state=state, target=target, retrieved_at=retrieved_at, fields=fields
    )


def _enrichment_records(
    pkg: PackageInfo,
    arguments: dict[str, object],
    failures: dict[str, str],
    timestamp: str,
    result_path: str,
) -> list[SourceRecord]:
    records: list[SourceRecord] = []
    if arguments.get("no_osv") is True and "osv" not in failures:
        records.append(
            _source(
                "osv",
                "skipped",
                pkg.name,
                timestamp,
                fields=[f"{result_path}.vulnerabilities"],
            )
        )
    if arguments.get("no_stats") is True:
        records.extend(
            _source(name, "skipped", pkg.name, timestamp, fields=[field])
            for name, field in (
                ("pypistats", f"{result_path}.download_count"),
                ("libraries.io", f"{result_path}.dependent_count"),
            )
        )
    return records


def _enrichment_fields(source: str, result_path: str = "result") -> list[str]:
    suffix = {
        "osv": "vulnerabilities",
        "pypistats": "download_count",
        "libraries.io": "dependent_count",
    }.get(source)
    return [f"{result_path}.{suffix}"] if suffix else []


def _at_result_path(record: SourceRecord, result_path: str) -> SourceRecord:
    fields = [
        field.replace("result", result_path, 1)
        if field == "result" or field.startswith("result.")
        else field
        for field in record.fields
    ]
    return replace(record, fields=fields)


def _source_records(
    packages: list[PackageInfo],
    arguments: dict[str, object] | None,
    timestamp: str,
    *,
    include_enrichment: bool,
    result_paths: list[str] | None = None,
) -> list[SourceRecord]:
    records: list[SourceRecord] = []
    args = arguments or {}
    paths = result_paths or ["result"] * len(packages)
    for pkg, result_path in zip(packages, paths, strict=True):
        records.append(
            SourceRecord(
                name=pkg.source,
                state="success",
                target=pkg.name,
                retrieved_at=pkg.retrieved_at,
                fields=[result_path],
            )
        )
        if not include_enrichment:
            continue
        if pkg.enrichment_sources:
            records.extend(
                _at_result_path(record, result_path)
                for record in pkg.enrichment_sources
            )
            continue
        failures = {
            failure.source: failure.reason for failure in pkg.enrichment_failures
        }
        records.extend(
            SourceRecord(
                name=source,
                state="failed",
                target=pkg.name,
                retrieved_at=timestamp,
                reason=reason,
                fields=_enrichment_fields(source, result_path),
            )
            for source, reason in failures.items()
        )
        records.extend(_enrichment_records(pkg, args, failures, timestamp, result_path))
    return records


def _warnings(packages: list[PackageInfo]) -> list[OutputMessage]:
    return [
        OutputMessage(
            code="enrichment_failed", message=failure.reason, source=failure.source
        )
        for pkg in packages
        for failure in pkg.enrichment_failures
    ]


def _dump(data: dict[str, object]) -> str:
    return json.dumps(data, indent=2)


def _package_envelope(
    command: CommandName,
    packages: list[PackageInfo],
    result: object,
    *,
    arguments: dict[str, object] | None,
    generated_at: str | None,
    empty: bool = False,
    include_enrichment: bool = True,
    result_paths: list[str] | None = None,
) -> str:
    timestamp = generated_at or utc_now()
    warnings = _warnings(packages)
    status: EnvelopeStatus = (
        "partial" if warnings else ("empty" if empty else "success")
    )
    envelope = make_envelope(
        command,
        arguments=arguments,
        status=status,
        result=result,
        sources=_source_records(
            packages,
            arguments,
            timestamp,
            include_enrichment=include_enrichment,
            result_paths=result_paths,
        ),
        warnings=warnings,
        generated_at=timestamp,
    )
    return _dump(envelope.to_dict())


def format_info(
    pkg: PackageInfo,
    *,
    arguments: dict[str, object] | None = None,
    generated_at: str | None = None,
) -> str:
    """Format package metadata in the versioned JSON envelope.

    Returns:
        An indented JSON string.
    """
    return _package_envelope(
        "info",
        [pkg],
        _package_dict(pkg),
        arguments=arguments,
        generated_at=generated_at,
    )


def format_compare(
    a: PackageInfo,
    b: PackageInfo,
    *,
    arguments: dict[str, object] | None = None,
    generated_at: str | None = None,
) -> str:
    """Format two packages in the versioned JSON envelope.

    Returns:
        An indented JSON string.
    """
    return _package_envelope(
        "compare",
        [a, b],
        {"packages": [_package_dict(a), _package_dict(b)]},
        arguments=arguments,
        generated_at=generated_at,
        result_paths=["result.packages[0]", "result.packages[1]"],
    )


def _node_dict(node: DependencyNode) -> dict[str, object]:
    return {
        "name": node.name,
        "version_spec": node.version_spec,
        "installed_version": node.installed_version,
        "circular": node.circular,
        "source": node.source,
        "children": [_node_dict(child) for child in node.children],
    }


def _dependency_sources(
    node: DependencyNode, field: str = "result"
) -> list[SourceRecord]:
    records: list[SourceRecord] = []
    if node.source is not None:
        records.append(
            SourceRecord(
                name=node.source,
                state="success",
                target=node.name,
                retrieved_at=node.retrieved_at,
                fields=[field],
            )
        )
    for index, child in enumerate(node.children):
        records.extend(_dependency_sources(child, f"{field}.children[{index}]"))
    return records


def format_dep_tree(
    node: DependencyNode,
    *,
    arguments: dict[str, object] | None = None,
    generated_at: str | None = None,
) -> str:
    """Format a dependency tree in the versioned JSON envelope.

    Returns:
        An indented JSON string.
    """
    envelope = make_envelope(
        "deps",
        arguments=arguments,
        status="success",
        result=_node_dict(node),
        sources=_dependency_sources(node),
        generated_at=generated_at,
    )
    return _dump(envelope.to_dict())


def format_why(
    target: str,
    paths: list[list[str]],
    *,
    arguments: dict[str, object] | None = None,
    generated_at: str | None = None,
    tree: DependencyNode | None = None,
) -> str:
    """Format dependency paths in the versioned JSON envelope.

    Returns:
        An indented JSON string.
    """
    envelope = make_envelope(
        "deps",
        arguments=arguments,
        status="success" if paths else "empty",
        result={"target": target, "paths": paths},
        sources=_dependency_sources(tree, "result.paths") if tree else [],
        generated_at=generated_at,
    )
    return _dump(envelope.to_dict())


def format_files(
    pkg: PackageInfo,
    *,
    arguments: dict[str, object] | None = None,
    generated_at: str | None = None,
) -> str:
    """Format an installed file list in the versioned JSON envelope.

    Returns:
        An indented JSON string.
    """
    files = pkg.files or []
    result = {"name": pkg.name, "version": pkg.version, "files": files}
    return _package_envelope(
        "files",
        [pkg],
        result,
        arguments=arguments,
        generated_at=generated_at,
        empty=not files,
        include_enrichment=False,
    )


def format_versions(
    name: str,
    versions: list[dict[str, str]],
    *,
    arguments: dict[str, object] | None = None,
    generated_at: str | None = None,
    retrieved_at: str | None = None,
) -> str:
    """Format published versions in the versioned JSON envelope.

    Returns:
        An indented JSON string.
    """
    timestamp = generated_at or utc_now()
    retrieval_time = retrieved_at or timestamp
    envelope = make_envelope(
        "versions",
        arguments=arguments,
        status="success" if versions else "empty",
        result={"name": name, "versions": versions},
        sources=[
            SourceRecord(
                name="pypi",
                state="success" if versions else "empty",
                target=name,
                retrieved_at=retrieval_time,
                fields=["result.versions"],
            )
        ],
        generated_at=timestamp,
    )
    return _dump(envelope.to_dict())


def format_error(
    command: CommandName,
    *,
    arguments: dict[str, object] | None,
    code: MessageCode,
    message: str,
    source: str | None = None,
    generated_at: str | None = None,
) -> str:
    """Format a fatal command error in the versioned JSON envelope.

    Returns:
        An indented JSON string.
    """
    envelope = make_envelope(
        command,
        arguments=arguments,
        status="failed",
        result=None,
        errors=[OutputMessage(code=code, message=message, source=source)],
        generated_at=generated_at,
    )
    return _dump(envelope.to_dict())
