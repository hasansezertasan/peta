"""Versioned JSON output formatters."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING

from peta.core.diff import diff_packages
from peta.core.output import (
    EnvelopeStatus,
    OutputMessage,
    SourceRecord,
    SourceState,
    make_envelope,
    utc_now,
)

if TYPE_CHECKING:
    from collections.abc import Container, Iterator

    from peta.core.artifacts import ArtifactFile, Publisher, ReleaseArtifacts
    from peta.core.cache import Freshness
    from peta.core.changes import ChangeSet
    from peta.core.diff import ReleaseEvidence
    from peta.core.models import DependencyNode, EnrichmentFailure, PackageInfo
    from peta.core.output import CommandName, MessageCode

__all__ = [
    "format_artifacts",
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


def _provider(source: str) -> str:
    """Name the provider behind a ``PackageInfo.source`` value.

    ``PackageInfo.source`` keeps its legacy ``"remote"`` value in ``result``,
    but provenance names the same provider ``pypi`` everywhere.

    Returns:
        The provenance name for ``source``.
    """
    return "local" if source == "local" else "pypi"


def _at_result_path(record: SourceRecord, result_path: str) -> SourceRecord:
    return replace(
        record, fields=[_remap_field(field, result_path) for field in record.fields]
    )


def _failure_fields(failure: EnrichmentFailure, result_path: str) -> list[str]:
    """Name the result path a failed source would have written to.

    Returns:
        The single rebased field, or nothing when the failure names none.
    """
    if failure.field is None:
        return []
    return [_remap_field(failure.field, result_path)]


def _remap_field(field: str, result_path: str) -> str:
    """Rebase a generic ``result``-rooted path onto a command's real path.

    Returns:
        The field rooted at ``result_path``, or unchanged if not ``result``-rooted.
    """
    if field == "result" or field.startswith("result."):
        return field.replace("result", result_path, 1)
    return field


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
                name=_provider(pkg.source),
                state="success",
                target=pkg.name,
                retrieved_at=pkg.retrieved_at or timestamp,
                freshness=pkg.freshness,
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
                name=failure.source,
                state="failed",
                target=pkg.name,
                retrieved_at=timestamp,
                reason=failure.reason,
                fields=_failure_fields(failure, result_path),
            )
            for failure in pkg.enrichment_failures
        )
        records.extend(_enrichment_records(pkg, args, failures, timestamp, result_path))
    return records


def _warnings(
    packages: list[PackageInfo], result_paths: list[str] | None = None
) -> list[OutputMessage]:
    """Report enrichment failures and provider conflicts as warnings.

    Conflict messages name the field the disagreement is about, rebased onto
    the command's real result path so it identifies which package in a
    multi-package result the warning describes.

    Returns:
        One warning per failure, then one per conflict.
    """
    paths = result_paths or ["result"] * len(packages)
    pairs = list(zip(packages, paths, strict=True))
    failures = [
        OutputMessage(
            code="enrichment_failed", message=failure.reason, source=failure.source
        )
        for pkg, _ in pairs
        for failure in pkg.enrichment_failures
    ]
    conflicts = [
        OutputMessage(
            code="provider_conflict",
            message=f"{_remap_field(conflict.field, path)}: {conflict.description}",
            source=conflict.kept,
        )
        for pkg, path in pairs
        for conflict in pkg.enrichment_conflicts
    ]
    provider_warnings = [
        OutputMessage(
            code="provider_warning",
            message=f"{path}: [{w.code}] {w.message}",
            source=w.source,
        )
        for pkg, path in pairs
        for w in pkg.provider_warnings
    ]
    return failures + conflicts + provider_warnings


def _dump(data: dict[str, object]) -> str:
    # Deliberately not redacted here. Credentials are stripped where a
    # diagnostic is built — ``EnrichmentError`` and ``fail`` — because that is
    # where peta's own API keys can appear. Sweeping every string in the
    # envelope instead would rewrite package metadata: ``_CREDENTIAL_PARAMS``
    # holds names as ordinary as ``key``, so a homepage of
    # ``https://example.com/docs?key=install`` would silently lose its query
    # and break the contract's promise to report what a package declared.
    return json.dumps(data, indent=2)


def _package_envelope(  # ruff: ignore[too-many-arguments]
    command: CommandName,
    packages: list[PackageInfo],
    result: object,
    *,
    arguments: dict[str, object] | None,
    generated_at: str | None,
    empty: bool = False,
    include_enrichment: bool = True,
    result_paths: list[str] | None = None,
    extra_sources: list[SourceRecord] | None = None,
    extra_warnings: list[OutputMessage] | None = None,
) -> str:
    timestamp = generated_at or utc_now()
    warnings = [*_warnings(packages, result_paths), *(extra_warnings or [])]
    status: EnvelopeStatus = (
        "partial" if warnings else ("empty" if empty else "success")
    )
    envelope = make_envelope(
        command,
        arguments=arguments,
        status=status,
        result=result,
        sources=[
            *_source_records(
                packages,
                arguments,
                timestamp,
                include_enrichment=include_enrichment,
                result_paths=result_paths,
            ),
            *(extra_sources or []),
        ],
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


def _diff_dict(diff: ChangeSet) -> dict[str, object]:
    """Represent a semantic diff as its change and unknown-group records.

    Returns:
        The ``result.diff`` mapping.
    """
    return {
        "changes": [
            {
                "group": change.group,
                "kind": change.kind,
                "subject": change.subject,
                "before": change.before,
                "after": change.after,
                "expected": change.expected,
            }
            for change in diff.changes
        ],
        "unknown": [
            {"group": entry.group, "reason": entry.reason} for entry in diff.unknown
        ],
    }


def _release_record(
    pkg: PackageInfo, evidence: ReleaseEvidence, timestamp: str
) -> SourceRecord:
    """Record one side's artifact listing lookup.

    A release PyPI does not list is ``empty``, not ``failed``: the source
    answered, and the answer was that there is nothing to list.

    Returns:
        A ``pypi`` record for the listing: successful, empty, or failed.
    """
    target = f"{pkg.name} {pkg.version}"
    fields = ["result.diff"]
    retrieval = evidence.retrieval
    if evidence.release is None and retrieval is None:
        return SourceRecord(
            name="pypi",
            state="failed",
            target=target,
            reason=evidence.reason,
            fields=fields,
        )
    listed = evidence.release is not None and bool(evidence.release.files)
    return SourceRecord(
        name="pypi",
        state="success" if listed else "empty",
        target=target,
        retrieved_at=retrieval.retrieved_at if retrieval else timestamp,
        freshness=retrieval.freshness if retrieval else None,
        reason=evidence.reason,
        fields=fields,
    )


def _release_warnings(
    releases: tuple[ReleaseEvidence, ReleaseEvidence] | None,
) -> list[OutputMessage]:
    return [
        OutputMessage(code="enrichment_failed", message=side.reason, source="pypi")
        for side in releases or ()
        if side.release is None and side.retrieval is None and side.reason
    ]


def format_compare(
    a: PackageInfo,
    b: PackageInfo,
    *,
    diff: ChangeSet | None = None,
    releases: tuple[ReleaseEvidence, ReleaseEvidence] | None = None,
    arguments: dict[str, object] | None = None,
    generated_at: str | None = None,
) -> str:
    """Format two packages and their semantic diff in the versioned envelope.

    ``result.diff.changes`` lists only what changed, each record with a stable
    ``kind`` and its ``before``/``after`` values; ``result.diff.unknown`` names
    the groups a side had no evidence for. With ``releases``, each side's
    artifact listing is recorded as a ``pypi`` source, and a failed listing
    makes the envelope ``partial`` rather than failing the comparison.

    Returns:
        An indented JSON string.
    """
    timestamp = generated_at or utc_now()
    # Built from ``releases`` when no diff is given, so the change list can
    # never disagree with the artifact sources recorded beside it.
    semantic = diff or diff_packages(
        a,
        b,
        a_release=releases[0] if releases else None,
        b_release=releases[1] if releases else None,
        osv_skipped=(arguments or {}).get("no_osv") is True,
    )
    return _package_envelope(
        "compare",
        [a, b],
        {
            "packages": [_package_dict(a), _package_dict(b)],
            "diff": _diff_dict(semantic),
        },
        arguments=arguments,
        generated_at=timestamp,
        result_paths=["result.packages[0]", "result.packages[1]"],
        extra_sources=[
            _release_record(pkg, side, timestamp)
            for pkg, side in zip((a, b), releases or (), strict=False)
        ],
        extra_warnings=_release_warnings(releases),
    )


def _node_dict(node: DependencyNode) -> dict[str, object]:
    failure = node.resolution_failure
    return {
        "name": node.name,
        "version_spec": node.version_spec,
        "selected_version": node.selected_version,
        "state": node.state,
        "source": node.source,
        "resolution": (
            {"state": failure.state, "source": failure.source, "reason": failure.reason}
            if failure
            else None
        ),
        "children": [_node_dict(child) for child in node.children],
    }


def _dependency_source(
    node: DependencyNode, field: str, timestamp: str
) -> SourceRecord | None:
    failure = node.resolution_failure
    if failure is not None:
        return SourceRecord(
            name=failure.source,
            state=failure.state,
            target=node.name,
            retrieved_at=failure.retrieved_at,
            reason=failure.reason,
            freshness=failure.freshness,
            fields=[field],
        )
    if node.source is None:
        return None
    return SourceRecord(
        name=_provider(node.source),
        state="success",
        target=node.name,
        retrieved_at=node.retrieved_at or timestamp,
        freshness=node.freshness,
        fields=[field],
    )


def _dependency_sources(
    node: DependencyNode, timestamp: str, field: str = "result"
) -> list[SourceRecord]:
    records: list[SourceRecord] = []
    record = _dependency_source(node, field, timestamp)
    if record is not None:
        records.append(record)
    for index, child in enumerate(node.children):
        records.extend(
            _dependency_sources(child, timestamp, f"{field}.children[{index}]")
        )
    return records


def _dependency_warnings(node: DependencyNode) -> list[OutputMessage]:
    warnings: list[OutputMessage] = []
    failure = node.resolution_failure
    if failure is not None:
        warnings.append(
            OutputMessage(
                code="dependency_resolution_failed",
                message=f"{node.name}: {failure.reason}",
                source=failure.source,
            )
        )
    if node.state == "conflicting":
        warnings.append(_conflict_warning(node))
    if node.state == "depth_limited":
        warnings.append(
            OutputMessage(
                code="dependency_depth_limited",
                message=f"{node.name}: expansion stopped at the depth limit",
                source=_provider(node.source) if node.source else None,
            )
        )
    for child in node.children:
        warnings.extend(_dependency_warnings(child))
    return warnings


def _conflict_warning(node: DependencyNode) -> OutputMessage:
    """Return the structured warning matching a conflict node.

    Returns:
        The warning for the node's version or target-environment conflict.
    """
    is_target_conflict = node.conflict_reason == "target" or (
        node.conflict_reason is None and not node.version_spec
    )
    if is_target_conflict:
        message = (
            f"{node.name}: selected {node.selected_version} is incompatible "
            "with the target environment"
        )
        return OutputMessage(
            code="dependency_target_incompatible",
            message=message,
            source=_provider(node.source) if node.source else None,
        )
    return OutputMessage(
        code="dependency_version_conflict",
        message=(
            f"{node.name}: selected {node.selected_version} does not satisfy "
            f"{node.version_spec}"
        ),
        source=_provider(node.source) if node.source else None,
    )


def _matching_node_paths(
    tree: DependencyNode, path: list[str]
) -> Iterator[list[DependencyNode]]:
    """Yield every node path represented by a name-only ``path``.

    Yields:
        Node paths in the tree's depth-first order.
    """
    if not path or tree.name != path[0]:
        return
    if len(path) == 1:
        yield [tree]
        return
    for child in tree.children:
        for child_path in _matching_node_paths(child, path[1:]):
            yield [tree, *child_path]


def _resolve_node_paths(
    tree: DependencyNode, paths: list[list[str]]
) -> list[list[DependencyNode]]:
    """Match repeated name paths to distinct tree paths in emission order.

    Returns:
        One node path per emitted name path, or an empty path for a mismatch.
    """
    occurrences: dict[tuple[str, ...], int] = {}
    resolved: list[list[DependencyNode]] = []
    for path in paths:
        key = tuple(path)
        occurrence = occurrences.get(key, 0)
        matches = list(_matching_node_paths(tree, path))
        resolved.append(matches[occurrence] if occurrence < len(matches) else [])
        occurrences[key] = occurrence + 1
    return resolved


def _path_sources(
    path: list[DependencyNode], path_index: int, timestamp: str
) -> list[SourceRecord]:
    records = (
        _dependency_source(node, f"result.paths[{path_index}][{index}]", timestamp)
        for index, node in enumerate(path)
    )
    return [record for record in records if record is not None]


def _walk_tree(tree: DependencyNode) -> Iterator[DependencyNode]:
    yield tree
    for child in tree.children:
        yield from _walk_tree(child)


def _off_path_warning_sources(
    tree: DependencyNode, timestamp: str, seen: Container[int]
) -> list[SourceRecord]:
    """Collect warning provenance on branches that no emitted path covers.

    Their ``fields`` list is empty: the warning arose outside the returned
    list-of-lists ``result.paths``, so no real result path identifies it.

    Returns:
        One field-less source record per unreported warned node.
    """
    records: list[SourceRecord] = []
    for node in _walk_tree(tree):
        warned = node.resolution_failure is not None or node.state in {
            "conflicting",
            "depth_limited",
        }
        record = _dependency_source(node, "result.paths", timestamp)
        if warned and record is not None and id(node) not in seen:
            records.append(replace(record, fields=[]))
    return records


def _why_sources(
    tree: DependencyNode, paths: list[list[str]], timestamp: str
) -> list[SourceRecord]:
    node_paths = _resolve_node_paths(tree, paths)
    records = [
        record
        for path_index, node_path in enumerate(node_paths)
        for record in _path_sources(node_path, path_index, timestamp)
    ]
    seen = {id(node) for node_path in node_paths for node in node_path}
    records.extend(_off_path_warning_sources(tree, timestamp, seen))
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
    timestamp = generated_at or utc_now()
    warnings = _dependency_warnings(node)
    envelope = make_envelope(
        "deps",
        arguments=arguments,
        status="partial" if warnings else "success",
        result=_node_dict(node),
        sources=_dependency_sources(node, timestamp),
        warnings=warnings,
        generated_at=timestamp,
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
    timestamp = generated_at or utc_now()
    warnings = _dependency_warnings(tree) if tree else []
    envelope = make_envelope(
        "deps",
        arguments=arguments,
        status="partial" if warnings else ("success" if paths else "empty"),
        result={"target": target, "paths": paths},
        sources=_why_sources(tree, paths, timestamp) if tree else [],
        warnings=warnings,
        generated_at=timestamp,
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
    freshness: Freshness | None = None,
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
                freshness=freshness,
                fields=["result.versions"],
            )
        ],
        generated_at=timestamp,
    )
    return _dump(envelope.to_dict())


def _publisher_dict(publisher: Publisher) -> dict[str, object]:
    """Represent one Trusted Publisher identity.

    Returns:
        The publisher's kind and its kind-specific claims.
    """
    return {"kind": publisher.kind, "claims": publisher.claims}


def _artifact_dict(file: ArtifactFile) -> dict[str, object]:
    """Represent one distribution file as structured data.

    ``compatible`` is nullable on purpose: ``null`` means peta could not read
    the evidence, which is not the same answer as ``false``. ``provenance``
    likewise reports what the index exposed, never a verification result.

    Returns:
        The file's JSON mapping.
    """
    return {
        "filename": file.filename,
        "url": file.url,
        "kind": file.kind,
        "size": file.size,
        "upload_time": file.upload_time,
        "sha256": file.sha256,
        "requires_python": file.requires_python,
        "yanked": file.yanked,
        "yanked_reason": file.yanked_reason,
        "core_metadata": file.core_metadata,
        "tags": list(file.tags),
        "compatible": file.compatibility.compatible,
        "incompatibility": file.compatibility.reason,
        "provenance": {
            "available": file.provenance_url is not None,
            "url": file.provenance_url,
            "publishers": [_publisher_dict(p) for p in file.publishers],
        },
    }


def _artifacts_result(release: ReleaseArtifacts) -> dict[str, object]:
    """Build the ``result`` payload for a release's artifacts.

    Returns:
        The release summary and its file list.
    """
    return {
        "name": release.name,
        "version": release.version,
        "target": {"python": release.target.version},
        "summary": {
            "files": len(release.files),
            "wheels": len(release.wheels),
            "sdists": len(release.sdists),
            "compatible": len(release.compatible),
            "total_size": release.total_size,
            "unsized_files": sum(f.size is None for f in release.files),
            "yanked": release.yanked,
            "with_provenance": len(release.with_provenance),
        },
        "files": [_artifact_dict(file) for file in release.files],
    }


def _publisher_paths(release: ReleaseArtifacts) -> tuple[list[str], list[str]]:
    """Name the result paths the publisher lookup did and did not reach.

    A reached path counts whether or not PyPI supplied a publisher for it:
    "asked, and there is none" is evidence, and folding it in with the paths
    that were never answered would lose the distinction.

    Returns:
        The paths the lookup completed for, and the paths it failed on.
    """
    index_of = {file.filename: index for index, file in enumerate(release.files)}

    def path(filename: str) -> str:
        return f"result.files[{index_of[filename]}].provenance.publishers"

    reached = [path(name) for name in release.publisher_lookups if name in index_of]
    missed = [
        path(failure.filename)
        for failure in release.publisher_failures
        if failure.filename in index_of
    ]
    return reached, missed


def _completed_record(
    release: ReleaseArtifacts, reached: list[str], target: str
) -> SourceRecord:
    """Describe the provenance lookup that did complete, or its absence.

    When no file in the release exposes provenance there is nothing to look
    up, so the record says ``skipped`` and carries no retrieval time. Dating
    it with the envelope's own timestamp would assert that the source answered
    at a moment no request was made — the kind of claim the provenance fields
    exist to prevent.

    Returns:
        The record for the completed side of the lookup.
    """
    retrieval = release.publisher_retrieval
    if retrieval is None:
        return SourceRecord(
            name="pypi-provenance",
            state="skipped",
            target=target,
            reason="no file exposes provenance",
        )
    return SourceRecord(
        name="pypi-provenance",
        state="success" if any(f.publishers for f in release.files) else "empty",
        target=target,
        retrieved_at=retrieval.retrieved_at,
        freshness=retrieval.freshness,
        fields=reached,
    )


def _publisher_sources(release: ReleaseArtifacts, timestamp: str) -> list[SourceRecord]:
    """Record what the PEP 740 provenance lookup produced, field by field.

    A completed lookup and a failed one are separate records, because one
    ``state`` cannot describe both and a consumer must be able to tell the
    paths PyPI supplied nothing for from the paths peta could not reach. The
    completed record survives a sibling failure: a file that was reached and
    genuinely has no publisher must not disappear because another file's
    request fell over.

    Returns:
        One record for the completed lookups, one for the failed ones, or
        whichever of the two actually happened.
    """
    del timestamp
    reached, missed = _publisher_paths(release)
    failures = release.publisher_failures
    target = f"{release.name} {release.version}"
    records: list[SourceRecord] = []
    if reached or not failures:
        records.append(_completed_record(release, reached, target))
    if failures:
        records.append(
            SourceRecord(
                name="pypi-provenance",
                state="failed",
                target=target,
                reason="; ".join(failure.description for failure in failures),
                fields=missed,
            )
        )
    return records


def format_artifacts(
    release: ReleaseArtifacts,
    *,
    arguments: dict[str, object] | None = None,
    generated_at: str | None = None,
    retrieved_at: str | None = None,
    freshness: Freshness | None = None,
    publishers: bool = False,
) -> str:
    """Format a release's artifacts in the versioned JSON envelope.

    Returns:
        An indented JSON string.
    """
    timestamp = generated_at or utc_now()
    files = release.files
    sources = [
        SourceRecord(
            name="pypi",
            state="success" if files else "empty",
            target=f"{release.name} {release.version}",
            retrieved_at=retrieved_at or timestamp,
            freshness=freshness,
            fields=["result.files"],
        )
    ]
    if publishers:
        sources.extend(_publisher_sources(release, timestamp))
    warnings = [
        OutputMessage(
            code="enrichment_failed",
            message=failure.description,
            source="pypi-provenance",
        )
        for failure in release.publisher_failures
    ]
    status: EnvelopeStatus = (
        "partial" if warnings else ("success" if files else "empty")
    )
    envelope = make_envelope(
        "artifacts",
        arguments=arguments,
        status=status,
        result=_artifacts_result(release),
        sources=sources,
        warnings=warnings,
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
