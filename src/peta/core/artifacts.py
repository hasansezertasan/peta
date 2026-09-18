"""Release artifacts: what a release ships, whether it fits, and who built it.

Answers three questions about one release from a single Simple API project
page: which files it publishes (wheels, sdists, their digests, sizes and
upload times), whether any of them can be installed on a chosen interpreter,
and what publication evidence PyPI exposes for them.

Compatibility is evaluated with packaging's own tag and specifier parsing, not
with filename substring tests, so ``cp313-abi3-manylinux_2_28_x86_64`` is
judged by the same rules an installer applies.
:func:`evaluate_compatibility` is the shared primitive: it takes a filename and
a ``Requires-Python`` value, so anything that needs to filter or explain wheel
selection can use it without going through the artifact view.

Absent evidence is reported as unknown or not supplied, never as a failed
verification: a file with no PEP 740 provenance URL has not failed anything,
and peta does not verify attestations — it reports what the index exposes.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass, field, replace
from functools import cache as _memoize, partial
from typing import TYPE_CHECKING, Literal, TypeAliasType, cast

import httpx
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.tags import compatible_tags, cpython_tags, sys_tags
from packaging.utils import InvalidWheelFilename, parse_wheel_filename

from peta.core import cache, http
from peta.core.cache import Provenance
from peta.core.concurrency import gather
from peta.core.index import (
    files_for_version,
    get_project_page,
    is_published,
    latest_version,
)
from peta.core.validation import expect_list, expect_mapping, optional_string

if TYPE_CHECKING:
    from packaging.tags import Tag

    from peta.core.index import IndexFile

__all__ = [
    "ArtifactFile",
    "Compatibility",
    "Publisher",
    "PublisherFailure",
    "ReleaseArtifacts",
    "Target",
    "evaluate_compatibility",
    "get_release",
    "parse_target",
]

ArtifactKind = TypeAliasType(  # ruff: ignore[non-pep695-type-alias]
    "ArtifactKind", Literal["wheel", "sdist", "other"]
)

_PROVENANCE_SOURCE = "PyPI provenance"

_SDIST_SUFFIXES = (".tar.gz", ".zip", ".tar.bz2", ".tar.xz", ".tgz", ".tar")


@_memoize
def _target_tags(python: str | None) -> frozenset[Tag]:
    """Build the tag set a wheel must match to be installable on a target.

    ``None`` asks packaging for the running interpreter's own tags, which is
    the exact set an installer would use here. A named version is resolved
    against *this* machine's platform tags, since the question peta answers is
    "can I install this here under that Python", not "on some other machine".

    Returns:
        Every tag the target accepts.
    """
    if python is None:
        return frozenset(sys_tags())
    version = _python_tuple(python)
    interpreter = f"cp{version[0]}{version[1]}"
    # ``compatible_tags`` is called twice on purpose. Without an interpreter it
    # yields the ``pyXY`` tags; with one it also yields ``cpXY-none-any``, which
    # ``cpython_tags`` never emits and ``sys_tags`` does include. Omitting it
    # made an explicit target stricter than the running one, so the same wheel
    # was installable under ``peta artifacts`` and not under
    # ``peta artifacts --python <this same version>``.
    return frozenset(cpython_tags(python_version=version)).union(
        compatible_tags(python_version=version),
        compatible_tags(python_version=version, interpreter=interpreter),
    )


def _python_tuple(python: str) -> tuple[int, int]:
    """Split a validated ``MAJOR.MINOR[.MICRO]`` version into the pair tags need.

    Returns:
        The major and minor version numbers.
    """
    parts = python.split(".")
    return int(parts[0]), int(parts[1])


@dataclass(frozen=True)
class Target:
    """The interpreter a release's files are judged against."""

    python: str | None = None
    """``MAJOR.MINOR`` to judge against, or ``None`` for the running one."""

    @property
    def version(self) -> str:
        """The Python version ``Requires-Python`` is evaluated against.

        Returns:
            The selected version, or the running interpreter's full version.
        """
        if self.python is not None:
            return self.python
        return platform.python_version()

    @property
    def tags(self) -> frozenset[Tag]:
        """Every platform tag this target accepts.

        Returns:
            The target's compatible tag set.
        """
        return _target_tags(self.python)


def parse_target(python: str | None) -> Target:
    """Build a target from a ``MAJOR.MINOR`` Python version string.

    Returns:
        The requested target, or one standing for the running interpreter.

    Raises:
        ValueError: If ``python`` is not a ``MAJOR.MINOR[.MICRO]`` version.
    """
    if python is None:
        return Target()
    parts = python.split(".")
    # Every component is checked, not just the first two. A value like
    # ``3.13.bad`` otherwise parses far enough to build a target, and then
    # answers every ``Requires-Python`` question with a silent ``False``
    # — a confident wrong answer, which is worse than the rejection here.
    if len(parts) not in {2, 3} or not all(part.isdigit() for part in parts):
        msg = f"Invalid Python version {python!r}; expected MAJOR.MINOR."
        raise ValueError(msg)
    return Target(python)


@dataclass(frozen=True)
class Compatibility:
    """Whether one file installs on a target, and why not when it does not."""

    compatible: bool | None
    """``None`` when the evidence cannot be read — unknown, not incompatible."""
    reason: str | None = None


@dataclass(frozen=True)
class Publisher:
    """The Trusted Publisher identity PyPI recorded for a file.

    Reported as PyPI supplied it. peta does not verify the attestation it came
    from, so this says who PyPI recorded as publishing the file, not that the
    file has been cryptographically verified here.

    Only ``kind`` is named. Every publisher kind PEP 740 defines describes
    itself with different keys — GitHub with a repository and a workflow,
    GitLab with a workflow filepath, Google with an email and subject — so
    naming one kind's fields would silently drop the identity of every other.
    The rest are carried through verbatim in :attr:`claims`.
    """

    kind: str
    claims: dict[str, str] = field(default_factory=dict)

    @property
    def description(self) -> str:
        """Summarize the identity in one line for human output.

        Returns:
            The publisher kind followed by its claims, in a stable order.
        """
        detail = " ".join(
            f"{key}={value}" for key, value in sorted(self.claims.items())
        )
        return f"{self.kind} {detail}".rstrip()


@dataclass(frozen=True)
class PublisherFailure:
    """A provenance lookup that did not complete, and the file it was for.

    The filename is kept separately from the reason so machine output can
    attribute the gap to a real result path, rather than leaving a consumer
    to parse a filename back out of a warning message.
    """

    filename: str
    reason: str

    @property
    def description(self) -> str:
        """Summarize the failure in one line for human output.

        Returns:
            The filename followed by why its lookup failed.
        """
        return f"{self.filename}: {self.reason}"


@dataclass(frozen=True)
class ArtifactFile:
    """One distribution file of a release, with its compatibility verdict."""

    filename: str
    url: str
    kind: ArtifactKind
    compatibility: Compatibility
    size: int | None = None
    upload_time: str | None = None
    sha256: str | None = None
    requires_python: str | None = None
    yanked: bool = False
    yanked_reason: str | None = None
    core_metadata: bool = False
    provenance_url: str | None = None
    """Where PyPI serves this file's PEP 740 provenance, when it has one."""
    tags: tuple[str, ...] = ()
    publishers: tuple[Publisher, ...] = ()
    """Filled only when publisher lookup was asked for and PyPI supplied any.

    Plural because PEP 740 groups attestations into one bundle per publisher
    and permits several, so reporting only the first would silently drop
    evidence this command exists to surface.
    """


@dataclass(frozen=True)
class ReleaseArtifacts:
    """Every distribution file published for one release."""

    name: str
    version: str
    target: Target
    files: list[ArtifactFile]
    publisher_failures: tuple[PublisherFailure, ...] = ()
    """Files whose provenance lookup failed, so a gap is never read as absence."""
    publisher_retrieval: Provenance | None = None
    """Where the publisher evidence came from, when any lookup completed."""

    @property
    def wheels(self) -> list[ArtifactFile]:
        """The release's wheels.

        Returns:
            Every file published as a wheel.
        """
        return [f for f in self.files if f.kind == "wheel"]

    @property
    def sdists(self) -> list[ArtifactFile]:
        """The release's source distributions.

        Returns:
            Every file published as an sdist.
        """
        return [f for f in self.files if f.kind == "sdist"]

    @property
    def compatible(self) -> list[ArtifactFile]:
        """The files installable on the target.

        Files whose compatibility is unknown are excluded, so the count never
        overstates what peta actually established.

        Returns:
            Every file judged compatible.
        """
        return [f for f in self.files if f.compatibility.compatible]

    @property
    def total_size(self) -> int:
        """The release's aggregate download size in bytes.

        Returns:
            The sum of the sizes the index reported; files without one
            contribute nothing.
        """
        return sum(f.size or 0 for f in self.files)

    @property
    def yanked(self) -> bool:
        """Whether the whole release is yanked.

        Returns:
            ``True`` when the release has files and every one is yanked.
        """
        return bool(self.files) and all(f.yanked for f in self.files)

    @property
    def publishers(self) -> list[str]:
        """Every distinct Trusted Publisher identity recorded for this release.

        Returns:
            One description per distinct publisher, in a stable order.
        """
        return sorted({
            publisher.description for f in self.files for publisher in f.publishers
        })

    @property
    def with_provenance(self) -> list[ArtifactFile]:
        """The files for which PyPI exposes provenance.

        Returns:
            Every file carrying a PEP 740 provenance URL.
        """
        return [f for f in self.files if f.provenance_url is not None]


def evaluate_compatibility(
    filename: str, requires_python: str | None, target: Target
) -> Compatibility:
    """Judge one distribution file against a target interpreter.

    ``Requires-Python`` is checked first, because it rules out a file whatever
    its tags say. A wheel is then compatible when any of its platform tags is
    one the target accepts. Anything that is not a wheel carries no tags, so
    ``Requires-Python`` alone decides it — a source distribution still has to
    be built, which this does not promise.

    Returns:
        The verdict, with a reason whenever it is not a plain yes.
    """
    if requires_python:
        try:
            specifier = SpecifierSet(requires_python)
        except InvalidSpecifier:
            return Compatibility(
                compatible=None,
                reason=f"unreadable Requires-Python {requires_python!r}",
            )
        if not specifier.contains(target.version):
            return Compatibility(
                compatible=False,
                reason=f"Python {target.version} is outside {requires_python}",
            )
    return _tag_compatibility(filename, target)


def _tag_compatibility(filename: str, target: Target) -> Compatibility:
    """Match a wheel's own tags against the ones the target accepts.

    Returns:
        The tag verdict; a plain yes for anything that is not a wheel.
    """
    if not filename.endswith(".whl"):
        return Compatibility(compatible=True)
    try:
        _, _, _, tags = parse_wheel_filename(filename)
    except InvalidWheelFilename:
        return Compatibility(
            compatible=None, reason=f"unreadable wheel filename {filename!r}"
        )
    if tags & target.tags:
        return Compatibility(compatible=True)
    return Compatibility(
        compatible=False, reason=f"no wheel tag matches Python {target.version} here"
    )


def _kind(filename: str) -> ArtifactKind:
    """Classify a distribution file by its extension.

    Returns:
        ``"wheel"``, ``"sdist"``, or ``"other"`` for anything else an index
        may serve (eggs, installers) that peta reports without interpreting.
    """
    if filename.endswith(".whl"):
        return "wheel"
    if filename.endswith(_SDIST_SUFFIXES):
        return "sdist"
    return "other"


def _wheel_tags(filename: str) -> tuple[str, ...]:
    """Read a wheel's platform tags from its filename.

    Returns:
        The tags in sorted order; empty for a non-wheel or an unreadable name.
    """
    if not filename.endswith(".whl"):
        return ()
    try:
        _, _, _, tags = parse_wheel_filename(filename)
    except InvalidWheelFilename:
        return ()
    return tuple(sorted(str(tag) for tag in tags))


def _yanked_state(entry: IndexFile) -> tuple[bool, str | None]:
    """Split PEP 592's overloaded ``yanked`` field into a flag and a reason.

    The field is a boolean or the reason string itself, so a file yanked with
    an explanation and one yanked without are the same state in the index.

    Returns:
        Whether the file is yanked, and the reason when one was given.
    """
    value = entry.get("yanked", False)
    if isinstance(value, str):
        return True, value or None
    return value, None


def _artifact(entry: IndexFile, target: Target) -> ArtifactFile:
    """Build one artifact record from a Simple API file entry.

    Returns:
        The file with its compatibility already evaluated.
    """
    filename = entry["filename"]
    requires_python = entry.get("requires_python")
    yanked, yanked_reason = _yanked_state(entry)
    return ArtifactFile(
        filename=filename,
        url=entry["url"],
        kind=_kind(filename),
        compatibility=evaluate_compatibility(filename, requires_python, target),
        size=entry.get("size"),
        upload_time=entry.get("upload_time"),
        sha256=entry.get("hashes", {}).get("sha256"),
        requires_python=requires_python,
        yanked=yanked,
        yanked_reason=yanked_reason,
        core_metadata=entry.get("core_metadata", False) is not False,
        provenance_url=entry.get("provenance"),
        tags=_wheel_tags(filename),
    )


def _publisher_in(bundle: object, index: int) -> Publisher | None:
    """Read one attestation bundle's publisher.

    Returns:
        The publisher, or ``None`` when the bundle names none.
    """
    path = f"$.attestation_bundles[{index}]"
    raw_bundle = expect_mapping(bundle, source=_PROVENANCE_SOURCE, path=path)
    if raw_bundle.get("publisher") is None:
        return None
    path = f"{path}.publisher"
    raw = expect_mapping(raw_bundle["publisher"], source=_PROVENANCE_SOURCE, path=path)
    kind = optional_string(raw, "kind", source=_PROVENANCE_SOURCE, path=path)
    if kind is None:
        return None
    claims = {
        key: value
        for key, value in raw.items()
        if key != "kind" and isinstance(value, str)
    }
    return Publisher(kind=kind, claims=claims)


def _publishers_from(body: object) -> tuple[Publisher, ...]:
    """Read every attestation bundle's publisher from a provenance document.

    A missing ``attestation_bundles`` key means the document supplies no
    publisher. A key that is present but is not an array is malformed, and is
    rejected rather than quietly treated as absence — the distinction this
    command exists to keep.

    A document that does not match PEP 740's shape raises, which
    :func:`_publisher_for` turns into a reported failure.

    Returns:
        One publisher per bundle that names one, in document order.
    """
    root = expect_mapping(body, source=_PROVENANCE_SOURCE, path="$")
    raw_bundles = root.get("attestation_bundles")
    if raw_bundles is None:
        return ()
    bundles = expect_list(
        raw_bundles, source=_PROVENANCE_SOURCE, path="$.attestation_bundles"
    )
    found = (_publisher_in(bundle, index) for index, bundle in enumerate(bundles))
    return tuple(publisher for publisher in found if publisher is not None)


@dataclass(frozen=True)
class _Lookup:
    """What one file's provenance lookup produced."""

    publishers: tuple[Publisher, ...] = ()
    failure: PublisherFailure | None = None
    retrieval: Provenance | None = None


def _publisher_for(file: ArtifactFile) -> _Lookup:
    """Fetch one file's PEP 740 provenance document and read its publishers.

    Every failure is returned rather than raised: this evidence is optional,
    and a provenance document peta could not retrieve or parse must not turn
    an otherwise complete artifact listing into a failed command.

    Returns:
        The publishers PyPI supplied, the reason the lookup failed, and where
        the answer came from.
    """
    url = file.provenance_url
    if url is None:
        return _Lookup()
    try:
        fetched = http.get(url, ttl=cache.DAILY, scope="provenance")
        _ = fetched.response.raise_for_status()
        publishers = _publishers_from(cast("object", fetched.response.json()))
    except (httpx.HTTPError, http.OfflineError, ValueError) as exc:
        return _Lookup(failure=PublisherFailure(file.filename, str(exc)))
    http.keep(fetched)
    return _Lookup(publishers=publishers, retrieval=fetched.provenance)


_FRESHNESS_ORDER = {"live": 0, "revalidated": 1, "cached": 2}
"""How to collapse many retrievals into one, most-recently-contacted first."""


def _merged_retrieval(lookups: list[_Lookup]) -> Provenance | None:
    """Summarize many per-file retrievals as one source-level provenance.

    A release is one source record, but its publisher evidence comes from one
    request per file, which can mix live answers with cached ones. The
    reported freshness is the strongest contact made and the timestamp the
    oldest, so the record never claims the whole of it is fresher than its
    stalest part.

    Returns:
        The merged provenance, or ``None`` when no lookup completed.
    """
    completed = [lookup.retrieval for lookup in lookups if lookup.retrieval]
    if not completed:
        return None
    freshest = min(completed, key=lambda item: _FRESHNESS_ORDER[item.freshness])
    return Provenance(freshest.freshness, min(item.retrieved_at for item in completed))


def _with_publishers(
    files: list[ArtifactFile],
) -> tuple[list[ArtifactFile], tuple[PublisherFailure, ...], Provenance | None]:
    """Attach each file's Trusted Publisher identities, fetched concurrently.

    Returns:
        The files with publishers filled in, one record per failed lookup, and
        where the completed lookups came from.
    """
    lookups = gather([partial(_publisher_for, file) for file in files])
    updated = [
        replace(file, publishers=lookup.publishers)
        for file, lookup in zip(files, lookups, strict=True)
    ]
    failures = tuple(lookup.failure for lookup in lookups if lookup.failure)
    return updated, failures, _merged_retrieval(lookups)


def get_release(
    name: str,
    version: str | None = None,
    *,
    target: Target | None = None,
    publishers: bool = False,
) -> tuple[ReleaseArtifacts | None, Provenance]:
    """Collect one release's distribution files from the Simple API.

    Args:
        name: Package name, in any spelling.
        version: The release to inspect; the newest non-prerelease by default.
        target: What to judge compatibility against; the running interpreter
            when omitted.
        publishers: Also fetch the PEP 740 provenance document of every file
            that has one, for its Trusted Publisher identity. One extra
            request per such file, so it is off by default.

    Returns:
        The release's artifacts and where the listing came from; the release
        is ``None`` when the index knows no such project, or no such version
        of it. A published release that happens to carry no files is a real
        release and comes back with an empty file list, which is a different
        answer from a version that was never published.
    """
    page, provenance = get_project_page(name)
    if not page["versions"]:
        return None, provenance
    if version is not None and not is_published(page, version):
        return None, provenance
    selected = version or latest_version(page["versions"])
    evaluated = target or Target()
    files = [_artifact(entry, evaluated) for entry in files_for_version(page, selected)]
    failures: tuple[PublisherFailure, ...] = ()
    retrieval: Provenance | None = None
    if publishers:
        files, failures, retrieval = _with_publishers(files)
    release = ReleaseArtifacts(
        name=page["name"],
        version=selected,
        target=evaluated,
        files=files,
        publisher_failures=failures,
        publisher_retrieval=retrieval,
    )
    return release, provenance
