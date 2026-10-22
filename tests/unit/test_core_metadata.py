"""Unit tests for the Core Metadata dossier of local and PyPI packages."""

from __future__ import annotations

import json
from email.message import Message
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from peta.cli.output.json import format_info
from peta.cli.output.markdown import format_info as markdown_info
from peta.cli.output.tables import render_info
from peta.cli.output.text import format_info as text_info
from peta.core.local import get_package as get_local
from peta.core.metadata import parse_people
from peta.core.models import CoreMetadata, EntryPointDeclaration, PackageInfo, Person
from peta.core.remote import NetworkError, get_package as get_remote

if TYPE_CHECKING:
    from tests.transport import FakeTransport

pytestmark = pytest.mark.unit


def test_people_split_only_the_email_field() -> None:
    people = parse_people("Ada", "Ada <ada@example.com>, Bob <bob@example.com>")
    assert people == [
        Person("Ada", "ada@example.com"),
        Person("Bob", "bob@example.com"),
    ]


def test_people_name_field_names_a_bare_address() -> None:
    assert parse_people("Ada", "ada@example.com") == [Person("Ada", "ada@example.com")]


def test_people_keep_a_name_the_email_field_does_not_carry() -> None:
    assert parse_people("Team", "a@example.com, b@example.com") == [
        Person("Team", None),
        Person(None, "a@example.com"),
        Person(None, "b@example.com"),
    ]


def test_people_name_field_alone_is_not_split() -> None:
    assert parse_people("Ada, Bob", None) == [Person("Ada, Bob", None)]
    assert parse_people(None, None) == []


def _local(headers: list[tuple[str, str]], points: list[MagicMock]) -> PackageInfo:
    msg = Message()
    for key, value in [("Name", "demo"), ("Version", "1.0"), *headers]:
        msg[key] = value
    dist = MagicMock()
    dist.metadata = msg
    dist.requires = None
    dist.files = None
    dist.entry_points = points
    with patch("peta.core.local.importlib_metadata") as mock_meta:
        mock_meta.distribution.return_value = dist
        return get_local("demo")


def test_local_keeps_multi_value_fields() -> None:
    point = MagicMock(group="console_scripts", value="demo.cli:main")
    point.name = "demo"
    package = _local(
        [
            ("Metadata-Version", "2.4"),
            ("License-File", "LICENSE"),
            ("License-File", "licenses/NOTICE"),
            ("Provides-Extra", "cli"),
            ("Provides-Extra", "docs"),
            ("Import-Name", "demo"),
            ("Import-Namespace", "ns.demo"),
            ("Author-email", "Ada <ada@example.com>, Bob <bob@example.com>"),
            ("Maintainer-email", "Cy <cy@example.com>"),
            ("Dynamic", "version"),
            ("Dynamic", "classifiers"),
        ],
        [point],
    )
    meta = package.core_metadata
    assert meta is not None
    assert meta.source == "installed"
    assert meta.metadata_version == "2.4"
    assert meta.license_files == ["LICENSE", "licenses/NOTICE"]
    assert meta.provides_extra == ["cli", "docs"]
    assert meta.import_names == ["demo"]
    assert meta.import_namespaces == ["ns.demo"]
    assert meta.entry_points == [
        EntryPointDeclaration("console_scripts", "demo", "demo.cli:main")
    ]
    assert [person.name for person in meta.authors] == ["Ada", "Bob"]
    assert meta.maintainers == [Person("Cy", "cy@example.com")]
    assert meta.dynamic == ["version", "classifiers"]
    assert meta.unrecognized == {}


def test_local_unknown_headers_are_kept_verbatim_not_modeled() -> None:
    package = _local(
        [("Metadata-Version", "9.9"), ("Future-Field", "a"), ("Future-Field", "b")], []
    )
    meta = package.core_metadata
    assert meta is not None
    assert meta.unrecognized == {"Future-Field": ["a", "b"]}


def test_remote_maps_the_same_model(fake_http: FakeTransport) -> None:
    fake_http.reply(
        json={
            "info": {
                "name": "demo",
                "version": "1.0",
                "author": "Ada",
                "author_email": "ada@example.com",
                "provides_extra": ["cli"],
                "license_files": ["LICENSE"],
                "dynamic": ["version"],
            }
        }
    )
    meta = get_remote("demo").core_metadata
    assert meta == CoreMetadata(
        source="pypi",
        license_files=["LICENSE"],
        provides_extra=["cli"],
        authors=[Person("Ada", "ada@example.com")],
        dynamic=["version"],
    )


def test_remote_without_the_fields_stays_empty(fake_http: FakeTransport) -> None:
    fake_http.reply(json={"info": {"name": "demo", "version": "1.0"}})
    meta = get_remote("demo").core_metadata
    assert meta is not None
    assert meta.metadata_version is None
    assert meta.entry_points == []


def test_remote_rejects_a_malformed_extras_field(fake_http: FakeTransport) -> None:
    fake_http.reply(
        json={"info": {"name": "demo", "version": "1.0", "provides_extra": "cli"}}
    )
    with pytest.raises(NetworkError, match="provides_extra"):
        _ = get_remote("demo")


def _package() -> PackageInfo:
    return PackageInfo(
        name="demo",
        version="1.0",
        source="local",
        core_metadata=CoreMetadata(
            source="installed",
            metadata_version="2.4",
            provides_extra=["cli", "docs"],
            license_files=["LICENSE"],
            entry_points=[EntryPointDeclaration("console_scripts", "demo", "d:m")],
            unrecognized={"Future-Field": ["x"]},
        ),
    )


def test_human_output_stays_concise() -> None:
    text = render_info(_package(), color=False)
    assert "Metadata-Version" in text
    assert "cli, docs" in text
    assert "Entry points" in text
    assert "Future-Field" not in text
    assert "console_scripts" not in text


def test_structured_output_carries_the_detail() -> None:
    result = json.loads(format_info(_package(), arguments={}))["result"]
    metadata = result["core_metadata"]
    assert metadata["source"] == "installed"
    assert metadata["entry_points"] == [
        {"group": "console_scripts", "name": "demo", "value": "d:m"}
    ]
    assert metadata["unrecognized"] == {"Future-Field": ["x"]}


def test_local_keeps_an_explicitly_empty_import_name() -> None:
    meta = _local([("Import-Name", "")], []).core_metadata
    assert meta is not None
    assert meta.import_names == [""]


def test_local_unknown_headers_merge_case_variants() -> None:
    meta = _local([("Future-Field", "a"), ("future-field", "b")], []).core_metadata
    assert meta is not None
    assert meta.unrecognized == {"Future-Field": ["a", "b"]}


def test_local_description_header_is_not_lost() -> None:
    meta = _local([("Description", "long text")], []).core_metadata
    assert meta is not None
    assert meta.unrecognized == {"Description": ["long text"]}


def test_text_and_markdown_views_show_the_summary() -> None:
    package = _package()
    for rendered in (text_info(package), markdown_info(package)):
        assert "Metadata-Version" in rendered
        assert "cli, docs" in rendered
        assert "Future-Field" not in rendered


def test_local_malformed_entry_points_do_not_break_the_dossier() -> None:
    dist = MagicMock()
    dist.metadata = Message()
    dist.metadata["Name"] = "demo"
    dist.metadata["Version"] = "1.0"
    dist.requires = None
    dist.files = None
    type(dist).entry_points = property(MagicMock(side_effect=TypeError("bad")))
    with patch("peta.core.local.importlib_metadata") as mock_meta:
        mock_meta.distribution.return_value = dist
        meta = get_local("demo").core_metadata
    assert meta is not None
    assert meta.entry_points == []
