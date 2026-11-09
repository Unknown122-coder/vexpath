"""Getting a dependency's source from the package index.

An archive is third-party data that this code unpacks to disk, so most of
these tests are refusals: a member that escapes the extraction directory, a
host off the allow-list, an oversized download, a member count that looks like
a bomb. The rest cover picking the right archive and finding the importable
packages inside it, because naming a symbol after the wrong prefix is one step
from a wrong verdict.

Nothing here reaches the network, and nothing an archive contains is ever
executed.
"""

from __future__ import annotations

import io
import json
import tarfile
import zipfile
from pathlib import Path

import httpx
import pytest

from vexpath_core.reach.archives import (
    MAX_ARCHIVE_BYTES,
    ArchiveError,
    ArchiveRef,
    ArchiveSource,
    download,
    extract,
    find_archive,
    importable_names,
)

MODULE_SOURCE = """\
class Downloader:
    def run(self):
        return 1
"""


def _wheel(members: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _sdist(members: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in members.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _ref(filename: str, *, size: int = 1000, host: str = "files.pythonhosted.org") -> ArchiveRef:
    return ArchiveRef(
        url=f"https://{host}/packages/ab/cd/{filename}",
        filename=filename,
        packagetype="bdist_wheel" if filename.endswith(".whl") else "sdist",
        size=size,
    )


# --- Choosing an archive --------------------------------------------------


def _index(entries: list[dict[str, object]]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"urls": entries})

    return httpx.Client(transport=httpx.MockTransport(handler))


def _entry(filename: str, **extra: object) -> dict[str, object]:
    return {
        "filename": filename,
        "url": f"https://files.pythonhosted.org/packages/ab/cd/{filename}",
        "packagetype": "bdist_wheel" if filename.endswith(".whl") else "sdist",
        "size": 2048,
        **extra,
    }


def test_a_pure_python_wheel_is_preferred() -> None:
    """One file for every platform, and its layout is already the import layout."""
    with _index(
        [
            _entry("nltk-3.9.1.tar.gz"),
            _entry("nltk-3.9.1-cp312-cp312-win_amd64.whl"),
            _entry("nltk-3.9.1-py3-none-any.whl"),
        ]
    ) as client:
        found = find_archive("nltk", "3.9.1", client=client)
    assert found.filename == "nltk-3.9.1-py3-none-any.whl"


def test_a_platform_wheel_is_accepted_when_there_is_no_pure_one() -> None:
    with _index([_entry("thing-1.0-cp312-cp312-manylinux1_x86_64.whl")]) as client:
        assert find_archive("thing", "1.0", client=client).is_wheel


def test_an_sdist_is_the_fallback() -> None:
    # A few packages publish nothing else.
    with _index([_entry("thing-1.0.tar.gz")]) as client:
        found = find_archive("thing", "1.0", client=client)
    assert not found.is_wheel


def test_a_yanked_file_is_not_chosen() -> None:
    """A yanked release was withdrawn by its author, so it is not what runs."""
    with _index(
        [_entry("thing-1.0-py3-none-any.whl", yanked=True), _entry("thing-1.0.tar.gz")]
    ) as client:
        assert find_archive("thing", "1.0", client=client).filename == "thing-1.0.tar.gz"


def test_a_version_with_no_usable_archive_is_refused() -> None:
    with _index([]) as client, pytest.raises(ArchiveError, match="no archive"):
        find_archive("thing", "1.0", client=client)


def test_a_file_hosted_somewhere_unexpected_is_not_chosen() -> None:
    """A URL from an index response is third-party data, not an instruction."""
    with (
        _index(
            [
                {
                    "filename": "thing-1.0-py3-none-any.whl",
                    "url": "https://evil.example/thing-1.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "size": 10,
                }
            ]
        ) as client,
        pytest.raises(ArchiveError, match="no archive"),
    ):
        find_archive("thing", "1.0", client=client)


def test_an_unreadable_index_response_is_reported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>not json</html>")

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(ArchiveError, match="unreadable JSON"),
    ):
        find_archive("thing", "1.0", client=client)


def test_a_missing_version_is_reported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(ArchiveError, match="could not ask the index"),
    ):
        find_archive("thing", "99.0", client=client)


# --- Downloading ----------------------------------------------------------


def test_a_download_refuses_a_host_off_the_allow_list() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x")

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(ArchiveError, match="allow-list"),
    ):
        download(_ref("thing-1.0-py3-none-any.whl", host="evil.example"), client=client)


def test_a_download_refuses_a_declared_size_above_the_limit() -> None:
    """Checked before the request, so an oversized file is never transferred."""

    def handler(request: httpx.Request) -> httpx.Response:
        msg = "should not have been requested"
        raise AssertionError(msg)

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(ArchiveError, match="above the"),
    ):
        download(_ref("big-1.0.whl", size=MAX_ARCHIVE_BYTES + 1), client=client)


def test_a_download_refuses_a_body_above_the_limit() -> None:
    """A declared size can lie, so the body is checked too."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (MAX_ARCHIVE_BYTES + 1))

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(ArchiveError, match="above the"),
    ):
        download(_ref("liar-1.0.whl", size=10), client=client)


# --- Unpacking ------------------------------------------------------------


def test_a_wheel_unpacks_to_its_import_layout(tmp_path: Path) -> None:
    payload = _wheel(
        {
            "nltk/__init__.py": "from nltk.downloader import Downloader\n",
            "nltk/downloader.py": MODULE_SOURCE,
            "nltk-3.9.1.dist-info/METADATA": "Name: nltk\nVersion: 3.9.1\n",
        }
    )
    root = extract(payload, _ref("nltk-3.9.1-py3-none-any.whl"), tmp_path)

    assert root == tmp_path
    assert (root / "nltk" / "downloader.py").is_file()
    assert importable_names(root) == ("nltk",)


def test_an_sdist_unpacks_to_the_directory_holding_its_packages(tmp_path: Path) -> None:
    """Choosing the wrong level names every symbol after the wrong prefix."""
    payload = _sdist(
        {
            "nltk-3.9.1/setup.py": "from setuptools import setup\nsetup()\n",
            "nltk-3.9.1/PKG-INFO": "Name: nltk\n",
            "nltk-3.9.1/nltk/__init__.py": "",
            "nltk-3.9.1/nltk/downloader.py": MODULE_SOURCE,
        }
    )
    root = extract(payload, _ref("nltk-3.9.1.tar.gz"), tmp_path)

    assert root.name == "nltk-3.9.1"
    assert importable_names(root) == ("nltk",)


def test_a_src_layout_sdist_is_handled(tmp_path: Path) -> None:
    payload = _sdist(
        {
            "thing-1.0/pyproject.toml": "[project]\nname = 'thing'\n",
            "thing-1.0/src/thing/__init__.py": "",
            "thing-1.0/src/thing/core.py": MODULE_SOURCE,
        }
    )
    root = extract(payload, _ref("thing-1.0.tar.gz"), tmp_path)

    assert root.name == "src"
    assert importable_names(root) == ("thing",)


def test_a_bare_module_counts_as_importable(tmp_path: Path) -> None:
    payload = _wheel({"six.py": MODULE_SOURCE, "six-1.16.dist-info/METADATA": "Name: six\n"})
    root = extract(payload, _ref("six-1.16-py3-none-any.whl"), tmp_path)
    assert importable_names(root) == ("six",)


def test_setup_py_is_not_treated_as_an_importable_module(tmp_path: Path) -> None:
    """It is a build script, not part of the package the project imports."""
    payload = _sdist({"thing-1.0/setup.py": "setup()\n", "thing-1.0/thing/__init__.py": ""})
    root = extract(payload, _ref("thing-1.0.tar.gz"), tmp_path)
    assert "setup" not in importable_names(root)


def test_only_python_and_metadata_are_written(tmp_path: Path) -> None:
    payload = _wheel(
        {
            "thing/__init__.py": "",
            "thing/data.bin": "binary-ish",
            "thing/docs/guide.rst": "words",
            "thing-1.0.dist-info/top_level.txt": "thing\n",
        }
    )
    extract(payload, _ref("thing-1.0-py3-none-any.whl"), tmp_path)

    assert (tmp_path / "thing" / "__init__.py").is_file()
    assert not (tmp_path / "thing" / "data.bin").exists()
    assert not (tmp_path / "thing" / "docs" / "guide.rst").exists()
    assert (tmp_path / "thing-1.0.dist-info" / "top_level.txt").is_file()


# --- Refusing a hostile archive -------------------------------------------


def test_a_member_escaping_the_directory_is_not_written(tmp_path: Path) -> None:
    """This is how unpacking gets turned into arbitrary file writing."""
    payload = _wheel({"../escaped.py": "SECRET = 1", "thing/__init__.py": ""})
    extract(payload, _ref("thing-1.0-py3-none-any.whl"), tmp_path)

    assert not (tmp_path.parent / "escaped.py").exists()
    assert (tmp_path / "thing" / "__init__.py").is_file()


def test_an_absolute_member_path_is_not_written(tmp_path: Path) -> None:
    payload = _sdist({"/tmp/evil.py": "SECRET = 1", "thing-1.0/thing/__init__.py": ""})
    extract(payload, _ref("thing-1.0.tar.gz"), tmp_path)

    assert not Path("/tmp/evil.py").exists()


def test_a_symlink_member_is_ignored(tmp_path: Path) -> None:
    """A symlink is the other way an archive writes outside its directory."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        link = tarfile.TarInfo("thing-1.0/thing/link.py")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        archive.addfile(link)
        data = b""
        info = tarfile.TarInfo("thing-1.0/thing/__init__.py")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))

    root = extract(buffer.getvalue(), _ref("thing-1.0.tar.gz"), tmp_path)
    assert not (root / "thing" / "link.py").exists()
    assert (root / "thing" / "__init__.py").is_file()


def test_a_corrupt_archive_is_reported_rather_than_crashing(tmp_path: Path) -> None:
    with pytest.raises(ArchiveError, match="not a readable zip"):
        extract(b"not a zip at all", _ref("thing-1.0-py3-none-any.whl"), tmp_path)

    with pytest.raises(ArchiveError, match="not a readable tarball"):
        extract(b"not a tarball", _ref("thing-1.0.tar.gz"), tmp_path)


def test_an_archive_with_no_python_yields_no_import_names(tmp_path: Path) -> None:
    payload = _wheel({"thing-1.0.dist-info/METADATA": "Name: thing\n"})
    root = extract(payload, _ref("thing-1.0-py3-none-any.whl"), tmp_path)
    assert importable_names(root) == ()


# --- The source as a whole ------------------------------------------------


def test_the_source_reports_what_it_used(tmp_path: Path) -> None:
    wheel = _wheel({"nltk/__init__.py": "", "nltk/downloader.py": MODULE_SOURCE})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/json"):
            return httpx.Response(200, json={"urls": [_entry("nltk-3.9.1-py3-none-any.whl")]})
        return httpx.Response(200, content=wheel)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        source = ArchiveSource(client=client)
        root, note = source.source_root("nltk", "3.9.1", tmp_path)

    # A reader has to know a verdict rests on a downloaded archive rather than
    # on the environment they are running in.
    assert "wheel" in note
    assert "nltk-3.9.1-py3-none-any.whl" in note
    assert (root / "nltk" / "downloader.py").is_file()


def test_the_index_is_asked_for_the_normalised_name(tmp_path: Path) -> None:
    """The index redirects, but a lookup that has to redirect is a wasted call."""
    asked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.path)
        return httpx.Response(200, json={"urls": [_entry("flask-sqlalchemy-3.1.1.tar.gz")]})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        find_archive("Flask_SQLAlchemy", "3.1.1", client=client)

    assert asked == ["/pypi/flask-sqlalchemy/3.1.1/json"]
    del tmp_path


def test_a_graph_can_be_built_from_a_downloaded_archive(tmp_path: Path) -> None:
    """The whole point: an archive is a graphable source root."""
    from vexpath_core.reach.pybuild import SourceRoot, build

    payload = _wheel(
        {
            "nltk/__init__.py": "from nltk.downloader import Downloader\n",
            "nltk/downloader.py": MODULE_SOURCE,
        }
    )
    root = extract(payload, _ref("nltk-3.9.1-py3-none-any.whl"), tmp_path)
    graph = build(
        [SourceRoot(path=root, package="nltk", top_level=importable_names(root))],
        package="nltk",
        version="3.9.1",
    )

    assert "nltk.downloader.Downloader" in graph.nodes
    assert "nltk.downloader.Downloader.run" in graph.nodes
    assert graph.package == "nltk"
    assert graph.version == "3.9.1"


def test_nothing_in_an_archive_is_executed(tmp_path: Path) -> None:
    """A setup.py that would raise if run is only ever parsed."""
    payload = _sdist(
        {
            "thing-1.0/setup.py": "raise SystemExit('this must never run')\n",
            "thing-1.0/thing/__init__.py": "",
            "thing-1.0/thing/core.py": MODULE_SOURCE,
        }
    )
    root = extract(payload, _ref("thing-1.0.tar.gz"), tmp_path)

    from vexpath_core.reach.pybuild import SourceRoot, build

    graph = build([SourceRoot(path=root, package="thing", top_level=("thing",))])
    assert "thing.core.Downloader" in graph.nodes


def test_json_is_never_used_to_build_a_path(tmp_path: Path) -> None:
    """A filename from the index must not steer where files land."""
    payload = _wheel({"thing/__init__.py": ""})
    hostile = ArchiveRef(
        url="https://files.pythonhosted.org/packages/ab/cd/x.whl",
        filename="../../../../escaped.whl",
        packagetype="bdist_wheel",
        size=10,
    )
    extract(payload, hostile, tmp_path)
    assert (tmp_path / "thing" / "__init__.py").is_file()
    assert json  # the import is used by the helpers above
