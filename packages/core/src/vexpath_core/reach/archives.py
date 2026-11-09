"""Get a dependency's source from the package index rather than the environment.

Reachability needs to traverse a dependency's own code. The cheapest source is
the project's installed environment, and that is what a developer's machine or
a CI job that ran `pip install` already has. But two situations have no such
environment:

- A scan of a lockfile alone, which is what a pull-request check often is: the
  lockfile changed, nothing has been installed, and installing it would run
  arbitrary setup code from every dependency.
- A benchmark over many projects, where building an environment per project
  costs more than the measurement.

In both, the package index has exactly the source needed. A wheel is a zip of
installed files; nothing in it runs until something imports it, and nothing
here imports anything. An sdist is a tarball of the project tree, which needs
one extra step to find the importable packages inside it.

**Nothing from an archive is ever executed.** Files are read as text and parsed
with `ast`. `setup.py` is parsed, never run. The archive is never installed.

Four limits keep a hostile or broken archive from costing more than it should:
a host allow-list, a download size cap, a count of members, and a refusal of
any member whose path escapes the extraction directory.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import httpx

from vexpath_core.purl import normalise_name

#: The index that answers "where is version X of package Y".
PYPI_API_BASE = "https://pypi.org/pypi"

#: Hosts an archive may be downloaded from. A URL that reaches this code came
#: from an index response, which is third-party data, so it is checked rather
#: than followed.
ALLOWED_ARCHIVE_HOSTS = frozenset({"files.pythonhosted.org", "pypi.org"})

#: Refuse an archive larger than this. The largest pure-Python wheels are a few
#: megabytes; the ones far above that are shipping compiled artefacts or data,
#: which hold no Python for a call graph anyway.
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024

#: Refuse an archive with more members than this. A zip bomb is cheap to make
#: and this is well above any real package.
MAX_MEMBERS = 20_000

#: Refuse a single member larger than this. A Python file above it is generated
#: or vendored data, and parsing it is not worth the memory.
MAX_MEMBER_BYTES = 4 * 1024 * 1024

_DEFAULT_TIMEOUT = 60.0


class ArchiveError(Exception):
    """Raised when a package's source cannot be obtained or read."""


@dataclass(frozen=True, slots=True)
class ArchiveRef:
    """One downloadable distribution file."""

    url: str
    filename: str
    #: ``bdist_wheel`` or ``sdist``, as the index reports it.
    packagetype: str
    size: int

    @property
    def is_wheel(self) -> bool:
        return self.filename.endswith(".whl")

    @property
    def host(self) -> str:
        without_scheme = self.url.removeprefix("https://").removeprefix("http://")
        return without_scheme.split("/", 1)[0].lower()


def find_archive(
    name: str, version: str, *, client: httpx.Client, api_base: str = PYPI_API_BASE
) -> ArchiveRef:
    """Ask the index for the best archive of one exact version.

    A wheel is preferred: it holds the files as installed, so the import names
    are already correct and no project layout has to be guessed. An sdist is
    the fallback, and a few packages publish nothing else.

    Raises:
        ArchiveError: if the version has no usable archive.
    """
    url = f"{api_base}/{normalise_name('PyPI', name)}/{version}/json"
    try:
        response = client.get(url)
        response.raise_for_status()
        payload = response.json()
    except httpx.HTTPError as exc:
        msg = f"could not ask the index about {name} {version}: {exc}"
        raise ArchiveError(msg) from exc
    except ValueError as exc:
        msg = f"the index returned unreadable JSON for {name} {version}: {exc}"
        raise ArchiveError(msg) from exc

    candidates = [
        ArchiveRef(
            url=str(entry.get("url") or ""),
            filename=str(entry.get("filename") or ""),
            packagetype=str(entry.get("packagetype") or ""),
            size=int(entry.get("size") or 0),
        )
        for entry in (payload.get("urls") or [])
        if isinstance(entry, dict) and not entry.get("yanked")
    ]

    wheels = [candidate for candidate in candidates if candidate.is_wheel]
    # A pure-Python wheel first: it is one file for every platform, and a
    # platform-specific one holds compiled objects this analysis cannot read.
    universal = [candidate for candidate in wheels if "-any.whl" in candidate.filename]
    sdists = [
        candidate
        for candidate in candidates
        if candidate.filename.endswith((".tar.gz", ".zip")) and not candidate.is_wheel
    ]

    for group in (universal, wheels, sdists):
        for candidate in group:
            if candidate.url and candidate.host in ALLOWED_ARCHIVE_HOSTS:
                return candidate

    msg = f"{name} {version} publishes no archive this analysis can read"
    raise ArchiveError(msg)


def download(reference: ArchiveRef, *, client: httpx.Client) -> bytes:
    """Fetch one archive, refusing anything oversized or off the allow-list."""
    if reference.host not in ALLOWED_ARCHIVE_HOSTS:
        msg = f"refusing to download from {reference.host}, which is not on the allow-list"
        raise ArchiveError(msg)
    if reference.size and reference.size > MAX_ARCHIVE_BYTES:
        msg = (
            f"{reference.filename} is {reference.size} bytes, above the "
            f"{MAX_ARCHIVE_BYTES} byte limit"
        )
        raise ArchiveError(msg)

    try:
        response = client.get(reference.url)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        msg = f"could not download {reference.filename}: {exc}"
        raise ArchiveError(msg) from exc

    if len(response.content) > MAX_ARCHIVE_BYTES:
        msg = (
            f"{reference.filename} returned {len(response.content)} bytes, above the "
            f"{MAX_ARCHIVE_BYTES} byte limit"
        )
        raise ArchiveError(msg)
    return response.content


def extract(payload: bytes, reference: ArchiveRef, destination: Path) -> Path:
    """Unpack an archive's Python files, and return the directory to graph.

    For a wheel that is the extraction root: a wheel's top level is what gets
    installed into site-packages, so the import names are already right.

    For an sdist it is the directory holding the importable packages, which
    sits one level down and may be a ``src`` layout. Getting this wrong would
    produce symbols named after the sdist directory, and a symbol in the wrong
    place is one step from a wrong verdict.
    """
    destination.mkdir(parents=True, exist_ok=True)
    if reference.is_wheel or reference.filename.endswith(".zip"):
        _extract_zip(payload, destination)
    else:
        _extract_tar(payload, destination)

    if reference.is_wheel:
        return destination
    return _sdist_root(destination)


def _extract_zip(payload: bytes, destination: Path) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            members = archive.infolist()
            if len(members) > MAX_MEMBERS:
                msg = f"the archive holds {len(members)} members, above the {MAX_MEMBERS} limit"
                raise ArchiveError(msg)
            for member in members:
                if member.is_dir() or not _is_interesting(member.filename):
                    continue
                if member.file_size > MAX_MEMBER_BYTES:
                    continue
                target = _safe_target(member.filename, destination)
                if target is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source:
                    target.write_bytes(source.read(MAX_MEMBER_BYTES))
    except (zipfile.BadZipFile, OSError) as exc:
        msg = f"the archive is not a readable zip: {exc}"
        raise ArchiveError(msg) from exc


def _extract_tar(payload: bytes, destination: Path) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
            count = 0
            for member in archive:
                count += 1
                if count > MAX_MEMBERS:
                    msg = f"the archive holds more than {MAX_MEMBERS} members"
                    raise ArchiveError(msg)
                # Only regular files, never a link: a symlink in an archive is
                # how extraction is made to write outside its directory.
                if not member.isfile() or not _is_interesting(member.name):
                    continue
                if member.size > MAX_MEMBER_BYTES:
                    continue
                target = _safe_target(member.name, destination)
                if target is None:
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(handle.read(MAX_MEMBER_BYTES))
    except (tarfile.TarError, OSError) as exc:
        msg = f"the archive is not a readable tarball: {exc}"
        raise ArchiveError(msg) from exc


def _is_interesting(name: str) -> bool:
    """Whether a member is worth writing to disk.

    Python source, plus the metadata files that say which import names a
    distribution provides. Everything else in a wheel is data, compiled
    objects or documentation, none of which a call graph reads.
    """
    path = PurePosixPath(name)
    if path.suffix == ".py":
        return True
    return path.name in {"top_level.txt", "METADATA", "RECORD", "PKG-INFO", "setup.cfg"} or (
        path.name == "pyproject.toml"
    )


def _safe_target(name: str, destination: Path) -> Path | None:
    """Resolve a member name inside ``destination``, or None if it escapes.

    An archive is third-party data. A member named ``../../etc/thing`` or with
    an absolute path is how extraction gets turned into arbitrary file writing,
    so the resolved path is checked rather than trusted.
    """
    candidate = PurePosixPath(name)
    if candidate.is_absolute() or any(part == ".." for part in candidate.parts):
        return None
    target = (destination / Path(*candidate.parts)).resolve()
    try:
        target.relative_to(destination.resolve())
    except ValueError:
        return None
    return target


def _sdist_root(destination: Path) -> Path:
    """Find the directory inside an unpacked sdist that holds the packages.

    An sdist unpacks to one directory named ``package-version``. Inside, the
    importable packages are either at that level or under ``src``. Choosing
    wrongly names every symbol after the wrong prefix.
    """
    entries = [path for path in destination.iterdir() if path.is_dir()]
    root = entries[0] if len(entries) == 1 else destination
    source = root / "src"
    if source.is_dir() and any(source.iterdir()):
        return source
    return root


@dataclass(frozen=True, slots=True)
class ArchiveSource:
    """Fetches a package's source from an index, for graphing.

    Held as an object so a scan configures the client and the cache once and
    every dependency reuses them.
    """

    client: httpx.Client
    api_base: str = PYPI_API_BASE

    def source_root(self, name: str, version: str, destination: Path) -> tuple[Path, str]:
        """Download and unpack one version, returning where to graph it from.

        Returns the directory and a note describing what was used, which the
        scan records so a reader knows the graph came from an archive rather
        than from the environment.

        Raises:
            ArchiveError: if the version cannot be obtained or read.
        """
        reference = find_archive(name, version, client=self.client, api_base=self.api_base)
        payload = download(reference, client=self.client)
        root = extract(payload, reference, destination)
        kind = "wheel" if reference.is_wheel else "sdist"
        return root, f"{name} {version} graphed from its {kind} ({reference.filename})"


def importable_names(root: Path) -> tuple[str, ...]:
    """The top-level import names present under an unpacked archive.

    Read from the directory rather than from metadata, because an sdist's
    metadata is often incomplete and the files are definitive. A package
    directory needs an ``__init__.py``; a bare module is a single file.
    """
    names: list[str] = []
    for path in sorted(root.iterdir()):
        if path.is_dir() and (path / "__init__.py").is_file() and not path.name.startswith("."):
            names.append(path.name)
        elif path.suffix == ".py" and path.stem != "setup":
            names.append(path.stem)
    return tuple(dict.fromkeys(names))


def python_files(root: Path, *, limit: int = MAX_MEMBERS) -> Iterator[Path]:
    """Every Python file under an unpacked archive, bounded."""
    for index, path in enumerate(sorted(root.rglob("*.py"))):
        if index >= limit:
            return
        yield path


def skip_reasons(names: Sequence[str]) -> str | None:
    """Why an unpacked archive cannot be graphed, if it cannot."""
    if not names:
        return "the archive contains no importable Python package"
    return None


__all__ = [
    "ALLOWED_ARCHIVE_HOSTS",
    "MAX_ARCHIVE_BYTES",
    "MAX_MEMBERS",
    "MAX_MEMBER_BYTES",
    "PYPI_API_BASE",
    "ArchiveError",
    "ArchiveRef",
    "ArchiveSource",
    "download",
    "extract",
    "find_archive",
    "importable_names",
    "python_files",
    "skip_reasons",
]
