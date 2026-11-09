"""Turn a repository path into the module name an advisory's symbol uses.

A fix commit changes ``src/requests/adapters.py``. Reachability searches for
``requests.adapters.HTTPAdapter.send``. Getting from one to the other is this
module's whole job, and getting it wrong means the extracted symbol never
matches anything in a call graph, silently.

Three things make it harder than splitting on slashes:

**Source layouts vary.** ``src/``, ``lib/``, a bare package directory, or a
package nested under the project name. The reliable anchor is the package's own
import name: find that directory component and take everything from there.

**Distribution names and import names differ.** ``pyyaml`` imports as ``yaml``,
``beautifulsoup4`` as ``bs4``, ``pillow`` as ``PIL``. A table covers the common
cases; beyond it, the repository's own build configuration is consulted.

**Confidence has to reflect which of those applied.** A path anchored on a
known import name is reliable. A path where the anchor had to be guessed is
not, and says so.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass

from vexpath_core.enums import Confidence
from vexpath_core.purl import normalise_name

#: Directory names that hold packages rather than being one. Stripped when no
#: better anchor is available.
SOURCE_ROOTS = ("src", "lib", "python", "sources")

#: Distributions whose import name differs from their package name. Not
#: exhaustive, and not meant to be: it covers what appears often enough in
#: advisory data to matter, and anything missing falls through to the build
#: configuration or to a lowered confidence.
IMPORT_NAME_OVERRIDES: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "beautifulsoup4": ("bs4",),
    "pillow": ("PIL",),
    "python-dateutil": ("dateutil",),
    "attrs": ("attr", "attrs"),
    "msgpack-python": ("msgpack",),
    "protobuf": ("google",),
    "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",),
    "python-jose": ("jose",),
    "pyjwt": ("jwt",),
    "python-multipart": ("multipart",),
    "typing-extensions": ("typing_extensions",),
    "scikit-learn": ("sklearn",),
    "opencv-python": ("cv2",),
    "mysqlclient": ("MySQLdb",),
    "psycopg2-binary": ("psycopg2",),
    "setuptools": ("setuptools", "pkg_resources"),
    "django": ("django",),
    "flask-cors": ("flask_cors",),
    "pyopenssl": ("OpenSSL",),
    "paramiko": ("paramiko",),
    "pyarrow": ("pyarrow",),
    "grpcio": ("grpc",),
    "ruamel-yaml": ("ruamel",),
    "memcached": ("memcache",),
}


@dataclass(frozen=True, slots=True)
class PackageLayout:
    """How a repository's paths map onto importable module names."""

    #: Distribution name as the advisory spells it.
    distribution: str
    #: Every import name this distribution might provide, including the guesses
    #: from the override table and the hyphen-to-underscore transformation.
    import_names: tuple[str, ...]
    #: The subset that is certain: names the repository declared in its build
    #: configuration, or the distribution's own name matching a directory
    #: outright. Anchoring on one of these is precise; anchoring on a guessed
    #: alias is merely likely, and the confidence says which happened.
    primary_names: tuple[str, ...] = ()
    #: Directories that hold packages rather than being one.
    source_roots: tuple[str, ...] = SOURCE_ROOTS
    #: True when the import names were read from the repository's own build
    #: configuration rather than guessed.
    declared: bool = False

    def module_for(self, path: str) -> tuple[str, Confidence] | None:
        """Return the module name for a repository path, and how sure we are.

        Returns None when the path cannot plausibly be part of this package,
        which is common: a fix commit often touches documentation, changelogs
        and continuous-integration files alongside the code.
        """
        normalised = path.replace("\\", "/")
        if not normalised.endswith(".py"):
            return None

        parts = normalised[: -len(".py")].split("/")
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        if not parts:
            return None

        # Anchor on the package's own import name wherever it appears. A match
        # against a declared or exact name is precise; one against a guessed
        # alias is likely but not certain.
        for index, part in enumerate(parts):
            if part in self.primary_names:
                return ".".join(parts[index:]), Confidence.HIGH
        for index, part in enumerate(parts):
            if part in self.import_names:
                return ".".join(parts[index:]), Confidence.MEDIUM

        # Otherwise strip a conventional source root and take what is left.
        stripped = list(parts)
        while stripped and stripped[0] in self.source_roots:
            stripped.pop(0)
        if not stripped:
            return None
        # The anchor was not found, so the first component may be a directory
        # that is not importable at all. Say so through the confidence.
        return ".".join(stripped), Confidence.LOW


def import_names_for(distribution: str) -> tuple[str, ...]:
    """Guess the import names a distribution provides.

    The conventional transformation, hyphens to underscores, plus the override
    table and the raw name. Returning several candidates is deliberate: the
    anchor only has to match one of them.
    """
    normalised = normalise_name("PyPI", distribution)
    candidates: list[str] = [*IMPORT_NAME_OVERRIDES.get(normalised, ())]
    candidates.append(normalised.replace("-", "_"))
    candidates.append(normalised)
    candidates.append(distribution)
    # Some distributions are published under a dotted namespace, as in
    # "zope.interface", whose top-level package is the first component.
    if "." in distribution:
        candidates.append(distribution.split(".")[0])
    return tuple(dict.fromkeys(candidate for candidate in candidates if candidate))


def layout_for(
    distribution: str, *, pyproject: str | None = None, setup_cfg: str | None = None
) -> PackageLayout:
    """Work out a repository's layout, reading its build configuration if given.

    The configuration is parsed as data. ``setup.py`` is never executed, so a
    project that declares its packages only in executable code falls back to
    the conventional guesses, with the confidence that implies.
    """
    declared: list[str] = []
    roots: list[str] = []

    if pyproject:
        names, found_roots = _from_pyproject(pyproject)
        declared.extend(names)
        roots.extend(found_roots)

    if setup_cfg and not declared:
        names, found_roots = _from_setup_cfg(setup_cfg)
        declared.extend(names)
        roots.extend(found_roots)

    if declared:
        primary = tuple(dict.fromkeys(declared))
        return PackageLayout(
            distribution=distribution,
            import_names=tuple(dict.fromkeys([*primary, *import_names_for(distribution)])),
            primary_names=primary,
            source_roots=tuple(dict.fromkeys([*roots, *SOURCE_ROOTS])),
            declared=True,
        )

    # Nothing declared. The distribution's own normalised name is still an
    # exact anchor when a directory carries it; everything else is a guess.
    normalised = normalise_name("PyPI", distribution)
    exact: tuple[str, ...] = (normalised, normalised.replace("-", "_"))
    return PackageLayout(
        distribution=distribution,
        import_names=import_names_for(distribution),
        primary_names=tuple(dict.fromkeys(exact)),
        source_roots=SOURCE_ROOTS,
    )


def _from_pyproject(content: str) -> tuple[list[str], list[str]]:
    """Read package names and source roots out of a pyproject file."""
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return [], []

    names: list[str] = []
    roots: list[str] = []
    tool = data.get("tool", {}) if isinstance(data.get("tool"), dict) else {}

    setuptools = tool.get("setuptools", {})
    if isinstance(setuptools, dict):
        packages = setuptools.get("packages")
        if isinstance(packages, list):
            names.extend(str(entry).split(".")[0] for entry in packages)
        elif isinstance(packages, dict):
            find = packages.get("find", {})
            if isinstance(find, dict):
                where = find.get("where", [])
                if isinstance(where, list):
                    roots.extend(str(entry).strip("./") for entry in where)
        package_dir = setuptools.get("package-dir")
        if isinstance(package_dir, dict):
            roots.extend(str(value).strip("./") for value in package_dir.values())

    poetry = tool.get("poetry", {})
    if isinstance(poetry, dict):
        for entry in poetry.get("packages", []) or []:
            if isinstance(entry, dict) and entry.get("include"):
                names.append(str(entry["include"]).split(".")[0])
                if entry.get("from"):
                    roots.append(str(entry["from"]).strip("./"))

    hatch = tool.get("hatch", {})
    if isinstance(hatch, dict):
        targets = (
            hatch.get("build", {}).get("targets", {})
            if isinstance(hatch.get("build"), dict)
            else {}
        )
        for target in targets.values() if isinstance(targets, dict) else []:
            if not isinstance(target, dict):
                continue
            for entry in target.get("packages", []) or []:
                parts = str(entry).strip("./").split("/")
                if parts:
                    names.append(parts[-1])
                    roots.extend(parts[:-1])

    flit = tool.get("flit", {})
    if isinstance(flit, dict):
        module = flit.get("module", {})
        if isinstance(module, dict) and module.get("name"):
            names.append(str(module["name"]).split(".")[0])

    return [name for name in names if name], [root for root in roots if root]


def _from_setup_cfg(content: str) -> tuple[list[str], list[str]]:
    """Read package names and source roots out of a setup.cfg file."""
    import configparser

    parser = configparser.ConfigParser()
    try:
        parser.read_string(content)
    except configparser.Error:
        return [], []

    names: list[str] = []
    roots: list[str] = []
    packages = parser.get("options", "packages", fallback="")
    for line in packages.replace(",", "\n").splitlines():
        candidate = line.strip()
        if candidate and not candidate.startswith("find"):
            names.append(candidate.split(".")[0])
    package_dir = parser.get("options.package_dir", "", fallback="") or parser.get(
        "options", "package_dir", fallback=""
    )
    for line in package_dir.replace(",", "\n").splitlines():
        _, separator, value = line.partition("=")
        if separator and value.strip():
            roots.append(value.strip().strip("./"))
    return names, roots


__all__ = [
    "IMPORT_NAME_OVERRIDES",
    "SOURCE_ROOTS",
    "PackageLayout",
    "import_names_for",
    "layout_for",
]
