"""Package URL construction, parsing and ecosystem-aware name normalisation.

A purl is the join key between an SBOM component and an advisory's affected
package list. If normalisation is wrong, matching silently misses
vulnerabilities, so the rules per ecosystem are spelled out here rather than
left to callers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from packageurl import PackageURL

from vexpath_core.enums import canonical_ecosystem, ecosystem_to_purl_type, purl_type_to_ecosystem

#: PEP 503: runs of -, _ or . collapse to a single - and the name lowercases.
_PYPI_SEPARATORS = re.compile(r"[-_.]+")


@dataclass(frozen=True, slots=True)
class PurlParts:
    """A purl decomposed into the fields this project joins on."""

    ecosystem: str
    name: str
    version: str | None
    purl: str

    @property
    def purl_base(self) -> str:
        """The purl without its version, used as an advisory lookup key."""
        return self.purl.split("@", 1)[0]


def normalise_name(ecosystem: str, name: str) -> str:
    """Return the canonical package name for an ecosystem.

    - **PyPI** applies PEP 503: lowercase, and runs of ``-``, ``_`` or ``.``
      collapse to one ``-``. ``Flask-SQLAlchemy`` and ``flask_sqlalchemy`` are
      the same project and must produce the same key.
    - **npm** lowercases. Scoped names keep their ``@scope/`` prefix.
    - **Maven** keeps case and its ``group:artifact`` shape.
    - **Go** keeps case, because module paths are case-sensitive.
    - Anything unrecognised is returned trimmed and otherwise unchanged. Never
      guess at an ecosystem whose rules are unknown.
    """
    canonical = canonical_ecosystem(ecosystem)
    trimmed = name.strip()
    if canonical == "PyPI":
        return _PYPI_SEPARATORS.sub("-", trimmed).lower()
    if canonical == "npm":
        return trimmed.lower()
    return trimmed


def build_purl(ecosystem: str, name: str, version: str | None = None) -> str:
    """Build a canonical purl string for a component.

    The name is normalised first, so two spellings of the same package always
    yield the same purl.
    """
    purl_type = ecosystem_to_purl_type(ecosystem)
    normalised = normalise_name(ecosystem, name)
    namespace, bare_name = _split_namespace(purl_type, normalised)
    return PackageURL(
        type=purl_type,
        namespace=namespace,
        name=bare_name,
        version=version or None,
    ).to_string()


def parse_purl(purl: str) -> PurlParts:
    """Parse a purl string into the ecosystem, name and version we join on.

    Raises:
        ValueError: if the string is not a parsable purl.
    """
    try:
        parsed = PackageURL.from_string(purl)
    except ValueError as exc:
        msg = f"not a valid purl: {purl!r}"
        raise ValueError(msg) from exc

    ecosystem = purl_type_to_ecosystem(parsed.type)
    name = _join_namespace(parsed.type, parsed.namespace, parsed.name)
    normalised = normalise_name(ecosystem, name)
    return PurlParts(
        ecosystem=ecosystem,
        name=normalised,
        version=parsed.version,
        purl=build_purl(ecosystem, normalised, parsed.version),
    )


def _split_namespace(purl_type: str, name: str) -> tuple[str | None, str]:
    """Split a composite package name into purl namespace and name."""
    if purl_type == "npm" and name.startswith("@") and "/" in name:
        scope, _, bare = name.partition("/")
        return scope, bare
    if purl_type in {"maven", "golang", "composer"} and _namespace_separator(purl_type) in name:
        separator = _namespace_separator(purl_type)
        namespace, _, bare = name.rpartition(separator)
        return namespace, bare
    return None, name


def _join_namespace(purl_type: str, namespace: str | None, name: str) -> str:
    """Rejoin a purl namespace and name into the ecosystem's own spelling."""
    if not namespace:
        return name
    if purl_type == "npm":
        return f"{namespace}/{name}"
    return f"{namespace}{_namespace_separator(purl_type)}{name}"


def _namespace_separator(purl_type: str) -> str:
    return ":" if purl_type == "maven" else "/"


__all__ = ["PurlParts", "build_purl", "normalise_name", "parse_purl"]
