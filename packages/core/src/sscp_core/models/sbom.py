"""Normalised SBOM model.

Every accepted input format (CycloneDX, SPDX, our own lockfile generators)
parses into this one shape, so the rest of the pipeline never branches on
document format. The dependency graph is kept, not just the component list,
because explaining *why* a transitive package is present is half of what makes
a finding actionable.
"""

from __future__ import annotations

from pydantic import AwareDatetime, Field

from sscp_core.enums import ComponentScope, SbomFormat, SbomGenerator
from sscp_core.models.common import Base, FileHash


class Component(Base):
    """One package in an SBOM."""

    #: Identifier used inside the source document to reference this component.
    #: Dependency edges are expressed in terms of these, not purls, because a
    #: document may legitimately contain the same purl twice.
    bom_ref: str
    purl: str
    ecosystem: str
    name: str
    version: str
    #: True when the project depends on this package directly rather than
    #: through another package.
    direct: bool = False
    scope: ComponentScope = ComponentScope.RUNTIME
    #: SPDX licence identifiers where they could be determined.
    licenses: tuple[str, ...] = ()
    hashes: tuple[FileHash, ...] = ()


class DependencyEdge(Base):
    """A "depends on" relationship between two components of one SBOM."""

    parent_ref: str
    child_ref: str


class Sbom(Base):
    """A parsed, normalised bill of materials."""

    format: SbomFormat
    spec_version: str
    #: SHA-256 of the original document bytes, so a result can be tied back to
    #: the exact file that produced it.
    document_sha256: str
    generated_by: SbomGenerator
    created_at: AwareDatetime
    #: The component the SBOM is *about*, when the document declares one.
    root_component: Component | None = None
    components: tuple[Component, ...] = ()
    edges: tuple[DependencyEdge, ...] = ()
    #: Validation findings against the CISA minimum elements, if checked.
    minimum_element_gaps: tuple[str, ...] = Field(default=())
    #: What this inventory could not determine, in plain language. Several
    #: lockfile formats record no dependency relationships at all, and a reader
    #: has to know that rather than assume an empty graph means no dependencies.
    notes: tuple[str, ...] = ()

    @property
    def component_count(self) -> int:
        return len(self.components)

    @property
    def direct_components(self) -> tuple[Component, ...]:
        return tuple(c for c in self.components if c.direct)

    def by_ref(self) -> dict[str, Component]:
        """Index components by their document reference."""
        return {c.bom_ref: c for c in self.components}

    def ecosystems(self) -> frozenset[str]:
        """Every ecosystem present, used to decide which advisories to load."""
        return frozenset(c.ecosystem for c in self.components)

    def parents_of(self, bom_ref: str) -> tuple[str, ...]:
        """Return the refs that depend on ``bom_ref``.

        Used to render the chain that explains a transitive dependency.
        """
        return tuple(e.parent_ref for e in self.edges if e.child_ref == bom_ref)


__all__ = ["Component", "DependencyEdge", "Sbom"]
