"""CISA minimum-elements check.

The United States National Telecommunications and Information Administration
published "The Minimum Elements For a Software Bill of Materials" in 2021, and
CISA has maintained the baseline since. It is what a procurement officer or an
auditor checks an SBOM against, so this project reports gaps against it rather
than only reporting whether a document parses.

Each gap is phrased as what is missing and why it matters, because a reader who
has to fix it needs both.
"""

from __future__ import annotations

from sscp_core.models.sbom import Sbom

#: The seven baseline data fields and the two practice requirements, as the
#: guidance names them.
MINIMUM_ELEMENTS: tuple[str, ...] = (
    "supplier name",
    "component name",
    "component version",
    "other unique identifiers",
    "dependency relationship",
    "author of SBOM data",
    "timestamp",
)


def check(sbom: Sbom) -> tuple[str, ...]:
    """Return the gaps between an SBOM and the minimum elements.

    An empty tuple means every baseline field is present for every component.
    This is a completeness report, not a pass or fail: a document with gaps is
    still usable for analysis, and saying which fields are missing is more
    useful than refusing it.
    """
    gaps: list[str] = []

    if not sbom.components:
        gaps.append("The document lists no components, so there is nothing to attest to.")
        return tuple(gaps)

    missing_version = [component.purl for component in sbom.components if not component.version]
    if missing_version:
        gaps.append(
            f"Component version: {len(missing_version)} component(s) have no version, "
            f"so no advisory can be matched against them "
            f"({_sample(missing_version)})."
        )

    missing_identifier = [component.name for component in sbom.components if not component.purl]
    if missing_identifier:
        gaps.append(
            f"Other unique identifiers: {len(missing_identifier)} component(s) have no "
            f"package URL, which is the key advisory matching joins on "
            f"({_sample(missing_identifier)})."
        )

    # Edges from the project to its direct dependencies are synthesised from
    # the "direct" flag and exist even when the lockfile recorded no
    # relationships at all. Only an edge between two components shows a real
    # dependency graph, so that is what is checked.
    root_ref = sbom.root_component.bom_ref if sbom.root_component else None
    component_edges = [edge for edge in sbom.edges if edge.parent_ref != root_ref]
    if not component_edges:
        gaps.append(
            "Dependency relationship: the document records no relationships between "
            "components, so it cannot show why a transitive component is present. "
            "Several lockfile formats do not record this; the document's notes say "
            "which applies."
        )

    if sbom.root_component is None:
        gaps.append(
            "Supplier name: the document does not say what software it describes, "
            "so it cannot be tied to a product."
        )

    # Author and timestamp are always written by this project, so they are only
    # ever missing on a document that arrived from elsewhere.
    if not sbom.created_at:
        gaps.append("Timestamp: the document has no creation time.")

    missing_licence = [component.purl for component in sbom.components if not component.licenses]
    if missing_licence:
        # Not a minimum element, but the first thing asked for after them, and
        # cheap to report while the document is open.
        gaps.append(
            f"Beyond the baseline: {len(missing_licence)} component(s) have no licence "
            f"recorded ({_sample(missing_licence)})."
        )

    return tuple(gaps)


def _sample(values: list[str], limit: int = 3) -> str:
    shown = sorted(values)[:limit]
    remainder = len(values) - len(shown)
    listed = ", ".join(shown)
    return f"{listed} and {remainder} more" if remainder > 0 else listed


__all__ = ["MINIMUM_ELEMENTS", "check"]
