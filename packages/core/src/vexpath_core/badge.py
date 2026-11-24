"""The status badge: what it says, and the SVG that says it.

A badge is the most widely copied artefact this system produces. It ends up in
READMEs, in slide decks and in screenshots, read by people who will never open
the report behind it -- so the rules for what it may claim are stricter than
anywhere else, and they live here rather than in whatever happens to be
rendering one.

**Deliberately pessimistic where the answer is not known.** A badge saying
"clear" when the analysis could not decide would be the single most misleading
thing this project could publish. "No scan", "N unknown" and "none reachable
(unverified)" are all distinct from "none reachable", and each keeps its own
colour.

**Two things render one.** The platform serves a badge from the database, and
this repository's own CI writes one to a file so the README does not depend on
a sleeping free-plan host. Both call this module: the rules are the thing that
must not differ, because two badges disagreeing about the same scan is worse
than either being wrong on its own.

**The SVG references nothing external.** No font file, no stylesheet, no
image. A badge that fetched anything would report every page view back to
wherever it fetched from, and a badge in a README is viewed by everybody who
looks at the repository.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from vexpath_core.enums import Verdict

if TYPE_CHECKING:
    from vexpath_core.models.results import ScanResults

#: State to colour, named in the shields.io palette so a published badge looks
#: like every other badge in a README rather than like something bespoke.
COLOURS = {
    "reachable": "critical",
    "investigating": "important",
    "clear": "success",
    "unknown": "inactive",
}

#: The shields.io palette itself, so the SVG carries no external reference.
PALETTE = {
    "critical": "#e05d44",
    "important": "#dfb317",
    "success": "#4c1",
    "inactive": "#9f9f9f",
}

#: What the left-hand side of the badge says. One word, because the badge has
#: to be legible at the size a README renders it.
LABEL = "reachable"


def state_for(
    *,
    reachable: int,
    investigating: int,
    reproducible: bool,
    scanned: bool = True,
) -> tuple[str, str]:
    """What the badge says, and which state it is in.

    Args:
        reachable: Findings whose vulnerable code can run.
        investigating: Findings nobody could decide.
        reproducible: Whether the verdicts can be re-derived, which means the
            scan named the advisory corpus it used.
        scanned: Whether there is a scan at all.

    The order is the whole rule, and it is pessimistic at every step: anything
    reachable wins, then anything undecided, and "none reachable" is reached
    only when a scan exists, decided everything, and can be checked.
    """
    if not scanned:
        return "no scan", "unknown"
    if reachable:
        return f"{reachable} reachable", "reachable"
    if investigating:
        return f"{investigating} unknown", "investigating"
    if not reproducible:
        # The verdicts cannot be re-derived, so "none reachable" would be an
        # assertion rather than a finding.
        return "none reachable (unverified)", "investigating"
    return "none reachable", "clear"


def state_for_results(results: ScanResults) -> tuple[str, str]:
    """The same decision, taken from a results document.

    Used by anything holding the document itself rather than a database row:
    this repository's CI, and anybody who wants a badge without the platform.
    """
    return state_for(
        reachable=len(results.reachable_findings()),
        investigating=results.counts_by_verdict().get(Verdict.UNDER_INVESTIGATION, 0),
        reproducible=results.is_reproducible,
    )


def render(label: str, message: str, colour: str) -> str:
    """A self-contained SVG badge.

    ``colour`` is a palette name from :data:`COLOURS`, not a hex value, so a
    caller cannot invent a fifth state by passing a new colour.
    """
    fill = PALETTE.get(colour, PALETTE["inactive"])
    label_width = 8 + 7 * len(label)
    message_width = 10 + 7 * len(message)
    total = label_width + message_width

    # Escaped by hand because this is not a template: the values come from a
    # project slug and a scan summary, and an unescaped angle bracket here
    # would be script injection into every page that embeds the badge.
    safe_label = escape(label)
    safe_message = escape(message)

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        f'role="img" aria-label="{safe_label}: {safe_message}">'
        f"<title>{safe_label}: {safe_message}</title>"
        f'<g shape-rendering="crispEdges">'
        f'<rect width="{label_width}" height="20" fill="#555"/>'
        f'<rect x="{label_width}" width="{message_width}" height="20" fill="{fill}"/>'
        f"</g>"
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{label_width / 2}" y="14">{safe_label}</text>'
        f'<text x="{label_width + message_width / 2}" y="14">{safe_message}</text>'
        f"</g></svg>"
    )


def render_state(label: str, state: str) -> str:
    """Render a badge for a state from :func:`state_for`."""
    return render(LABEL, label, COLOURS[state])


def escape(value: str) -> str:
    """Escape for XML text and attribute content."""
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        # &#39; rather than &apos;, which is what this rendered before the
        # rules moved here: the output is compared byte for byte by tests and
        # by anybody diffing a committed badge.
        .replace("'", "&#39;")
    )


__all__ = [
    "COLOURS",
    "LABEL",
    "PALETTE",
    "escape",
    "render",
    "render_state",
    "state_for",
    "state_for_results",
]
