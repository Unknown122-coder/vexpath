"""The badge rules, which are stricter than anything else here.

A badge is the most widely copied artefact this project produces: it goes into
READMEs and screenshots, read by people who will never open the report behind
it. Every test in this file is about what it is *not* allowed to claim.

The rules live in core rather than in a renderer because two things render
one -- the platform from a database row, this repository's CI to a committed
file -- and two badges disagreeing about the same scan would be worse than
either being wrong on its own.
"""

from __future__ import annotations

from vexpath_core import badge


def test_anything_reachable_wins() -> None:
    assert badge.state_for(reachable=2, investigating=9, reproducible=True) == (
        "2 reachable",
        "reachable",
    )


def test_undecided_findings_are_not_a_clearance() -> None:
    """The case the whole module exists for.

    Nine findings nobody could decide is not "none reachable". Saying so would
    turn an admitted unknown into a green badge, which is the single most
    misleading thing this system could publish.
    """
    label, state = badge.state_for(reachable=0, investigating=9, reproducible=True)

    assert label == "9 unknown"
    assert state == "investigating"
    assert badge.COLOURS[state] != badge.COLOURS["clear"]


def test_an_unverifiable_clean_scan_says_so() -> None:
    """No corpus named means the verdicts cannot be re-derived.

    "None reachable" would then be an assertion rather than a finding, so the
    badge keeps the word and drops the colour.
    """
    label, state = badge.state_for(reachable=0, investigating=0, reproducible=False)

    assert label == "none reachable (unverified)"
    assert state == "investigating"


def test_no_scan_is_its_own_state() -> None:
    label, state = badge.state_for(reachable=0, investigating=0, reproducible=False, scanned=False)

    assert (label, state) == ("no scan", "unknown")


def test_only_a_decided_reproducible_scan_is_green() -> None:
    label, state = badge.state_for(reachable=0, investigating=0, reproducible=True)

    assert (label, state) == ("none reachable", "clear")
    assert badge.COLOURS[state] == "success"


def test_every_state_has_a_colour_and_every_colour_a_value() -> None:
    """A state with no colour renders grey, which silently reads as unknown."""
    for state, colour in badge.COLOURS.items():
        assert colour in badge.PALETTE, f"{state} has no colour"


def test_the_svg_references_nothing_external() -> None:
    """A badge that fetched anything would report every repository view.

    No font file, no stylesheet, no image, no script. This is asserted rather
    than reviewed because the badge is embedded in pages this project does not
    control.
    """
    svg = badge.render_state("3 reachable", "reachable")

    # The namespace is the one URL allowed, and it is an identifier rather
    # than something a renderer fetches. Removed first so that what remains
    # can be checked for any URL at all, rather than against a list of the
    # ways one might be written.
    assert 'xmlns="http://www.w3.org/2000/svg"' in svg
    body = svg.replace('xmlns="http://www.w3.org/2000/svg"', "")

    assert "http" not in body
    for forbidden in ("<script", "@import", "url(", "<image", "<use", "<foreignObject"):
        assert forbidden not in body, f"the badge reaches for {forbidden}"


def test_a_hostile_label_cannot_inject_markup() -> None:
    """The message is built from a scan summary, not from a template.

    An unescaped angle bracket here would be script injection into every page
    that embeds the badge, including other people's READMEs.
    """
    svg = badge.render(badge.LABEL, '"><script>alert(1)</script>', "critical")

    assert "<script" not in svg
    assert "&lt;script&gt;" in svg
    assert "&quot;&gt;" in svg


def test_the_badge_is_legible_as_text() -> None:
    """Screen readers and link previews read the title and the label."""
    svg = badge.render_state("none reachable", "clear")

    assert 'role="img"' in svg
    assert 'aria-label="reachable: none reachable"' in svg
    assert "<title>reachable: none reachable</title>" in svg


def test_an_unknown_colour_falls_back_to_grey_rather_than_green() -> None:
    """If a caller invents a state, it must not come out looking clear."""
    svg = badge.render(badge.LABEL, "something new", "chartreuse")

    assert badge.PALETTE["inactive"] in svg
    assert badge.PALETTE["success"] not in svg
