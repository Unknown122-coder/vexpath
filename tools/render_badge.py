"""Write this repository's own status badge to a file.

The badge at the top of the README used to be served by the platform, which
means the README depended on a host being awake. That was survivable on Fly,
which woke a machine in about five seconds. It is not survivable on a free
plan that spins down after fifteen minutes and takes thirty to sixty seconds
to come back: GitHub's image proxy gives up long before that, so the first
visitor after an idle period saw a broken image at the top of the page -- the
worst possible place for one, on a project whose subject is trustworthy
reporting.

So CI renders it from the scan it already runs, and commits it when it
changes. The file is served by GitHub from the repository itself, so the badge
is as available as the page embedding it, and the link beside it still points
at the live report for anybody who wants the detail.

    uv run python tools/render_badge.py results.json docs/badge.svg

Exits non-zero if the results document cannot be read, because a badge that
silently keeps yesterday's answer is the failure this is meant to prevent.
"""

from __future__ import annotations

import sys
from pathlib import Path

from vexpath_core import badge
from vexpath_core.models.results import ScanResults


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2

    source, destination = Path(sys.argv[1]), Path(sys.argv[2])
    try:
        results = ScanResults.model_validate_json(source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"could not read {source}: {exc}", file=sys.stderr)
        return 1

    label, state = badge.state_for_results(results)
    svg = badge.render_state(label, state)

    destination.parent.mkdir(parents=True, exist_ok=True)
    # Written only when it differs, so a scan that changed nothing leaves the
    # file -- and therefore the commit history -- alone.
    if destination.is_file() and destination.read_text(encoding="utf-8") == svg:
        print(f"unchanged: {label}")
        return 0

    # newline="\n" rather than the platform default: this file is committed,
    # and CI regenerating it with different line endings would be a diff on
    # every run on a machine that does not match the last one.
    destination.write_text(svg, encoding="utf-8", newline="\n")
    print(f"wrote {destination}: {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
