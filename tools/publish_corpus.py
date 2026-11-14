"""Attach a built advisory corpus to a GitHub release.

The corpus is the expensive half of this tool: downloading advisories takes
twenty seconds, extracting which functions each fix changed takes hours of
cloning and diffing upstream repositories. The answer is the same for
everybody, so it is built once and published, and `vexpath advisory pull`
collects it.

Run from a machine that has just built one, because it cannot be built in CI
within a job's lifetime -- which is the honest reason this is a script a human
runs rather than a workflow step.

    uv run python tools/publish_corpus.py v0.1.2 var/snapshot-full

The files are uploaded as `corpus.snapshot.json` and `corpus.advisories.jsonl.gz`,
which is what `DEFAULT_CORPUS_URL` expects of
`releases/latest/download/corpus.*`.

**This is also what publishes the release.** The release workflow creates it as
a draft, because `releases/latest` skips drafts: until the corpus is attached,
"latest" stays on the previous release and every install already out there
keeps working. So a release that nobody attaches a corpus to is invisible
rather than broken, and the thing that makes it visible is the step that
cannot forget the corpus -- this one, which refuses to publish a release
missing anything the client downloads.
"""

from __future__ import annotations

import gzip
import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path

from vexpath_core.snapshot import ADVISORIES_FILE, SNAPSHOT_METADATA_FILE, read_snapshot

ROOT = Path(__file__).resolve().parents[1]

#: What the published files are called. The command line fetches
#: ``<base>.snapshot.json`` and ``<base>.advisories.jsonl.gz``, so these two
#: names and ``DEFAULT_CORPUS_URL`` have to agree.
PUBLISHED_METADATA = "corpus.snapshot.json"
PUBLISHED_ADVISORIES = "corpus.advisories.jsonl.gz"

#: What a release must hold before it may be published. Every name here is one
#: the command line downloads, so a release missing any of them is one that
#: answers 404 to `vexpath advisory pull`.
REQUIRED_ASSETS = (PUBLISHED_METADATA, PUBLISHED_ADVISORIES)


def missing_assets(present: Iterable[str], required: Sequence[str] = REQUIRED_ASSETS) -> list[str]:
    """Which required assets a release does not hold, in the order required.

    Separated from the subprocess work so the refusal can be tested without a
    network, a token or a release: the decision is the part worth testing, and
    `gh` is not.
    """
    have = set(present)
    return [name for name in required if name not in have]


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2

    tag, source = sys.argv[1], Path(sys.argv[2])

    # Verified before it is published, not after. A corpus whose contents do
    # not match its own hash would be refused by every client that downloaded
    # it, after they had each spent the bandwidth.
    metadata, records = read_snapshot(source)
    symbols = sum(len(record.symbols) for record in records)
    with_symbols = sum(1 for record in records if record.symbols)
    print(
        f"{len(records)} advisories, {symbols} symbols across {with_symbols} of them, "
        f"snapshot {metadata.id}"
    )
    if not symbols:
        print(
            "refusing to publish a corpus with no symbols: it would be no better "
            "than a live OSV query, which is what the client already falls back to",
            file=sys.stderr,
        )
        return 1

    with tempfile.TemporaryDirectory() as directory:
        staging = Path(directory)
        shutil.copy2(source / SNAPSHOT_METADATA_FILE, staging / PUBLISHED_METADATA)

        plain = source / ADVISORIES_FILE
        compressed = staging / PUBLISHED_ADVISORIES
        if plain.is_file():
            with plain.open("rb") as reader, gzip.open(compressed, "wb", compresslevel=6) as writer:
                shutil.copyfileobj(reader, writer, length=1024 * 1024)
        else:
            shutil.copy2(source / "advisories.jsonl.gz", compressed)

        size = compressed.stat().st_size
        print(f"uploading {size / 1e6:.1f}MB to release {tag}")

        # Resolved rather than trusted to PATH, so a machine without gh says
        # so plainly instead of raising FileNotFoundError from deep inside
        # subprocess after the corpus has already been compressed.
        gh = shutil.which("gh")
        if gh is None:
            print("gh is not on PATH; it is what uploads the release asset", file=sys.stderr)
            return 1

        result = subprocess.run(  # noqa: S603 - a fixed command, no shell
            [
                gh,
                "release",
                "upload",
                tag,
                str(staging / PUBLISHED_METADATA),
                str(compressed),
                # So re-publishing a corrected corpus onto the same release
                # does not need the old one deleted by hand first.
                "--clobber",
            ],
            cwd=str(ROOT),
            check=False,
        )
        if result.returncode != 0:
            return result.returncode

    return _publish_release(gh, tag)


def _publish_release(gh: str, tag: str) -> int:
    """Publish the draft, once the release holds everything the client needs.

    The check is the point of the draft: this runs after the upload, reads
    back what the release actually holds rather than what was just sent, and
    refuses to publish if anything the command line downloads is absent. A
    release that fails this stays a draft, so `latest` stays where it was and
    nobody's `advisory pull` breaks while it is sorted out.
    """
    view = subprocess.run(  # noqa: S603 - a fixed command, no shell
        [gh, "release", "view", tag, "--json", "isDraft,assets"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if view.returncode != 0:
        detail = view.stderr.strip() or f"exit {view.returncode}"
        print(f"could not read release {tag}: {detail}", file=sys.stderr)
        return 1

    payload = json.loads(view.stdout)
    present = [asset["name"] for asset in payload.get("assets", ())]
    absent = missing_assets(present)
    if absent:
        print(
            f"refusing to publish {tag}: it is missing {', '.join(absent)}, which "
            f"'vexpath advisory pull' downloads. The release stays a draft, so "
            f"latest still points at the previous one and nobody's pull is broken.",
            file=sys.stderr,
        )
        return 1

    if not payload.get("isDraft"):
        print(f"{tag} was already published; its corpus is now the one just uploaded")
        return 0

    edit = subprocess.run(  # noqa: S603 - a fixed command, no shell
        [gh, "release", "edit", tag, "--draft=false"],
        cwd=str(ROOT),
        check=False,
    )
    if edit.returncode != 0:
        return edit.returncode

    print(f"published {tag}. 'vexpath advisory pull' now serves this corpus")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
