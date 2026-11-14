"""The rule that a release must carry a corpus, checked without cutting one.

``vexpath advisory pull`` fetches ``releases/latest/download/corpus.*``, and
*latest* moves the moment a release is published. So a release published
without the corpus attached does not inconvenience the next person to
upgrade — it breaks the command for everybody who already installed, who did
nothing and asked for nothing. Their working tool starts answering 404.

That used to be prevented by a paragraph in ``docs/10-release.md`` asking the
releaser to remember. These are the tests for the mechanism that replaced it:
the workflow creates the release as a draft, GitHub's *latest* skips drafts,
and the only thing that publishes it is the step that attaches the corpus and
checks what it attached.

None of this needs a release, a token or a network. What is worth testing is
the decision — which assets are required, and what happens when one is
absent — and ``gh`` is not.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tools.publish_corpus import (
    PUBLISHED_ADVISORIES,
    PUBLISHED_METADATA,
    REQUIRED_ASSETS,
    missing_assets,
)
from vexpath.corpus import DEFAULT_CORPUS_URL
from vexpath_core.snapshot import ADVISORIES_FILE_GZ, SNAPSHOT_METADATA_FILE

ROOT = Path(__file__).resolve().parents[2]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def _workflow() -> dict[str, Any]:
    import yaml

    document: dict[str, Any] = yaml.safe_load(RELEASE_WORKFLOW.read_text(encoding="utf-8"))
    return document


def test_the_release_is_created_as_a_draft() -> None:
    """The whole mechanism rests on this one input.

    Without it the release is published the moment the provenance job uploads
    its attestation, which is before any human could attach a corpus — and
    *latest* has already moved by then.
    """
    provenance = _workflow()["jobs"]["provenance"]

    assert provenance["with"]["draft-release"] == "true"


def test_the_required_assets_are_exactly_what_the_client_downloads() -> None:
    """A drift test, because two files have to agree about three names.

    The client builds its URLs from ``DEFAULT_CORPUS_URL`` plus the snapshot
    file names; the publisher uploads under names it spells itself. Renaming
    either side alone would publish a release that passes every check here
    and still 404s, so the names are derived from the client's own constants
    and compared.
    """
    base = DEFAULT_CORPUS_URL.rsplit("/", 1)[-1]

    assert f"{base}.{SNAPSHOT_METADATA_FILE}" == PUBLISHED_METADATA
    assert f"{base}.{ADVISORIES_FILE_GZ}" == PUBLISHED_ADVISORIES
    assert set(REQUIRED_ASSETS) == {PUBLISHED_METADATA, PUBLISHED_ADVISORIES}


def test_a_release_holding_everything_is_publishable() -> None:
    present = [*REQUIRED_ASSETS, "multiple.intoto.jsonl", "something-else.txt"]

    assert missing_assets(present) == []


@pytest.mark.parametrize("absent", REQUIRED_ASSETS)
def test_a_release_missing_any_required_asset_is_refused(absent: str) -> None:
    """Each asset refused individually, rather than only the empty case.

    The empty case is the one that never happens. The one that does is a
    half-finished upload: the metadata lands, the ten-megabyte archive does
    not, and a release that passed a merely "are there assets" check would
    have been published with the file the client actually needs absent.
    """
    present = [name for name in REQUIRED_ASSETS if name != absent]

    assert missing_assets(present) == [absent]


def test_the_runbook_does_not_still_claim_nothing_refuses_this() -> None:
    """The document was the mechanism; it must not outlive it.

    A runbook that still says the old thing is worse than one that says
    nothing, because the next releaser believes it.
    """
    runbook = (ROOT / "docs" / "10-release.md").read_text(encoding="utf-8")

    assert "nothing yet refuses a *release* with no corpus" not in runbook
    assert "draft" in runbook
