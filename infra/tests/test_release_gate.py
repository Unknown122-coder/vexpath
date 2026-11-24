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
    fixture_identifiers,
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


# --- The corpus refreshes itself, and must not lose symbols doing it -------

REFRESH_WORKFLOW = ROOT / ".github" / "workflows" / "corpus-refresh.yml"


def _refresh() -> dict[str, Any]:
    import yaml

    document: dict[str, Any] = yaml.safe_load(REFRESH_WORKFLOW.read_text(encoding="utf-8"))
    return document


def _refresh_steps() -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = _refresh()["jobs"]["refresh"]["steps"]
    return steps


def test_the_refresh_carries_symbols_before_it_seeds_anything() -> None:
    """The order is the whole safety property.

    Seeding a fresh download deletes every extracted symbol, because an
    advisory's symbols are a fact the snapshot owns completely and OSV
    publishes none. So the merge has to happen first, over files: the corpus
    that reaches the database already has its symbols attached.
    """
    names = [step.get("name", "") for step in _refresh_steps()]
    merge_at = next(i for i, name in enumerate(names) if "carry the symbols" in name)
    seed_at = next(i for i, name in enumerate(names) if name == "Load the merged corpus")

    assert merge_at < seed_at


def test_the_refresh_starts_from_the_published_corpus() -> None:
    """Not from the repository's test snapshot, which holds fixture advisories.

    The published corpus is the thing whose coverage must not fall, so it is
    also the thing the merge inherits from.
    """
    steps = _refresh_steps()
    fetch = next(step for step in steps if "corpus being replaced" in step.get("name", ""))

    assert "advisory pull" in fetch["run"]


def test_extraction_may_fail_without_costing_the_refresh() -> None:
    """A vanished upstream or a timed-out fetch is an ordinary outcome.

    The advisories are worth publishing whether or not today's batch of
    symbol extraction got anywhere, and the queue is resumable, so the next
    run continues. Failing the job would throw away the fresh advisories over
    a git fetch.
    """
    steps = _refresh_steps()
    extract = next(step for step in steps if "Extract symbols" in step.get("name", ""))

    assert extract["continue-on-error"] is True
    assert "--batch" in extract["run"]
    assert "--cache-root" in extract["run"]


def test_the_refresh_publishes_over_the_newest_release() -> None:
    """Because that is the URL every existing install already fetches.

    `advisory pull` reads releases/latest/download/corpus.*, so a refresh
    reaches people who never upgrade -- and needs no new version, which is
    why this is an asset replacement rather than a release.
    """
    steps = _refresh_steps()
    publish = next(step for step in steps if "newest release" in step.get("name", ""))

    assert "gh release view --json tagName" in publish["run"]
    assert "tools/publish_corpus.py" in publish["run"]


def test_the_refresh_can_write_a_release_asset() -> None:
    job = _refresh()["jobs"]["refresh"]

    assert job["permissions"]["contents"] == "write"


def test_a_corpus_holding_test_fixtures_is_refused() -> None:
    """Three of them shipped to everybody before this existed.

    The snapshot was exported from a database integration tests had seeded,
    so CVE-2024-FIXTURE-DYNAMIC and two siblings went out in every download.
    Harmless in effect and still wrong: they are advisories this project
    invented.
    """
    assert fixture_identifiers(["CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"]) == []
    assert fixture_identifiers(["CVE-2024-FIXTURE-DYNAMIC"]) == ["CVE-2024-FIXTURE-DYNAMIC"]
    assert fixture_identifiers(["ZZTEST-1", "ZZAPI-2"]) == ["ZZAPI-2", "ZZTEST-1"]
