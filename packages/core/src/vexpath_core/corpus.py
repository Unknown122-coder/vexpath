"""Carry extracted symbols across a fresh advisory download.

A corpus is two things with wildly different costs. The advisories come from
OSV in about twenty seconds. The vulnerable symbols come from cloning every
upstream repository and diffing every fix commit, which takes hours and
produces the answer this whole product rests on -- without symbols a finding
reports ``symbols_unknown``, which is honest and useless.

So a refresh cannot simply download again. OSV publishes no symbols, and
``seed-advisories`` replaces an advisory's symbols with whatever the incoming
snapshot holds -- deliberately, because affected ranges and symbols are facts
the source owns completely. Point that at a fresh download and every extracted
symbol is deleted: 27,877 of them, silently, turning a corpus everybody
depends on into one that decides nothing. That is the failure this module
exists to prevent, and it is why the merge happens here, over snapshots,
before anything touches a database.

**Fresh is authoritative for everything except symbols.** Severity, EPSS, KEV,
affected ranges and withdrawal all come from the new download. Symbols are the
only thing inherited, because they are the only thing the download cannot
provide.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from vexpath_core.enums import SymbolsStatus
from vexpath_core.models.advisory import Advisory

#: Statuses that mean "this advisory's symbols are settled". Carried across a
#: refresh along with the symbols themselves, so the extraction queue -- which
#: takes anything ``pending`` -- does not spend hours re-deriving what is
#: already known.
SETTLED = frozenset({SymbolsStatus.EXTRACTED, SymbolsStatus.DERIVED_FROM_TAGS})


@dataclass(frozen=True, slots=True)
class MergeReport:
    """What a merge did, in the terms worth checking afterwards."""

    #: Advisories in the result. Always the fresh download's count.
    advisories: int
    #: Advisories whose symbols were inherited from the previous corpus.
    carried: int
    #: Symbols inherited, which is the number that must not collapse.
    symbols_carried: int
    #: Advisories that arrived with symbols of their own, which are kept.
    arrived_with_symbols: int
    #: Advisories new in this download, with no symbols yet.
    new: int
    #: Previously present and now absent: withdrawn upstream, so dropped.
    withdrawn: int
    #: Carried nothing because the advisory now names a different repository,
    #: so the old symbols describe commits it no longer claims.
    repository_changed: int

    def summary_line(self) -> str:
        return (
            f"{self.advisories} advisories, {self.symbols_carried} symbols carried "
            f"across {self.carried}, {self.new} new, {self.withdrawn} withdrawn, "
            f"{self.repository_changed} re-queued after a repository change"
        )


def merge(
    fresh: Sequence[Advisory], previous: Sequence[Advisory]
) -> tuple[tuple[Advisory, ...], MergeReport]:
    """Return the fresh advisories with the previous corpus's symbols attached.

    The rules, each for a reason:

    1. **Fresh wins on everything but symbols.** An advisory whose severity or
       EPSS score changed should report the new one; keeping the old record to
       keep its symbols would freeze the corpus at the day it was built.
    2. **Symbols are inherited only where the download has none.** An advisory
       that arrives with its own -- OSV ships them for a few ecosystems -- is
       left alone, because the source that published them owns them.
    3. **The settled status travels with the symbols.** The extraction queue
       takes anything ``pending``, so carrying symbols without carrying the
       status would re-extract the entire corpus on the next run and waste the
       hours this function exists to save.
    4. **An advisory absent from the download is dropped.** It was withdrawn
       upstream, and resurrecting it to preserve its symbols would report a
       vulnerability that no longer exists.
    5. **A changed repository drops the symbols.** They name commits in the
       repository the advisory used to point at; against a different one they
       are at best meaningless and at worst describe somebody else's code. The
       advisory goes back to ``pending`` so extraction can redo it properly.

    Rule 5 is a proxy rather than a proof: an advisory can keep its repository
    and still replace its fix commit, and this does not notice. The honest
    version compares the commits each symbol names against the ones the
    advisory now references, which needs the reference resolution that lives in
    the extraction job rather than here. Symbols record their ``fix_commit``,
    so it stays possible.
    """
    inherited = {advisory.id: advisory for advisory in previous}

    merged: list[Advisory] = []
    carried = symbols_carried = arrived = new = changed = 0

    for advisory in fresh:
        if advisory.symbols:
            arrived += 1
            merged.append(advisory)
            continue

        before = inherited.get(advisory.id)
        if before is None:
            new += 1
            merged.append(advisory)
            continue
        if not before.symbols:
            merged.append(advisory)
            continue
        if before.repo_url != advisory.repo_url:
            changed += 1
            merged.append(advisory)
            continue

        carried += 1
        symbols_carried += len(before.symbols)
        status = (
            before.symbols_status if before.symbols_status in SETTLED else SymbolsStatus.EXTRACTED
        )
        merged.append(
            advisory.model_copy(update={"symbols": before.symbols, "symbols_status": status})
        )

    # Built once rather than per candidate: a set comprehension inside the
    # generator would rebuild it for each of the previous corpus's advisories,
    # which at twenty thousand on each side is four hundred million
    # comparisons for a number nobody waits for.
    arriving = {advisory.id for advisory in fresh}
    withdrawn = sum(1 for identifier in inherited if identifier not in arriving)

    return tuple(merged), MergeReport(
        advisories=len(merged),
        carried=carried,
        symbols_carried=symbols_carried,
        arrived_with_symbols=arrived,
        new=new,
        withdrawn=withdrawn,
        repository_changed=changed,
    )


__all__ = ["SETTLED", "MergeReport", "merge"]
