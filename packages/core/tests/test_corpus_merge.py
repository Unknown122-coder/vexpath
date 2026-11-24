"""Carrying symbols across a refresh, which is the expensive thing to get wrong.

A refresh that loses symbols does not fail. It produces a corpus that parses,
verifies, publishes, and then reports ``symbols_unknown`` for everything --
and every install that downloads it quietly stops being able to clear a
finding. These tests are about that one outcome.
"""

from __future__ import annotations

from vexpath_core.corpus import merge
from vexpath_core.enums import Confidence, Severity, SymbolKind, SymbolSource, SymbolsStatus
from vexpath_core.models.advisory import Advisory, VulnerableSymbol


def _symbol(advisory_id: str, symbol: str = "lib.danger") -> VulnerableSymbol:
    return VulnerableSymbol(
        advisory_id=advisory_id,
        ecosystem="PyPI",
        package_name="lib",
        symbol=symbol,
        kind=SymbolKind.FUNCTION,
        source=SymbolSource.FIX_COMMIT,
        confidence=Confidence.HIGH,
    )


def _advisory(
    identifier: str = "CVE-2026-0001",
    *,
    symbols: tuple[VulnerableSymbol, ...] = (),
    status: SymbolsStatus = SymbolsStatus.PENDING,
    severity: Severity = Severity.HIGH,
    repo: str | None = "https://github.com/acme/lib",
) -> Advisory:
    return Advisory(
        id=identifier,
        summary="a problem",
        severity=severity,
        symbols_status=status,
        affected=(),
        symbols=symbols,
        repo_url=repo,
    )


def test_symbols_survive_a_refresh() -> None:
    """The whole point. OSV ships none, and re-deriving them takes hours."""
    previous = [
        _advisory(symbols=(_symbol("CVE-2026-0001"),), status=SymbolsStatus.EXTRACTED),
    ]
    fresh = [_advisory()]

    merged, report = merge(fresh, previous)

    assert len(merged[0].symbols) == 1
    assert report.symbols_carried == 1
    assert report.carried == 1


def test_the_settled_status_travels_with_them() -> None:
    """Otherwise the queue re-extracts the entire corpus on the next run.

    The extraction queue takes anything ``pending``. Carrying symbols while
    leaving the status alone would hand back work that is already done, which
    is the cost this function exists to avoid.
    """
    previous = [_advisory(symbols=(_symbol("CVE-2026-0001"),), status=SymbolsStatus.EXTRACTED)]

    merged, _ = merge([_advisory()], previous)

    assert merged[0].symbols_status is SymbolsStatus.EXTRACTED


def test_a_tag_derived_status_is_not_promoted() -> None:
    """Weaker provenance stays weaker: it decides the confidence downstream."""
    previous = [
        _advisory(symbols=(_symbol("CVE-2026-0001"),), status=SymbolsStatus.DERIVED_FROM_TAGS)
    ]

    merged, _ = merge([_advisory()], previous)

    assert merged[0].symbols_status is SymbolsStatus.DERIVED_FROM_TAGS


def test_fresh_metadata_wins_over_the_old_record() -> None:
    """Inheriting symbols must not freeze the corpus at the day it was built.

    Keeping the previous advisory whole would keep its severity, its EPSS
    score and its affected ranges too, which is how a corpus silently stops
    reflecting the advisories it claims to carry.
    """
    previous = [
        _advisory(
            symbols=(_symbol("CVE-2026-0001"),),
            status=SymbolsStatus.EXTRACTED,
            severity=Severity.LOW,
        )
    ]
    fresh = [_advisory(severity=Severity.CRITICAL)]

    merged, _ = merge(fresh, previous)

    assert merged[0].severity is Severity.CRITICAL
    assert len(merged[0].symbols) == 1


def test_an_advisory_that_arrived_with_symbols_keeps_its_own() -> None:
    """The source that published them owns them."""
    previous = [_advisory(symbols=(_symbol("CVE-2026-0001", "lib.old"),))]
    fresh = [_advisory(symbols=(_symbol("CVE-2026-0001", "lib.new"),))]

    merged, report = merge(fresh, previous)

    assert [s.symbol for s in merged[0].symbols] == ["lib.new"]
    assert report.arrived_with_symbols == 1
    assert report.carried == 0


def test_a_withdrawn_advisory_is_not_resurrected() -> None:
    """Keeping it to preserve its symbols would report a vulnerability that
    upstream has retracted."""
    previous = [_advisory("CVE-2026-0001", symbols=(_symbol("CVE-2026-0001"),))]
    fresh = [_advisory("CVE-2026-0002")]

    merged, report = merge(fresh, previous)

    assert [a.id for a in merged] == ["CVE-2026-0002"]
    assert report.withdrawn == 1


def test_a_changed_repository_drops_the_symbols() -> None:
    """They name commits in a repository this advisory no longer points at.

    Against a different one they are meaningless at best, and at worst
    describe somebody else's code -- so the advisory goes back to pending and
    extraction redoes it.
    """
    previous = [
        _advisory(
            symbols=(_symbol("CVE-2026-0001"),),
            status=SymbolsStatus.EXTRACTED,
            repo="https://github.com/acme/lib",
        )
    ]
    fresh = [_advisory(repo="https://github.com/acme/renamed")]

    merged, report = merge(fresh, previous)

    assert merged[0].symbols == ()
    assert merged[0].symbols_status is SymbolsStatus.PENDING
    assert report.repository_changed == 1


def test_a_new_advisory_is_left_for_extraction() -> None:
    merged, report = merge([_advisory("CVE-2026-9999")], [])

    assert merged[0].symbols == ()
    assert merged[0].symbols_status is SymbolsStatus.PENDING
    assert report.new == 1


def test_a_previous_advisory_with_no_symbols_carries_nothing() -> None:
    """And does not count as carried, which would overstate what was saved."""
    merged, report = merge([_advisory()], [_advisory()])

    assert merged[0].symbols == ()
    assert report.carried == 0
    assert report.symbols_carried == 0


def test_the_result_is_the_fresh_download_in_full() -> None:
    """Nothing is dropped and nothing is invented: the count is the download's."""
    previous = [_advisory("CVE-2026-0001", symbols=(_symbol("CVE-2026-0001"),))]
    fresh = [_advisory("CVE-2026-0001"), _advisory("CVE-2026-0002"), _advisory("CVE-2026-0003")]

    merged, report = merge(fresh, previous)

    assert len(merged) == 3
    assert report.advisories == 3
    assert [a.id for a in merged] == [a.id for a in fresh]
