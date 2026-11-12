"""Run symbol extraction for one advisory, end to end.

Resolve the fix, fetch the diff, map paths to module names, name the symbols.
The stages stay separate underneath so each can be tested on its own; this is
the one call a worker needs.

What comes back is always an answer, never an exception for the ordinary
failures. An advisory with no fix reference, a repository that cannot be
fetched, a commit that touched no Python: each is a fact about that advisory
that the corpus should record, not an error that should stop a sync of
thousands.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from vexpath_core.advisory.coverage import FixReferenceTier
from vexpath_core.enums import Confidence, SymbolSource, SymbolsStatus
from vexpath_core.models.advisory import Advisory, AffectedPackage, VulnerableSymbol
from vexpath_core.patchdiff.extract import extract
from vexpath_core.patchdiff.fetch import (
    MAX_FILES_PER_TAG_DIFF,
    MAX_SYMBOLS_PER_TAG_DIFF,
    CommitSource,
    FetchError,
)
from vexpath_core.patchdiff.layout import layout_for
from vexpath_core.patchdiff.references import (
    FixReference,
    UnresolvableFixError,
    resolve,
)


@dataclass(frozen=True, slots=True)
class PatchDiffResult:
    """What extraction concluded for one advisory."""

    advisory_id: str
    status: SymbolsStatus
    symbols: tuple[VulnerableSymbol, ...] = ()
    reference: FixReference | None = None
    #: Why the status is what it is, in plain language. Shown by
    #: ``vexpath advisory show`` so a reader can see why a finding stayed under
    #: investigation rather than being told only that it did.
    detail: str = ""
    notes: tuple[str, ...] = field(default=())

    @property
    def succeeded(self) -> bool:
        return self.status is SymbolsStatus.EXTRACTED

    @property
    def best_confidence(self) -> Confidence | None:
        if not self.symbols:
            return None
        return max((symbol.confidence for symbol in self.symbols), key=lambda value: value.rank)


def extract_for_advisory(
    advisory: Advisory, source: CommitSource, *, ecosystem: str = "PyPI"
) -> PatchDiffResult:
    """Extract vulnerable symbols for one advisory.

    Args:
        advisory: The advisory to work on.
        source: Where to fetch the commit from.
        ecosystem: Which of the advisory's affected packages to extract for.
            Only one ecosystem is handled per call, because symbol names are
            ecosystem-specific.
    """
    if advisory.is_malicious_package:
        # There is no fix to diff, and reachability is the wrong question:
        # installing malware runs it.
        return PatchDiffResult(
            advisory_id=advisory.id,
            status=SymbolsStatus.NONE,
            detail=(
                "This is a malicious-package record, not a vulnerability. There is "
                "no fix to diff, and its presence alone is the finding."
            ),
        )

    packages = [package for package in advisory.affected if package.ecosystem == ecosystem]
    if not packages:
        return PatchDiffResult(
            advisory_id=advisory.id,
            status=SymbolsStatus.NONE,
            detail=f"The advisory affects no {ecosystem} package.",
        )

    try:
        reference = resolve(advisory)
    except UnresolvableFixError as exc:
        return PatchDiffResult(advisory_id=advisory.id, status=SymbolsStatus.NONE, detail=str(exc))

    if reference.needs_resolution:
        resolved, detail = _resolve_release_range(advisory, reference, source, packages)
        if resolved is None:
            # A pull request still needs an API call this build does not make,
            # and a tag whose release could not be located stays unresolved.
            # Recording the reference means the next run can start there.
            return PatchDiffResult(
                advisory_id=advisory.id,
                status=SymbolsStatus.PENDING,
                reference=reference,
                detail=detail,
            )
        reference = resolved

    try:
        commit_diff = source.fetch(reference)
    except FetchError as exc:
        return PatchDiffResult(
            advisory_id=advisory.id,
            status=SymbolsStatus.FAILED,
            reference=reference,
            detail=f"Could not fetch {reference.commit} from {reference.repository}: {exc}",
        )

    if reference.is_release_range and len(commit_diff.files) > MAX_FILES_PER_TAG_DIFF:
        # Refused rather than truncated. Taking the first forty files of a
        # large release would name an arbitrary subset of its changes as the
        # vulnerable symbols, which is worse than naming none: it reads as
        # evidence.
        return PatchDiffResult(
            advisory_id=advisory.id,
            status=SymbolsStatus.NONE,
            reference=reference,
            detail=(
                f"The release that fixed this touches {len(commit_diff.files)} Python "
                f"files, above the {MAX_FILES_PER_TAG_DIFF} allowed for a release "
                f"diff. Every change in a release would be recorded as vulnerable, "
                f"which would make any project using this package look reachable."
            ),
            notes=commit_diff.notes,
        )

    if not commit_diff.files:
        return PatchDiffResult(
            advisory_id=advisory.id,
            status=SymbolsStatus.NONE,
            reference=reference,
            detail=(
                f"Commit {reference.commit[:12] if reference.commit else '?'} changed no "
                f"Python source outside tests. The fix may be in data, in another "
                f"language, or in the build."
            ),
            notes=commit_diff.notes,
        )

    collected: list[VulnerableSymbol] = []
    failures: list[str] = []
    refactor = False

    for package in packages:
        layout = layout_for(
            package.name,
            pyproject=commit_diff.pyproject,
            setup_cfg=commit_diff.setup_cfg,
        )
        symbols, report = extract(
            advisory.id,
            ecosystem,
            package.name,
            list(commit_diff.files),
            layout,
            reference_confidence=reference.confidence,
            commit=reference.commit,
            source=(
                SymbolSource.TAG_DIFF if reference.is_release_range else SymbolSource.FIX_COMMIT
            ),
        )
        collected.extend(symbols)
        failures.extend(report.failures)
        refactor = refactor or report.looks_like_refactor

    if reference.is_release_range and len(collected) > MAX_SYMBOLS_PER_TAG_DIFF:
        return PatchDiffResult(
            advisory_id=advisory.id,
            status=SymbolsStatus.NONE,
            reference=reference,
            detail=(
                f"The release that fixed this changed {len(collected)} functions, above "
                f"the {MAX_SYMBOLS_PER_TAG_DIFF} allowed for a release diff. A fix "
                f"commit names four at the median; a list this long is an inventory "
                f"of the package rather than evidence about the fix, and would make "
                f"every project importing it look reachable."
            ),
            notes=(*commit_diff.notes, *failures),
        )

    if not collected:
        return PatchDiffResult(
            advisory_id=advisory.id,
            status=SymbolsStatus.NONE,
            reference=reference,
            detail=(
                "The commit's changed files could not be mapped to importable "
                "modules of the affected package, so no symbol could be named."
            ),
            notes=(*commit_diff.notes, *failures),
        )

    if reference.is_release_range:
        detail = (
            f"Extracted {len(collected)} symbol(s) by diffing the release that fixed "
            f"this against the one before it, because the advisory names no fix "
            f"commit. These are the functions the *release* changed, so some of them "
            f"are unrelated to the fix."
        )
    else:
        detail = (
            f"Extracted {len(collected)} symbol(s) from commit "
            f"{reference.commit[:12] if reference.commit else '?'}."
        )
    if refactor:
        detail += (
            " The commit touches enough symbols to look like a refactor, so every "
            "symbol is recorded at low confidence and the advisory is worth a "
            "human look."
        )

    return PatchDiffResult(
        advisory_id=advisory.id,
        status=SymbolsStatus.EXTRACTED,
        symbols=tuple(collected),
        reference=reference,
        detail=detail,
        notes=(*commit_diff.notes, *failures),
    )


def _resolve_release_range(
    advisory: Advisory,
    reference: FixReference,
    source: CommitSource,
    packages: list[AffectedPackage],
) -> tuple[FixReference | None, str]:
    """Turn a reference naming only a fixed version into one naming commits.

    Returns the resolved reference, or None with the reason it stayed
    unresolved. The reason is the message a human reads next to the advisory,
    so it says which of the several ways this fails happened.
    """
    if reference.tier is not FixReferenceTier.TAG_DERIVABLE or not reference.fixed_version:
        return None, (
            f"The fix is identified by a {reference.tier.value.replace('_', ' ')} "
            f"rather than a commit, which has to be resolved before the diff "
            f"can be read."
        )

    # The versions the advisory says are affected narrow the span: the highest
    # of them is the last release known to be vulnerable.
    affected_versions = sorted({version for package in packages for version in package.versions})

    try:
        resolved = source.resolve_release_range(
            reference.repository,
            reference.fixed_version,
            affected_versions=affected_versions,
        )
    except FetchError as exc:
        return None, f"The release tags of {reference.repository} could not be read: {exc}"

    if resolved is None:
        return None, (
            f"No release tag matching {reference.fixed_version} was found in "
            f"{reference.repository}, so there is no release to diff. The project may "
            f"tag releases differently, or not at all."
        )

    base, commit = resolved
    return replace(reference, commit=commit, base=base), ""


def with_symbols(advisory: Advisory, result: PatchDiffResult) -> Advisory:
    """Return the advisory carrying what extraction found.

    Curated symbols are preserved and take precedence: a human reviewed them,
    and a later extraction run must not quietly replace that judgement.
    """
    from vexpath_core.enums import SymbolSource

    curated = tuple(symbol for symbol in advisory.symbols if symbol.source is SymbolSource.CURATED)
    curated_names = {(symbol.package_name, symbol.symbol) for symbol in curated}
    extracted = tuple(
        symbol
        for symbol in result.symbols
        if (symbol.package_name, symbol.symbol) not in curated_names
    )

    status = result.status
    if curated and status is not SymbolsStatus.EXTRACTED:
        # A curated symbol is itself a successful extraction, whatever the
        # commit lookup did.
        status = SymbolsStatus.EXTRACTED

    return advisory.model_copy(update={"symbols": (*curated, *extracted), "symbols_status": status})


__all__ = ["PatchDiffResult", "extract_for_advisory", "with_symbols"]
