"""Symbol extraction from fix commits.

The pipeline that turns "this commit fixed it" into "these functions are
vulnerable". Everything here runs offline, against diffs written out in the
tests, because every stage that decides what a symbol *is* was deliberately
kept clear of the network.

Two asymmetries recur and are each tested directly:

- A symbol the fix **deleted** must still be extracted. It is gone from the new
  file but present in every affected version, so reading only the post-image
  would lose exactly the symbol that matters.
- Naming too many symbols is noise; naming too few turns a reachable finding
  into a clean one. So the extractor errs toward naming more, and says so
  through confidence.
"""

from __future__ import annotations

import textwrap

import pytest

from vexpath_core.advisory.coverage import FixReferenceTier
from vexpath_core.enums import Confidence, SymbolKind, SymbolSource, SymbolsStatus
from vexpath_core.models.advisory import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    RangeEvent,
    RangeType,
    VulnerableSymbol,
)
from vexpath_core.models.common import Reference
from vexpath_core.patchdiff import (
    CommitDiff,
    FetchError,
    RecordedCommitSource,
    UnresolvableFixError,
    extract,
    extract_for_advisory,
    import_names_for,
    layout_for,
    parse,
    python_files,
    resolve,
    with_symbols,
)

SHA = "2d8df8b9a1c4e5f6a7b801020304050607080910"


def _diff(body: str) -> str:
    return textwrap.dedent(body).lstrip("\n")


def _advisory(
    *,
    references: tuple[Reference, ...] = (),
    repo_url: str | None = None,
    git_range: bool = False,
    fixed: str | None = "2.32.0",
    package: str = "requests",
    advisory_id: str = "CVE-2024-35195",
    symbols: tuple[VulnerableSymbol, ...] = (),
) -> Advisory:
    ranges: list[AffectedRange] = []
    if git_range:
        ranges.append(
            AffectedRange(
                type=RangeType.GIT,
                repo="https://github.com/psf/requests",
                events=(RangeEvent(introduced="0"), RangeEvent(fixed=SHA)),
            )
        )
    events = [RangeEvent(introduced="0")]
    if fixed:
        events.append(RangeEvent(fixed=fixed))
    ranges.append(AffectedRange(type=RangeType.ECOSYSTEM, events=tuple(events)))

    return Advisory(
        id=advisory_id,
        references=references,
        repo_url=repo_url,
        symbols=symbols,
        affected=(
            AffectedPackage(
                ecosystem="PyPI",
                name=package,
                purl_base=f"pkg:pypi/{package}",
                ranges=tuple(ranges),
            ),
        ),
    )


# --- Finding the fix -------------------------------------------------------


def test_a_commit_reference_resolves_to_a_commit() -> None:
    advisory = _advisory(
        references=(Reference(type="FIX", url=f"https://github.com/psf/requests/commit/{SHA}"),)
    )
    reference = resolve(advisory)
    assert reference.commit == SHA
    assert reference.owner == "psf"
    assert reference.name == "requests"
    assert reference.tier is FixReferenceTier.COMMIT
    assert reference.confidence is Confidence.HIGH
    assert not reference.needs_resolution


def test_a_git_range_carries_both_repository_and_commit() -> None:
    reference = resolve(_advisory(git_range=True))
    assert reference.commit == SHA
    assert reference.repository == "https://github.com/psf/requests"
    assert reference.confidence is Confidence.HIGH


def test_a_pull_request_still_needs_resolving() -> None:
    advisory = _advisory(
        references=(Reference(type="FIX", url="https://github.com/psf/requests/pull/6710"),)
    )
    reference = resolve(advisory)
    assert reference.pull_request == 6710
    assert reference.needs_resolution
    # One lookup away from a commit, so the symbols it yields are weaker.
    assert reference.confidence is Confidence.MEDIUM


def test_a_release_tag_is_the_weakest_reference() -> None:
    reference = resolve(_advisory(repo_url="https://github.com/psf/requests", references=()))
    assert reference.tier is FixReferenceTier.TAG_DERIVABLE
    assert reference.fixed_version == "2.32.0"
    # A release diff contains everything else that shipped in it.
    assert reference.confidence is Confidence.LOW


def test_a_gitlab_commit_resolves() -> None:
    advisory = _advisory(
        references=(Reference(type="FIX", url=f"https://gitlab.com/group/project/-/commit/{SHA}"),)
    )
    reference = resolve(advisory)
    assert reference.host == "gitlab.com"
    assert reference.commit == SHA


def test_an_advisory_with_nothing_to_diff_is_rejected() -> None:
    advisory = _advisory(
        references=(Reference(type="ADVISORY", url="https://nvd.nist.gov/vuln/detail/x"),),
        repo_url=None,
        fixed=None,
    )
    with pytest.raises(UnresolvableFixError, match="no usable fix reference"):
        resolve(advisory)


def test_a_commit_on_an_unknown_host_is_refused() -> None:
    """A repository URL comes from advisory data, which is attacker-influenced."""
    advisory = _advisory(
        references=(Reference(type="FIX", url=f"https://git.evil.invalid/a/b/commit/{SHA}"),),
        repo_url=None,
        fixed=None,
    )
    with pytest.raises(UnresolvableFixError):
        resolve(advisory)


# --- Reading the diff ------------------------------------------------------


def test_changed_lines_are_tracked_on_both_sides() -> None:
    diff = _diff(
        """
        diff --git a/pkg/mod.py b/pkg/mod.py
        index 111..222 100644
        --- a/pkg/mod.py
        +++ b/pkg/mod.py
        @@ -10,2 +10,3 @@ class Thing:
        -    old_one
        -    old_two
        +    new_one
        +    new_two
        +    new_three
        """
    )
    files = parse(diff)
    assert len(files) == 1
    assert files[0].path == "pkg/mod.py"
    assert files[0].removed_lines == [10, 11]
    assert files[0].added_lines == [10, 11, 12]


def test_context_lines_are_not_treated_as_changes() -> None:
    """A fix must not be attributed to every function sitting near it."""
    diff = _diff(
        """
        diff --git a/pkg/mod.py b/pkg/mod.py
        --- a/pkg/mod.py
        +++ b/pkg/mod.py
        @@ -5,7 +5,7 @@
         context one
         context two
        -    changed
        +    changed differently
         context three
        """
    )
    file_diff = parse(diff)[0]
    assert file_diff.removed_lines == [7]
    assert file_diff.added_lines == [7]


def test_an_added_file_is_recognised() -> None:
    diff = _diff(
        """
        diff --git a/pkg/new.py b/pkg/new.py
        new file mode 100644
        --- /dev/null
        +++ b/pkg/new.py
        @@ -0,0 +1,2 @@
        +def added():
        +    return 1
        """
    )
    file_diff = parse(diff)[0]
    assert file_diff.is_new_file
    assert file_diff.old_path is None
    assert file_diff.added_lines == [1, 2]


def test_a_deleted_file_is_recognised() -> None:
    diff = _diff(
        """
        diff --git a/pkg/gone.py b/pkg/gone.py
        deleted file mode 100644
        --- a/pkg/gone.py
        +++ /dev/null
        @@ -1,2 +0,0 @@
        -def gone():
        -    return 1
        """
    )
    file_diff = parse(diff)[0]
    assert file_diff.is_deleted_file
    assert file_diff.new_path is None
    assert file_diff.path == "pkg/gone.py"


def test_test_files_are_excluded_from_extraction() -> None:
    # A fix's test exercises the vulnerable function, so attributing the fix to
    # the test would name the wrong symbol.
    diff = _diff(
        """
        diff --git a/pkg/mod.py b/pkg/mod.py
        --- a/pkg/mod.py
        +++ b/pkg/mod.py
        @@ -1,1 +1,1 @@
        -old
        +new
        diff --git a/tests/test_mod.py b/tests/test_mod.py
        --- a/tests/test_mod.py
        +++ b/tests/test_mod.py
        @@ -1,1 +1,1 @@
        -old
        +new
        diff --git a/pkg/test_helper.py b/pkg/test_helper.py
        --- a/pkg/test_helper.py
        +++ b/pkg/test_helper.py
        @@ -1,1 +1,1 @@
        -old
        +new
        """
    )
    assert [file_diff.path for file_diff in python_files(diff)] == ["pkg/mod.py"]


def test_non_python_files_are_ignored() -> None:
    diff = _diff(
        """
        diff --git a/CHANGELOG.md b/CHANGELOG.md
        --- a/CHANGELOG.md
        +++ b/CHANGELOG.md
        @@ -1,1 +1,1 @@
        -old
        +new
        """
    )
    assert list(python_files(diff)) == []


def test_a_malformed_stanza_does_not_discard_the_rest() -> None:
    diff = _diff(
        """
        garbage line with no meaning
        diff --git a/pkg/mod.py b/pkg/mod.py
        --- a/pkg/mod.py
        +++ b/pkg/mod.py
        @@ -1,1 +1,1 @@
        -old
        +new
        """
    )
    assert [file_diff.path for file_diff in python_files(diff)] == ["pkg/mod.py"]


# --- Paths to module names -------------------------------------------------


def test_a_src_layout_is_anchored_on_the_package_name() -> None:
    # The distribution's own name matching a directory outright is precise.
    layout = layout_for("requests")
    assert layout.module_for("src/requests/adapters.py") == (
        "requests.adapters",
        Confidence.HIGH,
    )


def test_a_flat_layout_resolves() -> None:
    layout = layout_for("requests")
    assert layout.module_for("requests/sessions.py") == (
        "requests.sessions",
        Confidence.HIGH,
    )


def test_a_package_init_becomes_the_package() -> None:
    layout = layout_for("requests")
    assert layout.module_for("requests/__init__.py") == ("requests", Confidence.HIGH)


def test_a_distribution_whose_import_name_differs_still_resolves() -> None:
    # pyyaml imports as yaml; a table covers the cases that appear often. The
    # alias is likely rather than certain, so the confidence drops a step.
    layout = layout_for("pyyaml")
    assert layout.module_for("lib/yaml/constructor.py") == (
        "yaml.constructor",
        Confidence.MEDIUM,
    )


def test_a_declared_layout_raises_confidence() -> None:
    pyproject = _diff(
        """
        [project]
        name = "mystery-dist"

        [tool.hatch.build.targets.wheel]
        packages = ["src/mystery"]
        """
    )
    layout = layout_for("mystery-dist", pyproject=pyproject)
    assert layout.declared
    assert layout.module_for("src/mystery/core.py") == ("mystery.core", Confidence.HIGH)


def test_a_poetry_layout_is_read() -> None:
    pyproject = _diff(
        """
        [tool.poetry]
        name = "mystery-dist"
        packages = [{ include = "mystery", from = "src" }]
        """
    )
    layout = layout_for("mystery-dist", pyproject=pyproject)
    assert layout.module_for("src/mystery/core.py") == ("mystery.core", Confidence.HIGH)


def test_an_unanchored_path_is_reported_at_low_confidence() -> None:
    layout = layout_for("mystery-dist")
    mapped = layout.module_for("src/something_else/core.py")
    assert mapped is not None
    assert mapped[1] is Confidence.LOW


def test_a_non_python_path_maps_to_nothing() -> None:
    assert layout_for("requests").module_for("docs/index.md") is None


def test_import_name_guesses_include_the_underscore_form() -> None:
    assert "flask_sqlalchemy" in import_names_for("Flask-SQLAlchemy")


# --- Naming the symbols ----------------------------------------------------

POST_SOURCE = _diff(
    """
    class Session:
        def request(self, method, url):
            return self.send(None)

        def send(self, request):
            if not self.verify:
                raise ValueError("refusing")
            return self.adapter.send(request)
    """
)

PRE_SOURCE = _diff(
    """
    class Session:
        def request(self, method, url):
            return self.send(None)

        def send(self, request):
            return self.adapter.send(request)
    """
)


def _file_diff(path: str, added: list[int], removed: list[int]) -> object:
    from vexpath_core.patchdiff.unidiff import FileDiff

    return FileDiff(old_path=path, new_path=path, added_lines=added, removed_lines=removed)


def test_a_change_inside_a_method_names_that_method() -> None:
    symbols, report = extract(
        "CVE-2024-35195",
        "PyPI",
        "requests",
        [(_file_diff("requests/sessions.py", [6, 7], []), POST_SOURCE, PRE_SOURCE)],  # type: ignore[list-item]
        layout_for("requests"),
        commit=SHA,
    )
    names = {symbol.symbol for symbol in symbols}
    assert "requests.sessions.Session.send" in names
    # The sibling method was not touched and must not be named.
    assert "requests.sessions.Session.request" not in names
    assert not report.looks_like_refactor
    assert symbols[0].source is SymbolSource.FIX_COMMIT
    assert symbols[0].fix_commit == SHA


def test_a_deleted_function_is_still_extracted() -> None:
    """It is gone from the new file but present in every affected version."""
    pre = _diff(
        """
        def safe():
            return 1


        def dangerous():
            return eval("1")
        """
    )
    post = _diff(
        """
        def safe():
            return 1
        """
    )
    symbols, _ = extract(
        "CVE-x",
        "PyPI",
        "pkg",
        [(_file_diff("pkg/mod.py", [], [5, 6]), post, pre)],  # type: ignore[list-item]
        layout_for("pkg"),
    )
    assert "pkg.mod.dangerous" in {symbol.symbol for symbol in symbols}


def test_module_level_changes_name_the_module() -> None:
    # Importing the module runs the change, so the module is the symbol.
    source = _diff(
        """
        DEFAULT_LOADER = "unsafe"


        def helper():
            return 1
        """
    )
    symbols, _ = extract(
        "CVE-x",
        "PyPI",
        "pkg",
        [(_file_diff("pkg/mod.py", [1], []), source, source)],  # type: ignore[list-item]
        layout_for("pkg"),
    )
    found = {symbol.symbol: symbol for symbol in symbols}
    assert "pkg.mod" in found
    assert found["pkg.mod"].kind is SymbolKind.MODULE


def test_a_signature_only_change_is_medium_confidence() -> None:
    symbols, _ = extract(
        "CVE-x",
        "PyPI",
        "requests",
        # Line 5 is the def line of send(), not its body.
        [(_file_diff("requests/sessions.py", [5], []), POST_SOURCE, PRE_SOURCE)],  # type: ignore[list-item]
        layout_for("requests"),
    )
    send = next(symbol for symbol in symbols if symbol.symbol.endswith("send"))
    assert send.confidence is Confidence.MEDIUM


def test_a_weak_reference_caps_the_confidence() -> None:
    symbols, _ = extract(
        "CVE-x",
        "PyPI",
        "requests",
        [(_file_diff("requests/sessions.py", [6, 7], []), POST_SOURCE, PRE_SOURCE)],  # type: ignore[list-item]
        layout_for("requests"),
        reference_confidence=Confidence.LOW,
    )
    assert all(symbol.confidence is Confidence.LOW for symbol in symbols)


def test_a_class_level_change_names_the_class() -> None:
    source = _diff(
        """
        class Thing:
            SETTING = "unsafe"

            def method(self):
                return 1
        """
    )
    symbols, _ = extract(
        "CVE-x",
        "PyPI",
        "pkg",
        [(_file_diff("pkg/mod.py", [2], []), source, source)],  # type: ignore[list-item]
        layout_for("pkg"),
    )
    found = {symbol.symbol: symbol for symbol in symbols}
    assert found["pkg.mod.Thing"].kind is SymbolKind.CLASS
    assert "pkg.mod.Thing.method" not in found


def test_an_unparsable_file_is_reported_not_raised() -> None:
    symbols, report = extract(
        "CVE-x",
        "PyPI",
        "pkg",
        [(_file_diff("pkg/mod.py", [1], []), "def broken(:", None)],  # type: ignore[list-item]
        layout_for("pkg"),
    )
    assert symbols == ()
    assert report.failures
    assert "SyntaxError" in report.failures[0]


def test_a_refactor_sized_commit_marks_everything_low_confidence() -> None:
    """Every symbol is kept, because dropping them could hide the real one."""
    body = "\n\n".join(f"def function_{index}():\n    return {index}" for index in range(40))
    lines = list(range(1, body.count("\n") + 2))
    symbols, report = extract(
        "CVE-x",
        "PyPI",
        "pkg",
        [(_file_diff("pkg/mod.py", lines, []), body, body)],  # type: ignore[list-item]
        layout_for("pkg"),
    )
    assert report.looks_like_refactor
    assert len(symbols) > 25
    assert all(symbol.confidence is Confidence.LOW for symbol in symbols)


def test_files_outside_the_package_are_skipped() -> None:
    symbols, report = extract(
        "CVE-x",
        "PyPI",
        "requests",
        [(_file_diff("docs/conf.py", [1], []), "project = 'x'", None)],  # type: ignore[list-item]
        layout_for("requests"),
    )
    # docs/conf.py maps to a module name, but at low confidence rather than
    # being silently attributed to the package.
    assert all(symbol.confidence is Confidence.LOW for symbol in symbols)
    assert not report.failures


def test_symbols_from_another_package_are_rejected() -> None:
    """Measured against real advisories, this happens and matters.

    An advisory for one distribution often links the fix commit of a separate
    project it depends on. Recording those symbols under the affected package
    would attribute them to the wrong distribution, and a symbol in the wrong
    place drives verdicts: searched for in the wrong graph it is never found,
    and "not found" is one step from "cleared".
    """
    source = _diff(
        """
        class Multipass:
            def validate_next_url(self, url):
                return url
        """
    )
    symbols, report = extract(
        "CVE-2024-45399",
        "PyPI",
        # The advisory affects indico; the commit is in flask-multipass.
        "indico",
        [(_file_diff("flask_multipass/core.py", [2, 3], []), source, source)],  # type: ignore[list-item]
        layout_for("indico"),
    )
    assert symbols == ()
    assert "flask_multipass/core.py" in report.unmapped


def test_a_package_with_an_unusual_layout_also_yields_nothing() -> None:
    # The same rule costs us the occasional real symbol, which is the right
    # trade: no symbol keeps a finding under investigation, whereas a wrong
    # one can clear it.
    symbols, _ = extract(
        "CVE-x",
        "PyPI",
        "mystery-dist",
        [(_file_diff("weird_internal_name/core.py", [1], []), "VALUE = 1", None)],  # type: ignore[list-item]
        layout_for("mystery-dist"),
    )
    assert symbols == ()


# --- End to end ------------------------------------------------------------


def _recorded(files: tuple[object, ...], **kwargs: object) -> RecordedCommitSource:
    return RecordedCommitSource(
        diffs={
            SHA: CommitDiff(
                commit=SHA,
                repository="https://github.com/psf/requests",
                files=files,  # type: ignore[arg-type]
                **kwargs,  # type: ignore[arg-type]
            )
        }
    )


def test_the_pipeline_extracts_from_a_recorded_commit() -> None:
    advisory = _advisory(
        references=(Reference(type="FIX", url=f"https://github.com/psf/requests/commit/{SHA}"),)
    )
    source = _recorded(((_file_diff("requests/sessions.py", [6, 7], []), POST_SOURCE, PRE_SOURCE),))
    result = extract_for_advisory(advisory, source)

    assert result.succeeded
    assert result.status is SymbolsStatus.EXTRACTED
    assert "requests.sessions.Session.send" in {s.symbol for s in result.symbols}
    assert result.best_confidence is Confidence.HIGH
    assert "Extracted" in result.detail


def test_a_malicious_package_record_is_not_diffed() -> None:
    advisory = _advisory(advisory_id="MAL-2026-0001")
    result = extract_for_advisory(advisory, _recorded(()))
    assert result.status is SymbolsStatus.NONE
    assert "no fix to diff" in result.detail


def test_an_advisory_with_no_reference_is_recorded_as_such() -> None:
    advisory = _advisory(references=(), repo_url=None, fixed=None)
    result = extract_for_advisory(advisory, _recorded(()))
    assert result.status is SymbolsStatus.NONE
    assert "no usable fix reference" in result.detail


def test_a_pull_request_reference_stays_pending() -> None:
    advisory = _advisory(
        references=(Reference(type="FIX", url="https://github.com/psf/requests/pull/1"),)
    )
    result = extract_for_advisory(advisory, _recorded(()))
    assert result.status is SymbolsStatus.PENDING
    assert result.reference is not None
    assert result.reference.pull_request == 1


def test_a_fetch_failure_is_recorded_as_a_failure() -> None:
    advisory = _advisory(
        references=(Reference(type="FIX", url=f"https://github.com/psf/requests/commit/{SHA}"),)
    )

    class Failing:
        def fetch(self, reference: object) -> CommitDiff:
            msg = "network unreachable"
            raise FetchError(msg)

    result = extract_for_advisory(advisory, Failing())
    assert result.status is SymbolsStatus.FAILED
    assert "network unreachable" in result.detail


def test_a_commit_that_changed_no_python_is_recorded_as_none() -> None:
    advisory = _advisory(
        references=(Reference(type="FIX", url=f"https://github.com/psf/requests/commit/{SHA}"),)
    )
    result = extract_for_advisory(advisory, _recorded(()))
    assert result.status is SymbolsStatus.NONE
    assert "changed no Python source" in result.detail


def test_curated_symbols_survive_a_later_extraction() -> None:
    """A human reviewed them, so a machine must not quietly replace them."""
    curated = VulnerableSymbol(
        advisory_id="CVE-2024-35195",
        ecosystem="PyPI",
        package_name="requests",
        symbol="requests.sessions.Session.send",
        kind=SymbolKind.METHOD,
        source=SymbolSource.CURATED,
        confidence=Confidence.HIGH,
    )
    advisory = _advisory(
        references=(Reference(type="FIX", url=f"https://github.com/psf/requests/commit/{SHA}"),),
        symbols=(curated,),
    )
    source = _recorded(((_file_diff("requests/sessions.py", [6, 7], []), POST_SOURCE, PRE_SOURCE),))
    updated = with_symbols(advisory, extract_for_advisory(advisory, source))

    sends = [s for s in updated.symbols if s.symbol == "requests.sessions.Session.send"]
    assert len(sends) == 1
    assert sends[0].source is SymbolSource.CURATED
    assert updated.symbols_status is SymbolsStatus.EXTRACTED


def test_a_curated_symbol_alone_counts_as_extracted() -> None:
    curated = VulnerableSymbol(
        advisory_id="CVE-x",
        ecosystem="PyPI",
        package_name="requests",
        symbol="requests.sessions.Session.send",
        kind=SymbolKind.METHOD,
        source=SymbolSource.CURATED,
        confidence=Confidence.HIGH,
    )
    advisory = _advisory(
        advisory_id="CVE-x", references=(), repo_url=None, fixed=None, symbols=(curated,)
    )
    updated = with_symbols(advisory, extract_for_advisory(advisory, _recorded(())))
    assert updated.symbols_status is SymbolsStatus.EXTRACTED
    assert len(updated.symbols) == 1


def test_the_build_configuration_from_the_commit_is_used() -> None:
    advisory = _advisory(
        package="mystery-dist",
        advisory_id="CVE-y",
        references=(Reference(type="FIX", url=f"https://github.com/psf/requests/commit/{SHA}"),),
    )
    source = _recorded(
        ((_file_diff("src/mystery/core.py", [1], []), "VALUE = 1", None),),
        pyproject='[tool.hatch.build.targets.wheel]\npackages = ["src/mystery"]\n',
    )
    result = extract_for_advisory(advisory, source)
    assert result.succeeded
    assert "mystery.core" in {symbol.symbol for symbol in result.symbols}
    assert result.best_confidence is Confidence.HIGH
