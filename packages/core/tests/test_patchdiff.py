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
from collections.abc import Sequence
from pathlib import Path

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


def test_a_pull_request_the_forge_no_longer_advertises_stays_pending() -> None:
    advisory = _advisory(
        references=(Reference(type="FIX", url="https://github.com/psf/requests/pull/1"),)
    )
    result = extract_for_advisory(advisory, _recorded(()))
    assert result.status is SymbolsStatus.PENDING
    assert result.reference is not None
    assert result.reference.pull_request == 1
    # And it says which of the two ways this fails happened, because they
    # need different things done about them.
    assert "no longer advertises its refs" in result.detail


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


# --- Fetching: tags and partial clones -------------------------------------


def _patched_git(
    monkeypatch: pytest.MonkeyPatch, answers: dict[str, str | None]
) -> tuple[object, list[list[str]]]:
    """A GitCommitSource whose git invocations are answered from a table.

    The parsing and the fallback are what is under test; running git against a
    real remote would make these depend on the network and on another
    project's tags. Patched on the class because instances use ``__slots__``.
    """
    from vexpath_core.patchdiff.fetch import GitCommitSource

    calls: list[list[str]] = []

    def fake_run(
        self: object,
        arguments: Sequence[str],
        workspace: Path,
        *,
        timeout: int = 0,
        allow_failure: bool = False,
    ) -> str | None:
        calls.append(list(arguments))
        return answers.get(arguments[0], "")

    monkeypatch.setattr(GitCommitSource, "_run", fake_run)
    return GitCommitSource(git="git"), calls


def test_a_release_tag_resolves_to_its_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    listing = "\n".join(
        [
            "1111111111111111111111111111111111111111\trefs/tags/v1.2.2",
            "2222222222222222222222222222222222222222\trefs/tags/v1.2.3",
            "3333333333333333333333333333333333333333\trefs/tags/1.2.3",
        ]
    )
    source, _ = _patched_git(monkeypatch, {"ls-remote": listing})
    # The first candidate that exists wins: projects spell one release several
    # ways, and the caller states its preference by ordering them.
    assert source.resolve_tag("https://github.com/psf/requests", ["v1.2.3", "1.2.3"]) == "2" * 40
    assert source.resolve_tag("https://github.com/psf/requests", ["1.2.3", "v1.2.3"]) == "3" * 40


def test_an_absent_tag_resolves_to_nothing_rather_than_guessing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, _ = _patched_git(
        monkeypatch,
        {"ls-remote": "1111111111111111111111111111111111111111\trefs/tags/v9.9.9"},
    )
    assert source.resolve_tag("https://github.com/psf/requests", ["v1.2.3"]) is None


def test_resolving_a_tag_refuses_a_host_off_the_allow_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A repository URL comes from advisory data, which is attacker-influenced."""
    from vexpath_core.patchdiff.fetch import FetchError

    source, calls = _patched_git(monkeypatch, {})
    with pytest.raises(FetchError, match="allow-list"):
        source.resolve_tag("https://evil.example/x/y", ["v1"])
    assert calls == [], "nothing should be contacted"


def test_a_fetch_prefers_a_blobless_clone(monkeypatch: pytest.MonkeyPatch) -> None:
    """A depth-2 fetch still transfers every blob in both trees.

    Measured on cryptography and feast, that timed out at five minutes. Only
    the handful of files the diff names are ever read, so their contents are
    fetched on demand instead.
    """
    source, calls = _patched_git(monkeypatch, {"fetch": ""})
    source._fetch_commit(Path(), "a" * 40)

    fetches = [call for call in calls if call[0] == "fetch"]
    assert len(fetches) == 1
    assert "--filter=blob:none" in fetches[0]


def test_a_server_without_partial_clone_still_works(monkeypatch: pytest.MonkeyPatch) -> None:
    """Servers refuse an unsupported filter rather than ignoring it."""
    from vexpath_core.patchdiff.fetch import GitCommitSource

    attempts: list[list[str]] = []

    def fake_run(
        self: object,
        arguments: Sequence[str],
        workspace: Path,
        *,
        timeout: int = 0,
        allow_failure: bool = False,
    ) -> str | None:
        attempts.append(list(arguments))
        return None if "--filter=blob:none" in arguments else ""

    monkeypatch.setattr(GitCommitSource, "_run", fake_run)
    GitCommitSource(git="git")._fetch_commit(Path(), "a" * 40)

    assert len(attempts) == 2
    assert "--filter=blob:none" not in attempts[1]


def test_a_cache_root_is_created_rather_than_discovered_missing(tmp_path: Path) -> None:
    """A cache directory that does not exist yet is a fresh deployment.

    Discovering it one advisory at a time spent their retry budget on a
    configuration detail, which is how this was found.
    """
    from vexpath_core.patchdiff.fetch import GitCommitSource

    root = tmp_path / "nested" / "cache"
    GitCommitSource(git="git", cache_root=root)
    assert root.is_dir()


def test_each_repository_gets_its_own_cache_directory() -> None:
    from vexpath_core.patchdiff.fetch import _repository_slug

    one = _repository_slug("https://github.com/psf/requests")
    two = _repository_slug("https://github.com/psf/requests.git")
    three = _repository_slug("https://github.com/urllib3/urllib3")

    # Readable, so a person looking at the cache can tell what is in it.
    assert one.startswith("github.com-psf-requests")
    assert one != three
    # The .git suffix names the same upstream, so it shares the object store.
    assert one == two


# --- Resolving a release tag ----------------------------------------------
#
# 2,441 PyPI advisories -- most of what is left after fix commits run out --
# name only "fixed in 2.11.3". The resolver exists to turn that into
# something diffable, and the diff is a release rather than a commit, which
# is the whole reason these symbols are recorded differently.


def test_a_fixed_version_resolves_to_the_span_that_closed_it() -> None:
    from vexpath_core.patchdiff.fetch import _previous_release

    tags = {"2.11.1": "a" * 40, "2.11.2": "b" * 40, "2.11.3": "c" * 40}
    assert _previous_release(tags, "2.11.3") == ("2.11.2", "b" * 40)


def test_tags_are_ordered_by_version_and_not_by_string() -> None:
    """2.11.10 is above 2.11.9, which sorting text gets backwards."""
    from vexpath_core.patchdiff.fetch import _previous_release

    tags = {"2.11.9": "a" * 40, "2.11.10": "b" * 40, "2.11.11": "c" * 40}
    assert _previous_release(tags, "2.11.11") == ("2.11.10", "b" * 40)


def test_a_release_candidate_is_not_the_previous_release() -> None:
    """Diffing from an rc would blame the fix for the rc's own changes."""
    from vexpath_core.patchdiff.fetch import _previous_release

    tags = {"3.0.0": "a" * 40, "3.1.0rc1": "b" * 40, "3.1.0": "c" * 40}
    assert _previous_release(tags, "3.1.0") == ("3.0.0", "a" * 40)


def test_the_last_affected_version_narrows_the_span() -> None:
    """The advisory knows which releases were vulnerable; use the newest.

    Without it the span is "the tag that happens to sort next", which over a
    project that ships often is the same thing, and over one that does not is
    needlessly wide.
    """
    from vexpath_core.patchdiff.fetch import _previous_release

    tags = {"1.0": "a" * 40, "2.0": "b" * 40, "3.0": "c" * 40, "4.0": "d" * 40}
    assert _previous_release(tags, "4.0", affected_versions=["1.0", "2.0"]) == ("2.0", "b" * 40)


def test_the_spellings_projects_actually_use_are_tried() -> None:
    from vexpath_core.patchdiff.fetch import _match_tag

    for spelling in ("2.11.3", "v2.11.3", "release-2.11.3", "rel-2.11.3"):
        assert _match_tag({spelling: SHA}, "2.11.3") == (spelling, SHA)
    assert _match_tag({"2.11.4": SHA}, "2.11.3") is None


def _release_source(
    files: tuple[object, ...], *, tags: dict[str, str] | None = None
) -> RecordedCommitSource:
    """A source whose diff is keyed on the fixed release's commit."""
    return RecordedCommitSource(
        diffs={
            "c" * 40: CommitDiff(
                commit="c" * 40,
                repository="https://github.com/psf/requests",
                files=files,  # type: ignore[arg-type]
            )
        },
        tags=tags if tags is not None else {"2.31.0": "b" * 40, "2.32.0": "c" * 40},
    )


def test_an_advisory_with_only_a_fixed_version_is_now_extracted() -> None:
    """The 2,441 advisories this was built for.

    No fix commit anywhere in the record, only "fixed in 2.32.0". Before the
    resolver these stayed pending for ever: the queue re-served them, each
    run reported "needs a reference resolved", and seven passes of two
    hundred extracted nothing at all.
    """
    advisory = _advisory(references=(), repo_url="https://github.com/psf/requests")
    source = _release_source(
        ((_file_diff("requests/sessions.py", [6, 7], []), POST_SOURCE, PRE_SOURCE),)
    )

    result = extract_for_advisory(advisory, source)

    assert result.status is SymbolsStatus.EXTRACTED
    assert "requests.sessions.Session.send" in {symbol.symbol for symbol in result.symbols}


def test_symbols_from_a_release_say_they_came_from_a_release() -> None:
    """Not fix_commit. The distinction is the honesty of the whole corpus.

    A symbol found by diffing a release is a function that *changed in that
    release*, which is weaker evidence than one the fix itself touched, and
    the confidence and the source both have to say so or a reader cannot
    tell the two apart.
    """
    advisory = _advisory(references=(), repo_url="https://github.com/psf/requests")
    source = _release_source(
        ((_file_diff("requests/sessions.py", [6, 7], []), POST_SOURCE, PRE_SOURCE),)
    )

    result = extract_for_advisory(advisory, source)

    assert {symbol.source for symbol in result.symbols} == {SymbolSource.TAG_DIFF}
    assert result.best_confidence is Confidence.LOW
    assert "release" in result.detail


def test_a_release_with_no_matching_tag_stays_pending() -> None:
    advisory = _advisory(references=(), repo_url="https://github.com/psf/requests")
    source = _release_source((), tags={"1.0.0": "a" * 40})

    result = extract_for_advisory(advisory, source)

    assert result.status is SymbolsStatus.PENDING
    assert "No release tag matching 2.32.0" in result.detail


def test_a_release_touching_too_much_is_refused_rather_than_truncated() -> None:
    """Taking the first forty files of a big release would read as evidence.

    A release contains everything changed since the last one. Recording its
    symbols means claiming the fix touched all of them, and a corpus where a
    popular package has hundreds of vulnerable symbols makes every project
    that imports it look reachable -- which is indistinguishable from having
    no reachability analysis.
    """
    from vexpath_core.patchdiff.fetch import MAX_FILES_PER_TAG_DIFF

    advisory = _advisory(references=(), repo_url="https://github.com/psf/requests")
    many = tuple(
        (_file_diff(f"requests/module{index}.py", [6, 7], []), POST_SOURCE, PRE_SOURCE)
        for index in range(MAX_FILES_PER_TAG_DIFF + 1)
    )
    source = _release_source(many)

    result = extract_for_advisory(advisory, source)

    assert result.status is SymbolsStatus.NONE
    assert "above the" in result.detail
    assert not result.symbols


def test_a_release_naming_too_many_functions_is_refused() -> None:
    """Measured, not guessed: the file cap let 248 symbols through.

    Across this corpus a fix commit names 4 symbols at the median and 22 at
    the ninetieth percentile. A release diff named 25 at the median and 104
    at the ninetieth, and one release touching only thirty files named 248
    functions for a single advisory. A list that long is an inventory of the
    package, not evidence about a fix, and it would make every project
    importing that package look reachable -- a confident wrong answer where
    "nobody could look" was the truth.
    """
    from vexpath_core.patchdiff.fetch import MAX_SYMBOLS_PER_TAG_DIFF

    advisory = _advisory(references=(), repo_url="https://github.com/psf/requests")
    # Few files, many functions in each: the shape the file cap misses.
    crowded = "\n".join(f"def handler{index}():\n    return {index}" for index in range(60))
    files = tuple(
        (_file_diff(f"requests/part{index}.py", list(range(1, 121)), []), crowded, None)
        for index in range(3)
    )
    source = _release_source(files)

    result = extract_for_advisory(advisory, source)

    assert result.status is SymbolsStatus.NONE
    assert f"above the {MAX_SYMBOLS_PER_TAG_DIFF}" in result.detail
    assert not result.symbols


# --- A module is only the symbol when module-level *code* changed ---------


def _module_symbols(source: str, lines: list[int]) -> list[str]:
    import ast

    from vexpath_core.patchdiff.extract import _symbols_at

    return [symbol for symbol, _, _ in _symbols_at(ast.parse(source), "pkg.mod", lines)]


MODULE_SOURCE = '''"""A module docstring."""
import os

PATTERN = r"[a-z]+"

CONFIGURED = bool(os.environ.get("X"))

def handler(value):
    return PATTERN + value
'''


def test_a_changed_import_does_not_make_the_module_vulnerable() -> None:
    """Otherwise a fix that adds an import condemns every importer.

    A module symbol is treated as confirmed reachability -- importing the
    module does run module-level code -- so anything recorded as a module
    symbol tells every project that imports the package that its vulnerable
    code can run. An import statement runs on import and cannot carry a
    vulnerability; it binds a name. Fixes add imports constantly.
    """
    assert _module_symbols(MODULE_SOURCE, [2]) == []


def test_a_changed_docstring_does_not_make_the_module_vulnerable() -> None:
    """The indefensible case, and it was real.

    A reflowed docstring marked the module as the vulnerable symbol, which
    marked every importer of the package as confirmed reachable, on the
    evidence of a string literal.
    """
    assert _module_symbols(MODULE_SOURCE, [1]) == []


def test_a_changed_module_constant_is_still_evidence() -> None:
    """Not every module-level line is inert, and this is the reason.

    A changed regular expression is a plausible fix for a denial of service,
    so an assignment stays evidence even though it only binds a value.
    Dropping constants along with imports would have thrown that away.
    """
    assert _module_symbols(MODULE_SOURCE, [4]) == ["pkg.mod"]


def test_module_level_code_is_still_evidence() -> None:
    assert _module_symbols(MODULE_SOURCE, [6]) == ["pkg.mod"]


def test_an_import_changed_beside_real_code_keeps_the_module() -> None:
    """The exclusion is per line, not per commit.

    A fix that adds an import *and* changes a constant is still a fix to the
    constant.
    """
    assert _module_symbols(MODULE_SOURCE, [2, 4]) == ["pkg.mod"]


def test_a_changed_function_is_attributed_to_the_function() -> None:
    assert _module_symbols(MODULE_SOURCE, [9]) == ["pkg.mod.handler"]


# --- Resolving a merge request --------------------------------------------
#
# 1,343 PyPI advisories point at a pull request and nothing else. No forge
# API is involved: the hosts advertise refs/pull/N/head over plain git, so
# this needs no token and has no hourly limit.


def _pull_source(files: tuple[object, ...]) -> RecordedCommitSource:
    return RecordedCommitSource(
        diffs={
            "c" * 40: CommitDiff(
                commit="c" * 40,
                repository="https://github.com/psf/requests",
                files=files,  # type: ignore[arg-type]
            )
        },
        pull_requests={7: ("b" * 40, "c" * 40)},
    )


def test_a_pull_request_is_resolved_and_extracted() -> None:
    advisory = _advisory(
        references=(Reference(type="FIX", url="https://github.com/psf/requests/pull/7"),)
    )
    source = _pull_source(
        ((_file_diff("requests/sessions.py", [6, 7], []), POST_SOURCE, PRE_SOURCE),)
    )

    result = extract_for_advisory(advisory, source)

    assert result.status is SymbolsStatus.EXTRACTED
    assert "requests.sessions.Session.send" in {symbol.symbol for symbol in result.symbols}


def test_a_resolved_pull_request_is_a_range_not_a_single_commit() -> None:
    """Both ends, so the diff is the branch rather than its last commit.

    A pull request is bracketed by two commits. Recording only the head and
    diffing it against its own parent would read just the final commit of the
    branch, which is what the ``/head`` fallback has to settle for -- but when
    the pair is known, the whole range is read.
    """
    advisory = _advisory(
        references=(Reference(type="FIX", url="https://github.com/psf/requests/pull/7"),)
    )
    source = _pull_source(
        ((_file_diff("requests/sessions.py", [6, 7], []), POST_SOURCE, PRE_SOURCE),)
    )

    result = extract_for_advisory(advisory, source)

    assert result.reference is not None
    assert result.reference.spans_commits
    assert result.reference.base == "b" * 40
    assert result.reference.commit == "c" * 40


def test_the_pull_ref_prefix_follows_the_forge() -> None:
    """GitLab calls the same thing a merge request and files it elsewhere."""
    from vexpath_core.patchdiff.fetch import _pull_ref_prefix

    assert _pull_ref_prefix("https://github.com/psf/requests") == "refs/pull"
    assert _pull_ref_prefix("https://codeberg.org/a/b") == "refs/pull"
    assert _pull_ref_prefix("https://gitlab.com/a/b") == "refs/merge-requests"


def test_a_pull_request_is_not_labelled_or_capped_like_a_release() -> None:
    """A pull request is the fix. A release merely contains it.

    Both span two commits, and for a while that was the only distinction the
    code made -- so a resolved merge request would have had its symbols
    recorded as ``tag_diff`` and refused above twenty-five of them, the limit
    that exists because a release diff is an inventory of everything shipped.
    A branch that fixes one bug across thirty functions is still a fix.
    """
    from vexpath_core.patchdiff.fetch import MAX_SYMBOLS_PER_TAG_DIFF

    advisory = _advisory(
        references=(Reference(type="FIX", url="https://github.com/psf/requests/pull/7"),)
    )
    crowded = "\n".join(f"def handler{index}():\n    return {index}" for index in range(60))
    files = tuple(
        (_file_diff(f"requests/part{index}.py", list(range(1, 121)), []), crowded, None)
        for index in range(2)
    )

    result = extract_for_advisory(advisory, _pull_source(files))

    assert result.status is SymbolsStatus.EXTRACTED
    assert len(result.symbols) > MAX_SYMBOLS_PER_TAG_DIFF
    assert {symbol.source for symbol in result.symbols} == {SymbolSource.FIX_COMMIT}
    assert "merge request's range" in result.detail


def test_a_release_is_still_labelled_and_capped() -> None:
    """The other half of the same distinction, so neither drifts."""
    advisory = _advisory(references=(), repo_url="https://github.com/psf/requests")
    source = _release_source(
        ((_file_diff("requests/sessions.py", [6, 7], []), POST_SOURCE, PRE_SOURCE),)
    )

    result = extract_for_advisory(advisory, source)

    assert {symbol.source for symbol in result.symbols} == {SymbolSource.TAG_DIFF}
    assert "release" in result.detail
