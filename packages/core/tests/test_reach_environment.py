"""Dependency graphs, the cache, and reachability inside a whole scan.

These cover the stages between "the engine works" and "the command works":
finding a project's installed dependencies, reusing their graphs, and running
the whole pipeline so a finding is actually cleared or confirmed.

A synthetic environment is built in a temporary directory rather than relying
on whatever happens to be installed, so the tests describe one fixed situation
and keep describing it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from vexpath_core.advisory import SnapshotSource
from vexpath_core.enums import EdgeKind, SymbolKind, Verdict
from vexpath_core.protocols import FixedClock
from vexpath_core.reach.cache import (
    FORMAT_VERSION,
    CacheError,
    GraphCache,
    default_cache_directory,
    from_bytes,
    to_bytes,
)
from vexpath_core.reach.dependencies import (
    discover_installed,
    graphs_for,
    site_packages_directories,
)
from vexpath_core.reach.graph import BUILDER_VERSION, CallGraph, Edge, GraphQuality, Node
from vexpath_core.scan import ScanOptions, scan

CLOCK = FixedClock(datetime(2026, 11, 9, 12, 0, tzinfo=UTC))


def _install(
    site_packages: Path, distribution: str, version: str, import_name: str, source_root: Path
) -> None:
    """Lay out a distribution the way an installer would."""
    import shutil

    shutil.copytree(source_root / import_name, site_packages / import_name)
    info = site_packages / f"{distribution}-{version}.dist-info"
    info.mkdir(parents=True, exist_ok=True)
    (info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {distribution}\nVersion: {version}\n\nDescription.\n",
        encoding="utf-8",
    )
    (info / "top_level.txt").write_text(f"{import_name}\n", encoding="utf-8")


@pytest.fixture
def environment(tmp_path: Path, fixture_repos_dir: Path) -> Path:
    """A synthetic environment holding the direct-call fixture's dependencies."""
    site_packages = tmp_path / "env" / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    vendor = fixture_repos_dir / "direct-call" / "vendor"
    _install(site_packages, "requests", "2.31.0", "requests", vendor)
    _install(site_packages, "urllib3", "1.26.17", "urllib3", vendor)
    return tmp_path / "env"


# --- Serialisation and caching --------------------------------------------


def _graph() -> CallGraph:
    return CallGraph(
        package="lib",
        version="1.2.3",
        nodes={
            "lib": Node("lib", SymbolKind.MODULE, file="lib/__init__.py", line=1, package="lib"),
            "lib.run": Node(
                "lib.run",
                SymbolKind.FUNCTION,
                file="lib/__init__.py",
                line=4,
                end_line=6,
                opaque=True,
                package="lib",
            ),
        },
        edges={"lib": (Edge("lib", "lib.run", EdgeKind.IMPORT, 4),)},
        entry_points=("lib",),
        quality=GraphQuality(call_sites=7, unresolved_call_sites=2, files_parsed=1),
    )


def test_a_graph_survives_a_round_trip() -> None:
    restored = from_bytes(to_bytes(_graph()))
    original = _graph()
    assert restored.package == original.package
    assert restored.version == original.version
    assert restored.nodes.keys() == original.nodes.keys()
    assert restored.nodes["lib.run"].opaque
    assert restored.nodes["lib.run"].end_line == 6
    assert restored.successors("lib")[0].kind is EdgeKind.IMPORT
    assert restored.entry_points == ("lib",)
    assert restored.quality.unresolved_call_sites == 2


def test_a_corrupt_payload_is_refused_rather_than_trusted() -> None:
    """A wrong graph produces a wrong verdict, so a damaged one is discarded."""
    with pytest.raises(CacheError, match="not readable msgpack"):
        from_bytes(b"this is not msgpack at all")


def test_a_payload_from_another_format_is_refused() -> None:
    import msgpack

    payload = msgpack.packb({"format": FORMAT_VERSION + 1, "nodes": [], "edges": []})
    with pytest.raises(CacheError, match="expected"):
        from_bytes(payload)


def test_a_structurally_invalid_payload_is_refused() -> None:
    import msgpack

    payload = msgpack.packb({"format": FORMAT_VERSION, "nodes": [["x"]], "edges": []})
    with pytest.raises(CacheError, match="structurally invalid"):
        from_bytes(payload)


def test_the_cache_stores_and_returns_a_graph(tmp_path: Path) -> None:
    cache = GraphCache(tmp_path / "cache")
    assert cache.get("lib", "1.2.3") is None
    cache.put(_graph())
    restored = cache.get("lib", "1.2.3")
    assert restored is not None
    assert restored.nodes.keys() == _graph().nodes.keys()
    assert cache.hits == 1
    assert cache.misses == 1
    assert cache.hit_ratio == pytest.approx(0.5)


def test_the_cache_key_includes_the_builder_version(tmp_path: Path) -> None:
    """Improving the builder must invalidate graphs without deleting them."""
    cache = GraphCache(tmp_path / "cache")
    cache.put(_graph())
    old = cache.path_for("lib", "1.2.3", "an-older-builder")
    current = cache.path_for("lib", "1.2.3", BUILDER_VERSION)
    assert old != current
    assert current.is_file()
    assert not old.is_file()


def test_a_damaged_cache_entry_is_removed_and_treated_as_a_miss(tmp_path: Path) -> None:
    cache = GraphCache(tmp_path / "cache")
    cache.put(_graph())
    path = cache.path_for("lib", "1.2.3")
    path.write_bytes(b"corrupted")

    assert cache.get("lib", "1.2.3") is None
    # Removed, so the next run does not pay to rediscover the same thing.
    assert not path.is_file()


def test_a_graph_with_no_key_is_not_cached(tmp_path: Path) -> None:
    """A first-party graph has no package version, so it has nothing to key on."""
    root = tmp_path / "cache"
    cache = GraphCache(root)
    cache.put(CallGraph())
    assert list(root.rglob("*.msgpack")) == []


def test_the_cache_directory_respects_an_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VEXPATH_CACHE_DIR", str(Path("/tmp/somewhere")))
    assert default_cache_directory() == Path("/tmp/somewhere") / "callgraphs"


# --- Discovering installed dependencies -----------------------------------


def test_installed_distributions_are_read_from_their_metadata(environment: Path) -> None:
    locations = site_packages_directories(environment)
    assert locations, "site-packages should be found under the environment root"

    installed = discover_installed(locations)
    assert installed["requests"].version == "2.31.0"
    assert installed["requests"].top_level == ("requests",)
    assert installed["urllib3"].version == "1.26.17"


def test_an_environment_root_is_resolved_to_its_site_packages(environment: Path) -> None:
    # The root is not itself a package directory, and confusing the two means
    # finding nothing installed.
    assert site_packages_directories(environment) == [environment / "Lib" / "site-packages"]


def test_distribution_names_are_normalised(tmp_path: Path) -> None:
    site_packages = tmp_path / "Lib" / "site-packages"
    info = site_packages / "Flask_SQLAlchemy-3.1.1.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text("Name: Flask-SQLAlchemy\nVersion: 3.1.1\n", encoding="utf-8")
    (info / "top_level.txt").write_text("flask_sqlalchemy\n", encoding="utf-8")
    (site_packages / "flask_sqlalchemy").mkdir()

    installed = discover_installed([site_packages])
    # Keyed the way an SBOM component is, so the two join directly.
    assert "flask-sqlalchemy" in installed


def test_top_level_names_are_derived_when_not_declared(tmp_path: Path) -> None:
    # Modern build backends often omit top_level.txt.
    site_packages = tmp_path / "Lib" / "site-packages"
    info = site_packages / "thing-1.0.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text("Name: thing\nVersion: 1.0\n", encoding="utf-8")
    (info / "RECORD").write_text(
        "thing/__init__.py,sha256=x,10\nthing/core.py,sha256=y,20\n"
        "thing-1.0.dist-info/METADATA,sha256=z,30\n",
        encoding="utf-8",
    )
    (site_packages / "thing").mkdir()
    (site_packages / "thing" / "__init__.py").write_text("", encoding="utf-8")

    installed = discover_installed([site_packages])
    assert installed["thing"].top_level == ("thing",)


def test_graphs_are_built_for_matching_versions(environment: Path, fixture_repos_dir: Path) -> None:
    from vexpath_core.sbom import generate_sbom

    sbom = generate_sbom(fixture_repos_dir / "unused-transitive", clock=CLOCK)
    result = graphs_for(
        sbom.components, locations=site_packages_directories(environment), cache=None
    )
    assert {"requests", "urllib3"} <= result.analysed
    assert len(result.graphs) >= 2
    assert any("requests.sessions.Session.send" in graph.nodes for graph in result.graphs)


def test_a_version_mismatch_is_refused_rather_than_graphed(
    environment: Path, fixture_repos_dir: Path
) -> None:
    """Graphing the wrong version describes code the project does not ship."""
    from vexpath_core.sbom import generate_sbom

    project = fixture_repos_dir / "direct-call"
    sbom = generate_sbom(project, clock=CLOCK)
    bumped = sbom.model_copy(
        update={
            "components": tuple(
                component.model_copy(update={"version": "2.99.0"})
                if component.name == "requests"
                else component
                for component in sbom.components
            )
        }
    )
    result = graphs_for(
        bumped.components, locations=site_packages_directories(environment), cache=None
    )
    assert "requests" not in result.analysed
    assert "does not ship" in result.unavailable["requests"]


def test_a_missing_dependency_is_reported_with_a_reason(
    tmp_path: Path, fixture_repos_dir: Path
) -> None:
    from vexpath_core.sbom import generate_sbom

    empty = tmp_path / "empty"
    empty.mkdir()
    sbom = generate_sbom(fixture_repos_dir / "direct-call", clock=CLOCK)
    result = graphs_for(sbom.components, locations=[empty], cache=None)
    assert result.analysed == set()
    assert "not installed" in result.unavailable["requests"]


def test_the_cache_is_used_on_a_second_run(
    environment: Path, fixture_repos_dir: Path, tmp_path: Path
) -> None:
    from vexpath_core.sbom import generate_sbom

    sbom = generate_sbom(fixture_repos_dir / "direct-call", clock=CLOCK)
    cache = GraphCache(tmp_path / "cache")
    locations = site_packages_directories(environment)

    first = graphs_for(sbom.components, locations=locations, cache=cache)
    assert first.cache_misses >= 1
    assert first.cache_hits == 0

    second = graphs_for(sbom.components, locations=locations, cache=cache)
    assert second.cache_hits >= 1
    assert second.cache_misses == 0
    assert second.analysed == first.analysed


# --- Reachability inside a whole scan -------------------------------------


@pytest.fixture
def source(snapshot_dir: Path) -> SnapshotSource:
    return SnapshotSource(snapshot_dir)


def _scan(project: Path, environment: Path, source: SnapshotSource, **extra: object):
    options = ScanOptions(environment=environment, use_cache=False, **extra)  # type: ignore[arg-type]
    return scan(project, source, options=options, clock=CLOCK)


def test_a_scan_confirms_a_reachable_finding(
    environment: Path, fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    results = _scan(fixture_repos_dir / "direct-call", environment, source)
    finding = results.findings[0]

    assert finding.verdict is Verdict.AFFECTED
    assert finding.reach is not None
    assert finding.reach.status.is_reachable
    # The path runs through the dependency's internals, not just its surface.
    symbols = [step.symbol for step in finding.reach.shortest_path]
    assert symbols[0].startswith("app.")
    assert symbols[-1] == "requests.sessions.Session.send"
    assert len(symbols) >= 4


def test_a_scan_clears_an_unused_dependency(
    environment: Path, fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    """The finding this product exists to remove from the list."""
    results = _scan(fixture_repos_dir / "unused-transitive", environment, source)

    assert results.findings
    assert all(finding.verdict is Verdict.NOT_AFFECTED for finding in results.findings)
    for finding in results.findings:
        assert finding.reach is not None
        assert finding.reach.status.may_suppress
        assert finding.justification is not None


def test_a_scan_without_the_dependency_installed_clears_nothing(
    tmp_path: Path, fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    empty = tmp_path / "empty-env"
    (empty / "Lib" / "site-packages").mkdir(parents=True)
    results = _scan(fixture_repos_dir / "unused-transitive", empty, source)

    assert results.findings
    assert all(finding.verdict is Verdict.UNDER_INVESTIGATION for finding in results.findings)
    assert results.analysis_notes
    # The note says why, not merely that: "not installed" and "installed
    # at a different version" call for opposite responses.
    assert "could not be analysed" in results.analysis_notes[0]
    assert "not installed" in results.analysis_notes[0]


def test_a_scan_reports_the_graph_it_used(
    environment: Path, fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    results = _scan(fixture_repos_dir / "direct-call", environment, source)
    assert results.graph is not None
    assert results.graph.first_party_nodes > 0
    assert results.graph.linked_packages >= 1
    assert results.entry_points is not None
    assert results.entry_points.count > 0


def test_configured_entry_points_are_used_and_reported(
    environment: Path, fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    from vexpath_core.enums import EntryPointSource

    results = _scan(
        fixture_repos_dir / "direct-call",
        environment,
        source,
        entry_points=("app.main:main",),
    )
    assert results.entry_points is not None
    assert results.entry_points.source is EntryPointSource.CONFIG


def test_turning_reachability_off_clears_nothing(
    environment: Path, fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    results = _scan(
        fixture_repos_dir / "unused-transitive", environment, source, reachability=False
    )
    assert all(finding.reach is None for finding in results.findings)
    assert all(finding.verdict is not Verdict.NOT_AFFECTED for finding in results.findings)
    assert results.graph is None
    assert any("not run" in note for note in results.analysis_notes)


def test_a_module_level_symbol_is_reached_by_the_import_alone(
    tmp_path: Path, fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    site_packages = tmp_path / "env" / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    _install(
        site_packages,
        "pyyaml",
        "5.3.1",
        "yaml",
        fixture_repos_dir / "module-level" / "vendor",
    )
    results = _scan(fixture_repos_dir / "module-level", tmp_path / "env", source)

    finding = results.findings[0]
    assert finding.verdict is Verdict.AFFECTED
    assert finding.reach is not None
    assert "yaml.constructor" in finding.reach.matched_symbols
    assert all(step.edge_kind is EdgeKind.IMPORT for step in finding.reach.shortest_path[1:])
