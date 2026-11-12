"""The ``vexpath scan`` command: the default way the tool is used."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from vexpath import credentials
from vexpath.commands import auth
from vexpath.exit_codes import ExitCode
from vexpath.output import OutputFormat, emit, emit_json, fail, fail_config, note
from vexpath.sources import SNAPSHOT_ENV, advisory_source, close_source
from vexpath_core import report
from vexpath_core.advisory.source import AdvisorySourceError
from vexpath_core.enums import ComponentScope
from vexpath_core.policy import PRESETS, PolicyError
from vexpath_core.sbom import LockfileError, UnknownSbomFormatError
from vexpath_core.sbom.cyclonedx import CycloneDxError
from vexpath_core.sbom.spdx import SpdxError
from vexpath_core.scan import ScanOptions, scanned_lockfile
from vexpath_core.scan import scan as run_scan


def command(
    path: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False, help="Project directory to scan."),
    ] = Path(),
    sbom: Annotated[
        Path | None,
        typer.Option(
            "--sbom",
            exists=True,
            dir_okay=False,
            help="Analyse this SBOM instead of generating one from a lockfile.",
        ),
    ] = None,
    lockfile: Annotated[
        Path | None,
        typer.Option(
            "--lockfile",
            exists=True,
            dir_okay=False,
            help="Use this lockfile instead of searching the directory.",
        ),
    ] = None,
    snapshot: Annotated[
        Path | None,
        typer.Option(
            "--snapshot",
            exists=True,
            file_okay=False,
            help=(
                "Read advisories from this local snapshot, making the scan "
                f"reproducible and offline. Defaults to ${SNAPSHOT_ENV}."
            ),
        ),
    ] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.TABLE,
    no_reach: Annotated[
        bool,
        typer.Option(
            "--no-reach",
            help="Skip reachability analysis and report matching only.",
        ),
    ] = False,
    ignore_dev: Annotated[
        bool,
        typer.Option(
            "--ignore-dev",
            help="Exclude development dependencies from analysis.",
        ),
    ] = False,
    show_cleared: Annotated[
        bool,
        typer.Option("--show-cleared", help="List findings that were cleared, too."),
    ] = False,
    entry_point: Annotated[
        str | None,
        typer.Option(
            "--entry-point",
            "-e",
            help=(
                "Comma-separated entry points to start the reachability search "
                "from, as module.path:function. Nothing beats being told how the "
                "application starts."
            ),
        ),
    ] = None,
    environment: Annotated[
        Path | None,
        typer.Option(
            "--environment",
            exists=True,
            file_okay=False,
            help=(
                "Virtual environment holding the installed dependencies. "
                "Defaults to the one this command is running in."
            ),
        ),
    ] = None,
    download_missing: Annotated[
        bool,
        typer.Option(
            "--download-missing",
            help=(
                "Fetch a dependency's source from the package index when it is "
                "not installed. Reaches the network. Without it, a scan of a "
                "lockfile alone can confirm findings but never clear them."
            ),
        ),
    ] = False,
    no_cache: Annotated[
        bool,
        typer.Option(
            "--no-cache", help="Rebuild dependency graphs instead of reusing cached ones."
        ),
    ] = False,
    policy: Annotated[
        str | None,
        typer.Option(
            "--policy",
            help=(
                "The gate: 'project' to use the policy set in the dashboard for "
                "--project, or a preset name, a CEL expression, or a path to a "
                "file holding one. Exits 1 when it fails. Run 'vexpath policy "
                "list' to see the presets. Without this, nothing is gated and "
                "the scan only reports."
            ),
        ),
    ] = None,
    upload: Annotated[
        bool,
        typer.Option(
            "--upload",
            help=(
                "Send the result to the platform after the scan. Needs a "
                "credential from 'vexpath login' or "
                f"${credentials.KEY_ENVIRONMENT_VARIABLE}, and --project."
            ),
        ),
    ] = False,
    project: Annotated[
        str | None,
        typer.Option(
            "--project",
            help="Slug of the project to upload to. Required with --upload.",
        ),
    ] = None,
    fail_on_findings: Annotated[
        bool,
        typer.Option(
            "--fail-on-findings/--no-fail-on-findings",
            help=(
                "Exit with code 1 when anything needs attention at all. A blunt "
                "alternative to --policy, kept because it needs no expression "
                "written and sometimes that is the right trade."
            ),
        ),
    ] = False,
) -> None:
    """Scan a project for vulnerable dependencies.

    Reachability analysis runs by default and is what makes the report short:
    a finding is cleared only when the vulnerable code provably cannot run.
    Pass ``--no-reach`` to report matching alone, in which case nothing is
    cleared and the output says so.
    """
    if no_reach:
        note(
            "Reachability analysis is off, so this reports matching only. No "
            "finding will be cleared."
        )

    # Resolved before any analysis runs. A missing credential or a forgotten
    # --project discovered after a four-minute scan has thrown the scan away,
    # and the person who sees that message is already in a hurry.
    credential = _upload_credential(upload=upload, project=project, policy=policy)
    # Before any analysis too, and for the same reason: a policy that cannot
    # be fetched should not be discovered after a four-minute scan. This may
    # resolve a credential even without --upload, because reading the
    # project's policy is itself an authenticated call.
    resolved_policy = _resolve_policy(policy, project=project, credential=credential)

    source = advisory_source(snapshot, result_noun="scan")
    scopes = (
        frozenset({ComponentScope.RUNTIME, ComponentScope.OPTIONAL})
        if ignore_dev
        else frozenset(ComponentScope)
    )
    options = ScanOptions(
        sbom_path=sbom,
        lockfile=lockfile,
        include_scopes=scopes,
        policy=resolved_policy,
        reachability=not no_reach,
        entry_points=tuple(
            entry.strip() for entry in (entry_point or "").split(",") if entry.strip()
        ),
        environment=environment,
        use_cache=not no_cache,
        download_missing=download_missing,
    )

    try:
        results = run_scan(path, source, options=options)
    except PolicyError as exc:
        # A gate that cannot be evaluated is a configuration problem, and must
        # never be reported as a gate that passed.
        fail_config(str(exc))
    except (LockfileError, UnknownSbomFormatError, CycloneDxError, SpdxError) as exc:
        fail(str(exc))
    except AdvisorySourceError as exc:
        fail(
            f"{exc}. To scan without network access, download a snapshot with "
            f"'vexpath advisory sync' and pass --snapshot."
        )
    finally:
        close_source(source)

    _render(results, output_format, path, options, show_cleared=show_cleared)

    if credential is not None:
        # Uploaded before the policy decides the exit code, deliberately: the
        # scan the platform most needs is the one that just failed a gate, and
        # exiting first would mean the record of the failure never arrives.
        assert project is not None  # guaranteed by _upload_credential
        _upload(credential, project, results)

    if results.policy is not None and not results.policy.passed:
        raise typer.Exit(code=int(ExitCode.POLICY_FAILED))

    needs_attention = len(results.findings_needing_attention())
    if fail_on_findings and needs_attention:
        raise typer.Exit(code=int(ExitCode.POLICY_FAILED))


def _upload_credential(
    *, upload: bool, project: str | None, policy: str | None = None
) -> credentials.Credential | None:
    """The credential to upload with, or None when no upload was asked for.

    Resolved up front so the two mistakes that waste a whole scan -- no
    credential, and --upload without --project -- are reported before the
    analysis starts rather than after it.

    ``--project`` also means something without ``--upload``: ``--policy
    project`` names the project whose policy to fetch. Refusing that
    combination made it impossible to check a build against the
    organisation's gate without also publishing the results, which are two
    unrelated decisions.
    """
    wants_project_policy = (policy or "").strip() == PROJECT_POLICY

    if not upload:
        if project is not None and not wants_project_policy:
            # Saying nothing would silently discard the flag, and the person
            # would wait for a result that never appears on the platform.
            fail_config("--project only means something with --upload or --policy project.")
        if wants_project_policy:
            # Reading the policy is itself authenticated, so the credential
            # is resolved here for the same reason: before the analysis.
            return auth.credential_or_exit()
        return None
    if not project:
        fail_config("--upload needs --project to say where the result goes.")
    return auth.credential_or_exit()


def _upload(credential: credentials.Credential, project: str, results: object) -> None:
    from vexpath_core.models.results import ScanResults

    assert isinstance(results, ScanResults)
    stored = auth.upload_results(
        credential, project, results.model_dump(mode="json", by_alias=True)
    )
    scan_id = stored.get("id", "unknown")
    note(f"uploaded to {credential.api_url} as scan {scan_id}")


#: What ``--policy`` means when it means "ask the platform".
PROJECT_POLICY = "project"


def _resolve_policy(
    source: str | None,
    *,
    project: str | None = None,
    credential: object | None = None,
) -> str | None:
    """Turn the flag into something the core can compile.

    A preset name wins over a file of the same name: the presets are a closed
    vocabulary, and a file called ``balanced`` in a working directory must not
    silently change what the default means.

    ``--policy project`` fetches the expression the dashboard holds for
    ``--project``, so a rule written once governs every build instead of
    every build repeating it. Nothing local can shadow that word: it is
    checked before the preset table and before the filesystem, because a file
    called ``project`` quietly replacing the organisation's gate is exactly
    the substitution this flag must not allow.
    """
    if source is None:
        return None

    if source.strip() == PROJECT_POLICY:
        if not project:
            fail_config("--policy project needs --project to say which project's policy to use")
        resolved = credential or auth.credential_or_exit()
        assert isinstance(resolved, credentials.Credential)  # narrowed for the type checker
        return auth.fetch_policy(resolved, project)

    if source in PRESETS:
        return source
    candidate = Path(source)
    if candidate.is_file():
        try:
            return candidate.read_text(encoding="utf-8").strip()
        except OSError as exc:
            fail_config(f"{candidate} could not be read: {exc}")
    return source


def _render(
    results: object,
    output_format: OutputFormat,
    path: Path,
    options: ScanOptions,
    *,
    show_cleared: bool,
) -> None:
    from vexpath_core.models.results import ScanResults

    assert isinstance(results, ScanResults)  # narrowed for the type checker

    if output_format is OutputFormat.JSON:
        emit_json(results.model_dump(mode="json", by_alias=True))
        return
    if output_format is OutputFormat.SARIF:
        emit(report.render_sarif_json(results, lockfile_path=scanned_lockfile(path, options)))
        return
    if output_format is OutputFormat.MARKDOWN:
        emit(report.render_markdown(results, show_cleared=show_cleared))
        return
    emit(report.render_text(results, show_cleared=show_cleared))


__all__ = ["SNAPSHOT_ENV", "command"]
