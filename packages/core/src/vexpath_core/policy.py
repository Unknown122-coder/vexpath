"""Decide whether a scan should fail the build.

A scanner that reports is useful; a scanner that gates is what actually keeps a
vulnerable dependency out of production. The gate has to be something a team
can write down, argue about, review in a pull request and apply identically in
CI and on a laptop, which is why it is an expression language rather than a
pile of flags.

CEL, not a bespoke matcher. A policy is a thing people write, share and copy
between projects, and a syntax invented for one tool is a syntax that has to be
learned for one tool.

**An expression evaluates to true when the build must fail.** Stated that way
round deliberately: a policy describes what is unacceptable, so an empty or
missing policy fails nothing, and a typo that evaluates to a non-boolean is an
error rather than a silent pass. The alternative convention, true meaning pass,
turns every mistake into a green build.

**A policy can only read what the scan concluded.** The context is built here,
from the results, and holds no clock, no network and no filesystem. The same
results and the same policy give the same answer anywhere, which is what makes
a local run worth trusting before pushing.

**A policy that cannot be evaluated fails loudly.** A malformed expression
exits with a configuration error naming the problem, never with a pass. The one
thing worse than a gate nobody can read is a gate that silently stopped
working.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import celpy
from celpy import celtypes
from celpy.adapter import json_to_cel
from celpy.celparser import CELParseError
from celpy.evaluation import CELEvalError

from vexpath_core.enums import Severity, Verdict
from vexpath_core.models.finding import Finding
from vexpath_core.models.results import PolicyResult, PolicyViolation, ScanResults

#: Named policies, so the common intentions do not have to be written out.
#: Each is the expression a team would write, kept short enough to read.
PRESETS: dict[str, str] = {
    # Anything reported and serious fails. For a team that has not yet
    # decided how much it trusts reachability, or does not want to.
    "strict": ('findings.exists(f, f.verdict == "affected" && f.severity in ["CRITICAL", "HIGH"])'),
    # The default, and the one the product exists to make possible: fail on
    # serious findings whose vulnerable code was *proven* reachable, plus
    # anything known to be exploited in the wild whatever the analysis said.
    "balanced": (
        "findings.exists(f, "
        'f.verdict == "affected" && f.reach.status == "reachable_confirmed" '
        '&& f.severity in ["CRITICAL", "HIGH"]'
        ") || "
        'findings.exists(f, f.kev && f.verdict != "not_affected")'
    ),
    # For a team drowning in alerts that wants one signal it cannot ignore.
    "kev-only": 'findings.exists(f, f.kev && f.verdict != "not_affected")',
    # Fails on anything at all that still needs a human. Useful as a tripwire
    # on a release branch.
    "nothing-outstanding": (
        'findings.exists(f, f.verdict == "affected" || f.verdict == "under_investigation")'
    ),
    # Reports only. Named rather than left implicit, so a configuration can
    # say "we have decided not to gate" instead of appearing unfinished.
    "report-only": "false",
}

#: The default when nothing is chosen.
DEFAULT_PRESET = "balanced"


class PolicyError(Exception):
    """Raised when a policy cannot be compiled or evaluated.

    Always fatal to the caller. A policy that does not work must not be
    reported as a policy that passed.
    """


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    """A policy ready to evaluate, with the source it came from."""

    name: str
    expression: str
    _program: Any

    def evaluate(self, results: ScanResults) -> PolicyResult:
        """Run this policy against one scan's results.

        Returns:
            Whether the build passes, and which findings caused it not to. The
            violations are computed separately from the overall answer, because
            an expression can fail a build without naming anything and a
            report that says only "failed" is not actionable.
        """
        return self.evaluate_context(raw_context(results))

    def evaluate_context(self, context: dict[str, Any]) -> PolicyResult:
        """Run this policy against a context of plain Python values.

        The entry point the hosted platform uses. It keeps findings as
        database rows rather than the uploaded document, so it assembles these
        variables from rows; both paths then run the identical expression
        against the identical variable names, which is the only way a policy
        can mean the same thing in CI and on a dashboard.
        """
        outcome = self._run(context)
        if not isinstance(outcome, celtypes.BoolType):
            msg = (
                f"policy {self.name!r} evaluated to {type(outcome).__name__} rather "
                f"than a boolean. An expression says what is unacceptable, so it "
                f"has to answer true or false."
            )
            raise PolicyError(msg)

        failed = bool(outcome)
        return PolicyResult(
            name=self.name,
            passed=not failed,
            violations=self._violations(context) if failed else (),
        )

    def _run(self, context: dict[str, Any]) -> Any:
        """Evaluate against one context, converting it on the way in.

        The conversion happens here rather than in the caller so that a
        context can be sliced -- one finding at a time, to attribute a failure
        -- while still being ordinary Python up to this point.
        """
        try:
            return self._program.evaluate(
                {key: json_to_cel(value) for key, value in context.items()}
            )
        except CELEvalError as exc:
            msg = f"policy {self.name!r} could not be evaluated: {exc}"
            raise PolicyError(msg) from exc

    def _violations(self, context: dict[str, Any]) -> tuple[PolicyViolation, ...]:
        """Which findings individually satisfy this policy.

        Evaluated per finding, which is an approximation: an expression can
        fail a build for a reason no single finding explains, such as a count
        across the whole set. When nothing matches individually, one violation
        records that honestly rather than leaving the report blank.
        """
        entries = context.get("findings") or []
        matched: list[PolicyViolation] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            try:
                outcome = self._run({**context, "findings": [entry]})
            except PolicyError:
                # One finding that cannot be evaluated must not lose the
                # attribution of every other.
                continue
            if isinstance(outcome, celtypes.BoolType) and bool(outcome):
                matched.append(
                    PolicyViolation(
                        message=_reason(entry),
                        rule=self.name,
                        finding_id=str(entry.get("id") or ""),
                        advisory_id=str(entry.get("advisory") or ""),
                        component=str(entry.get("purl") or ""),
                    )
                )

        if matched:
            return tuple(matched)
        return (
            PolicyViolation(
                message=(
                    "The policy failed on the finding set as a whole rather than "
                    "on any single finding, so no one advisory explains it."
                ),
                rule=self.name,
            ),
        )


def compile_policy(source: str, *, name: str | None = None) -> CompiledPolicy:
    """Compile a preset name or a CEL expression.

    Args:
        source: A preset name, or a CEL expression.
        name: What to call this policy in a report. Defaults to the preset
            name, or ``custom`` for an expression.

    Raises:
        PolicyError: if the expression does not compile. The message carries
            the position the parser objected to, because a policy is written by
            hand and the common failure is a typo.
    """
    expression = PRESETS.get(source.strip(), source)
    resolved_name = name or (source.strip() if source.strip() in PRESETS else "custom")

    if not expression.strip():
        msg = (
            f"policy {resolved_name!r} is empty. An expression says what is "
            f"unacceptable; to gate on nothing, use the 'report-only' preset so "
            f"the choice is visible."
        )
        raise PolicyError(msg)

    environment = celpy.Environment()
    try:
        program = environment.program(environment.compile(expression))
    except CELParseError as exc:
        msg = f"policy {resolved_name!r} is not valid CEL: {exc}"
        raise PolicyError(msg) from exc

    return CompiledPolicy(name=resolved_name, expression=expression, _program=program)


def evaluate(results: ScanResults, source: str = DEFAULT_PRESET) -> PolicyResult:
    """Compile and run a policy in one step."""
    return compile_policy(source).evaluate(results)


def raw_context(results: ScanResults) -> dict[str, Any]:
    """The variables a policy can read, as plain Python.

    Deliberately a projection of the results and nothing else: no clock, no
    environment, no filesystem. A policy that could read the time would give
    different answers on different days for the same scan, and a gate like that
    is not one anybody can reason about.
    """
    return {
        "findings": [_finding_context(finding) for finding in results.findings],
        "scan": {
            "mode": results.mode.value,
            "git_ref": results.project.git_ref or "",
            "git_sha": results.project.git_sha or "",
            "reproducible": results.is_reproducible,
            "snapshot": results.advisory_snapshot_id or "",
        },
        "project": {"slug": results.project.slug or ""},
        "counts": {verdict.value: count for verdict, count in results.counts_by_verdict().items()},
    }


def build_context(results: ScanResults) -> dict[str, Any]:
    """The same variables, converted for CEL. **For inspection only.**

    Useful for showing a caller what an expression can see, in the types the
    evaluator will see them as.

    **Do not pass this to** :meth:`CompiledPolicy.evaluate_context`, which
    converts its own input. Converting twice is not a no-op: celpy's
    ``BoolType`` subclasses ``int``, so a second pass turns ``True`` into
    ``IntType(1)``, and an expression using ``!`` or ``||`` on it then fails
    to evaluate -- reported as a policy that "could not be evaluated", which
    sends you looking at the expression rather than at the context. Use
    :func:`raw_context` for evaluation.
    """
    return {key: json_to_cel(value) for key, value in raw_context(results).items()}


#: Every field a policy can read on a finding, and on ``f.reach``. Published
#: because the hosted platform builds this same shape from database rows: a
#: field present in one builder and absent from the other would silently
#: change what an expression means between CI and the dashboard, and an
#: expression that errors is a build that fails for the wrong reason. A test
#: asserts the two agree.
FINDING_FIELDS: tuple[str, ...] = (
    "id",
    "advisory",
    "aliases",
    "component",
    "purl",
    "ecosystem",
    "version",
    "severity",
    "severity_rank",
    "cvss",
    "cvss_v4",
    "epss",
    "kev",
    "verdict",
    "justification",
    "fixed_in",
    "has_fix",
    "age_days",
    "scope",
    "direct",
    "suppressed",
    "reach",
)

REACH_FIELDS: tuple[str, ...] = (
    "analysed",
    "conclusive",
    "status",
    "reason",
    "confidence",
    "confidence_rank",
    "reachable",
    "path_length",
    "via_dynamic_edges",
)

#: The top-level variables an expression can read. No clock, no environment,
#: no filesystem: a policy that could read the time would give different
#: answers on different days for the same scan.
CONTEXT_VARIABLES: tuple[str, ...] = ("findings", "scan", "project", "counts")


def _finding_context(finding: Finding) -> dict[str, Any]:
    """One finding, as a policy sees it.

    Every field a policy might gate on is present and none is ``null``: a
    policy comparing against a missing field would error at evaluation time,
    which turns a reasonable expression into a broken build. Absent values get
    the empty string or zero, and the field that says whether reachability ran
    at all is ``reach.analysed``.
    """
    reach = finding.reach
    return {
        # Present so a violation can point at the finding it came from, not
        # for gating: an expression comparing against a ULID is a mistake.
        "id": finding.id,
        "advisory": finding.advisory.id,
        "aliases": list(finding.advisory.aliases),
        "component": finding.component.name,
        "purl": finding.component.purl,
        "ecosystem": finding.component.ecosystem,
        "version": finding.component.version,
        "severity": finding.advisory.severity.value,
        "severity_rank": finding.advisory.severity.rank,
        "cvss": finding.advisory.cvss_v3_score or 0.0,
        "cvss_v4": finding.advisory.cvss_v4_score or 0.0,
        "epss": finding.advisory.epss_score or 0.0,
        "kev": finding.advisory.kev,
        "verdict": finding.verdict.value,
        "justification": finding.justification.value if finding.justification else "",
        "fixed_in": finding.fixed_in or "",
        "has_fix": bool(finding.fixed_in),
        "age_days": finding.age_days or 0,
        "scope": finding.component.scope.value,
        "direct": finding.component.direct,
        "suppressed": finding.suppressed_by is not None,
        "reach": {
            # Whether reachability ran at all. True even when it ran and
            # could conclude nothing, which is why it is not the field to
            # gate on -- see `conclusive`.
            "analysed": reach is not None,
            # Whether it reached an answer. False for symbols_unknown and
            # graph_incomplete: the advisory named no functions, or the call
            # graph could not be completed. This is the field that separates
            # "not reachable" from "nobody could look", and a gate wanting to
            # refuse the second reads `!f.reach.conclusive`.
            "conclusive": reach.status.is_conclusive if reach else False,
            "status": reach.status.value if reach else "",
            "reason": reach.reason.value if reach and reach.reason else "",
            "confidence": reach.confidence.value if reach else "",
            "confidence_rank": reach.confidence.rank if reach else 0,
            "reachable": reach.status.is_reachable if reach else False,
            "path_length": len(reach.shortest_path) if reach else 0,
            "via_dynamic_edges": reach.via_dynamic_edges if reach else False,
        },
    }


def _reason(entry: dict[str, Any]) -> str:
    """Why this finding failed the policy, in one line a reader can act on.

    Built from the context entry rather than from the model, so the hosted
    platform's violations read identically to the command line's: one
    renderer, one wording, no drift between the two places a person sees it.
    """
    reach = entry.get("reach") or {}
    parts = [
        f"{entry.get('severity', 'UNKNOWN')} {entry.get('advisory', '')}".strip(),
        f"in {entry.get('component', '')} {entry.get('version', '')}".strip(),
        f"is {entry.get('verdict', '')}",
    ]
    if isinstance(reach, dict) and reach.get("analysed"):
        parts.append(f"({reach.get('status', '')}, {reach.get('confidence', '')} confidence)")
    if entry.get("kev"):
        parts.append("and is known to be exploited in the wild")
    if entry.get("fixed_in"):
        parts.append(f"- fixed in {entry['fixed_in']}")
    return " ".join(parts)


def explain(name: str) -> str:
    """What a preset does, in a sentence, for ``vexpath policy list``."""
    descriptions = {
        "strict": (
            "Fails on any critical or high finding that is reported as affected, "
            "whether or not reachability was consulted."
        ),
        "balanced": (
            "Fails on critical and high findings whose vulnerable code was proven "
            "reachable, and on anything known to be exploited in the wild."
        ),
        "kev-only": (
            "Fails only on advisories in the CISA Known Exploited Vulnerabilities "
            "catalogue that were not cleared."
        ),
        "nothing-outstanding": (
            "Fails on anything still needing a human, including findings under investigation."
        ),
        "report-only": "Fails nothing. Reports only.",
    }
    return descriptions.get(name, "")


def severity_at_least(level: Severity) -> str:
    """A CEL fragment matching findings at or above one severity.

    Offered because ``severity in [...]`` is the expression people get wrong,
    and a rank comparison does not read as clearly as it should.
    """
    allowed = [
        severity.value for severity in Severity if severity.rank >= level.rank and severity.rank > 0
    ]
    return "f.severity in [" + ", ".join(f'"{name}"' for name in allowed) + "]"


def needs_attention_expression() -> str:
    """The expression matching what a report shows by default."""
    affected = Verdict.AFFECTED.value
    open_verdict = Verdict.UNDER_INVESTIGATION.value
    return f'findings.exists(f, f.verdict == "{affected}" || f.verdict == "{open_verdict}")'


__all__ = [
    "CONTEXT_VARIABLES",
    "DEFAULT_PRESET",
    "FINDING_FIELDS",
    "PRESETS",
    "REACH_FIELDS",
    "CompiledPolicy",
    "PolicyError",
    "build_context",
    "compile_policy",
    "evaluate",
    "explain",
    "needs_attention_expression",
    "raw_context",
    "severity_at_least",
]
