# ADR-0013 · The name is `vexpath`

## Context

The project was built under the placeholder `sscp`, short for its own
description. A placeholder was fine while nothing was published, but the name
reaches further than a command: it is the PyPI distribution, the import
namespace, the environment-variable prefix, the repository configuration file,
the namespaced properties written into every CycloneDX document, the results
schema identifier, the API key prefix, the Action in the Marketplace, and the
badge URLs people paste into READMEs. Every one of those becomes a compatibility
obligation the moment someone outside this repository depends on it. So the
name had to be settled before the first release, not after.

Requirements, in the order they constrained the choice:

1. **Free** on PyPI, as a GitHub organisation, and in the Action Marketplace.
2. **Unambiguous** against the tools this one sits beside: syft, grype, trivy,
   osv-scanner, cosign, vexctl, bomctl, scorecard, guac, in-toto.
3. **Short enough to type** as a command people run in every build.
4. **Self-describing to the audience that matters.** A security engineer
   skimming a repository should be able to guess what it does.

## Decision

The project is named **`vexpath`**.

It names the two things that make the product what it is. **VEX** is the signed
exploitability document it emits, which is the artefact a regulator or a
customer actually asks for. **Path** is the call path through the code, which is
the evidence behind every verdict and the thing no other open tool produces.

Verified free at the time of the decision: `vexpath` returns 404 on
`pypi.org/pypi/vexpath/json` and on `github.com/vexpath`.

The alternatives, and why they lost:

- **Real English words** such as `winnow` or `vouch` describe the product well
  but already belong to other companies and projects. That costs search
  visibility and invites a trademark argument, for no gain.
- **Anything built on `reach` alone** names the method but not the output, and
  the output is what gets cited in an audit.
- **Short invented nonsense**, in the tradition of `syft` and `trivy`, is
  on-pattern for this ecosystem but tells a reader nothing. This project is
  judged partly on whether someone can see what it does at a glance.
- **`reachvex`** says the same thing in the other order and reads slightly more
  like a product. It lost only on length: `vexpath` is shorter to type.

## Consequences

What the name now fixes, and therefore what a future rename would break:

| Surface | Value |
|---|---|
| Command and PyPI distribution | `vexpath` |
| Import namespace | `vexpath_core`, `vexpath_platform`, `vexpath_db`, `vexpath_api`, `vexpath_worker` |
| Environment prefix | `VEXPATH_` |
| Repository configuration | `.vexpath.yml` |
| Results schema | `vexpath.results/1` |
| CycloneDX properties | `vexpath:scope`, `vexpath:direct`, `vexpath:note`, `vexpath:reach.*` |
| API key prefix | `vexpath_live_` |

The results schema identifier and the CycloneDX property names are the two that
bind hardest, because they appear inside documents this tool has already
written. Changing either later means supporting both spellings for as long as
old documents exist, which is why they are settled now while nothing has been
published.

The rename itself was mechanical and is recorded in one commit, so reverting it
or choosing differently costs one scripted pass. That stops being true the day
someone installs from PyPI.
