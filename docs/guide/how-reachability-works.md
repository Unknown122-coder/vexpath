# How reachability works

A scanner tells you `jinja2` has a critical advisory. That is a fact about
`jinja2`, not about you. The question you actually have is whether the part of
`jinja2` that is broken can run in your application, and nobody answers it
because answering it is work.

This is the work.

## The four steps

**1. What is in your tree.** A lockfile or an SBOM becomes a list of
components with exact versions. Unpinned requirements are refused rather than
guessed at: a scan of versions you might have is a report about a project that
might exist.

**2. Which advisories apply.** Each component is matched against the advisory
corpus by purl and version range. This part is the same as every other
scanner, and it is where every other scanner stops.

**3. Which functions are actually broken.** An advisory says "jinja2 before
3.1.3 is vulnerable". It almost never says *which functions*. So the fix
commit is fetched — a bare, blobless, depth-2 clone, nothing checked out, hooks
disabled — and diffed. Every definition containing a changed line becomes a
**vulnerable symbol**: `jinja2.sandbox.SandboxedEnvironment.call`, not
"jinja2".

This is the part nobody else publishes, and it is why the package pages exist.

**4. Whether anything you run reaches them.** A call graph is built from your
code and from each dependency's own source, by parsing — never importing, never
executing. Then a breadth-first search from your entry points asks whether any
of those symbols is reachable.

Only then: a finding is cleared **only** when the dependency's own code was
traversed and no path reached the advisory's symbols.

## The five rules that make a clearance honest

Each of these was a bug that looked like working code. Each one makes the tool
clear *fewer* findings, which is the direction a safety property has to err.

**Importing a module does not reach the functions it defines.** Treating a
definition as execution makes every function of every installed package
reachable, so nothing can ever be cleared — while the tool still appears to
work. An import edge reaches module-level code, class bodies and decorators,
and nothing else.

**A dependency whose own call graph is unavailable can never be cleared.** A
direct call to a vulnerable symbol still gives a sound *reachable* verdict, but
an absence of paths through code that was never read proves nothing. That case
reports `package_not_analysed`, which is not a clearance and does not look like
one.

**Cross-package dispatch resolves at link time, not build time.** Dependency
graphs are built separately and cached per package version, then linked. A
method called through a re-exported class, or dispatched dynamically, has to
resolve when the graphs are joined — otherwise the edge silently does not
exist and the finding is wrongly cleared.

**A class reached only by import is not evidence its methods run.** Importing a
module executes its `class` statements, so any code importing `nltk` reached
`Downloader` by three import edges, and the verdict read "the vulnerable code
can run". It does not say that. Such a match is `reachable_possible`, with the
reason printed. A *module* reached by import is still a confirmation, because a
fix to module-level code does run on import.

**A class does not expand to methods the advisory did not name.** Expanding
`nltk`'s `Downloader` added all 36 of its members, two of which run on
instantiation, so an unrelated method counted as reaching the vulnerability. A
class expands to its methods only when the advisory names no method inside it.

The last two were found only by scanning a real installed package. No fixture
would have shown them.

## What the verdicts mean

| Verdict | What it says |
|---|---|
| `reachable_confirmed` | A path exists through statically resolved calls. Act on this. |
| `reachable_possible` | A path exists, but it depends on a call that could not be resolved exactly — dynamic dispatch, or a class reached only by import. Conservative on purpose. |
| `unreachable` | The dependency's code was read and no path reached the symbols. **This is the clearance.** |
| `package_not_analysed` | The dependency's source was not available. Not a clearance. |
| `no_symbols` | The advisory's fix could not be resolved to functions, so reachability could not narrow anything. The finding stands on the version match alone. |

"Not reachable" and "nobody looked" are never shown as the same thing. The
finding page says *Nobody looked* in those words, and the policy language has
`reach.analysed` so a gate can tell them apart.

## What a clearance rests on, and how to check it

Every cleared finding carries:

- **the symbols that were searched for**, and where each came from (a fix
  commit, a manual record) with a confidence;
- **the entry points** the search started from, and how they were found;
- **the graph's quality** — nodes, edges, linked packages, and the unresolved
  call ratio, which is the single best indicator of how much the graph could
  see;
- and for a reachable finding, **the shortest path**, hop by hop, with the file
  and line of each call, and any hop that was resolved conservatively marked as
  such.

```bash
vexpath reach . --advisory CVE-2026-1234
```

If a clearance is wrong, one of those is wrong, and this is where you see
which. We would rather you check than trust.

## What this does not prove

Reachability is a statement about **static call paths from the entry points you
declared**. It is not a proof of safety:

- A path can exist that this analysis cannot see — through `getattr`, a plugin
  registry, a template, a serialised callable, or C code. Unresolved calls are
  counted and published for exactly this reason.
- A vulnerability can be exploitable without your code calling anything: a
  parser invoked on untrusted input by a framework you did not write about, a
  dependency with a malicious install script (which is why malicious-package
  advisories are never subject to reachability at all).
- Entry points drive everything. A finding unreachable from your web handlers
  may be reachable from a management command you did not declare.

The honest framing: a `reachable_confirmed` verdict is a strong reason to act.
An `unreachable` verdict is a strong reason to **deprioritise**, with the
evidence attached so somebody else can disagree.

## How good is it, really

Measured on five real repositories, scanned through the real command with
nothing installed and every dependency's source downloaded from the index:
**68 of 146 findings cleared, none of them unsoundly.** Flask went from 38
findings to 10 worth looking at.

The lever on that number is not the engine — it is how many advisories have
had their fix commits diffed into symbols. The same five projects cleared 51
of 146 with 1,453 symbols available, and 68 of 146 with 7,548. Forty-five of
the seventy-four advisories those projects hit still had no symbols at all.

See [limitations](limitations.md) for what that means today.
