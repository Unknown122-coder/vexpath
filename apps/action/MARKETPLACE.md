# Publishing the Action to GitHub Marketplace

What is ready, what is not, and the one decision that has to be made first.

## Ready

| Requirement | State |
|---|---|
| Public repository | Yes, since 2026-11-13 |
| A published release to point at | `v0.1.1` |
| `name` unique on Marketplace | `vexpath` — check at publish time; the name is claimed by whoever lists first |
| `description` | In `action.yml` |
| `author` | In `action.yml` |
| `branding.icon` / `branding.color` | `git-merge`, `green` — required, and easy to forget until the form refuses |
| A README the listing can show | `apps/action/README.md` |
| `action.yml` in the repository root | Yes, moved there 2026-11-13 |

## The move, and why the file is where it is

`action.yml` sits in the **repository root**, which looks odd in a repository
that is a platform rather than an action, and is not a style choice: GitHub
only lists an action whose metadata is in the root of its repository. At
`apps/action/action.yml` the action worked perfectly well by path --

```yaml
- uses: Unknown122-coder/vexpath/apps/action@v0.1.1
```

-- and the **Publish to Marketplace** banner never appeared on a release.

Moving it cost little, because the file references no sibling and no
`github.action_path`: the file itself, one `uses:` in the dogfooding workflow,
one path in the test, and the documentation. The reference it leaves behind is
the one the action's own README had been documenting all along:

```yaml
- uses: Unknown122-coder/vexpath@v0.1.1
```

Everything else about the action -- its README, its tests, its changelog --
stays in `apps/action/`, which is where somebody reading the repository would
look for it.

## Listing it

On the release page for the tag, use **Publish this Action to the GitHub
Marketplace**, accept the developer agreement, pick a primary and secondary
category (Security, and Continuous integration), and publish.

## What the listing should not claim

The description is the one place where a security tool is most tempted to
overstate. This one says what it does -- fails a build when a vulnerable
function is reachable -- and the README behind it says plainly what it cannot
do: reachability analysis is implemented for PyPI only, findings from other
ecosystems are reported but never cleared, and an advisory whose fix commit
cannot be read produces "nobody could look" rather than a clearance.
