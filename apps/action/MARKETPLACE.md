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

## The blocker

**GitHub requires an action's `action.yml` to be in the root of its
repository**, and requires that a repository publishing an action contains
only that one action. This one lives at `apps/action/action.yml`, which is
fine for using it —

```yaml
- uses: Unknown122-coder/vexpath/apps/action@v0.1.1
```

— and means the **Publish to Marketplace** banner never appears on a release.

Three ways out, and they are genuinely different choices rather than one
obvious answer:

**Move `action.yml` to the repository root.** Cheap: the file is
self-contained, referencing no sibling and no `github.action_path`, so moving
it touches the file itself, the one `uses: ./apps/action` in
`.github/workflows/vexpath.yml`, the path in `apps/action/tests/`, and the
documentation. It also shortens the reference to
`uses: Unknown122-coder/vexpath@v0.1.1`, which is what people expect. The cost
is a `action.yml` sitting in the root of a repository that is a platform
rather than an action, which reads oddly to anyone who opens it.

**Publish from a second repository.** `vexpath-action` holding only the
action, released in step with this one. Keeps this repository's layout honest
and adds a second thing to release, which is the cost people underestimate: a
tag here means a tag there, for ever.

**Do not list it.** The action works today by path, and most people who adopt
it will arrive through the documentation rather than through Marketplace
search. Listing is discovery, not distribution.

## If the move is chosen

```sh
git mv apps/action/action.yml action.yml
# then: the uses: in .github/workflows/vexpath.yml, the path in
# apps/action/tests/test_action.py, and the examples in README.md
```

Then on the release page for the tag, use **Publish this Action to the GitHub
Marketplace**, accept the developer agreement, pick a primary and secondary
category (Security, and Continuous integration), and publish.

## What the listing should not claim

The description is the one place where a security tool is most tempted to
overstate. This one says what it does -- fails a build when a vulnerable
function is reachable -- and the README behind it says plainly what it cannot
do: reachability analysis is implemented for PyPI only, findings from other
ecosystems are reported but never cleared, and an advisory whose fix commit
cannot be read produces "nobody could look" rather than a clearance.
