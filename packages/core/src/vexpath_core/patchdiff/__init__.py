"""Extract vulnerable symbols from the commit that fixed an advisory.

Reachability needs to know which functions are vulnerable. For every ecosystem
but Go, OSV does not say, so the answer has to be recovered from the fix
itself: find the commit, diff it, and name the definitions its changed lines
belong to.

The stages are separated so that only one of them needs the network:

| Stage | Module | Network |
|---|---|---|
| Find the fix | `references` | no |
| Fetch the diff and sources | `fetch` | yes |
| Parse the diff | `unidiff` | no |
| Map paths to module names | `layout` | no |
| Name the symbols | `extract` | no |

Everything that decides what a symbol *is* runs offline and is tested offline.
Fetching is isolated behind a protocol, so the whole extraction can be
exercised against recorded diffs.
"""

from __future__ import annotations

from vexpath_core.patchdiff.extract import (
    ExtractedSymbol,
    ExtractionReport,
    extract,
    extract_from_file,
)
from vexpath_core.patchdiff.fetch import (
    CommitDiff,
    CommitSource,
    FetchError,
    GitCommitSource,
    RecordedCommitSource,
)
from vexpath_core.patchdiff.layout import PackageLayout, import_names_for, layout_for
from vexpath_core.patchdiff.pipeline import (
    PatchDiffResult,
    extract_for_advisory,
    with_symbols,
)
from vexpath_core.patchdiff.references import (
    FixReference,
    UnresolvableFixError,
    resolve,
)
from vexpath_core.patchdiff.unidiff import FileDiff, parse, python_files

__all__ = [
    "CommitDiff",
    "CommitSource",
    "ExtractedSymbol",
    "ExtractionReport",
    "FetchError",
    "FileDiff",
    "FixReference",
    "GitCommitSource",
    "PackageLayout",
    "PatchDiffResult",
    "RecordedCommitSource",
    "UnresolvableFixError",
    "extract",
    "extract_for_advisory",
    "extract_from_file",
    "import_names_for",
    "layout_for",
    "parse",
    "python_files",
    "resolve",
    "with_symbols",
]
