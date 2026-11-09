"""Parse a unified diff into the lines a commit actually changed.

Only the changed lines matter. Context lines are there for humans and for
patch application, and counting them as changes would attribute a fix to every
function that happens to sit near it.

The parser tracks two line numbers at once, in the file before the change and
in the file after it. Both are needed: the post-image locates the function the
fix now lives in, and the pre-image locates one the fix deleted, which would
otherwise vanish from the analysis entirely.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

#: ``@@ -old_start,old_count +new_start,new_count @@`` with counts optional.
_HUNK_HEADER = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)

#: Git's marker for a file with no trailing newline. Not a content line.
_NO_NEWLINE = "\\ No newline at end of file"

#: A diff this large is a vendored dependency bump or a generated file, and
#: extracting symbols from it would name half the package.
MAX_CHANGED_LINES_PER_FILE = 2000


@dataclass(slots=True)
class FileDiff:
    """What one commit changed in one file."""

    old_path: str | None
    new_path: str | None
    #: Line numbers changed, as numbered in the file before the commit.
    removed_lines: list[int] = field(default_factory=list)
    #: Line numbers changed, as numbered in the file after the commit.
    added_lines: list[int] = field(default_factory=list)
    is_new_file: bool = False
    is_deleted_file: bool = False
    is_rename: bool = False
    #: True when the diff was truncated for size, so callers can lower
    #: confidence rather than treat a partial reading as complete.
    truncated: bool = False

    @property
    def path(self) -> str:
        """The path to report this change under."""
        return self.new_path or self.old_path or "<unknown>"

    @property
    def changed_line_count(self) -> int:
        return len(self.removed_lines) + len(self.added_lines)

    @property
    def is_python(self) -> bool:
        return self.path.endswith(".py")


def parse(diff: str) -> list[FileDiff]:
    """Parse a unified diff.

    Tolerant by design: a diff comes from a third party, and one malformed
    stanza should not discard the rest of a commit.
    """
    files: list[FileDiff] = []
    current: FileDiff | None = None
    old_line = 0
    new_line = 0

    for line in diff.splitlines():
        if line.startswith("diff --git "):
            current = _start_file(line)
            files.append(current)
            continue

        if current is None:
            continue

        if line.startswith("--- "):
            current.old_path = _strip_prefix(line[4:])
            continue
        if line.startswith("+++ "):
            current.new_path = _strip_prefix(line[4:])
            continue
        if line.startswith("new file mode"):
            current.is_new_file = True
            continue
        if line.startswith("deleted file mode"):
            current.is_deleted_file = True
            continue
        if line.startswith(("rename from", "rename to", "similarity index")):
            current.is_rename = True
            continue
        if line.startswith(("index ", "old mode", "new mode", "Binary files")):
            continue

        header = _HUNK_HEADER.match(line)
        if header is not None:
            old_line = int(header.group("old_start"))
            new_line = int(header.group("new_start"))
            continue

        if line == _NO_NEWLINE:
            continue

        if line.startswith("-"):
            if current.changed_line_count < MAX_CHANGED_LINES_PER_FILE:
                current.removed_lines.append(old_line)
            else:
                current.truncated = True
            old_line += 1
        elif line.startswith("+"):
            if current.changed_line_count < MAX_CHANGED_LINES_PER_FILE:
                current.added_lines.append(new_line)
            else:
                current.truncated = True
            new_line += 1
        elif line.startswith(" ") or not line:
            # Context. It advances both files and changes neither.
            old_line += 1
            new_line += 1

    return files


def _start_file(line: str) -> FileDiff:
    """Read the paths out of a ``diff --git`` header.

    The header repeats the path twice, which is how a rename is visible before
    the ``rename from`` lines arrive.
    """
    remainder = line[len("diff --git ") :]
    halves = remainder.split(" b/", 1)
    if len(halves) == 2:
        return FileDiff(
            old_path=_strip_prefix(halves[0]),
            new_path=_strip_prefix(f"b/{halves[1]}"),
        )
    return FileDiff(old_path=None, new_path=None)


def _strip_prefix(path: str) -> str | None:
    """Remove git's ``a/`` and ``b/`` prefixes, and recognise absence."""
    cleaned = path.strip().strip('"')
    if cleaned == "/dev/null":
        return None
    for prefix in ("a/", "b/"):
        if cleaned.startswith(prefix):
            return cleaned[len(prefix) :]
    return cleaned


def python_files(diff: str) -> Iterator[FileDiff]:
    """Yield only the Python files a diff touched, excluding tests.

    Tests are excluded for the same reason they are excluded from call graphs:
    a fix's test exercises the vulnerable function, so attributing the fix to
    the test would name the wrong symbol.
    """
    for file_diff in parse(diff):
        if not file_diff.is_python:
            continue
        if is_test_path(file_diff.path):
            continue
        if file_diff.changed_line_count == 0:
            continue
        yield file_diff


def is_test_path(path: str) -> bool:
    """Whether a path belongs to a test suite rather than the package."""
    parts = path.replace("\\", "/").split("/")
    if any(part in {"tests", "test", "testing", "_test"} for part in parts[:-1]):
        return True
    name = parts[-1]
    return name.startswith(("test_", "conftest")) or name.endswith("_test.py")


__all__ = [
    "MAX_CHANGED_LINES_PER_FILE",
    "FileDiff",
    "is_test_path",
    "parse",
    "python_files",
]
