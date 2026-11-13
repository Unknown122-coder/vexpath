"""Where the command-line tool gets its advisories.

Every command that reads advisories faces the same choice, with the same
consequence: a local snapshot makes the result reproducible, a live query does
not. Keeping the choice and the warning in one place means no command can
quietly omit the warning, and the environment variable is spelled once.
"""

from __future__ import annotations

import os
from pathlib import Path

from vexpath.corpus import default_corpus_directory
from vexpath.output import fail, note, warn
from vexpath_core.advisory import OsvApiSource, SnapshotSource
from vexpath_core.protocols import AdvisorySource
from vexpath_core.snapshot import SNAPSHOT_METADATA_FILE, SnapshotIntegrityError

#: Environment variable naming a local advisory snapshot. Set it and commands
#: become reproducible and offline by default.
SNAPSHOT_ENV = "VEXPATH_ADVISORY_SNAPSHOT_DIR"
#: Override for the OSV endpoint, so tests can point at something local.
OSV_BASE_ENV = "VEXPATH_OSV_API_BASE"


def snapshot_directory(explicit: Path | None = None) -> Path | None:
    """Resolve the snapshot to read: the flag, the environment, or the cache.

    The last of those is what makes this tool useful to somebody who has not
    built a corpus. ``vexpath advisory pull`` downloads the published one, and
    every command finds it from then on without being told -- which matters
    because the alternative is a live OSV query, and OSV does not publish
    which functions a fix changed. Without a corpus nearly every finding comes
    back ``symbols_unknown``: an honest answer, and not a useful one.

    Order is deliberate. An explicit flag beats the environment, the
    environment beats the cache, and a cache that is merely present never
    overrides something the caller asked for.
    """
    if explicit is not None:
        return explicit

    raw = os.environ.get(SNAPSHOT_ENV, "").strip()
    if raw:
        candidate = Path(raw)
        if candidate.is_dir():
            return candidate
        warn(f"${SNAPSHOT_ENV} points at {candidate}, which is not a directory; ignoring it.")
        return None

    downloaded = default_corpus_directory()
    if (downloaded / SNAPSHOT_METADATA_FILE).is_file():
        return downloaded
    return None


def advisory_source(snapshot: Path | None, *, result_noun: str = "scan") -> AdvisorySource:
    """Open an advisory source, preferring a reproducible snapshot.

    Args:
        snapshot: Snapshot directory from a command-line flag, if given.
        result_noun: What the caller is producing, for the warning text. A
            warning that names the thing about to become unreproducible is one
            people act on.

    Exits the process with a configuration error if a snapshot was named but
    cannot be trusted. A corrupted corpus changes verdicts, so continuing with
    it would be worse than stopping.
    """
    directory = snapshot_directory(snapshot)
    if directory is not None:
        try:
            source = SnapshotSource(directory)
        except FileNotFoundError as exc:
            fail(str(exc))
        except SnapshotIntegrityError as exc:
            fail(f"advisory snapshot is not trustworthy: {exc}")
        note(f"using advisory snapshot {source.snapshot_id} from {directory}")
        return source

    warn(
        f"No advisory snapshot was given, so advisories will be read live from "
        f"OSV and this {result_noun} will not be reproducible. Run "
        f"'vexpath advisory sync' and set ${SNAPSHOT_ENV} to fix that."
    )
    return OsvApiSource(base_url=os.environ.get(OSV_BASE_ENV, "https://api.osv.dev"))


def close_source(source: object) -> None:
    """Release a source's resources, if it holds any.

    A snapshot source holds none; a live one holds an HTTP connection pool.
    """
    close = getattr(source, "close", None)
    if callable(close):
        close()


__all__ = [
    "OSV_BASE_ENV",
    "SNAPSHOT_ENV",
    "advisory_source",
    "close_source",
    "snapshot_directory",
]
