"""Fetching the published advisory corpus.

Building the corpus is the expensive half of this tool and nobody should have
to repeat it. Downloading advisories from OSV takes twenty seconds; extracting
which functions each fix changed takes hours of cloning and diffing upstream
repositories, and the result is identical for everyone. So it is built once and
published, and this is the half that collects it.

Without it a new user gets the honest but useless answer: almost every finding
comes back ``symbols_unknown`` -- the advisory never said which functions its
fix changed, so nothing can be searched for -- and the tool that promises to
tell you what is reachable tells you it could not look.

**Published to a GitHub release rather than served from the platform.** Release
assets cost nothing to serve and are already covered by the release's
provenance; the platform is one small machine that sleeps when idle, and
sending every user ten megabytes from it would be the first thing to fall over.

The download is verified rather than trusted: ``read_snapshot`` recomputes the
content hash over the normalised records and refuses a corpus whose contents do
not match what the snapshot claims. A corrupted or substituted corpus changes
verdicts, so loading one is not an acceptable degraded mode.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import httpx

from vexpath_core.snapshot import (
    ADVISORIES_FILE_GZ,
    SNAPSHOT_METADATA_FILE,
    SnapshotIntegrityError,
    read_snapshot,
)

#: Where a published corpus is fetched from when nothing says otherwise.
#:
#: ``releases/latest/download`` is GitHub's redirect to whatever the newest
#: release is, so this URL does not have to name a version and does not go
#: stale.
DEFAULT_CORPUS_URL = "https://github.com/Unknown122-coder/vexpath/releases/latest/download/corpus"

#: Override, for a fork, a mirror, or a corpus built in-house.
CORPUS_URL_ENVIRONMENT_VARIABLE = "VEXPATH_CORPUS_URL"

#: How long to wait for the corpus. It is around ten megabytes compressed, and
#: a slow connection is not a failure.
DOWNLOAD_TIMEOUT = 300.0

#: Refuse anything larger. The published corpus is about ten megabytes; a
#: response far above that is a redirect to something else, a captive portal,
#: or a mistake, and streaming it to disk unchecked would fill the disk.
MAX_CORPUS_BYTES = 200 * 1024 * 1024


class CorpusError(Exception):
    """Raised when a corpus cannot be fetched or cannot be trusted."""


def default_corpus_directory() -> Path:
    """Where a downloaded corpus lives.

    Beside the call-graph cache and following the same platform convention,
    because both are rebuildable data rather than configuration: losing either
    costs time, not information.
    """
    override = os.environ.get("VEXPATH_CACHE_DIR")
    if override:
        return Path(override) / "corpus"
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "vexpath" / "corpus"
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "vexpath" / "corpus"


def corpus_url() -> str:
    """The base URL to fetch from, honouring the override."""
    return os.environ.get(CORPUS_URL_ENVIRONMENT_VARIABLE, "").strip() or DEFAULT_CORPUS_URL


def pull(
    destination: Path | None = None,
    *,
    base_url: str | None = None,
    client: httpx.Client | None = None,
) -> tuple[Path, int, int]:
    """Download and verify a published corpus.

    Returns the directory, the number of advisories and the number of symbols.

    Downloaded into a temporary directory and moved into place only once it
    verifies, so an interrupted or corrupted download cannot replace a corpus
    that was working. The client is injectable so the tests exercise the real
    code against recorded bytes rather than the network.

    Raises:
        CorpusError: if the corpus cannot be fetched, is implausibly large, or
            does not match its own content hash.
    """
    target = destination or default_corpus_directory()
    root = (base_url or corpus_url()).rstrip("/")

    owns_client = client is None
    http = client or httpx.Client(timeout=DOWNLOAD_TIMEOUT, follow_redirects=True)
    try:
        with tempfile.TemporaryDirectory() as directory:
            staging = Path(directory)
            _download(http, f"{root}.{SNAPSHOT_METADATA_FILE}", staging / SNAPSHOT_METADATA_FILE)
            _download(http, f"{root}.{ADVISORIES_FILE_GZ}", staging / ADVISORIES_FILE_GZ)

            # Verifies the content hash, which is the point of doing it here
            # rather than after the move: a corpus that fails this never
            # replaces one that works.
            metadata, records = read_snapshot(staging)
            symbols = sum(len(record.symbols) for record in records)

            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                shutil.rmtree(target)
            shutil.move(str(staging), str(target))
    except httpx.HTTPError as exc:
        msg = f"the corpus could not be downloaded from {root}: {exc}"
        raise CorpusError(msg) from exc
    except SnapshotIntegrityError as exc:
        # The check that makes downloading a corpus acceptable at all. A
        # substituted one changes verdicts -- drop an advisory's symbols and
        # every project using that package is quietly cleared -- so this is
        # fatal, and the message says to try again rather than how to skip it.
        msg = (
            f"the corpus from {root} does not match its own content hash and was "
            f"discarded: {exc}"
        )
        raise CorpusError(msg) from exc
    except (OSError, ValueError) as exc:
        msg = f"the corpus from {root} could not be read: {exc}"
        raise CorpusError(msg) from exc
    finally:
        if owns_client:
            http.close()

    del metadata
    return target, len(records), symbols


def _download(client: httpx.Client, url: str, destination: Path) -> None:
    """Stream one file to disk, refusing an implausible one."""
    with client.stream("GET", url) as response:
        if response.status_code == 404:
            msg = (
                f"{url} does not exist. No corpus has been published for this "
                f"release yet; 'vexpath advisory sync' builds one locally instead."
            )
            raise CorpusError(msg)
        response.raise_for_status()

        written = 0
        with destination.open("wb") as handle:
            for chunk in response.iter_bytes():
                written += len(chunk)
                if written > MAX_CORPUS_BYTES:
                    msg = (
                        f"{url} is larger than the {MAX_CORPUS_BYTES} byte limit, "
                        f"which a published corpus is not"
                    )
                    raise CorpusError(msg)
                handle.write(chunk)


__all__ = [
    "CORPUS_URL_ENVIRONMENT_VARIABLE",
    "DEFAULT_CORPUS_URL",
    "MAX_CORPUS_BYTES",
    "CorpusError",
    "corpus_url",
    "default_corpus_directory",
    "pull",
]
