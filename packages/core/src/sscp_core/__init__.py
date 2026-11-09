"""Analysis core for the software supply-chain security platform.

This package decides verdicts. It is used unchanged by the CLI, the GitHub
Action and the platform workers, so that where a scan runs never affects what
it concludes.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:  # pragma: no cover - depends on install mode
    __version__ = version("sscp-core")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0+unknown"

#: Version of the ``sscp.results`` JSON schema this build emits.
RESULTS_SCHEMA = "sscp.results/1"

__all__ = ["RESULTS_SCHEMA", "__version__"]
