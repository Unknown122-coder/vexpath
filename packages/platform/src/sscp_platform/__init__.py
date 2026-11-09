"""Shared platform concerns: configuration and structured logging.

Used by the API and the workers. Never imported by ``sscp_core``: an analysis
verdict must not depend on how the process was configured.
"""

from __future__ import annotations

from sscp_platform.logging import configure_logging, get_logger
from sscp_platform.settings import Environment, LogFormat, Settings, get_settings

__all__ = [
    "Environment",
    "LogFormat",
    "Settings",
    "configure_logging",
    "get_logger",
    "get_settings",
]
