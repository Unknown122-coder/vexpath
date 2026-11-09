"""Structured logging.

JSON in deployed environments so logs are queryable, human-readable colour
locally. Fields that could carry customer data are redacted centrally rather
than at each call site, because the threat model forbids SBOM contents, source
code and API keys from reaching the logs (see ``docs/06-threat-model.md``).
"""

from __future__ import annotations

import logging
import sys
from collections.abc import MutableMapping
from typing import Any

import structlog

from vexpath_platform.settings import LogFormat, Settings

#: Keys whose values are replaced before a log line is emitted, wherever in the
#: event dictionary they appear.
_REDACTED_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "secret_key",
        "password",
        "token",
        "github_token",
        "s3_secret_access_key",
        "sbom",
        "source",
    }
)
_REDACTED = "[redacted]"


def _redact(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Replace sensitive values anywhere in the event dictionary."""
    for key in list(event_dict):
        if key.lower() in _REDACTED_KEYS:
            event_dict[key] = _REDACTED
    return event_dict


def configure_logging(settings: Settings) -> None:
    """Configure structlog and route standard-library logging through it."""
    level = logging.getLevelNamesMapping().get(settings.log_level.upper(), logging.INFO)

    shared_processors: list[structlog.typing.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _redact,
    ]

    renderer: structlog.typing.Processor = (
        structlog.processors.JSONRenderer()
        if settings.log_format is LogFormat.JSON
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )

    # Uvicorn and SQLAlchemy log through the standard library; send those
    # records to the same place so there is one log stream, not three.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=level,
        force=True,
    )
    for noisy in ("uvicorn.access", "uvicorn.error", "sqlalchemy.engine"):
        logging.getLogger(noisy).handlers.clear()
        logging.getLogger(noisy).propagate = True


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a bound logger for a module."""
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    return logger


__all__ = ["configure_logging", "get_logger"]
