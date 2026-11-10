"""Error reporting, and what must never leave the process with it.

Sentry is useful and it is also an exfiltration channel pointed at a third
party, so the question is not whether to send errors but what travels with
them. The threat model forbids SBOM contents, source code and credentials from
reaching the logs (``docs/06-threat-model.md``); an error reporter that shipped
them to somebody else's bucket would be the same leak with extra steps and a
contract attached.

So three things are off, deliberately, and each would be on by default:

**No personally identifying information.** ``send_default_pii`` would attach
the request body, headers and cookies. The body of a scan upload *is* a
dependency inventory, and a cookie is a live session.

**No local variables in stack frames.** A frame inside the scanner holds the
source it was parsing and a frame inside the auth path holds the presented
key. A traceback with locals is the most detailed possible dump of exactly the
things that must not leave.

**A scrubbing hook on the way out**, as the last line rather than the only
one. It drops request data entirely and redacts anything whose key looks like
a credential, including inside ``extra``, because the two settings above can
be re-enabled by somebody who does not know why they were off.

Sentry is an optional dependency. A deployment with no DSN configured runs
with none of this and loses nothing but the reporting, which is the right
default for a tool people run against their own code.
"""

from __future__ import annotations

from typing import Any

from vexpath_platform.logging import get_logger
from vexpath_platform.settings import Settings

log = get_logger(__name__)

#: Keys whose values never leave the process, wherever they appear in an event.
#: A superset of the logging module's list: this one also covers the fields a
#: web framework attaches by itself.
SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "cookies",
        "csrf_token",
        "github_token",
        "password",
        "secret",
        "secret_key",
        "secret_encrypted",
        "session",
        "sbom",
        "source",
        "s3_secret_access_key",
        "token",
        "token_hash",
        "x-api-key",
    }
)

REDACTED = "[redacted]"

#: Event keys removed wholesale rather than redacted field by field. ``request``
#: carries the body, the query string and the headers; a scan upload's body is
#: a dependency inventory, which is a map of where a company is behind on
#: patches.
DROPPED_SECTIONS = ("request",)


def scrub(event: dict[str, Any], _hint: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Remove from an error report everything that must not leave.

    Written as a plain function so it can be tested without Sentry installed,
    which matters: an untested scrubber is a scrubber nobody knows the shape
    of, and the one thing it must never do is pass something through because
    it was nested one level deeper than expected.
    """
    for section in DROPPED_SECTIONS:
        event.pop(section, None)
    _scrub_in_place(event)
    return event


def _scrub_in_place(value: Any, depth: int = 0) -> None:
    """Redact sensitive keys at every depth.

    Bounded, because an event is JSON from a library and a cyclic or absurdly
    nested structure must not turn error reporting into a hang.
    """
    if depth > 12:
        return
    if isinstance(value, dict):
        for key in list(value):
            if isinstance(key, str) and key.lower() in SENSITIVE_KEYS:
                value[key] = REDACTED
            else:
                _scrub_in_place(value[key], depth + 1)
    elif isinstance(value, list):
        for item in value:
            _scrub_in_place(item, depth + 1)


def configure_sentry(settings: Settings) -> bool:
    """Start error reporting if this deployment has a DSN.

    Returns whether it was started, so the caller can say so once at start-up
    rather than leaving an operator to guess whether errors are going
    anywhere.
    """
    if not settings.sentry_dsn:
        return False

    try:
        import sentry_sdk
    except ImportError:
        # Configured but not installed. Said out loud rather than ignored: a
        # deployment that believes it has error reporting and does not is
        # worse off than one that knows it has none.
        log.warning("sentry.not_installed", hint="install the 'sentry' extra")
        return False

    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.env.value,
        release=settings.release,
        traces_sample_rate=settings.sentry_traces_sample_rate,
        # Each of the next three would default the other way, and each one
        # would ship something the threat model forbids. See the module
        # docstring for which.
        send_default_pii=False,
        include_local_variables=False,
        max_request_body_size="never",
        before_send=scrub,
    )
    log.info("sentry.configured", environment=settings.env.value)
    return True


__all__ = ["DROPPED_SECTIONS", "REDACTED", "SENSITIVE_KEYS", "configure_sentry", "scrub"]
