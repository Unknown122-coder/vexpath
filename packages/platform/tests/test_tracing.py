"""What never leaves the process with an error report.

Sentry is an exfiltration channel pointed at a third party, so these tests are
about the scrubber rather than about the reporting. Each one names something
that would travel by default and asserts it does not:

a scan upload's request body, which *is* a dependency inventory and therefore
a map of where a company is behind on patches; a session cookie, which is a
live credential; an API key in a header; and the source a scanner frame was
holding when it raised.

The nesting tests matter as much as the top-level ones. A scrubber that only
looks one level down passes a credential through the moment a library wraps it
in a dictionary, which is what every web framework does.
"""

from __future__ import annotations

from typing import Any

from vexpath_platform import tracing
from vexpath_platform.settings import Environment, Settings


def test_the_request_section_is_dropped_entirely() -> None:
    event: dict[str, Any] = {
        "message": "boom",
        "request": {
            "url": "https://api.vexpath.dev/v1/scans",
            "data": {"results": {"findings": ["a dependency inventory"]}},
            "headers": {"Authorization": "Bearer vexpath_live_xxx"},
            "cookies": "vexpath_session=live",
        },
    }
    scrubbed = tracing.scrub(event)
    assert scrubbed is not None
    # Not redacted field by field: the whole section goes, because the body of
    # a scan upload is the thing this product exists to keep private.
    assert "request" not in scrubbed
    assert "dependency inventory" not in str(scrubbed)


def test_a_credential_is_redacted_wherever_it_appears() -> None:
    event: dict[str, Any] = {
        "extra": {
            "authorization": "Bearer vexpath_live_xxx",
            "nested": {"api_key": "vexpath_live_yyy", "fine": "keep me"},
            "list": [{"token": "whsec_zzz"}],
        }
    }
    scrubbed = tracing.scrub(event)
    assert scrubbed is not None
    text = str(scrubbed)
    # A scrubber that only looks one level down passes a credential through
    # the moment a library wraps it in a dictionary.
    assert "vexpath_live_xxx" not in text
    assert "vexpath_live_yyy" not in text
    assert "whsec_zzz" not in text
    assert "keep me" in text


def test_a_cookie_is_redacted() -> None:
    event: dict[str, Any] = {"extra": {"cookies": {"vexpath_session": "live-token"}}}
    scrubbed = tracing.scrub(event)
    assert scrubbed is not None
    # A session cookie is a live credential, not a diagnostic.
    assert "live-token" not in str(scrubbed)


def test_a_webhook_secret_is_redacted() -> None:
    event: dict[str, Any] = {"extra": {"secret_encrypted": "gAAAA...", "secret": "whsec_x"}}
    scrubbed = tracing.scrub(event)
    assert scrubbed is not None
    assert "whsec_x" not in str(scrubbed)
    assert "gAAAA" not in str(scrubbed)


def test_the_sbom_and_source_keys_are_redacted() -> None:
    event: dict[str, Any] = {
        "extra": {"sbom": {"components": ["everything we depend on"]}, "source": "def f(): ..."}
    }
    scrubbed = tracing.scrub(event)
    assert scrubbed is not None
    assert "everything we depend on" not in str(scrubbed)
    assert "def f()" not in str(scrubbed)


def test_ordinary_diagnostic_fields_survive() -> None:
    event: dict[str, Any] = {
        "message": "something failed",
        "level": "error",
        "extra": {"scan_id": "01JSCAN", "org_id": "01JORG", "route": "/v1/scans"},
    }
    scrubbed = tracing.scrub(event)
    assert scrubbed is not None
    # A scrubber that removed these would make the reporting useless, which is
    # the other way to get this wrong.
    assert scrubbed["extra"]["scan_id"] == "01JSCAN"
    assert scrubbed["extra"]["route"] == "/v1/scans"


def test_a_deeply_nested_structure_does_not_hang() -> None:
    event: dict[str, Any] = {}
    cursor = event
    for _ in range(200):
        nested: dict[str, Any] = {}
        cursor["next"] = nested
        cursor = nested
    cursor["token"] = "deep"
    # Bounded depth: an event is JSON from a library, and error reporting must
    # not become a hang because something arrived absurdly nested. The cost is
    # that something very deep is not reached, which is why the section drop
    # and the no-locals setting are the first lines rather than this.
    assert tracing.scrub(event) is not None


def test_a_cycle_does_not_hang() -> None:
    event: dict[str, Any] = {"extra": {}}
    event["extra"]["self"] = event
    assert tracing.scrub(event) is not None


# --- Configuration ----------------------------------------------------------


def test_no_dsn_means_no_reporting() -> None:
    settings = Settings(env=Environment.TEST)
    assert settings.error_reporting_configured is False
    # Returns False rather than raising: the right default for a tool people
    # run against their own code is to send nothing anywhere.
    assert tracing.configure_sentry(settings) is False


def test_a_dsn_without_the_library_says_so_rather_than_pretending() -> None:
    import sys

    settings = Settings(env=Environment.TEST, sentry_dsn="https://key@example.ingest.test/1")
    saved = sys.modules.get("sentry_sdk")
    sys.modules["sentry_sdk"] = None  # type: ignore[assignment]
    try:
        # A deployment that believes it has error reporting and does not is
        # worse off than one that knows it has none.
        assert tracing.configure_sentry(settings) is False
    finally:
        if saved is None:
            del sys.modules["sentry_sdk"]
        else:
            sys.modules["sentry_sdk"] = saved
