"""Credential handling and the upload path.

Two things are tested here that matter more than the happy path.

**The secret never appears anywhere it could be read later.** Not in output,
not in a repr, not in a file anybody else can open. A test asserts the absence
of the secret in every stream a command writes, because the ways a credential
leaks are all variations on "something printed it once".

**Which credential is in use is never ambiguous.** The environment overrides
the stored file on purpose, and the commands say so. A build machine where a
stale file silently shadows the CI secret is the failure this ordering exists
to prevent, so the ordering is asserted rather than assumed.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from vexpath import credentials
from vexpath.exit_codes import ExitCode
from vexpath.main import app

runner = CliRunner()

#: Shaped like a real key, long enough to pass the shape check, and obviously
#: not a real one to anybody who finds it in a log.
KEY = "vexpath_live_" + "t" * 43
OTHER_KEY = "vexpath_live_" + "z" * 43

IDENTITY = {
    "org_id": "01JTEST0000000000000000000",
    "org_slug": "acme",
    "org_name": "Acme Corporation",
    "actor_type": "api_key",
    "actor_id": "01JKEY00000000000000000000",
    "project_count": 3,
}

API = "https://platform.example"


class Platform:
    """A stand-in for the API, recording what the CLI actually sent.

    Recording the requests rather than only their effects is deliberate: the
    thing most worth checking about an upload is the header it carried and the
    body it posted, and neither is visible from the response.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.me_status = 200
        self.scan_status = 201
        self.scan_body: dict[str, Any] = {"id": "01JSCAN0000000000000000000"}
        self.accepted_key = KEY

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/v1/me":
            if request.headers.get("Authorization") != f"Bearer {self.accepted_key}":
                return httpx.Response(401, json={"detail": "nope"})
            return httpx.Response(self.me_status, json=IDENTITY)
        if request.url.path == "/v1/scans":
            return httpx.Response(self.scan_status, json=self.scan_body)
        return httpx.Response(404, json={"detail": "no such path"})


@pytest.fixture
def platform(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Platform]:
    """A CLI pointed at a fake platform, with its own configuration directory.

    The configuration directory is redirected for every test in this module so
    no test can touch a real developer's credential file, and so a test that
    forgets to clean up cannot affect the next one.
    """
    fake = Platform()
    original: Callable[..., httpx.Client] = httpx.Client

    def client(**kwargs: Any) -> httpx.Client:
        kwargs.pop("transport", None)
        return original(transport=httpx.MockTransport(fake.handle), **kwargs)

    monkeypatch.setattr(httpx, "Client", client)
    monkeypatch.setenv(credentials.HOME_ENVIRONMENT_VARIABLE, str(tmp_path / "config"))
    monkeypatch.setenv(credentials.URL_ENVIRONMENT_VARIABLE, API)
    monkeypatch.delenv(credentials.KEY_ENVIRONMENT_VARIABLE, raising=False)
    yield fake


# --- Storing a credential --------------------------------------------------


def test_login_verifies_the_key_before_storing_it(platform: Platform) -> None:
    result = runner.invoke(app, ["login", "--key", KEY, "--api-url", API])
    assert result.exit_code == 0, result.output
    # Verified first: storing an unchecked key turns a typo into an
    # authentication failure on some later command, with nothing connecting
    # the two.
    assert [request.url.path for request in platform.requests] == ["/v1/me"]
    assert credentials.credential_path().is_file()


def test_login_does_not_store_a_key_the_platform_rejects(platform: Platform) -> None:
    result = runner.invoke(app, ["login", "--key", OTHER_KEY, "--api-url", API])
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    assert not credentials.credential_path().exists()
    assert "rejected that key" in result.output


def test_login_refuses_something_that_is_not_shaped_like_a_key(platform: Platform) -> None:
    platform.accepted_key = "hunter2"
    result = runner.invoke(app, ["login", "--key", "hunter2", "--api-url", API])
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    assert not credentials.credential_path().exists()
    assert "does not look like an API key" in result.output


def test_login_never_prints_the_secret(platform: Platform) -> None:
    result = runner.invoke(app, ["login", "--key", KEY, "--api-url", API])
    assert result.exit_code == 0
    # The whole key must not appear in any stream. The visible prefix is what
    # identifies a key in a confirmation, and it is all that is needed.
    assert KEY not in result.output
    assert credentials.display_prefix_of(KEY) in result.output


def test_login_reads_the_key_from_the_terminal_without_echoing(platform: Platform) -> None:
    result = runner.invoke(app, ["login", "--api-url", API], input=KEY + "\n")
    assert result.exit_code == 0, result.output
    # Prompted rather than passed on the command line, so the key does not
    # land in shell history or in a process listing.
    assert KEY not in result.output
    assert json.loads(credentials.credential_path().read_text(encoding="utf-8"))["api_key"] == KEY


def test_login_says_where_the_credential_was_written(platform: Platform) -> None:
    result = runner.invoke(app, ["login", "--key", KEY, "--api-url", API])
    # A credential whose location is a mystery is one nobody rotates.
    assert str(credentials.credential_path()) in result.output


def test_login_warns_when_an_exported_key_will_shadow_the_stored_one(
    platform: Platform, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(credentials.KEY_ENVIRONMENT_VARIABLE, OTHER_KEY)
    platform.accepted_key = OTHER_KEY
    result = runner.invoke(app, ["login", "--key", OTHER_KEY, "--api-url", API])
    assert result.exit_code == 0, result.output
    # Said at the moment of storing, not discovered three commands later.
    assert "takes precedence" in result.output


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_the_credential_file_is_readable_only_by_its_owner(platform: Platform) -> None:
    runner.invoke(app, ["login", "--key", KEY, "--api-url", API])
    mode = stat.S_IMODE(credentials.credential_path().stat().st_mode)
    assert mode == stat.S_IRUSR | stat.S_IWUSR


def test_login_rejects_a_platform_without_the_identity_endpoint(platform: Platform) -> None:
    result = runner.invoke(app, ["login", "--key", KEY, "--api-url", f"{API}/wrong"])
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    # The remedy named is the one that fixes it: the URL, not the key.
    assert "--api-url" in result.output


# --- Which credential is in use --------------------------------------------


def test_the_environment_wins_over_the_stored_file(
    platform: Platform, monkeypatch: pytest.MonkeyPatch
) -> None:
    credentials.store(KEY, API)
    monkeypatch.setenv(credentials.KEY_ENVIRONMENT_VARIABLE, OTHER_KEY)

    credential = credentials.load()
    assert credential is not None
    # CI supplies a key from a secret; a stale file on a shared build machine
    # must not silently shadow it.
    assert credential.secret == OTHER_KEY
    assert credential.source == "environment"


def test_the_stored_file_is_used_when_nothing_is_exported(platform: Platform) -> None:
    credentials.store(KEY, API)
    credential = credentials.load()
    assert credential is not None
    assert credential.secret == KEY
    assert credential.source == "file"


def test_whoami_names_the_source_that_won(
    platform: Platform, monkeypatch: pytest.MonkeyPatch
) -> None:
    credentials.store(KEY, API)
    monkeypatch.setenv(credentials.KEY_ENVIRONMENT_VARIABLE, KEY)

    result = runner.invoke(app, ["whoami"])
    assert result.exit_code == 0, result.output
    # "Which key am I using" is the question behind most authentication
    # confusion, so the answer is on the screen rather than inferable.
    assert f"${credentials.KEY_ENVIRONMENT_VARIABLE}" in result.output
    assert "Acme Corporation" in result.output
    assert KEY not in result.output


def test_whoami_names_the_file_when_the_file_won(platform: Platform) -> None:
    credentials.store(KEY, API)
    result = runner.invoke(app, ["whoami"])
    assert result.exit_code == 0, result.output
    assert str(credentials.credential_path()) in result.output


def test_whoami_json_carries_the_source(platform: Platform) -> None:
    credentials.store(KEY, API)
    result = runner.invoke(app, ["whoami", "--format", "json"])
    payload = json.loads(result.stdout)
    assert payload["source"] == "file"
    assert payload["org_slug"] == "acme"
    # A machine-readable identity must not carry the secret either: this
    # output gets pasted into issues.
    assert KEY not in result.stdout


def test_whoami_without_a_credential_exits_three(platform: Platform) -> None:
    result = runner.invoke(app, ["whoami"])
    # Three rather than one: there is nothing wrong with the code under
    # analysis, the tool is not configured. CI can tell them apart.
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "vexpath login" in result.output


def test_a_corrupt_credential_file_says_how_to_recover(platform: Platform) -> None:
    path = credentials.credential_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")

    result = runner.invoke(app, ["whoami"])
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "Delete it" in result.output


def test_a_credential_repr_hides_the_secret() -> None:
    credential = credentials.Credential(secret=KEY, api_url=API, source="file")
    # Tracebacks are produced exactly when attention is elsewhere.
    assert KEY not in repr(credential)
    assert credentials.display_prefix_of(KEY) in repr(credential)


# --- Logging out -----------------------------------------------------------


def test_logout_removes_the_file(platform: Platform) -> None:
    credentials.store(KEY, API)
    result = runner.invoke(app, ["logout"])
    assert result.exit_code == 0
    assert not credentials.credential_path().exists()


def test_logout_is_not_an_error_when_there_was_nothing_stored(platform: Platform) -> None:
    result = runner.invoke(app, ["logout"])
    assert result.exit_code == 0
    assert "no stored credential" in result.output


def test_logout_says_when_an_exported_key_still_authenticates(
    platform: Platform, monkeypatch: pytest.MonkeyPatch
) -> None:
    credentials.store(KEY, API)
    monkeypatch.setenv(credentials.KEY_ENVIRONMENT_VARIABLE, KEY)

    result = runner.invoke(app, ["logout"])
    assert result.exit_code == 0
    # Believing you have signed out when you have not is worse than being
    # told the awkward truth now.
    assert "still set" in result.output


# --- Uploading -------------------------------------------------------------


@pytest.fixture
def results_document(tmp_path: Path, fixture_repos_dir: Path, snapshot_dir: Path) -> Path:
    """A real scan result, produced by the CLI rather than written by hand.

    Hand-written fixtures drift from what the analysis emits, and this is
    exactly the document whose compatibility with the server is the point.
    """
    environment = dict(os.environ)
    environment["VEXPATH_ADVISORY_SNAPSHOT_DIR"] = str(snapshot_dir)
    result = runner.invoke(
        app,
        ["scan", str(fixture_repos_dir / "direct-call"), "--format", "json", "--no-reach"],
        env={"VEXPATH_ADVISORY_SNAPSHOT_DIR": str(snapshot_dir)},
    )
    assert result.exit_code == 0, result.output
    path = tmp_path / "results.json"
    path.write_text(result.stdout, encoding="utf-8")
    return path


def test_upload_sends_the_document_with_the_project(
    platform: Platform, results_document: Path
) -> None:
    credentials.store(KEY, API)
    result = runner.invoke(app, ["upload", str(results_document), "--project", "web"])
    assert result.exit_code == 0, result.output

    posted = [request for request in platform.requests if request.url.path == "/v1/scans"]
    assert len(posted) == 1
    body = json.loads(posted[0].content)
    assert body["project"] == "web"
    assert body["results"]["schema"] == "vexpath.results/1"
    assert posted[0].headers["Authorization"] == f"Bearer {KEY}"


def test_upload_validates_the_document_before_sending_it(
    platform: Platform, tmp_path: Path
) -> None:
    credentials.store(KEY, API)
    broken = tmp_path / "broken.json"
    broken.write_text('{"schema": "vexpath.results/1"}', encoding="utf-8")

    result = runner.invoke(app, ["upload", str(broken), "--project", "web"])
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    # Nothing was sent: the message is about the file, not a 422 describing a
    # field the user never chose.
    assert not [request for request in platform.requests if request.url.path == "/v1/scans"]
    assert str(broken) in result.output


def test_upload_rejects_a_file_that_is_not_json(platform: Platform, tmp_path: Path) -> None:
    credentials.store(KEY, API)
    path = tmp_path / "notes.txt"
    path.write_text("ran the scan, looked fine", encoding="utf-8")

    result = runner.invoke(app, ["upload", str(path), "--project", "web"])
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "not readable JSON" in result.output


def test_upload_without_a_credential_exits_three(
    platform: Platform, results_document: Path
) -> None:
    result = runner.invoke(app, ["upload", str(results_document), "--project", "web"])
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "vexpath login" in result.output


def test_upload_to_a_project_that_does_not_exist_says_which(
    platform: Platform, results_document: Path
) -> None:
    credentials.store(KEY, API)
    platform.scan_status = 404
    result = runner.invoke(app, ["upload", str(results_document), "--project", "typo"])
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "'typo'" in result.output


def test_a_refused_upload_says_the_scan_itself_completed(
    platform: Platform, results_document: Path
) -> None:
    credentials.store(KEY, API)
    platform.scan_status = 500
    result = runner.invoke(app, ["upload", str(results_document), "--project", "web"])
    assert result.exit_code == int(ExitCode.ANALYSIS_ERROR)
    # A CI log read in a hurry must not leave anyone thinking the analysis
    # failed when it was the upload.
    assert "scan completed" in result.output


# --- scan --upload ---------------------------------------------------------


def test_scan_upload_posts_the_result(
    platform: Platform, fixture_repos_dir: Path, snapshot_dir: Path
) -> None:
    credentials.store(KEY, API)
    result = runner.invoke(
        app,
        [
            "scan",
            str(fixture_repos_dir / "direct-call"),
            "--no-reach",
            "--upload",
            "--project",
            "web",
        ],
        env={"VEXPATH_ADVISORY_SNAPSHOT_DIR": str(snapshot_dir)},
    )
    assert result.exit_code == 0, result.output
    posted = [request for request in platform.requests if request.url.path == "/v1/scans"]
    assert len(posted) == 1
    assert json.loads(posted[0].content)["project"] == "web"


def test_scan_upload_needs_a_project(
    platform: Platform, fixture_repos_dir: Path, snapshot_dir: Path
) -> None:
    credentials.store(KEY, API)
    result = runner.invoke(
        app,
        ["scan", str(fixture_repos_dir / "direct-call"), "--no-reach", "--upload"],
        env={"VEXPATH_ADVISORY_SNAPSHOT_DIR": str(snapshot_dir)},
    )
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "--project" in result.output


def test_scan_checks_for_a_credential_before_doing_the_work(
    platform: Platform, fixture_repos_dir: Path, snapshot_dir: Path
) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            str(fixture_repos_dir / "direct-call"),
            "--no-reach",
            "--upload",
            "--project",
            "web",
        ],
        env={"VEXPATH_ADVISORY_SNAPSHOT_DIR": str(snapshot_dir)},
    )
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    # Nothing was analysed and nothing was reported: the credential was
    # checked first, so a long scan is not thrown away.
    assert "advisories" not in result.output
    assert "vexpath login" in result.output


def test_project_without_upload_is_refused_rather_than_ignored(
    platform: Platform, fixture_repos_dir: Path, snapshot_dir: Path
) -> None:
    result = runner.invoke(
        app,
        ["scan", str(fixture_repos_dir / "direct-call"), "--no-reach", "--project", "web"],
        env={"VEXPATH_ADVISORY_SNAPSHOT_DIR": str(snapshot_dir)},
    )
    # Ignoring the flag would mean waiting for a result that never arrives on
    # the platform.
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "--upload" in result.output


def test_a_failing_policy_is_still_uploaded(
    platform: Platform, fixture_repos_dir: Path, snapshot_dir: Path
) -> None:
    credentials.store(KEY, API)
    result = runner.invoke(
        app,
        [
            "scan",
            str(fixture_repos_dir / "direct-call"),
            "--no-reach",
            "--fail-on-findings",
            "--upload",
            "--project",
            "web",
        ],
        env={"VEXPATH_ADVISORY_SNAPSHOT_DIR": str(snapshot_dir)},
    )
    assert result.exit_code == int(ExitCode.POLICY_FAILED)
    # The scan the platform most needs is the one that just failed a gate.
    # Exiting before the upload would mean the record never arrives.
    assert [request for request in platform.requests if request.url.path == "/v1/scans"]


def test_an_upload_failure_does_not_hide_the_report(
    platform: Platform, fixture_repos_dir: Path, snapshot_dir: Path
) -> None:
    credentials.store(KEY, API)
    platform.scan_status = 503
    result = runner.invoke(
        app,
        [
            "scan",
            str(fixture_repos_dir / "direct-call"),
            "--no-reach",
            "--upload",
            "--project",
            "web",
        ],
        env={"VEXPATH_ADVISORY_SNAPSHOT_DIR": str(snapshot_dir)},
    )
    assert result.exit_code == int(ExitCode.ANALYSIS_ERROR)
    # The findings were printed before the upload was attempted, so an outage
    # at the platform does not cost the developer the answer they asked for.
    assert "CVE" in result.output or "GHSA" in result.output
