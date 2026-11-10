"""Run the application for the acceptance tests, in its own process.

A separate process rather than a thread, because of a genuine conflict between
two requirements on Windows:

- psycopg's asynchronous mode needs a **selector** event loop, which is why
  ``vexpath_platform.eventloop.configure_event_loop()`` sets that policy for
  the process;
- Playwright's synchronous API starts its driver with
  ``asyncio.create_subprocess_exec``, which a selector loop does not support
  at all — it raises ``NotImplementedError``.

One process cannot satisfy both, and the event-loop policy is process-wide. So
the server gets its own process with the selector policy it needs, and the test
process keeps the proactor policy Playwright needs. Running them together in
one process fails immediately and confusingly, which is why this file exists
and says so.

The fake identity provider lives here, in test code, rather than behind a
setting the application reads. A deployment must have no way to switch its
sign-in for a stand-in, so there is no flag to find.

Invoked as:

    python run_server.py --port 8123 --database-url ... --secret-key ...
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field


@dataclass
class FakeProvider:
    """Signs in without a network, a secret, or somebody's GitHub account."""

    identities: dict[str, object] = field(default_factory=dict)

    @property
    def provider(self) -> str:
        return "github"

    def authorize_url(self, *, redirect_uri: str, state: str) -> str:
        # Straight back to the callback, which is what a real provider does
        # once the user approves. This application's half of the flow is what
        # is under test.
        return f"{redirect_uri}?code=ok&state={state}"

    async def identity(self, *, code: str, redirect_uri: str) -> object:
        del redirect_uri
        from vexpath_api.oauth import Identity, OAuthError

        if code != "ok":
            msg = "unknown code"
            raise OAuthError(msg)
        return Identity(subject="E2E-1", login="acceptance", name="Acceptance Ltd", email=None)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--secret-key", required=True)
    arguments = parser.parse_args()

    import uvicorn

    from vexpath_api.main import create_app
    from vexpath_db.engine import create_app_engine
    from vexpath_platform.settings import Environment, Settings

    settings = Settings(
        env=Environment.TEST,
        database_url=arguments.database_url,
        secret_key=arguments.secret_key,
        base_url=f"http://127.0.0.1:{arguments.port}",
        # Off: the acceptance tests make a few dozen requests in a few
        # seconds, which is the shape a limiter exists to refuse, and what is
        # under test here is the interface rather than the limiter.
        rate_limit_enabled=False,
    )
    engine = create_app_engine(arguments.database_url)
    app = create_app(settings, engine=engine, identity_provider=FakeProvider())
    from vexpath_platform.eventloop import UVICORN_LOOP_FACTORY

    # The flag the Makefile and the Dockerfile pass, for the same reason:
    # uvicorn builds its own loop and would pick one psycopg cannot use.
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=arguments.port,
        log_level="warning",
        loop=UVICORN_LOOP_FACTORY,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
