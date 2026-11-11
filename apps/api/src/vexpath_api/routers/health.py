"""Liveness and readiness.

The two are separate on purpose. ``/healthz`` answers "is this process alive",
which is what a container orchestrator restarts on. ``/readyz`` answers "can it
serve traffic", which depends on the database and must not cause a restart loop
when a dependency is briefly unavailable.
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from vexpath_api import __version__
from vexpath_api.dependencies import get_engine
from vexpath_core import RESULTS_SCHEMA
from vexpath_core import __version__ as core_version
from vexpath_core.enums import REACHABILITY_ECOSYSTEMS
from vexpath_platform.logging import get_logger

log = get_logger(__name__)

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Liveness payload."""

    status: Literal["ok"]
    api_version: str
    core_version: str
    results_schema: str
    #: Ecosystems this build can analyse for reachability. Published here so a
    #: client can tell what a verdict from this deployment actually covers.
    reachability_ecosystems: list[str]


class DependencyStatus(BaseModel):
    """State of one external dependency."""

    name: str
    ok: bool
    detail: str | None = None


class ReadinessResponse(BaseModel):
    """Readiness payload."""

    ready: bool
    dependencies: list[DependencyStatus]


@router.get("/healthz", response_model=HealthResponse, summary="Liveness probe")
async def healthz() -> HealthResponse:
    """Report that the process is alive.

    Deliberately touches nothing external: a database outage must not make the
    orchestrator kill a process that is working fine.
    """
    return HealthResponse(
        status="ok",
        api_version=__version__,
        core_version=core_version,
        results_schema=RESULTS_SCHEMA,
        reachability_ecosystems=sorted(REACHABILITY_ECOSYSTEMS),
    )


#: How long the readiness probe may take to answer.
#:
#: Belt and braces over the connection timeout in ``vexpath_db.engine``: that
#: one bounds *connecting*, and a server that accepts a connection and then
#: never answers ``SELECT 1`` would still hang here. Shorter than the
#: orchestrator's own check timeout (``infra/fly.toml`` says five seconds), so
#: the probe gets to report "not ready" rather than being cut off and leaving
#: the reason nowhere.
PROBE_TIMEOUT_SECONDS = 3.0


@router.get("/readyz", response_model=ReadinessResponse, summary="Readiness probe")
async def readyz(
    response: Response,
    engine: Annotated[AsyncEngine, Depends(get_engine)],
) -> ReadinessResponse:
    """Report whether the process can serve traffic.

    Returns 503 when a dependency is down, so a load balancer stops sending
    requests, while leaving the process running.
    """
    dependencies = [await _check_database(engine)]
    ready = all(dependency.ok for dependency in dependencies)
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(ready=ready, dependencies=dependencies)


async def _check_database(engine: AsyncEngine) -> DependencyStatus:
    try:
        async with asyncio.timeout(PROBE_TIMEOUT_SECONDS):
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
    except TimeoutError:
        # Reported like any other failure, but named, because "it did not
        # answer in time" and "it refused the connection" send an operator to
        # different places.
        log.warning("readiness.database_timeout", seconds=PROBE_TIMEOUT_SECONDS)
        return DependencyStatus(name="database", ok=False, detail="TimeoutError")
    except Exception as exc:  # noqa: BLE001 - any failure means "not ready"
        # The exception type varies by driver and failure mode; the probe only
        # needs to report that the database is unreachable, with enough detail
        # for an operator to act on.
        log.warning("readiness.database_unavailable", error=str(exc))
        return DependencyStatus(name="database", ok=False, detail=type(exc).__name__)
    return DependencyStatus(name="database", ok=True)


__all__ = ["router"]
