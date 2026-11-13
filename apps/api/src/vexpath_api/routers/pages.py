"""HTML routes.

Server-rendered pages (ADR-0011). Handlers here return complete documents, or
fragments when HTMX asks for one. No handler returns JSON; that is what ``/v1``
is for.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine

from vexpath_api.api_reference import sections
from vexpath_api.dependencies import get_engine, get_settings_from_app
from vexpath_api.templating import render
from vexpath_core import __version__ as core_version
from vexpath_core.enums import REACHABILITY_ECOSYSTEMS
from vexpath_db.tables import vulnerable_symbols
from vexpath_platform.logging import get_logger

log = get_logger(__name__)

router = APIRouter(include_in_schema=False)


@router.get("/", response_class=HTMLResponse, summary="Home page")
async def home(
    request: Request, engine: Annotated[AsyncEngine, Depends(get_engine)]
) -> HTMLResponse:
    """The public home page.

    Reads one number -- how many packages have had their vulnerable functions
    extracted -- because a claim about the corpus should be counted rather
    than written down, and a number typed into a template is wrong the day
    after it is typed.

    The number is decorative and the page is not. Taking a connection as a
    dependency made the landing page fail outright when the database was
    unavailable: ``/healthz`` would answer while the front page returned 500.
    So the engine arrives lazily, the count is attempted, and a failure
    leaves the page with one sentence missing instead of no page at all.
    """
    return render(
        request,
        "index.html",
        {
            "core_version": core_version,
            "reachability_ecosystems": sorted(REACHABILITY_ECOSYSTEMS),
            "package_count": await _package_count(engine),
        },
    )


async def _package_count(engine: AsyncEngine) -> int | None:
    """Packages with extracted symbols, or None if the corpus cannot be read.

    ``vulnerable_symbols`` is a global table the application may only read,
    so this needs no tenant or public context -- just a connection.
    """
    try:
        async with engine.connect() as connection:
            result = await connection.execute(
                select(func.count(func.distinct(vulnerable_symbols.c.package_name)))
            )
            return int(result.scalar_one())
    except Exception as exc:  # noqa: BLE001 - any failure means "no number"
        log.warning("api.home.package_count_unavailable", error=str(exc))
        return None


@router.get("/api", response_class=HTMLResponse, summary="API reference")
async def api_reference(request: Request) -> HTMLResponse:
    """The API reference, rendered from the application's own schema.

    Generated per request rather than from a committed copy: a reference
    cannot be out of date with the routes if it is built from them. The
    previous answer here was a link to ``/docs``, which production disables
    because Swagger UI needs a third-party script this site's
    Content-Security-Policy refuses -- so both links in the navigation
    answered 404.
    """
    settings = get_settings_from_app(request)
    return render(
        request,
        "api_reference.html",
        {
            "sections": sections(request.app.openapi()),
            "version": core_version,
            "base_url": settings.base_url.rstrip("/"),
            # Only when the raw document is actually served. Linking to it
            # otherwise would replace one dead link with another.
            "spec_url": request.app.openapi_url,
        },
    )


__all__ = ["router"]
