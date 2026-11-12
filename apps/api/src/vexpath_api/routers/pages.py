"""HTML routes.

Server-rendered pages (ADR-0011). Handlers here return complete documents, or
fragments when HTMX asks for one. No handler returns JSON; that is what ``/v1``
is for.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from vexpath_api.api_reference import sections
from vexpath_api.dependencies import get_settings_from_app
from vexpath_api.templating import render
from vexpath_core import __version__ as core_version
from vexpath_core.enums import REACHABILITY_ECOSYSTEMS

router = APIRouter(include_in_schema=False)


@router.get("/", response_class=HTMLResponse, summary="Home page")
async def home(request: Request) -> HTMLResponse:
    """The public home page."""
    return render(
        request,
        "index.html",
        {
            "core_version": core_version,
            "reachability_ecosystems": sorted(REACHABILITY_ECOSYSTEMS),
        },
    )


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
