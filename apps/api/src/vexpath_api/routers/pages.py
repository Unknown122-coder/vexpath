"""HTML routes.

Server-rendered pages (ADR-0011). Handlers here return complete documents, or
fragments when HTMX asks for one. No handler returns JSON; that is what ``/v1``
is for.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

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


__all__ = ["router"]
