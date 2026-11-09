"""Jinja2 environment for the HTML UI.

Autoescaping is on for every template, without exception. Component names,
licence strings and advisory text all originate outside this system, and the
threat model treats every one of them as attacker-controlled.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from vexpath_api import __version__
from vexpath_platform.settings import Settings

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


def build_templates(settings: Settings) -> Jinja2Templates:
    """Create the template environment.

    ``autoescape`` is Jinja2's default for ``.html`` through
    ``select_autoescape``, and is asserted here rather than assumed.
    """
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.autoescape = True
    templates.env.trim_blocks = True
    templates.env.lstrip_blocks = True
    # Values every page needs. Keeping them in globals avoids each handler
    # having to remember to pass them.
    templates.env.globals.update(
        app_version=__version__,
        environment=settings.env.value,
        base_url=settings.base_url,
    )
    return templates


def render(
    request: Request,
    name: str,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
) -> HTMLResponse:
    """Render a template with the shared environment."""
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name=name,
        context=context or {},
        status_code=status_code,
    )


__all__ = ["STATIC_DIR", "TEMPLATES_DIR", "build_templates", "render"]
