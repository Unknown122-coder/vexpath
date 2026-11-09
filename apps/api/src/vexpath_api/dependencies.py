"""Shared FastAPI dependencies.

Long-lived resources (the database engine, the template environment) are
created once during the application lifespan and reached through these
accessors, so that nothing is constructed per request and tests can replace
them wholesale.
"""

from __future__ import annotations

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncEngine

from vexpath_platform.settings import Settings


def get_settings_from_app(request: Request) -> Settings:
    """Return the settings this application was built with."""
    settings: Settings = request.app.state.settings
    return settings


def get_engine(request: Request) -> AsyncEngine:
    """Return the shared database engine."""
    engine: AsyncEngine = request.app.state.engine
    return engine


__all__ = ["get_engine", "get_settings_from_app"]
