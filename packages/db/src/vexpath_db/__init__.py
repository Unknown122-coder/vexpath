"""Database schema and engine helpers shared by the API and the workers.

The analysis core deliberately knows nothing about this package: a scan must
work with no database present. Everything here serves persistence and history,
never verdicts.
"""

from __future__ import annotations

from vexpath_db.tables import metadata

__all__ = ["metadata"]
