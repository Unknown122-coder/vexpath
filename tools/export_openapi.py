"""Write the OpenAPI document to ``apps/api/openapi.json``.

The specification is committed rather than only served, and that is a decision
with a point: a committed document turns an accidental breaking change into a
diff somebody has to look at. Renaming a field, narrowing a type or dropping an
endpoint all show up in review, where they are cheap, instead of in a client's
CI, where they are not.

A test asserts the file matches what the application would serve, so the
document cannot drift. Run this when an endpoint changes:

    uv run python tools/export_openapi.py

Only ``/v1`` is in here. The HTML routes are excluded at the router, because a
schema describing pages nobody calls programmatically is noise that makes the
part people do call harder to read.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "apps" / "api" / "openapi.json"


def document() -> dict[str, Any]:
    """The specification the application would serve.

    Built from an application with no database connection: generating a schema
    must not require a running Postgres, or the document becomes something
    only CI can produce.
    """
    from vexpath_api.main import create_app
    from vexpath_platform.settings import Environment, Settings

    # A non-production environment, because production turns the schema route
    # off and would hand back nothing.
    app = create_app(Settings(env=Environment.LOCAL))
    schema: dict[str, Any] = app.openapi()
    return schema


def render(schema: dict[str, Any]) -> str:
    """Serialise deterministically.

    Sorted keys and a trailing newline, so the diff of a real change is the
    change and not a reordering.
    """
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    text = render(document())
    existing = DESTINATION.read_text(encoding="utf-8") if DESTINATION.is_file() else None
    if existing == text:
        print(f"{DESTINATION.relative_to(ROOT)} is already up to date")
        return 0

    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    DESTINATION.write_text(text, encoding="utf-8")
    print(f"wrote {DESTINATION.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
