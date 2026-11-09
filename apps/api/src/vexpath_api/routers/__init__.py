"""HTTP routers.

Two groups, deliberately separate (ADR-0011): modules serving JSON under
``/v1`` and modules serving HTML everywhere else. Both call the same service
layer, so a page and an API response can never disagree.
"""

from __future__ import annotations
