"""Resolves the handler method by name at runtime."""

from fixturelib.handlers import Handler


def handle(action: str, payload: dict[str, str]) -> str:
    handler = Handler()
    # The callee cannot be determined statically: 'process' is only one of the
    # names this can produce.
    method = getattr(handler, action)
    result: str = method(payload)
    return result
