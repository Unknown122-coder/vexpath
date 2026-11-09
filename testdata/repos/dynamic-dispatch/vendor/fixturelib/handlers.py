"""Handlers, one of which is the fixture's vulnerable symbol."""


class Handler:
    def process(self, payload: dict[str, str]) -> str:
        """The vulnerable symbol for CVE-2024-FIXTURE-DYNAMIC."""
        return ";".join(f"{key}={value}" for key, value in payload.items())

    def validate(self, payload: dict[str, str]) -> str:
        return "ok" if payload else "empty"
