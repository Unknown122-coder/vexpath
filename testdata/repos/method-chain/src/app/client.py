"""Holds a session on an attribute, then calls through it."""

from requests import Session


class UpstreamClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        # Assigned here, called in fetch(): resolving this needs the
        # assignment-flow pass, not just name resolution.
        self.session = Session()

    def fetch(self, path: str) -> str:
        response = self.session.get(f"{self.base_url}{path}", timeout=10)
        return response.text


def build_client() -> UpstreamClient:
    client = UpstreamClient("https://example.invalid")
    client.fetch("/health")
    return client
