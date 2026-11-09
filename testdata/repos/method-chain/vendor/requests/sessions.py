"""Sessions. Session.send is the symbol CVE-2024-35195 points at."""

from .adapters import HTTPAdapter


class Session:
    def __init__(self):
        self.adapter = HTTPAdapter()

    def request(self, method, url, **kwargs):
        return self.send(None, **kwargs)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, data=None, **kwargs):
        return self.request("POST", url, **kwargs)

    def send(self, request, **kwargs):
        return self.adapter.send(request, **kwargs)
