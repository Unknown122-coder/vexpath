"""Transport adapters. HTTPAdapter.send is the second affected symbol."""


class HTTPAdapter:
    def send(self, request, **kwargs):
        return None
