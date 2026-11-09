"""Top-level helpers, which open a session per call."""

from .sessions import Session


def get(url, **kwargs):
    session = Session()
    return session.request("GET", url, **kwargs)


def post(url, data=None, **kwargs):
    session = Session()
    return session.request("POST", url, **kwargs)
