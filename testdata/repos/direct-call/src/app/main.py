"""Fetches a URL on every run, reaching the vulnerable request path."""

import requests


def fetch(url: str) -> str:
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return response.text


def main() -> None:
    print(fetch("https://example.invalid/status"))


if __name__ == "__main__":
    main()
