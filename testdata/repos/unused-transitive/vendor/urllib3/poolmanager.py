"""PoolManager.urlopen is the symbol CVE-2023-45803 points at."""


class PoolManager:
    def urlopen(self, method, url, **kwargs):
        return None
