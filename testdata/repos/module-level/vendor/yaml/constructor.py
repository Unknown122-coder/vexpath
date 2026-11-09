"""Constructors. The module itself is the symbol the advisory names."""


class SafeConstructor:
    def construct(self, node):
        return {}


def safe_load(stream):
    return SafeConstructor().construct(stream)
