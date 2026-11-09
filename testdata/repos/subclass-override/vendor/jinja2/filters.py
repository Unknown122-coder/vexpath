"""Filters. do_xmlattr is the symbol CVE-2024-22195 points at."""


def do_xmlattr(environment, d, autospace=True):
    return " ".join(f'{key}="{value}"' for key, value in d.items())
