"""Minimal stand-in for PyYAML.

The advisory for CVE-2020-14343 names the yaml.constructor *module*,
not a function in it, so importing this package has to reach it. That
is exactly what the real package does.
"""

from .constructor import SafeConstructor
