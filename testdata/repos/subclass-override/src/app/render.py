"""Renders markup through a subclass that enables the vulnerable filter."""

from jinja2 import Environment
from jinja2.filters import do_xmlattr


class Renderer:
    """Base renderer. Reaches nothing vulnerable."""

    def attributes(self, values: dict[str, str]) -> str:
        return " ".join(f'{key}="{value}"' for key, value in values.items())


class XmlAttrRenderer(Renderer):
    """Override that delegates to the vulnerable filter."""

    def attributes(self, values: dict[str, str]) -> str:
        return do_xmlattr(Environment(autoescape=True), values)


def render_page(renderer: Renderer, values: dict[str, str]) -> str:
    # Statically this is Renderer.attributes; only hierarchy analysis finds the
    # override that actually runs.
    return f"<div {renderer.attributes(values)}></div>"


def main() -> None:
    print(render_page(XmlAttrRenderer(), {"class": "card"}))
