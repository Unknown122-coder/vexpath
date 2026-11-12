"""The API reference, shaped for a server-rendered page.

The obvious thing here is FastAPI's ``/docs``, and it cannot work. Swagger UI
loads its JavaScript from a CDN, this site sends ``script-src 'self'``, and the
result is a blank page with a console error nobody reads -- so the route was
disabled in production and two links in the navigation pointed at it anyway,
answering ``{"detail":"Not Found"}`` for however long nobody clicked them.

So the reference is rendered here, from the application's own schema rather
than from a committed copy of it: a document generated at request time cannot
go stale, and staleness is the failure mode a hand-written reference has.

Shaping happens in Python rather than in the template because it is a
transformation, and a transformation expressed in Jinja is one nobody can
test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: The order tags appear in. Anything not named here follows, alphabetically:
#: a new router should appear in the reference without being added to a list,
#: just not necessarily where its author would have put it.
TAG_ORDER: tuple[str, ...] = (
    "health",
    "projects",
    "scans",
    "findings",
    "suppressions",
    "webhooks",
    "keys",
)

#: Methods, in the order a reader expects rather than alphabetically.
METHOD_ORDER: tuple[str, ...] = ("get", "post", "put", "patch", "delete")


@dataclass(frozen=True, slots=True)
class Parameter:
    """One path, query or header parameter."""

    name: str
    location: str
    required: bool
    schema: str
    description: str = ""


@dataclass(frozen=True, slots=True)
class Response:
    """One documented response."""

    status: str
    description: str


@dataclass(frozen=True, slots=True)
class Operation:
    """One endpoint, as a reader needs it."""

    method: str
    path: str
    summary: str
    description: str
    authenticated: bool
    parameters: tuple[Parameter, ...] = ()
    request_body: str | None = None
    responses: tuple[Response, ...] = ()


@dataclass(frozen=True, slots=True)
class Section:
    """A group of endpoints under one tag."""

    tag: str
    operations: list[Operation] = field(default_factory=list)


def sections(schema: dict[str, Any]) -> list[Section]:
    """Group an OpenAPI document into tags, in reading order."""
    grouped: dict[str, list[Operation]] = {}

    for path, operations in sorted(schema.get("paths", {}).items()):
        if not isinstance(operations, dict):
            continue
        for method in METHOD_ORDER:
            operation = operations.get(method)
            if not isinstance(operation, dict):
                continue
            tags = operation.get("tags") or ["other"]
            tag = str(tags[0])
            grouped.setdefault(tag, []).append(
                Operation(
                    method=method.upper(),
                    path=path,
                    summary=str(operation.get("summary") or ""),
                    description=_first_paragraph(operation.get("description")),
                    # Every /v1 route takes a bearer API key and nothing else
                    # takes one, so the absence of a security block is worth
                    # showing rather than hiding: a reader needs to know
                    # which calls need a key.
                    authenticated=bool(operation.get("security")) or path.startswith("/v1"),
                    parameters=_parameters(operation),
                    request_body=_request_body(operation),
                    responses=_responses(operation),
                )
            )

    ordered: list[Section] = []
    for tag in TAG_ORDER:
        if tag in grouped:
            ordered.append(Section(tag=tag, operations=grouped.pop(tag)))
    for tag in sorted(grouped):
        ordered.append(Section(tag=tag, operations=grouped[tag]))
    return ordered


def _first_paragraph(description: object) -> str:
    """The summary line of a docstring, without the Args and Raises sections.

    A handler's docstring is written for somebody reading the code, and the
    parts that say which exception is raised are noise on a page about HTTP.
    """
    if not isinstance(description, str):
        return ""
    paragraphs = [block.strip() for block in description.split("\n\n") if block.strip()]
    if not paragraphs:
        return ""
    first = paragraphs[0]
    for heading in ("Args:", "Raises:", "Returns:"):
        if first.startswith(heading):
            return ""
    return " ".join(first.split())


def _parameters(operation: dict[str, Any]) -> tuple[Parameter, ...]:
    found: list[Parameter] = []
    for raw in operation.get("parameters") or []:
        if not isinstance(raw, dict):
            continue
        found.append(
            Parameter(
                name=str(raw.get("name") or ""),
                location=str(raw.get("in") or ""),
                required=bool(raw.get("required")),
                schema=_type_of(raw.get("schema")),
                description=_first_paragraph(raw.get("description")),
            )
        )
    return tuple(found)


def _request_body(operation: dict[str, Any]) -> str | None:
    body = operation.get("requestBody")
    if not isinstance(body, dict):
        return None
    content = body.get("content")
    if not isinstance(content, dict):
        return None
    for media_type, details in content.items():
        if not isinstance(details, dict):
            continue
        name = _schema_name(details.get("schema"))
        return name or str(media_type)
    return None


def _responses(operation: dict[str, Any]) -> tuple[Response, ...]:
    found: list[Response] = []
    for status, details in sorted((operation.get("responses") or {}).items()):
        description = ""
        if isinstance(details, dict):
            description = str(details.get("description") or "")
        found.append(Response(status=str(status), description=description))
    return tuple(found)


def _schema_name(schema: object) -> str | None:
    """The model name behind a ``$ref``, or None for an inline schema."""
    if not isinstance(schema, dict):
        return None
    reference = schema.get("$ref")
    if isinstance(reference, str):
        return reference.rsplit("/", 1)[-1]
    items = schema.get("items")
    if isinstance(items, dict):
        inner = _schema_name(items)
        if inner:
            return f"{inner}[]"
    return None


def _type_of(schema: object) -> str:
    """A short type name for a parameter, good enough to read in a table."""
    if not isinstance(schema, dict):
        return "string"
    name = _schema_name(schema)
    if name:
        return name
    declared = schema.get("type")
    if isinstance(declared, str):
        return declared
    # anyOf covers the optional parameters, which are the common case.
    for key in ("anyOf", "oneOf"):
        options = schema.get(key)
        if isinstance(options, list):
            names = [
                str(option.get("type"))
                for option in options
                if isinstance(option, dict) and option.get("type") not in (None, "null")
            ]
            if names:
                return " or ".join(dict.fromkeys(names))
    return "string"


__all__ = [
    "METHOD_ORDER",
    "TAG_ORDER",
    "Operation",
    "Parameter",
    "Response",
    "Section",
    "sections",
]
