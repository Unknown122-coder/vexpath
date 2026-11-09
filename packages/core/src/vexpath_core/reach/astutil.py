"""Small AST helpers shared by the builder and entry-point detection."""

from __future__ import annotations

import ast


def dotted_name(node: ast.AST) -> str | None:
    """Flatten ``a.b.c`` into a string, or return None if it is not a name.

    Used wherever a written expression has to be matched against an import
    table. Anything more complex than a name or an attribute chain, such as a
    subscript or a call result, is deliberately not guessed at.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def decorator_names(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> list[str]:
    """Return each decorator as a dotted name, ignoring its arguments.

    ``@app.route("/x", methods=["GET"])`` yields ``app.route``, which is what
    identifies the framework convention.
    """
    names: list[str] = []
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = dotted_name(target)
        if name:
            names.append(name)
    return names


def is_dunder_main_guard(node: ast.AST) -> bool:
    """Whether a statement is ``if __name__ == "__main__":``."""
    if not isinstance(node, ast.If):
        return False
    test = node.test
    if not isinstance(test, ast.Compare) or len(test.comparators) != 1:
        return False
    left = test.left
    right = test.comparators[0]
    return (
        isinstance(left, ast.Name)
        and left.id == "__name__"
        and isinstance(right, ast.Constant)
        and right.value == "__main__"
    )


__all__ = ["decorator_names", "dotted_name", "is_dunder_main_guard"]
