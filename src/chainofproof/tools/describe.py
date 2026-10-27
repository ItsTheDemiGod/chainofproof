"""Typed, compact tool signatures for prompts, and templated argument errors.

Built from the registry's pydantic parameter models (JSON schema), never hand-written, so the
model sees the real names and types. Error messages are templated from the validation error
(parameter name and expected type) and NEVER echo the value the model supplied.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ValidationError

ISO_EXAMPLE = "2000-01-01T00:00:00Z"
ENUM_MAX = 40


def _resolve(node: dict[str, Any], defs: dict[str, Any]) -> dict[str, Any]:
    ref = node.get("$ref")
    return defs[ref.rsplit("/", 1)[-1]] if ref else node


def _type(node: dict[str, Any], defs: dict[str, Any]) -> list[str]:
    """Alternatives of a schema node as short strings (null dropped)."""
    node = _resolve(node, defs)
    if node.get("description") and "anyOf" not in node and "enum" not in node:
        return [node["description"]]
    if "anyOf" in node:
        out: list[str] = []
        for alt in node["anyOf"]:
            out += [t for t in _type(alt, defs) if t not in out]
        return out
    if "enum" in node:
        vals = "|".join(str(v) for v in node["enum"])
        return [f"enum[{vals}]"]
    t = node.get("type")
    if t == "null":
        return []
    if t == "array":
        inner = "|".join(_type(node.get("items", {}), defs)) or "any"
        return [f"list[{inner}]"]
    return [{"string": "str", "integer": "int", "number": "float", "boolean": "bool",
             "object": "object"}.get(t or "", "any")]  # fmt: skip


def param_type(model: type[BaseModel], field: str) -> str:
    """Human-readable expected type of one parameter."""
    schema = model.model_json_schema()
    node = schema.get("properties", {}).get(field, {})
    if node.get("description"):
        return node["description"]
    return "|".join(_type(node, schema.get("$defs", {}))) or "any"


def param_text(model: type[BaseModel], field: str, required: bool, default: Any) -> str:
    """``name[?]: type[=default]`` for one parameter."""
    t = f"{field}{'' if required else '?'}: {param_type(model, field)}"
    return t if required or default in (None, "") else f"{t}={default}"


def signature(name: str, model: type[BaseModel], description: str) -> str:
    """One compact line: name(params): description."""
    params = ", ".join(
        param_text(model, k, f.is_required(), f.default) for k, f in model.model_fields.items()
    )
    return f"{name}({params}): {description}"


def tool_signature(name: str) -> str | None:
    """The signature line of one registered tool, or None for an unknown name."""
    from chainofproof.tools.registry import TOOLS

    spec = TOOLS.get(name)
    return signature(spec.name, spec.params, spec.description) if spec else None


def tool_signature_lines(role: str) -> list[str]:
    """One signature line per tool the role may call (sorted by tool name)."""
    from chainofproof.tools.registry import TOOLS, allowed_tools

    return [signature(n, TOOLS[n].params, TOOLS[n].description) for n in allowed_tools(role)]


def arg_error_message(name: str, model: type[BaseModel], err: ValidationError) -> str:
    """Templated 'invalid arguments' text: parameter names and expected types only."""
    fields = set(model.model_fields)
    parts: dict[str, str] = {}
    unknown = False
    for e in err.errors():
        top = str(e["loc"][0]) if e["loc"] else ""
        if top not in fields:
            unknown = True
        elif e["type"] == "missing":
            parts.setdefault(top, f"{top} is required")
        else:
            parts.setdefault(top, f"{top} expects {param_type(model, top)}")
    msgs = [parts[k] for k in sorted(parts)]
    if unknown:
        msgs.append(f"unknown parameter (allowed: {', '.join(sorted(fields)) or 'none'})")
    return f"invalid arguments for {name}: " + "; ".join(msgs)
