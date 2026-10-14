
"""Check whether a requested tool is registered and policy-allowed."""

from collections.abc import Mapping, Set
from typing import Any


def val_tool_name(
    tool_name: str,
    registered_tools: Mapping[str, Any],
    allowed_tools: Set[str],
) -> bool:
    """Raise an exception unless the tool passes both checks."""

    if not isinstance(tool_name, str) or not tool_name.strip():
        raise ValueError("Invalid tool name.")

    if not isinstance(registered_tools, Mapping):
        raise TypeError("Tool registry must be a mapping.")

    if not isinstance(allowed_tools, Set):
        raise TypeError("Allowed tools must be a set or similar collection.")

    # Check the allowlist before dispatching the tool.
    if tool_name not in allowed_tools:
        raise PermissionError(
            f"Tool '{tool_name}' is not allowed by policy."
        )

    # Registered tools must have callable implementations.
    if tool_name not in registered_tools:
        raise PermissionError(
            f"Tool '{tool_name}' is not registered."
        )

    if not callable(registered_tools[tool_name]):
        raise PermissionError(
            f"Tool '{tool_name}' has no callable implementation."
        )

    return True

