
"""Validate tool names and arguments before tool execution."""

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit


TOOL_SCHEMAS = {
    "read_file": {"path": str},
    "write_file": {"path": str, "content": str},
    "delete_file": {"path": str},
    "query_database": {"query": str, "params": dict},
    "execute_command": {"command": str, "args": list},
    "fetch_url": {"url": str},
}

MAX_STRING_LENGTH = 100_000
MAX_CONTAINER_ITEMS = 1_000


def val_tool_arg(tool_name: str, arguments: Mapping[str, Any]) -> bool:
    """Raise an exception if the tool arguments are invalid."""

    if not isinstance(tool_name, str) or not tool_name:
        raise ValueError("Invalid tool name.")

    schema = TOOL_SCHEMAS.get(tool_name)
    if schema is None:
        raise PermissionError(
            f"No schema defined for tool '{tool_name}'."
        )

    if not isinstance(arguments, Mapping):
        raise ValueError("Arguments must be a mapping.")

    # Require exactly the expected keys.
    if set(arguments.keys()) != set(schema.keys()):
        raise ValueError(
            f"Incorrect argument names for '{tool_name}'."
        )

    for name, expected_type in schema.items():
        value = arguments[name]

        # Exact types avoid accepting subclasses unexpectedly.
        if type(value) is not expected_type:
            raise ValueError(
                f"'{name}' must be a {expected_type.__name__}."
            )

        if isinstance(value, str):
            if not value.strip():
                raise ValueError(f"'{name}' cannot be empty.")

            if len(value) > MAX_STRING_LENGTH:
                raise ValueError(
                    f"'{name}' exceeds the size limit."
                )

        elif isinstance(value, (dict, list)):
            if len(value) > MAX_CONTAINER_ITEMS:
                raise ValueError(
                    f"'{name}' contains too many items."
                )

    # Basic URL syntax check; this is not SSRF protection.
    if tool_name == "fetch_url":
        parsed = urlsplit(arguments["url"])

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("URL must be a valid HTTP or HTTPS URL.")

        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing credentials are not allowed.")

    return True
