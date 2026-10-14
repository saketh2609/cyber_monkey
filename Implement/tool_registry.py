
"""Central registry of tools available to Hackurity."""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.file_tools import (
    read_file,
    list_files,
    write_file,
    delete_file,
)

TOOL_HANDLERS = {
    "read_file": read_file,
    "list_files": list_files,
    "write_file": write_file,
    "delete_file": delete_file,
}


def get_tool_handler(tool_name: str):
    """Return a registered tool handler or reject unknown tools."""
    if tool_name not in TOOL_HANDLERS:
        raise PermissionError(f"Tool is not registered: {tool_name}")

    return TOOL_HANDLERS[tool_name]
