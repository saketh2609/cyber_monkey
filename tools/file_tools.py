
"""Filesystem tools for Hackurity.

These handlers expect an authorized, resolved target path
from the central runtime gateway.
"""

from pathlib import Path
from typing import Any, Mapping


def read_file(target: Path, arguments: Mapping[str, Any]) -> str:
    if not target.is_file():
        raise ValueError("Target is not an existing file.")

    if target.is_symlink():
        raise PermissionError("Symbolic links are not permitted.")

    return target.read_text(encoding="utf-8")


def list_files(target: Path, arguments: Mapping[str, Any]) -> list[str]:
    if not target.is_dir():
        raise ValueError("Target is not an existing directory.")

    if target.is_symlink():
        raise PermissionError("Symbolic links are not permitted.")

    return sorted(item.name for item in target.iterdir())


def write_file(target: Path, arguments: Mapping[str, Any]) -> str:
    content = arguments.get("content")

    if not isinstance(content, str):
        raise ValueError("File content must be a string.")

    if not target.parent.is_dir():
        raise ValueError("Parent directory does not exist.")

    if target.is_symlink():
        raise PermissionError("Symbolic links are not permitted.")

    target.write_text(content, encoding="utf-8")
    return f"File written: {target.name}"


def delete_file(target: Path, arguments: Mapping[str, Any]) -> str:
    if not target.is_file():
        raise ValueError("Target is not an existing file.")

    if target.is_symlink():
        raise PermissionError("Symbolic links are not permitted.")

    target.unlink()
    return f"File deleted: {target.name}"
