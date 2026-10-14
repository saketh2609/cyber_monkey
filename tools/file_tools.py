
"""Filesystem handlers for Hackurity's authorized runtime."""

from pathlib import Path
from typing import Any, Mapping

MAX_READ_BYTES = 1_000_000
MAX_WRITE_BYTES = 1_000_000


def _reject_symlink(path: Path) -> None:
    """Reject symlinks in the target path and its parent chain."""
    current = path

    while True:
        if current.is_symlink():
            raise PermissionError("Symbolic links are not allowed.")

        parent = current.parent
        if parent == current:
            break
        current = parent


def read_file(target: Path, arguments: Mapping[str, Any]) -> str:
    """Read a bounded-size regular file."""
    _reject_symlink(target)

    if not target.is_file():
        raise ValueError("Target is not an existing file.")

    if target.stat().st_size > MAX_READ_BYTES:
        raise ValueError("File exceeds the read size limit.")

    return target.read_text(encoding="utf-8")


def list_files(target: Path, arguments: Mapping[str, Any]) -> list[str]:
    """List entries in an authorized directory."""
    _reject_symlink(target)

    if not target.is_dir():
        raise ValueError("Target is not an existing directory.")

    return sorted(item.name for item in target.iterdir())


def write_file(target: Path, arguments: Mapping[str, Any]) -> str:
    """Write bounded text after authorization and confirmation."""
    _reject_symlink(target)

    content = arguments.get("content")
    if not isinstance(content, str):
        raise ValueError("Content must be a string.")

    if len(content.encode("utf-8")) > MAX_WRITE_BYTES:
        raise ValueError("Content exceeds the write size limit.")

    if not target.parent.is_dir():
        raise ValueError("Parent directory does not exist.")

    target.write_text(content, encoding="utf-8")
    return f"File written: {target.name}"


def delete_file(target: Path, arguments: Mapping[str, Any]) -> str:
    """Delete a regular file after authorization and confirmation."""
    _reject_symlink(target)

    if not target.is_file():
        raise ValueError("Target is not an existing file.")

    target.unlink()
    return f"File deleted: {target.name}"
