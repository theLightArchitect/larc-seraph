"""Normalize macOS telemetry into the larc-seraph Sigma field contract.

The rules use Image, CommandLine, ParentImage, TargetFilename, and User.
Collectors do not. These functions are the field mapping for three shapes:

- eslogger JSON, as printed by ``eslogger`` on macOS 13 and later. For an
  exec event the acting process is the parent and ``event.exec.target`` is
  the new image. Arguments are joined with spaces.
- Elastic Common Schema, including Elastic Defend's macOS Endpoint Security
  documents.
- osquery ``process_events`` and ``file_events`` rows. Parent path is read
  from ``parent_path`` when a join has already filled it. osquery's stock
  ``process_events`` table stores the parent pid, not the parent path.

Nothing here opens a socket.
"""

from __future__ import annotations

from typing import Any


def _dig(value: Any, *keys: str) -> Any:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _string(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _clean(event: dict[str, Any]) -> dict[str, str]:
    return {key: value for key, value in event.items() if value}


def normalize_eslogger(event: dict[str, Any]) -> dict[str, str]:
    """Map one eslogger JSON object onto the Sigma field contract."""

    exec_event = _dig(event, "event", "exec")
    image = _string(_dig(exec_event, "target", "executable", "path"))
    parent = None
    command = None
    if isinstance(exec_event, dict) and image:
        parent = _string(_dig(event, "process", "executable", "path"))
        args = exec_event.get("args")
        if isinstance(args, list) and args:
            command = " ".join(str(item) for item in args)
        else:
            command = _string(exec_event.get("command"))
    else:
        image = _string(_dig(event, "process", "executable", "path"))
        parent = _string(_dig(event, "process", "parent", "executable", "path"))
    target = (
        _string(_dig(event, "event", "create", "target", "path"))
        or _string(_dig(event, "event", "write", "target", "path"))
        or _string(_dig(event, "event", "rename", "destination", "path"))
    )
    user = _string(_dig(event, "process", "user_name")) or _string(
        _dig(event, "process", "username")
    )
    return _clean(
        {
            "Image": image,
            "CommandLine": command,
            "ParentImage": parent,
            "TargetFilename": target,
            "User": user,
        }
    )


def normalize_ecs(event: dict[str, Any]) -> dict[str, str]:
    """Map one Elastic Common Schema document onto the Sigma field contract."""

    process = event.get("process") if isinstance(event.get("process"), dict) else {}
    parent = process.get("parent") if isinstance(process.get("parent"), dict) else {}
    file_doc = event.get("file") if isinstance(event.get("file"), dict) else {}
    user = event.get("user") if isinstance(event.get("user"), dict) else {}
    return _clean(
        {
            "Image": _string(process.get("executable")),
            "CommandLine": _string(process.get("command_line")),
            "ParentImage": _string(parent.get("executable")),
            "TargetFilename": _string(file_doc.get("path")),
            "User": _string(user.get("name")),
        }
    )


def normalize_osquery(row: dict[str, Any]) -> dict[str, str]:
    """Map one osquery process_events or file_events row onto the contract.

    ``parent_path`` is not a stock ``process_events`` column. Rows that have
    it were joined. A row with only ``parent`` (a pid) leaves ParentImage
    empty, and rules that require a parent will not fire.
    """

    return _clean(
        {
            "Image": _string(row.get("path") or row.get("image")),
            "CommandLine": _string(row.get("cmdline") or row.get("command_line")),
            "ParentImage": _string(row.get("parent_path")),
            "TargetFilename": _string(row.get("target_path")),
            "User": _string(row.get("username") or row.get("user")),
        }
    )


NORMALIZERS = {
    "eslogger": normalize_eslogger,
    "ecs": normalize_ecs,
    "osquery": normalize_osquery,
}
