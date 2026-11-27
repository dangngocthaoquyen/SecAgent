"""Shared durable file persistence helpers (atomic replace + fsync + exclusive creation).

Used across GenericRunService, testing.generic_runner, and Legacy BatchOrchestrator so that
write failures or process interruptions never corrupt or truncate a previously valid JSON file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from time import sleep
from typing import Any
from uuid import uuid4


def write_atomic_bytes(
    path: Path,
    data: bytes,
    *,
    retries: int = 20,
    retry_delay: float = 0.01,
) -> None:
    """Write ``data`` to a unique sibling temp file, fsync, and atomically replace ``path``.

    If writing, fsyncing, or replacing fails, the temporary file is removed and any existing
    valid file at ``path`` remains untouched.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        max_attempts = max(1, int(retries))
        for attempt in range(max_attempts):
            try:
                os.replace(temporary, target)
                return
            except PermissionError:
                if attempt == max_attempts - 1:
                    raise
                sleep(retry_delay)  # Windows readers briefly deny replacement.
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def write_atomic_json(
    path: Path,
    value: Any,
    *,
    sort_keys: bool = False,
    indent: int | None = None,
    separators: tuple[str, str] | None = None,
    ensure_ascii: bool = True,
    trailing_newline: bool = False,
    retries: int = 20,
    retry_delay: float = 0.01,
) -> None:
    """Serialize ``value`` as UTF-8 JSON and persist it atomically with fsync."""
    text = json.dumps(
        value,
        sort_keys=sort_keys,
        indent=indent,
        separators=separators,
        ensure_ascii=ensure_ascii,
    )
    if trailing_newline:
        text += "\n"
    write_atomic_bytes(
        path,
        text.encode("utf-8"),
        retries=retries,
        retry_delay=retry_delay,
    )


def write_exclusive_json(
    path: Path,
    payload: Any,
    *,
    sort_keys: bool = False,
) -> None:
    """Create a new UTF-8 JSON file exclusively (``open('x')``) with flush + fsync."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as stream:
        json.dump(payload, stream, sort_keys=sort_keys)
        stream.flush()
        os.fsync(stream.fileno())
