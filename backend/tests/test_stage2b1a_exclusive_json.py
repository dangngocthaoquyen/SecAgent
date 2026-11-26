"""Regression tests for Stage 2B.1a exclusive JSON writer consolidation."""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from workflow.batch import write_exclusive_json


def test_write_exclusive_json_matches_legacy_bytes_and_utf8(tmp_path: Path) -> None:
    payload = {"zeta": "tiếng Việt", "alpha": 1, "nested": {"b": 2, "a": 1}}
    helper_path = tmp_path / "helper.json"
    legacy_path = tmp_path / "legacy.json"

    write_exclusive_json(helper_path, payload)
    with legacy_path.open("x", encoding="utf-8") as stream:
        json.dump(payload, stream)
        stream.flush()
        os.fsync(stream.fileno())

    assert helper_path.read_bytes() == legacy_path.read_bytes()


def test_write_exclusive_json_rejects_existing_file_without_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "existing.json"
    target.write_text('{"original": true}', encoding="utf-8")

    with pytest.raises(FileExistsError):
        write_exclusive_json(target, {"original": False})

    assert target.read_text(encoding="utf-8") == '{"original": true}'


def test_write_exclusive_json_flushes_and_fsyncs(tmp_path: Path) -> None:
    target = tmp_path / "synced.json"
    fsync_fds: list[int] = []

    real_fsync = os.fsync

    def spy_fsync(fd: int) -> None:
        fsync_fds.append(fd)
        real_fsync(fd)

    with patch("workflow.batch.os.fsync", side_effect=spy_fsync):
        write_exclusive_json(target, {"ok": True})

    assert len(fsync_fds) == 1
    assert json.loads(target.read_text(encoding="utf-8")) == {"ok": True}


def test_write_exclusive_json_missing_parent_dir_raises_file_not_found(tmp_path: Path) -> None:
    missing_parent = tmp_path / "does-not-exist" / "claim.json"
    with pytest.raises(FileNotFoundError):
        write_exclusive_json(missing_parent, {"ok": True})


def test_write_exclusive_json_propagates_permission_and_fsync_errors(tmp_path: Path) -> None:
    target = tmp_path / "perm.json"
    with patch.object(Path, "open", side_effect=PermissionError("denied")):
        with pytest.raises(PermissionError, match="denied"):
            write_exclusive_json(target, {"ok": True})

    fsync_target = tmp_path / "fsync_fail.json"
    with patch("workflow.batch.os.fsync", side_effect=OSError("io fault")):
        with pytest.raises(OSError, match="io fault"):
            write_exclusive_json(fsync_target, {"ok": True})


def test_write_exclusive_json_preserves_unserializable_type_error(tmp_path: Path) -> None:
    target = tmp_path / "bad.json"
    with pytest.raises(TypeError):
        write_exclusive_json(target, {"bad": object()})


def test_write_exclusive_json_concurrent_claim_only_one_succeeds(tmp_path: Path) -> None:
    target = tmp_path / "race.json"

    def attempt(worker_id: int) -> bool:
        try:
            write_exclusive_json(target, {"worker": worker_id})
            return True
        except FileExistsError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, range(8)))

    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 7
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["worker"] in range(8)
