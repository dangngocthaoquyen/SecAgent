"""Regression and byte-level parity tests for Stage 2B.1b report persistence."""

import copy
from hashlib import sha256
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from workflow.batch import CaseResult, persist_batch_case_report


def _sample_summary(verdict: str = "PASS", reason: str | None = "benign_ok") -> dict:
    return {
        "engine": "native",
        "testcase_id": "CASE-0",
        "target_id": "synthetic-target",
        "source_provenance": "synthetic_mock",
        "evaluation": {
            "run_id": "evalrun001",
            "final_result": {"status": verdict, "reason": reason},
            "observation": {"response_text": "ALLOWED", "response_complete": True},
        },
        "zeta_extra": {"b": 2, "a": 1, "note": "tiếng Việt"},
    }


def test_persist_batch_case_report_matches_legacy_bytes_sha256_and_caseresult(
    tmp_path: Path,
) -> None:
    run_id = "a" * 32
    exec_id = "b" * 32
    summary = _sample_summary()
    snapshot = copy.deepcopy(summary)

    helper_dir = tmp_path / "helper"
    helper_dir.mkdir()
    fsync_calls: list[int] = []
    real_fsync = os.fsync

    def spy_fsync(fd: int) -> None:
        fsync_calls.append(fd)
        real_fsync(fd)

    with patch("workflow.batch.os.fsync", side_effect=spy_fsync):
        case_result = persist_batch_case_report(
            helper_dir,
            run_id=run_id,
            testcase_id="CASE-0",
            target_id="synthetic-target",
            summary=summary,
            verdict="PASS",
            request_count=1,
            response_captured=True,
            response_complete=True,
            artifact_provenance="synthetic_mock",
            batch_execution_id=exec_id,
            input_sha256="c" * 64,
            asset_sha256="d" * 64,
        )

    assert len(fsync_calls) == 2
    assert summary == snapshot  # No caller mutation.

    report_path = helper_dir / f"native-CASE-0-{run_id}.secagent.json"
    summary_path = helper_dir / "run-summary.json"
    expected_report_bytes = json.dumps(snapshot, sort_keys=True).encode("utf-8")
    assert report_path.read_bytes() == expected_report_bytes
    expected_hash = sha256(expected_report_bytes).hexdigest()

    expected_summary = {
        "workflow_schema_version": "1.0.0",
        "run_id": run_id,
        "native_execution_id": "evalrun001",
        "testcase_id": "CASE-0",
        "target_id": "synthetic-target",
        "execution_status": "completed",
        "historical_verdict": "PASS",
        "target_request_count": 1,
        "report_persisted": True,
        "report_file": f"native-CASE-0-{run_id}.secagent.json",
        "report_sha256": expected_hash,
        "response_captured": True,
        "response_complete": True,
        "artifact_provenance": "synthetic_mock",
        "batch_execution_id": exec_id,
        "input_sha256": "c" * 64,
        "asset_sha256": "d" * 64,
    }
    assert summary_path.read_bytes() == json.dumps(expected_summary, sort_keys=True).encode("utf-8")
    assert case_result == CaseResult(
        "completed",
        "PASS",
        1,
        run_id,
        expected_hash,
        True,
        True,
        "synthetic_mock",
        preflight_id=None,
        evaluation_reason="benign_ok",
    )


def test_persist_batch_case_report_supports_error_verdict_preflight_and_extra_fields(
    tmp_path: Path,
) -> None:
    run_id = "1" * 32
    preflight_id = "2" * 32
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    summary = _sample_summary(verdict="ERROR", reason="provider_timeout")

    case_result = persist_batch_case_report(
        run_dir,
        run_id=run_id,
        testcase_id="GH-WEB-001",
        target_id="dvaa-researchbot",
        summary=summary,
        verdict="ERROR",
        request_count=2,
        response_captured=False,
        response_complete=None,
        artifact_provenance="target_observation",
        batch_execution_id="3" * 32,
        input_sha256="e" * 64,
        asset_sha256="f" * 64,
        preflight_id=preflight_id,
        extra_summary_fields={"dataset_id": "ds-001"},
    )

    assert case_result.execution_status == "error"
    assert case_result.verdict == "ERROR"
    assert case_result.preflight_id == preflight_id
    summary_obj = json.loads((run_dir / "run-summary.json").read_text(encoding="utf-8"))
    assert summary_obj["execution_status"] == "failed"
    assert summary_obj["preflight_id"] == preflight_id
    assert summary_obj["dataset_id"] == "ds-001"


def test_persist_batch_case_report_preserves_failure_and_partial_artifact_semantics(
    tmp_path: Path,
) -> None:
    run_id = "4" * 32
    summary = _sample_summary()

    # Missing output directory.
    with pytest.raises(FileNotFoundError):
        persist_batch_case_report(
            tmp_path / "missing",
            run_id=run_id,
            testcase_id="CASE-0",
            target_id="t1",
            summary=summary,
            verdict="PASS",
            request_count=1,
            response_captured=True,
            response_complete=True,
            artifact_provenance="synthetic_mock",
            batch_execution_id="5" * 32,
            input_sha256="a" * 64,
            asset_sha256="b" * 64,
        )

    # Collision on native report leaves existing report untouched and creates no run-summary.json.
    collide_dir = tmp_path / "collide_report"
    collide_dir.mkdir()
    report_path = collide_dir / f"native-CASE-0-{run_id}.secagent.json"
    report_path.write_text('{"keep": true}', encoding="utf-8")
    with pytest.raises(FileExistsError):
        persist_batch_case_report(
            collide_dir,
            run_id=run_id,
            testcase_id="CASE-0",
            target_id="t1",
            summary=summary,
            verdict="PASS",
            request_count=1,
            response_captured=True,
            response_complete=True,
            artifact_provenance="synthetic_mock",
            batch_execution_id="5" * 32,
            input_sha256="a" * 64,
            asset_sha256="b" * 64,
        )
    assert report_path.read_text(encoding="utf-8") == '{"keep": true}'
    assert not (collide_dir / "run-summary.json").exists()

    # Partial failure: native report exists and run-summary.json collides -> preserves native report without silent rollback.
    partial_dir = tmp_path / "partial_summary_fail"
    partial_dir.mkdir()
    (partial_dir / "run-summary.json").write_text('{"existing_summary": true}', encoding="utf-8")
    with pytest.raises(FileExistsError):
        persist_batch_case_report(
            partial_dir,
            run_id=run_id,
            testcase_id="CASE-0",
            target_id="t1",
            summary=summary,
            verdict="PASS",
            request_count=1,
            response_captured=True,
            response_complete=True,
            artifact_provenance="synthetic_mock",
            batch_execution_id="5" * 32,
            input_sha256="a" * 64,
            asset_sha256="b" * 64,
        )
    assert (partial_dir / f"native-CASE-0-{run_id}.secagent.json").exists()
    assert (partial_dir / "run-summary.json").read_text(encoding="utf-8") == '{"existing_summary": true}'

    # fsync failure propagates cleanly.
    fsync_dir = tmp_path / "fsync_fail"
    fsync_dir.mkdir()
    with patch("workflow.batch.os.fsync", side_effect=OSError("fsync failed")):
        with pytest.raises(OSError, match="fsync failed"):
            persist_batch_case_report(
                fsync_dir,
                run_id=run_id,
                testcase_id="CASE-0",
                target_id="t1",
                summary=summary,
                verdict="PASS",
                request_count=1,
                response_captured=True,
                response_complete=True,
                artifact_provenance="synthetic_mock",
                batch_execution_id="5" * 32,
                input_sha256="a" * 64,
                asset_sha256="b" * 64,
            )
