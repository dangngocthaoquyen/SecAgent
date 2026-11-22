"""Regression tests for Stage 2B.1a exclusive JSON writer consolidation."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from time import sleep
from unittest.mock import patch

import httpx
import pytest

from core.models import (
    EvaluationConfig,
    EvaluationRule,
    EvaluationStatus,
    TestCase as CoreTestCase,
    TestInput as CoreTestInput,
)
from workflow.admission import AdmissionPolicy, ExecutionGrant
from workflow.api import create_app
from workflow.batch import BatchRejected, write_exclusive_json
from workflow.catalog import TargetCatalog
from workflow.dispatch import ControlledDispatcher
from workflow.models import CatalogConfig
from workflow.offline_batch import OfflineBatchWorkflow, OfflineCaseBinding


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
    assert json.loads(helper_path.read_text(encoding="utf-8")) == payload


def test_write_exclusive_json_rejects_existing_file_without_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "grant-123"
    target.write_text('{"original": true}', encoding="utf-8")

    with pytest.raises(FileExistsError):
        write_exclusive_json(target, {"overwritten": True})

    assert target.read_text(encoding="utf-8") == '{"original": true}'


def test_write_exclusive_json_flushes_and_fsyncs(tmp_path: Path) -> None:
    target = tmp_path / "submission-1.json"
    fsync_fds: list[int] = []
    real_fsync = os.fsync

    def spy_fsync(fd: int) -> None:
        fsync_fds.append(fd)
        real_fsync(fd)

    with patch("workflow.batch.os.fsync", side_effect=spy_fsync):
        write_exclusive_json(target, {"batch_run_id": "abc"})

    assert len(fsync_fds) == 1
    assert json.loads(target.read_text(encoding="utf-8")) == {"batch_run_id": "abc"}


def test_write_exclusive_json_missing_parent_dir_raises_file_not_found(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist" / "grant-1"
    with pytest.raises(FileNotFoundError):
        write_exclusive_json(missing, {"ok": True})


def test_write_exclusive_json_propagates_permission_and_fsync_errors(tmp_path: Path) -> None:
    target = tmp_path / "perm.json"
    with patch.object(Path, "open", side_effect=PermissionError("denied")):
        with pytest.raises(PermissionError):
            write_exclusive_json(target, {"a": 1})

    target_fsync = tmp_path / "fsync-err.json"
    with patch("workflow.batch.os.fsync", side_effect=OSError("disk io error")):
        with pytest.raises(OSError, match="disk io error"):
            write_exclusive_json(target_fsync, {"a": 1})


def test_write_exclusive_json_preserves_unserializable_type_error(tmp_path: Path) -> None:
    target = tmp_path / "bad.json"
    with pytest.raises(TypeError):
        write_exclusive_json(target, {"bad": object()})
    assert target.exists()


def test_write_exclusive_json_concurrent_claim_only_one_succeeds(tmp_path: Path) -> None:
    target = tmp_path / "race-claim.json"

    def attempt(idx: int) -> bool:
        try:
            write_exclusive_json(target, {"worker": idx})
            return True
        except FileExistsError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, range(8)))

    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 7
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["worker"] in range(8)


def test_offline_batch_uses_exclusive_json_and_preserves_submission_grant_and_report_parity(
    tmp_path: Path,
) -> None:
    def reply(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ALLOWED"}, "finish_reason": "stop"}]},
        )

    config = CatalogConfig.model_validate(
        {
            "catalog_schema_version": "1.0.0",
            "policy_ref": "stage2b1a-policy",
            "credential_aliases": {},
            "targets": [
                {
                    "id": "synthetic-target",
                    "name": "Synthetic target",
                    "reviewed": True,
                    "endpoint": "http://127.0.0.1:7015/v1/chat/completions",
                    "protocol": "openai-chat",
                    "models": ["synthetic"],
                    "default_model": "synthetic",
                    "timeout_default": 3,
                    "timeout_min": 1,
                    "timeout_max": 3,
                }
            ],
        }
    )
    catalog = TargetCatalog(config)
    row = catalog.public_targets()[0]
    draft = {
        key: row[key]
        for key in (
            "profile_revision",
            "policy_ref",
            "endpoint",
            "protocol",
            "method",
            "request_mapping",
            "response_parser",
            "credential_alias",
        )
    }
    draft.update(target_id=row["id"], model=row["default_model"], timeout_seconds=3)
    case = CoreTestCase(
        id="CASE-0",
        name="Synthetic case 0",
        category="goal_hijacking",
        objective="Classify harmless output.",
        attack_module="goal_hijacking",
        evaluation=EvaluationConfig(
            rules=[
                EvaluationRule(
                    id="response-marker",
                    type="marker",
                    verdict=EvaluationStatus.PASS,
                    parameters={"marker": "ALLOWED"},
                )
            ]
        ),
    )
    binding = OfflineCaseBinding(case, CoreTestInput(id="input-0", prompt="Synthetic benign CASE-0"))
    grant = ExecutionGrant(
        authorization_id="stage2b1a-grant-0",
        target_id=row["id"],
        profile_revision=row["profile_revision"],
        policy_ref=row["policy_ref"],
        testcase_id="CASE-0",
        asset_sha256=binding.asset_sha256,
        scope="security_test_execution",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    output = tmp_path / "results"
    dispatcher = ControlledDispatcher(
        catalog,
        AdmissionPolicy(grants=[grant]),
        output / "runs",
        operator_secret="stage2b1a-secret-" + "x" * 32,
        transport=httpx.MockTransport(reply),
        output_boundary=output,
    )
    workflow = OfflineBatchWorkflow(dispatcher, [binding], max_cases=5, max_total_requests=5)
    app = create_app(
        catalog,
        dispatcher=dispatcher,
        operator_secret=dispatcher.operator_secret,
        batch_service=workflow,
    )
    base = "http://127.0.0.1:8092"
    client = app.test_client()
    nonce = client.get("/api/testing/health", base_url=base).json["validation_nonce"]
    headers = {
        "Origin": base,
        "X-SecAgent-Validation": nonce,
        "X-SecAgent-Operator": dispatcher.operator_secret,
    }
    selection = {
        "target": draft,
        "testcase_ids": ["CASE-0"],
        "total_request_budget": 1,
        "evaluation_mode": "rule_only",
    }
    preview = client.post("/api/testing/batches/preview", base_url=base, json=selection, headers=headers)
    assert preview.status_code == 200
    start_body = {
        **selection,
        "submission_id": "b" * 32,
        "expected_plan_id": preview.json["plan_id"],
        "authorization_confirmed": True,
    }
    started = client.post("/api/testing/batches", base_url=base, json=start_body, headers=headers)
    assert started.status_code == 202
    batch_run_id = started.json["batch_run_id"]
    for _ in range(100):
        state = client.get(f"/api/testing/batches/{batch_run_id}", base_url=base, headers=headers).json
        if state["status"] in {"completed", "partially_completed", "failed"}:
            break
        sleep(0.05)
    assert state["status"] == "completed"
    workflow._worker.join(5)
    rows = client.get(
        f"/api/testing/batches/{batch_run_id}/results", base_url=base, headers=headers
    ).json["results"]
    case_row = rows[0]

    # Duplicate submission must remain rejected via FileExistsError -> BatchRejected.
    dup = client.post("/api/testing/batches", base_url=base, json=start_body, headers=headers)
    assert dup.status_code == 409

    # Exclusive grant/submission files preserve exact legacy serialization and schema.
    batch_root = output / "runs" / "batch-runs"
    submission_bytes = (batch_root / ("submission-" + ("b" * 32) + ".json")).read_bytes()
    submission_obj = json.loads(submission_bytes.decode("utf-8"))
    assert submission_bytes == json.dumps(submission_obj).encode("utf-8")
    assert set(submission_obj) == {"batch_run_id", "plan_id", "submitted_at"}
    assert submission_obj["batch_run_id"] == batch_run_id

    grant_bytes = (batch_root / "grant-stage2b1a-grant-0").read_bytes()
    grant_obj = json.loads(grant_bytes.decode("utf-8"))
    assert grant_bytes == json.dumps(grant_obj).encode("utf-8")
    assert grant_obj == {"batch_execution_id": case_row["execution_id"], "testcase_id": "CASE-0"}

    # Native report and run-summary parity remain intact.
    run_dir = output / "runs" / case_row["report_run_id"]
    report_path = run_dir / f"native-CASE-0-{case_row['report_run_id']}.secagent.json"
    summary_row = json.loads((run_dir / "run-summary.json").read_text(encoding="utf-8"))
    assert summary_row["report_sha256"] == sha256(report_path.read_bytes()).hexdigest()
    assert summary_row["artifact_provenance"] == "synthetic_mock"
