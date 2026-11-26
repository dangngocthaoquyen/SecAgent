"""Validation parity and duplicate dictionary key tests for Stage 2B.1c."""

import ast
import json
from pathlib import Path
from time import sleep

import httpx
from pydantic import ValidationError
import pytest

from workflow.admission import AdmissionPolicy
from workflow.api import create_app
from workflow.dataset_normalizer import normalize_dataset
from workflow.dataset_repository import DatasetRepository
from workflow.dispatch import ControlledDispatcher
from workflow.generic_imported_batch import (
    GenericImportedBatchWorkflow,
    ImportedBatchSelection,
    ImportedBatchStart,
)
from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
from workflow.models import CatalogConfig


def _valid_target_draft() -> dict:
    return {
        "target_id": "dvaa-researchbot",
        "profile_revision": "a" * 64,
        "policy_ref": "policy-ref-1",
        "endpoint": "http://127.0.0.1:7015/v1/chat/completions",
        "protocol": "openai-chat",
        "method": "POST",
        "model": "researchbot",
        "request_mapping": "openai-chat-user-message-v1",
        "response_parser": "choices.0.message.content",
        "timeout_seconds": 3,
        "credential_alias": None,
    }


def _selection_payload(**overrides) -> dict:
    base = {
        "target": _valid_target_draft(),
        "testcase_ids": ["CASE-1", "CASE-2"],
        "total_request_budget": 2,
        "evaluation_mode": "rule_only",
    }
    base.update(overrides)
    return base


def _start_payload(**overrides) -> dict:
    base = _selection_payload() | {
        "expected_plan_id": "b" * 64,
        "submission_id": "c" * 32,
        "authorization_confirmed": True,
    }
    base.update(overrides)
    return base


BATCH_MODELS = [
    ("ImportedBatchSelection", ImportedBatchSelection, _selection_payload, frozenset({"rule_only", "hybrid"}), "Invalid imported batch selection."),
    ("ImportedBatchStart", ImportedBatchStart, _start_payload, frozenset({"rule_only", "hybrid"}), "Invalid imported batch selection."),
]


@pytest.mark.parametrize("_name,model_cls,builder,allowed_modes,_msg", BATCH_MODELS)
def test_valid_evaluation_modes_and_dump_parity(
    _name: str,
    model_cls: type,
    builder,
    allowed_modes: frozenset[str],
    _msg: str,
) -> None:
    for mode in sorted(allowed_modes):
        payload = builder(evaluation_mode=mode)
        validated = model_cls.model_validate(payload)
        dumped = validated.model_dump(mode="json")
        assert dumped["evaluation_mode"] == mode
        assert dumped["testcase_ids"] == ["CASE-1", "CASE-2"]
        assert "_allowed_evaluation_modes" not in dumped
        assert "_selection_error_message" not in dumped


@pytest.mark.parametrize("_name,model_cls,builder,allowed_modes,expected_msg", BATCH_MODELS)
def test_disallowed_evaluation_modes_and_case_variations_rejected(
    _name: str,
    model_cls: type,
    builder,
    allowed_modes: frozenset[str],
    expected_msg: str,
) -> None:
    rejected_modes = ["custom", "RULE_ONLY", "HYBRID"]
    if "hybrid" not in allowed_modes:
        rejected_modes.append("hybrid")
    for mode in rejected_modes:
        with pytest.raises(ValidationError) as exc_info:
            model_cls.model_validate(builder(evaluation_mode=mode))
        errs = exc_info.value.errors()
        assert len(errs) == 1
        assert errs[0]["loc"] == ()
        assert errs[0]["type"] == "value_error"
        assert expected_msg in errs[0]["msg"]


@pytest.mark.parametrize("_name,model_cls,builder,_modes,expected_msg", BATCH_MODELS)
def test_duplicate_empty_extra_strict_and_case_sensitive_ids(
    _name: str,
    model_cls: type,
    builder,
    _modes,
    expected_msg: str,
) -> None:
    # Duplicate testcase IDs rejected with model-specific message.
    with pytest.raises(ValidationError) as dup_exc:
        model_cls.model_validate(builder(testcase_ids=["GH-C01", "GH-C01"]))
    assert expected_msg in dup_exc.value.errors()[0]["msg"]
    assert dup_exc.value.errors()[0]["loc"] == ()

    # Distinct-case IDs remain accepted (case-sensitive comparison preserved).
    case_var = model_cls.model_validate(builder(testcase_ids=["GH-C01", "gh-c01"]))
    assert case_var.testcase_ids == ["GH-C01", "gh-c01"]

    # Empty testcase list prohibited by Field(min_length=1).
    with pytest.raises(ValidationError) as empty_exc:
        model_cls.model_validate(builder(testcase_ids=[]))
    assert empty_exc.value.errors()[0]["loc"] == ("testcase_ids",)
    assert empty_exc.value.errors()[0]["type"] == "too_short"

    # Extra/internal class-attribute names rejected by extra="forbid".
    for forbidden in ("unknown_field", "_allowed_evaluation_modes", "_selection_error_message"):
        with pytest.raises(ValidationError) as extra_exc:
            model_cls.model_validate(builder(**{forbidden: "x"}))
        assert extra_exc.value.errors()[0]["type"] == "extra_forbidden"

    # strict=True preserves type rejection (e.g., string instead of int).
    with pytest.raises(ValidationError) as type_exc:
        model_cls.model_validate(builder(total_request_budget="1"))
    assert type_exc.value.errors()[0]["loc"] == ("total_request_budget",)

    # Invalid budget / pattern checks preserved.
    with pytest.raises(ValidationError):
        model_cls.model_validate(builder(total_request_budget=101))
    with pytest.raises(ValidationError):
        model_cls.model_validate(builder(dataset_id="not-32-hex"))
    with pytest.raises(ValidationError):
        model_cls.model_validate(builder(testcase_ids=None))


@pytest.mark.parametrize("_name,model_cls,builder,_modes,expected_msg", [m for m in BATCH_MODELS if "Start" in m[0]])
def test_start_models_confirmation_and_validator_order(
    _name: str,
    model_cls: type,
    builder,
    _modes,
    expected_msg: str,
) -> None:
    # Unconfirmed start rejected with explicit confirmation message.
    with pytest.raises(ValidationError) as unconf:
        model_cls.model_validate(builder(authorization_confirmed=False))
    assert unconf.value.errors()[0]["loc"] == ()
    assert "Explicit execution confirmation required." in unconf.value.errors()[0]["msg"]

    # When both evaluation_mode and authorization_confirmed are invalid,
    # unique_and_rule_only runs BEFORE confirmed (preserving Pydantic validation order).
    with pytest.raises(ValidationError) as both:
        model_cls.model_validate(builder(evaluation_mode="invalid", authorization_confirmed=False))
    assert expected_msg in both.value.errors()[0]["msg"]
    assert "Explicit execution confirmation required." not in both.value.errors()[0]["msg"]


def test_imported_models_preserve_asi_category() -> None:
    for cat in ("unclassified", "ASI03", "ASI05"):
        sel = ImportedBatchSelection.model_validate(_selection_payload(asi_category=cat))
        start = ImportedBatchStart.model_validate(_start_payload(asi_category=cat))
        assert sel.asi_category == cat
        assert start.asi_category == cat

    with pytest.raises(ValidationError):
        ImportedBatchSelection.model_validate(_selection_payload(asi_category="ASI01"))


def test_workflow_source_has_no_duplicate_dict_keys_and_runtime_snapshot_model_intact(
    tmp_path: Path,
) -> None:
    wf_dir = Path(__file__).resolve().parents[1] / "src" / "workflow"
    for py_file in sorted(wf_dir.glob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                str_keys = [
                    k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)
                ]
                assert len(str_keys) == len(set(str_keys)), f"Duplicate dict keys in {py_file.name}: {str_keys}"

    # Verify GenericImportedBatchWorkflow preserves runtime_snapshot["model"] end-to-end.
    catalog = ManagedTargetCatalog(
        CatalogConfig(catalog_schema_version="1.0.0", policy_ref="imported-reviewed-lab", targets=[]),
        tmp_path / "operator-data",
        local_single_user=True,
    )
    row = catalog.save_profile(
        SaveProfile(
            profile=ManagedProfile(
                id="dvaa-researchbot",
                name="DVAA direct chat agent",
                platform_id="dvaa",
                platform_name="DVAA",
                endpoint="http://127.0.0.1:7015/v1/chat/completions",
                protocol="openai-chat",
                model="researchbot",
                timeout_seconds=3,
            )
        )
    )
    row = catalog.review_profile(
        ReviewProfile(
            target_id=row["id"],
            profile_revision=row["profile_revision"],
            policy_ref=row["policy_ref"],
            endpoint=row["endpoint"],
            protocol=row["protocol"],
            model=row["default_model"],
            capabilities=["chat"],
            authorization_confirmed=True,
        )
    )
    draft = {
        k: row[k]
        for k in (
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
    output = tmp_path / "results"
    secret = "stage2b1c-secret-" + "x" * 32
    dispatcher = ControlledDispatcher(
        catalog,
        AdmissionPolicy(),
        output / "runs",
        operator_secret=secret,
        transport=httpx.MockTransport(
            lambda _req: httpx.Response(
                200, json={"choices": [{"message": {"content": "Safe response."}, "finish_reason": "stop"}]}
            )
        ),
        output_boundary=output,
    )
    repo = DatasetRepository(tmp_path / "operator-data")
    fixture = Path(__file__).parent / "fixtures/datasets/codebot_asi02.synthetic.json"
    envelope = normalize_dataset(fixture.read_bytes(), "testcases_dvaa_codebot_asi02.json")
    repo.save_dataset(envelope)
    workflow = GenericImportedBatchWorkflow(dispatcher, repo)
    app = create_app(
        catalog,
        dispatcher=dispatcher,
        operator_secret=secret,
        local_single_user=True,
        batch_service=workflow,
        dataset_repository=repo,
    )
    base = "http://127.0.0.1:8092"
    client = app.test_client()
    nonce = client.get("/api/testing/health", base_url=base).json["validation_nonce"]
    headers = {"Origin": base, "X-SecAgent-Validation": nonce, "X-SecAgent-Operator": secret}
    sel = {
        "target": draft,
        "dataset_id": envelope.dataset_id,
        "testcase_ids": [envelope.testcases[0].internal_id],
        "total_request_budget": 1,
        "evaluation_mode": "rule_only",
        "transport_mode": "offline_mock",
    }
    preview = client.post("/api/testing/batches/preview", base_url=base, json=sel, headers=headers)
    assert preview.status_code == 200
    start = client.post(
        "/api/testing/batches",
        base_url=base,
        json=sel | {"expected_plan_id": preview.json["plan_id"], "submission_id": "a" * 32, "authorization_confirmed": True},
        headers=headers,
    )
    assert start.status_code == 202
    batch_id = start.json["batch_run_id"]
    for _ in range(100):
        st = client.get(f"/api/testing/batches/{batch_id}", base_url=base, headers=headers).json
        if st["status"] in {"completed", "partially_completed", "failed"}:
            break
        sleep(0.05)
    workflow._worker.join(5)
    res = client.get(f"/api/testing/batches/{batch_id}/results", base_url=base, headers=headers).json["results"][0]
    run_dir = output / "runs" / res["report_run_id"]
    report_obj = json.loads(list(run_dir.glob("native-*.secagent.json"))[0].read_bytes().decode("utf-8"))
    assert report_obj["runtime_snapshot"]["model"] == "researchbot"
