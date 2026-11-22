"""Isolated browser acceptance server: real Workflow API, mock target only."""

import argparse
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from time import sleep

import httpx

from core.models import EvaluationConfig, EvaluationRule, EvaluationStatus, TestCase, TestInput
from workflow.admission import AdmissionPolicy, ExecutionGrant
from workflow.api import create_app
from workflow.catalog import TargetCatalog
from workflow.dispatch import ControlledDispatcher
from workflow.models import CatalogConfig
from workflow.offline_batch import OfflineBatchWorkflow, OfflineCaseBinding
from workflow.plans import TestcaseCatalog


def binding(index):
    marker, verdict = ({0: ("ALLOWED", EvaluationStatus.PASS),
                        1: ("BAD", EvaluationStatus.FAIL)}.get(index,
                        ("UNMATCHED", EvaluationStatus.PASS)))
    return OfflineCaseBinding(TestCase(id=f"CASE-{index}", name=f"Synthetic case {index}",
        category="goal_hijacking", objective="Classify a harmless synthetic response.",
        attack_module="goal_hijacking", evaluation=EvaluationConfig(rules=[
            EvaluationRule(id="response-marker", type="marker", verdict=verdict,
                           parameters={"marker": marker})])),
        TestInput(id=f"input-{index}", prompt=f"Synthetic benign CASE-{index}"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Select a local test port.")
    token = os.environ.get("SECAGENT_LOCAL_PROXY_TOKEN", "")
    if len(token) < 32:
        parser.error("Isolated proxy credential is required.")
    args.state_dir.mkdir(parents=True, exist_ok=True)
    config = CatalogConfig.model_validate({"catalog_schema_version": "1.0.0",
        "policy_ref": "synthetic-browser-policy", "credential_aliases": {}, "targets": [{
            "id": "synthetic-target", "name": "Synthetic offline agent", "reviewed": True,
            "endpoint": "http://127.0.0.1:7015/v1/chat/completions",
            "protocol": "openai-chat", "models": ["synthetic"], "default_model": "synthetic",
            "timeout_default": 3, "timeout_min": 1, "timeout_max": 3}]})
    catalog = TargetCatalog(config)
    preset = catalog.public_targets()[0]
    bindings = [binding(index) for index in range(9)]
    grants = [ExecutionGrant(authorization_id=f"browser-grant-{index}",
        target_id=preset["id"], profile_revision=preset["profile_revision"],
        policy_ref=preset["policy_ref"], testcase_id=item.testcase.id,
        asset_sha256=item.asset_sha256, scope="security_test_execution",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10))
        for index, item in enumerate(bindings) if index != 4]
    def answer(request):
        prompt = json.loads(request.content)["messages"][0]["content"]
        index = int(prompt.split("CASE-")[1])
        if index == 0:
            sleep(0.7)
        if index == 6:
            sleep(1.5)
        if index == 3:
            return httpx.Response(500, text="Synthetic provider fault")
        content = {0: "ALLOWED", 1: "BAD", 2: "neutral"}.get(index, "neutral")
        return httpx.Response(200, json={"choices": [{"message": {"content": content},
            "finish_reason": "stop"}]})
    output = args.state_dir / "results"
    dispatcher = ControlledDispatcher(catalog, AdmissionPolicy(grants=grants), output / "runs",
        operator_secret=token, transport=httpx.MockTransport(answer), output_boundary=output)
    workflow = OfflineBatchWorkflow(dispatcher, bindings, max_cases=10, max_total_requests=10)
    inventory = TestcaseCatalog.__new__(TestcaseCatalog)
    inventory.invalid_records = 0
    inventory.paths = {}
    inventory.items = [{"id": case.testcase.id, "name": case.testcase.name,
        "asi_category": "ASI01", "description": "Harmless offline synthetic case.",
        "compatibility": "unknown", "reason": "Synthetic mock fixture only.",
        "requirements": ["Isolated offline batch service"], "required_capabilities": [],
        "taxonomy_basis": "synthetic_test_fixture"} for case in bindings]
    inventory.items.append({"id": "UNKNOWN", "name": "Unsupported synthetic case",
        "asi_category": "ASI01", "description": "No server binding exists.",
        "compatibility": "unknown", "reason": "No server binding exists.",
        "requirements": ["No executable binding"], "required_capabilities": [],
        "taxonomy_basis": "synthetic_test_fixture"})
    interrupted = "e" * 32
    directory = workflow.root / interrupted
    directory.mkdir(exist_ok=True)
    digest = sha256(b"synthetic-interrupted").hexdigest()
    (directory / "state.json").write_text(json.dumps({"schema_version": "1.0.0",
        "batch_run_id": interrupted, "snapshot": {"target_id": preset["id"],
            "profile_revision": preset["profile_revision"], "policy_ref": preset["policy_ref"],
            "evaluation_mode": "rule_only", "total_request_budget": 1,
            "cases": [{"testcase_id": "CASE-9", "name": "Interrupted synthetic case",
                "asi_category": "ASI01", "asset_sha256": digest, "input_sha256": digest,
                "request_budget": 1}]}, "snapshot_sha256": digest,
        "status": "interrupted", "total": 1, "processed": 0,
        "target_request_count": 0, "request_budget_consumed": 0,
        "request_count_unknown": False, "active_testcase_id": None,
        "results": [], "events": [{"at": datetime.now(timezone.utc).isoformat(),
            "stage": "interrupted", "testcase_id": None}]}), encoding="utf-8")
    app = create_app(catalog, port=args.port, testcase_catalog=inventory,
        dispatcher=dispatcher, operator_secret=token, batch_service=workflow)
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
