"""Test-only loopback APIs for continuous browser acceptance; no target or Pi I/O."""

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import secrets
from threading import Thread
import time

import httpx
from werkzeug.serving import make_server

from reporting.api import create_app as reporting_app
from reporting.repository import load_dataset
from testing import RunnerEvaluationConfig
from workflow.admission import AdmissionPolicy, AdmissionRequest, AdmissionService, ExecutionGrant
from workflow.api import create_app as workflow_app
from workflow.catalog import TargetCatalog
from workflow.dispatch import ControlledDispatcher
from workflow.models import CatalogConfig

from test_runner_judge_integration import FakeJudge
from test_workflow_targets import config as example_config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    root = args.state_dir.absolute()
    root.mkdir(parents=True, exist_ok=False)
    catalog_data = example_config()
    preset = catalog_data["targets"][0]
    preset.update(id="synthetic-researchbot", name="Synthetic ResearchBot",
                  platform_id="synthetic", platform_name="Synthetic lab",
                  endpoint="http://127.0.0.1:7999/v1/chat/completions")
    catalog = TargetCatalog(CatalogConfig.model_validate(catalog_data))
    public = catalog.public_targets()[0]
    draft = {key: public[key] for key in ("profile_revision", "policy_ref", "endpoint", "protocol",
        "method", "request_mapping", "response_parser", "credential_alias")}
    draft.update(target_id=public["id"], model=public["default_model"],
                 timeout_seconds=public["timeout_default"])
    selection = AdmissionRequest(target=draft, asi_categories=["ASI01"], testcase_ids=["GH-C01"])
    asset = AdmissionService(catalog).assess(selection)["asset_sha256"]["GH-C01"]
    policy = AdmissionPolicy(grants=[ExecutionGrant(target_id=public["id"],
        profile_revision=public["profile_revision"], policy_ref=public["policy_ref"],
        testcase_id="GH-C01", asset_sha256=asset, scope="security_test_execution",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15))])
    responses = ["SecAgent is a prototype AI agent security testing system.",
                 "Synthetic response needs review."]
    target_calls = []

    def mock_target(request):
        target_calls.append(request)
        if len(target_calls) > len(responses):
            raise AssertionError("Synthetic acceptance exceeded its two-request budget.")
        return httpx.Response(200, json={"choices": [{"message": {"content": responses[len(target_calls)-1]}}]})

    judge = FakeJudge(label="ORIGINAL_GOAL")
    token = secrets.token_urlsafe(32)
    runs = root / "runs"
    dispatcher = ControlledDispatcher(catalog, policy, runs, operator_secret=token,
        transport=httpx.MockTransport(mock_target), output_boundary=root,
        hybrid_config=RunnerEvaluationConfig(mode="hybrid", judge_enabled=True, max_judge_calls=1),
        judge_provider=judge)
    manifest = root / "reporting-manifest.json"
    manifest.write_text(json.dumps({"dataset_schema_version": "1.0.0",
        "allowed_roots": {"controlled": "runs"}, "controlled_runs_root": "controlled",
        "reports": [], "verification_jobs": []}), encoding="utf-8")
    workflow_server = make_server("127.0.0.1", 8092,
        workflow_app(catalog, admission_policy=policy, dispatcher=dispatcher), threaded=True)
    reporting_server = make_server("127.0.0.1", 8091,
        reporting_app(load_dataset(manifest)), threaded=True)
    (root / "control.json").write_text(json.dumps({"target_id": public["id"],
        "reporting_manifest": str(manifest)}), encoding="utf-8")
    Thread(target=workflow_server.serve_forever, daemon=True).start()
    Thread(target=reporting_server.serve_forever, daemon=True).start()
    print("READY " + token, flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        workflow_server.shutdown()
        reporting_server.shutdown()


if __name__ == "__main__":
    main()
