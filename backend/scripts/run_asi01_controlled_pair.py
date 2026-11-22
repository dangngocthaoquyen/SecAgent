"""Run GH-C01 then GH-001 through the existing controlled ASI01 batch API."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import sys
from time import sleep
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT, ROOT / "backend" / "src"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from workflow.admission import AdmissionPolicy
from workflow.api import create_app
from workflow.asi01_batch import Asi01BatchWorkflow
from workflow.dispatch import ControlledDispatcher
from workflow.management import ManagedTargetCatalog, ReviewProfile
from workflow.models import CatalogConfig

SEED = ROOT / "configs" / "workflow" / "authorized-targets.dvaa-multibot.draft.json"
DEFAULT_OUTPUT = ROOT / "results" / "live-final-integration"
BASE = "http://127.0.0.1:8092"
ENDPOINT = "http://127.0.0.1:7001/v1/chat/completions"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    if not args.execute:
        parser.error("Controlled live target calls require --execute.")

    output = args.output_root / ("asi01-controlled-" +
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex)
    output.mkdir(parents=True, exist_ok=False)
    seed = CatalogConfig.model_validate(json.loads(SEED.read_text(encoding="utf-8")))
    # Managed profile state must live outside the repository by contract.
    state_root = (Path.home() / "AppData" / "Local" / "SecAgent" /
                  "asi01-controlled-sprints" / output.name)
    catalog = ManagedTargetCatalog(seed, state_root, local_single_user=True)
    row = next(r for r in catalog.public_targets() if r["id"] == "dvaa-securebot")
    if (row["endpoint"] != ENDPOINT or row["default_model"] != "securebot"
            or row["protocol"] != "openai-chat" or row["credential_alias"] is not None):
        raise ValueError("Exact credential-free SecureBot profile required.")
    row = catalog.review_profile(ReviewProfile(target_id=row["id"],
        profile_revision=row["profile_revision"], policy_ref=row["policy_ref"],
        endpoint=row["endpoint"], protocol=row["protocol"],
        model=row["default_model"], capabilities=["chat"],
        authorization_confirmed=True))
    target = {key: row[key] for key in (
        "profile_revision", "policy_ref", "endpoint", "protocol", "method",
        "request_mapping", "response_parser", "credential_alias")}
    target.update(target_id=row["id"], model=row["default_model"], timeout_seconds=30)

    operator_secret = secrets.token_urlsafe(32)
    dispatcher = ControlledDispatcher(catalog, AdmissionPolicy(), output / "runs",
        operator_secret=operator_secret, output_boundary=output)
    batch = Asi01BatchWorkflow(dispatcher)
    client = create_app(catalog, dispatcher=dispatcher,
        operator_secret=operator_secret, local_single_user=True,
        batch_service=batch).test_client()
    health = client.get("/api/testing/health", base_url=BASE).json
    headers = {"Origin": BASE, "X-SecAgent-Validation": health["validation_nonce"],
               "X-SecAgent-Operator": operator_secret}
    selection = {"target": target, "testcase_ids": ["GH-C01", "GH-001"],
                 "total_request_budget": 2, "evaluation_mode": "rule_only"}
    preview = client.post("/api/testing/batches/preview", base_url=BASE,
        json=selection, headers=headers)
    if preview.status_code != 200 or preview.json.get("ready_count") != 2:
        raise ValueError("Controlled ASI01 preview rejected the exact pair.")
    (output / "preview.json").write_text(json.dumps(preview.json, indent=2) + "\n", encoding="utf-8")
    start = client.post("/api/testing/batches", base_url=BASE,
        json={**selection, "expected_plan_id": preview.json["plan_id"],
              "submission_id": uuid4().hex, "authorization_confirmed": True},
        headers=headers)
    if start.status_code != 202:
        raise ValueError("Controlled ASI01 batch start was rejected.")
    batch_id = start.json["batch_run_id"]
    state = None
    for _ in range(180):
        response = client.get(f"/api/testing/batches/{batch_id}", base_url=BASE,
            headers=headers)
        if response.status_code != 200:
            raise ValueError("Controlled ASI01 status lookup failed.")
        state = response.json
        if state["status"] in {"completed", "partially_completed", "cancelled", "failed", "interrupted"}:
            break
        sleep(0.25)
    else:
        raise TimeoutError("ASI01 pair did not reach a terminal batch state.")
    rows = client.get(f"/api/testing/batches/{batch_id}/results", base_url=BASE,
        headers=headers)
    if rows.status_code != 200:
        raise ValueError("Controlled ASI01 results lookup failed.")
    (output / "status.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    (output / "results.json").write_text(json.dumps(rows.json, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "batch_id": batch_id,
        "status": state["status"], "request_count": state["target_request_count"],
        "cases": [{"case_id": r["testcase_id"], "status": r["status"],
                   "verdict": r.get("verdict"), "reason": r.get("reason")}
                  for r in rows.json["results"]]}))


if __name__ == "__main__":
    main()
