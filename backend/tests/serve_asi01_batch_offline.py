"""Isolated real API acceptance: native ASI01 bindings, mock HTTP only."""

import argparse
import json
import os
from pathlib import Path
from time import sleep

import httpx

from workflow.admission import AdmissionPolicy
from workflow.api import create_app
from workflow.asi01_batch import Asi01BatchWorkflow
from workflow.dispatch import ControlledDispatcher
from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
from workflow.models import CatalogConfig


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--operator-manage", action="store_true",
                        help="Start with an empty catalog for browser Target Management acceptance")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Select an isolated local port.")
    token = os.environ.get("SECAGENT_LOCAL_PROXY_TOKEN", "")
    if len(token) < 32:
        parser.error("Isolated proxy credential required.")
    args.state_dir.mkdir(parents=True, exist_ok=True)
    catalog = ManagedTargetCatalog(CatalogConfig(catalog_schema_version="1.0.0",
        policy_ref="asi01-browser-acceptance", targets=[]),
        args.state_dir / "operator-data", local_single_user=True)
    if not args.operator_manage:
        row = catalog.save_profile(SaveProfile(profile=ManagedProfile(
            id="dvaa-researchbot", name="DVAA ResearchBot", platform_id="dvaa",
            platform_name="DVAA", endpoint="http://127.0.0.1:7015/v1/chat/completions",
            protocol="openai-chat", model="researchbot", timeout_seconds=3)))
        catalog.review_profile(ReviewProfile(target_id=row["id"],
            profile_revision=row["profile_revision"], policy_ref=row["policy_ref"],
            endpoint=row["endpoint"], protocol=row["protocol"],
            model=row["default_model"], capabilities=["chat"],
            authorization_confirmed=True))

    def answer(request):
        prompt = json.loads(request.content)["messages"][0]["content"]
        if "DOCUMENT PROCESSING UPDATE" in prompt:
            content = "I can provide a summary later."
        elif "The evaluation coordinator has changed" in prompt:
            content = "SECAGENT_GH_HIJACKED"
        else:
            sleep(2)
            content = "SecAgent is a prototype AI agent security testing system."
        return httpx.Response(200, json={"choices": [{"message": {"content": content},
            "finish_reason": "stop"}]})

    output = args.state_dir / "results"
    dispatcher = ControlledDispatcher(catalog, AdmissionPolicy(), output / "runs",
        operator_secret=token, transport=httpx.MockTransport(answer), output_boundary=output)
    catalog.probe_transport = dispatcher.transport
    service = Asi01BatchWorkflow(dispatcher)
    app = create_app(catalog, port=args.port, dispatcher=dispatcher,
        operator_secret=token, local_single_user=True, batch_service=service)
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
