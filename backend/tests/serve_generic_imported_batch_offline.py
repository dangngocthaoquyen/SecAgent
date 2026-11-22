"""Isolated browser acceptance server: real APIs, native Runner, mock direct-chat target."""
import argparse
import os
import json
import socket
from threading import Lock
from pathlib import Path

import httpx

from workflow.admission import AdmissionPolicy
from workflow.api import create_app
from workflow.dataset_repository import DatasetRepository
from workflow.dispatch import ControlledDispatcher
from workflow.generic_imported_batch import GenericImportedBatchWorkflow
from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
from workflow.models import CatalogConfig


def mock_chat_response(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={
        "id": "chatcmpl-mock-offline",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "researchbot",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Understood. I will follow security constraints and not execute unsafe commands."
            },
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 45, "completion_tokens": 15, "total_tokens": 60}
    })


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--live-local-fixture", action="store_true",
                        help="Exercise the Live Local policy with an in-process HTTP boundary only")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Use an isolated local port.")
    token = os.environ.get("SECAGENT_LOCAL_PROXY_TOKEN", "")
    if len(token) < 32:
        parser.error("Isolated proxy credential required.")
    args.state_dir.mkdir(parents=True, exist_ok=True)
    operator_data = args.state_dir / "operator-data"
    catalog = ManagedTargetCatalog(
        CatalogConfig(catalog_schema_version="1.0.0", policy_ref="imported-browser-acceptance", targets=[]),
        operator_data,
        local_single_user=True,
    )
    # The original offline fixture keeps its reviewed example. Live fixture
    # starts empty so the browser must add, authorize and probe its own URL.
    if not args.live_local_fixture:
        saved = next((row for row in catalog.public_targets() if row["id"] == "dvaa-researchbot"), None) or catalog.save_profile(SaveProfile(profile=ManagedProfile(
            id="dvaa-researchbot",
            name="DVAA direct chat agent",
            platform_id="dvaa",
            platform_name="DVAA",
            endpoint="http://127.0.0.1:7015/v1/chat/completions",
            protocol="openai-chat",
            model="researchbot",
            timeout_seconds=3,
        )))
        catalog.review_profile(ReviewProfile(
            target_id=saved["id"],
            profile_revision=saved["profile_revision"],
            policy_ref=saved["policy_ref"],
            endpoint=saved["endpoint"],
            protocol=saved["protocol"],
            model=saved["default_model"],
            capabilities=["chat"],
            authorization_confirmed=True,
        ))

    dataset_repo = DatasetRepository(operator_data)
    output = args.state_dir / "results"
    ledger_lock = Lock()
    def recorded_response(request):
        with ledger_lock, (args.state_dir / "requests.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"url": str(request.url), "body": json.loads(request.content)}, ensure_ascii=True) + "\n")
        return mock_chat_response(request)
    def forbidden_connect(*args, **kwargs):
        raise RuntimeError("Offline browser fixture cannot initiate network connections.")
    socket.socket.connect = forbidden_connect
    socket.socket.connect_ex = forbidden_connect
    mock_transport = httpx.MockTransport(recorded_response)
    dispatcher = ControlledDispatcher(
        catalog,
        AdmissionPolicy(),
        output / "runs",
        operator_secret=token,
        output_boundary=output,
        transport=None if args.live_local_fixture else mock_transport,
    )
    service = GenericImportedBatchWorkflow(dispatcher, dataset_repo,
        execution_mode="both" if args.live_local_fixture else "offline_mock",
        mock_live_transport=mock_transport if args.live_local_fixture else None)
    app = create_app(
        catalog,
        port=args.port,
        dispatcher=dispatcher,
        operator_secret=token,
        local_single_user=True,
        batch_service=service,
        dataset_repository=dataset_repo,
    )
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
