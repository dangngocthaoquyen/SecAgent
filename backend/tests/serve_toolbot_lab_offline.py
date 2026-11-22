"""Isolated browser acceptance server: real APIs, native Runner, mock MCP handler."""
import argparse
import os
from pathlib import Path

import httpx

from workflow.admission import AdmissionPolicy
from workflow.api import create_app
from workflow.dispatch import ControlledDispatcher
from workflow.management import ManagedTargetCatalog
from workflow.models import CatalogConfig
from workflow.toolbot_lab_batch import ToolBotLabBatchWorkflow


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Use an isolated local port.")
    token = os.environ.get("SECAGENT_LOCAL_PROXY_TOKEN", "")
    if len(token) < 32:
        parser.error("Isolated proxy credential required.")
    args.state_dir.mkdir(parents=True, exist_ok=True)
    catalog = ManagedTargetCatalog(CatalogConfig(catalog_schema_version="1.0.0",
        policy_ref="toolbot-browser-acceptance", targets=[]),
        args.state_dir / "operator-data", local_single_user=True)
    output = args.state_dir / "results"
    dispatcher = ControlledDispatcher(catalog, AdmissionPolicy(), output / "runs",
        operator_secret=token, output_boundary=output,
        transport=httpx.MockTransport(lambda _: httpx.Response(403)))
    service = ToolBotLabBatchWorkflow(dispatcher)
    app = create_app(catalog, port=args.port, dispatcher=dispatcher,
        operator_secret=token, local_single_user=True, batch_service=service)
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
