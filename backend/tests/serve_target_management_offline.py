"""Isolated real Workflow API for browser acceptance; target transport is mocked."""
import argparse
import json
from pathlib import Path

import httpx

from workflow.api import create_app
from workflow.admission import AdmissionPolicy
from workflow.dispatch import ControlledDispatcher
from workflow.management import ManagedTargetCatalog
from workflow.models import CatalogConfig


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--local-run", action="store_true")
    parser.add_argument("--seed-researchbot", action="store_true")
    parser.add_argument("--seed-toolbot", action="store_true")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Select a local test port.")
    seed = CatalogConfig.model_validate({"catalog_schema_version": "1.0.0",
        "policy_ref": "offline-browser-v1", "credential_aliases": {},
        "targets": ([{"id": "dvaa-researchbot", "name": "DVAA ResearchBot",
            "platform_id": "dvaa", "platform_name": "DVAA",
            "endpoint": "http://127.0.0.1:7015/v1/chat/completions", "protocol": "openai-chat",
            "models": ["researchbot"], "default_model": "researchbot"}]
            if args.seed_researchbot else []) + ([{
            "id": "local-agent-7010", "name": "Saved ToolBot", "platform_id": "local-agent",
            "platform_name": "Local Agent", "endpoint": "http://127.0.0.1:7010/",
            "protocol": "mcp-jsonrpc", "models": ["mcp-service"],
            "default_model": "mcp-service"}] if args.seed_toolbot else [])})
    def answer(request):
        prompt = request.content.decode("utf-8")
        if json.loads(prompt).get("method") == "tools/list":
            if request.url.port != 7010:
                return httpx.Response(404)
            return httpx.Response(200, json={"jsonrpc": "2.0",
                "id": "secagent-connection-check", "result": {"tools": [{"name": "read_file"}]}})
        text = ("ready" if "Reply with one word: ready." in prompt else
                "SecAgent is a prototype AI agent security testing system.")
        return httpx.Response(200, json={"choices": [{"message": {"content": text},
            "finish_reason": "stop"}]})
    transport = httpx.MockTransport(answer)
    def metadata(request):
        if request.method == "POST" and request.url.port == 7010:
            return httpx.Response(200, json={"jsonrpc": "2.0",
                "id": "secagent-discovery", "result": {"tools": [{"name": "read_file"}]}})
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "advertised-model"}]})
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json={"paths": {"/v1/chat/completions": {"post": {}}}})
        if request.url.path == "/.well-known/agent.json":
            return httpx.Response(200, json={"name": "Offline Agent", "skills": [{"name": "summary"}]})
        return httpx.Response(404)
    discovery_transport = httpx.MockTransport(metadata)
    catalog = ManagedTargetCatalog(seed, args.state_dir / "operator-data", probe_transport=transport,
                                   local_single_user=args.local)
    dispatcher = (ControlledDispatcher(catalog, AdmissionPolicy(),
                  args.state_dir / "results" / "runs",
                  operator_secret="offline-browser-test-operator-secret-123456",
                  transport=transport, output_boundary=args.state_dir / "results")
                  if args.local_run and args.local else None)
    app = create_app(catalog, port=args.port, dispatcher=dispatcher,
                     operator_secret="offline-browser-test-operator-secret-123456",
                     local_single_user=args.local, discovery_transport=discovery_transport)
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
