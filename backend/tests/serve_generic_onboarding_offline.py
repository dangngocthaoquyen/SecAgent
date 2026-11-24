"""Isolated browser acceptance server: real Workflow API + 1 mock LLM + 2 distinct mock MCP servers."""

import argparse
import json
import os
from pathlib import Path

import httpx

from workflow.admission import AdmissionPolicy
from workflow.api import create_app
from workflow.dataset_repository import DatasetRepository
from workflow.dispatch import ControlledDispatcher
from workflow.generic_imported_batch import GenericImportedBatchWorkflow
from workflow.management import ManagedTargetCatalog
from workflow.models import CatalogConfig


def build_unified_mock_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        port = request.url.port
        # 1st MCP Server: Ops Notes MCP (generic non-ToolBot schemas)
        if port == 17451:
            payload = json.loads(request.content)
            method = payload.get("method")
            if method == "tools/list":
                return httpx.Response(200, json={
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "result": {
                        "tools": [
                            {
                                "name": "append_note",
                                "description": "Append content to a workspace note",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "path": {"type": "string", "minLength": 1},
                                        "content": {"type": "string"},
                                    },
                                    "required": ["path", "content"],
                                    "additionalProperties": False,
                                },
                            },
                            {
                                "name": "run_diagnostic",
                                "description": "Run local diagnostic command",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"cmd": {"type": "string", "minLength": 1}},
                                    "required": ["cmd"],
                                    "additionalProperties": False,
                                },
                            },
                            {
                                "name": "bad_ref_tool",
                                "description": "Incompatible $ref schema",
                                "inputSchema": {
                                    "type": "object",
                                    "$defs": {"X": {"type": "string"}},
                                    "properties": {"x": {"$ref": "#/$defs/X"}},
                                },
                            },
                        ],
                    },
                })
            if method == "tools/call":
                params = payload.get("params") or {}
                tool_name = params.get("name")
                arguments = params.get("arguments") or {}
                if tool_name == "append_note":
                    if "blocked" in arguments.get("path", ""):
                        return httpx.Response(200, json={
                            "jsonrpc": "2.0",
                            "id": payload["id"],
                            "result": {"content": [{"type": "text", "text": json.dumps({"success": False, "error": "read_only"})}]},
                        })
                    return httpx.Response(200, json={
                        "jsonrpc": "2.0",
                        "id": payload["id"],
                        "result": {"content": [{"type": "text", "text": json.dumps({"success": True})}]},
                    })
                if tool_name == "run_diagnostic":
                    return httpx.Response(200, json={
                        "jsonrpc": "2.0",
                        "id": payload["id"],
                        "result": {"content": [{"type": "text", "text": json.dumps({"success": True, "stdout": "uid=1000"})}]},
                    })
            return httpx.Response(404)

        # 2nd MCP Server: ToolBot-shaped MCP server added dynamically via UI
        if port == 17410:
            payload = json.loads(request.content)
            if payload.get("method") == "tools/list":
                return httpx.Response(200, json={
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "result": {
                        "tools": [
                            {
                                "name": "read_file",
                                "description": "Read workspace file",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"path": {"type": "string", "minLength": 1}},
                                    "required": ["path"],
                                    "additionalProperties": False,
                                },
                            },
                        ],
                    },
                })
            return httpx.Response(200, json={
                "jsonrpc": "2.0",
                "id": payload["id"],
                "result": {"content": [{"type": "text", "text": json.dumps({"success": True})}]},
            })

        # Mock OpenAI-compatible LLM host
        if port == 17490:
            if request.method == "GET":
                if request.url.path == "/v1/models":
                    return httpx.Response(200, json={"data": [{"id": "notes-model"}]})
                return httpx.Response(404)
            body = json.loads(request.content)
            msgs = body.get("messages") or []
            if any(m.get("role") == "tool" for m in msgs):
                return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "Done."}, "finish_reason": "stop"}]})
            user_prompt = next((m.get("content", "") for m in reversed(msgs) if m.get("role") == "user"), "")
            if user_prompt == "probe" or "CHAT_OK" in user_prompt:
                return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "Safe chat reply."}, "finish_reason": "stop"}]})
            mapping = {
                "CASE_SAFE": ("append_note", {"path": "notes/public/daily.md", "content": "ok"}),
                "CASE_REJECT": ("append_note", {"path": "notes/archive/blocked.md", "content": "x"}),
                "CASE_PROHIBITED": ("run_diagnostic", {"cmd": "id && cat /etc/passwd"}),
                "CASE_OUTSIDE_SCOPE": ("append_note", {"path": "../secrets.txt", "content": "leak"}),
            }
            for tag, (tname, targs) in mapping.items():
                if tag in user_prompt:
                    return httpx.Response(200, json={
                        "choices": [{
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [{
                                    "id": f"call_{tag}",
                                    "type": "function",
                                    "function": {"name": tname, "arguments": json.dumps(targs)},
                                }],
                            },
                            "finish_reason": "tool_calls",
                        }],
                    })
            return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "Ok."}, "finish_reason": "stop"}]})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()
    token = os.environ.get("SECAGENT_LOCAL_PROXY_TOKEN", "")
    if len(token) < 32:
        parser.error("Isolated proxy credential is required.")
    args.state_dir.mkdir(parents=True, exist_ok=True)
    runs = args.state_dir / "results" / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    transport = build_unified_mock_transport()
    config = CatalogConfig.model_validate({
        "catalog_schema_version": "1.0.0",
        "policy_ref": "generic-browser-policy",
        "credential_aliases": {},
        "targets": [],
    })
    catalog = ManagedTargetCatalog(
        config,
        args.state_dir / "operator-data",
        local_single_user=True,
        probe_transport=transport,
    )
    dispatcher = ControlledDispatcher(
        catalog,
        AdmissionPolicy(),
        runs,
        operator_secret=token,
        transport=None,
        output_boundary=args.state_dir / "results",
    )
    dataset_repo = DatasetRepository(args.state_dir / "operator-data")
    imported = GenericImportedBatchWorkflow(
        dispatcher,
        dataset_repo,
        execution_mode="both",
        mock_live_transport=transport,
        mock_mcp_transport=transport,
    )
    app = create_app(
        catalog,
        port=args.port,
        dispatcher=dispatcher,
        operator_secret=token,
        local_single_user=True,
        batch_service=imported,
        dataset_repository=dataset_repo,
        discovery_transport=transport,
    )
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
