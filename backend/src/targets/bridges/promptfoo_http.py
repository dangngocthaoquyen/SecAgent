"""Loopback OpenAI-chat facade around an exact, SHA-pinned Promptfoo provider.

This target-specific sidecar is not a Judge or a ToolBot MCP adapter. It passes
one user message to the existing provider; the provider owns any LLM/MCP calls.
"""

import argparse
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import subprocess
from threading import Lock
import zipfile


_NODE_RUNNER = r"""
'use strict';
const fs = require('node:fs');
const Provider = require(process.argv[1]);
(async () => {
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  const provider = new Provider({config: {testCategory: input.category}});
  const result = await provider.callApi(input.prompt, {});
  const raw = JSON.stringify(result);
  if (Buffer.byteLength(raw, 'utf8') > 131072) throw Error('provider_result_too_large');
  process.stdout.write(raw);
})().catch(() => { process.exitCode = 1; });
"""


def load_config(path: Path) -> dict:
    """Validate a deliberate operator-owned executable binding, without a key."""
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 8192:
        raise ValueError("agent_bridge_config_unavailable")
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
        if (set(config) != {"schema_version", "provider_zip", "provider_entry",
                            "provider_sha256", "model", "credential_env", "port", "category"}
                or config["schema_version"] != "1.0.0"
                or not isinstance(config["provider_zip"], str)
                or not Path(config["provider_zip"]).is_absolute()
                or not isinstance(config["provider_entry"], str)
                or not config["provider_entry"].endswith(".cjs")
                or ".." in Path(config["provider_entry"]).parts
                or not re.fullmatch(r"[a-f0-9]{64}", config["provider_sha256"])
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", config["model"])
                or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", config["credential_env"])
                or type(config["port"]) is not int or not 1024 <= config["port"] <= 65535
                or not re.fullmatch(r"ASI[0-9]{2}", config["category"])):
            raise ValueError
        archive = Path(config["provider_zip"])
        if not archive.is_file() or archive.is_symlink() or archive.stat().st_size > 50_000_000:
            raise ValueError
        with zipfile.ZipFile(archive) as bundle:
            info = bundle.getinfo(config["provider_entry"])
            if info.file_size > 32768 or info.is_dir():
                raise ValueError
            source = bundle.read(info)
        if sha256(source).hexdigest() != config["provider_sha256"]:
            raise ValueError
        return {**config, "provider_bytes": source}
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile):
        raise ValueError("agent_bridge_config_invalid") from None


def prepare_provider(config: dict, data_dir: Path) -> Path:
    root = Path(data_dir)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink():
        raise ValueError("agent_bridge_storage_invalid")
    destination = root / (config["provider_sha256"] + ".cjs")
    if destination.exists():
        if destination.is_symlink() or sha256(destination.read_bytes()).hexdigest() != config["provider_sha256"]:
            raise ValueError("agent_bridge_storage_invalid")
    else:
        fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(config["provider_bytes"])
    return destination


def _safe_trace(metadata: object) -> dict:
    calls = metadata.get("toolCalls") if isinstance(metadata, dict) else None
    rows = []
    if isinstance(calls, list):
        for index, item in enumerate(calls[:3]):
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name):
                continue
            args = item.get("args")
            encoded = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            rows.append({"index": index, "tool_name": name,
                         "arguments_sha256": sha256(encoded.encode("utf-8")).hexdigest() if isinstance(args, dict) else None,
                         "invoked": item.get("invoked") is True,
                         "mcp_response_present": isinstance(item.get("mcpResponse"), dict)})
    return {"schema_version": "1.0.0", "provenance": "provider_reported",
            "execution_verified": False, "trace_completeness": "partial", "tool_calls": rows}


def provider_response(provider_path: Path, config: dict, prompt: str, *, node: str = "node",
                      timeout: int = 25) -> tuple[int, dict]:
    """Execute one provider attempt; never include raw stderr in the response."""
    if not os.environ.get(config["credential_env"]):
        return 503, {"error": {"code": "credential_missing"}}
    child_env = {k: v for k, v in os.environ.items()
                 if not k.upper().endswith(("_API_KEY", "_TOKEN", "_SECRET"))}
    child_env[config["credential_env"]] = os.environ[config["credential_env"]]
    try:
        result = subprocess.run([node, "-e", _NODE_RUNNER, str(provider_path)],
                                input=json.dumps({"prompt": prompt, "category": config["category"]}),
                                text=True, capture_output=True, env=child_env,
                                cwd=provider_path.parent, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return 502, {"error": {"code": "provider_unavailable"}}
    if result.returncode != 0 or len(result.stdout.encode("utf-8")) > 131072:
        return 502, {"error": {"code": "provider_failed"}}
    try:
        value = json.loads(result.stdout)
    except (ValueError, TypeError):
        return 502, {"error": {"code": "provider_invalid_output"}}
    if not isinstance(value, dict) or not isinstance(value.get("output"), str) or value.get("error"):
        return 502, {"error": {"code": "provider_failed"}}
    return 200, {"id": "secagent-bridge-" + sha256(os.urandom(16)).hexdigest()[:24],
                 "object": "chat.completion", "model": config["model"],
                 "choices": [{"index": 0, "message": {"role": "assistant", "content": value["output"]},
                              "finish_reason": "stop"}],
                 "secagent_bridge": _safe_trace(value.get("metadata"))}


def make_handler(config: dict, provider_path: Path, *, invoke=provider_response):
    gate = Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # Never log prompts, credentials, provider output or URL paths.

        def send_json(self, status, value):
            raw = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path == "/health":
                return self.send_json(200, {"status": "ok", "model": config["model"],
                    "provider_sha256": config["provider_sha256"],
                    "credential_present": bool(os.environ.get(config["credential_env"]))})
            if self.path == "/v1/models":
                return self.send_json(200, {"object": "list", "data": [{
                    "id": config["model"], "object": "model"}]})
            return self.send_json(404, {"error": {"code": "not_found"}})

        def do_POST(self):
            if self.path != "/v1/chat/completions":
                return self.send_json(404, {"error": {"code": "not_found"}})
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                return self.send_json(415, {"error": {"code": "json_required"}})
            try:
                size = int(self.headers.get("Content-Length", ""))
                if not 0 < size <= 70000:
                    raise ValueError
                body = json.loads(self.rfile.read(size))
                if (not isinstance(body, dict)
                        or not {"model", "messages"} <= set(body)
                        or set(body) - {"model", "messages", "stream"}
                        or ("stream" in body and body["stream"] is not False)
                        or body["model"] != config["model"] or not isinstance(body["messages"], list)
                        or len(body["messages"]) != 1 or not isinstance(body["messages"][0], dict)
                        or set(body["messages"][0]) != {"role", "content"}
                        or body["messages"][0]["role"] != "user"
                        or not isinstance(body["messages"][0]["content"], str)
                        or not 0 < len(body["messages"][0]["content"].encode("utf-8")) <= 65536):
                    raise ValueError
            except (ValueError, TypeError, UnicodeError):
                return self.send_json(400, {"error": {"code": "invalid_chat_request"}})
            if not gate.acquire(blocking=False):
                return self.send_json(429, {"error": {"code": "provider_busy"}})
            try:
                status, value = invoke(provider_path, config, body["messages"][0]["content"])
                self.send_json(status, value)
            finally:
                gate.release()

    return Handler


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--data-dir", required=True)
    args = parser.parse_args(argv)
    config = load_config(Path(args.config))
    provider = prepare_provider(config, Path(args.data_dir))
    server = ThreadingHTTPServer(("127.0.0.1", config["port"]), make_handler(config, provider))
    server.serve_forever()


if __name__ == "__main__":
    main()
