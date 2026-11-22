"""Bounded, metadata-only discovery for explicitly authorized local targets.

This service never submits chat messages, follows redirects, resolves remote
references, or turns advertised capabilities into execution authorization.
Literal loopback IPs avoid DNS rebinding; nonlocal discovery needs a separately
reviewed network policy rather than a permissive URL fetcher.
"""

from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from pydantic import Field, model_validator

from workflow.models import ClosedModel, Identifier


MAX_REQUESTS = 3
MAX_BYTES = 16384
TIMEOUT_SECONDS = 3.0
METADATA_PATHS = ("/v1/models", "/openapi.json", "/.well-known/agent.json")
INPUT_PATHS = ("/", "/v1/chat/completions", "/chat/completions",
               "/openapi.json", "/.well-known/agent.json", "/mcp", "/jsonrpc")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/ -]{0,127}$")
SAFE_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}$")


class DiscoveryRequest(ClosedModel):
    url: str = Field(min_length=1, max_length=256)
    authorization_confirmed: bool
    protocol_hint: str | None = None
    credential_alias: Identifier | None = None

    @model_validator(mode="after")
    def confirmed(self):
        if self.authorization_confirmed is not True:
            raise ValueError("Explicit metadata discovery authorization required.")
        if self.protocol_hint not in {None, "openai-chat", "openapi-http", "a2a", "mcp-jsonrpc"}:
            raise ValueError("Unsupported discovery protocol hint.")
        return self


class DiscoveryError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def canonical_input(raw: str) -> tuple[str, str, str]:
    if any(ord(char) < 33 or char in "\\%" for char in raw) or raw != raw.strip():
        raise DiscoveryError("invalid_discovery_url")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except (ValueError, TypeError):
        raise DiscoveryError("invalid_discovery_url") from None
    if (parsed.scheme not in {"http", "https"} or not parsed.netloc or
            parsed.username is not None or parsed.password is not None or
            parsed.query or parsed.fragment or port is None):
        raise DiscoveryError("invalid_discovery_url")
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError:
        raise DiscoveryError("unsafe_discovery_destination") from None
    if not address.is_loopback or parsed.path not in INPUT_PATHS:
        raise DiscoveryError("unsafe_discovery_destination")
    host = f"[{address.compressed}]" if address.version == 6 else str(address)
    origin = f"{parsed.scheme}://{host}:{port}"
    path = parsed.path or "/"
    return origin, path, origin + path


def _short(value, pattern=SAFE_NAME) -> str | None:
    return value if isinstance(value, str) and pattern.fullmatch(value) else None


class DiscoveryEngine:
    def __init__(self, data_dir: Path, *, transport: httpx.BaseTransport | None = None,
                 evidence_providers=()):
        self.root = Path(data_dir).resolve() / "discoveries"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink():
            raise DiscoveryError("unsafe_discovery_storage")
        self.transport = transport
        self.evidence_providers = tuple(evidence_providers)

    def _read_mcp_tools(self, client: httpx.Client, endpoint: str) -> tuple[str, list[str]]:
        # tools/list is the only MCP discovery method. Never invoke a tool here.
        checked_origin, path, checked = canonical_input(endpoint)
        if checked != endpoint or path not in {"/", "/mcp", "/jsonrpc"}:
            raise DiscoveryError("unsafe_discovery_destination")
        try:
            with client.stream("POST", endpoint, headers={"Accept": "application/json",
                    "Content-Type": "application/json"}, json={"jsonrpc": "2.0",
                    "id": "secagent-discovery", "method": "tools/list", "params": {}}) as response:
                if 300 <= response.status_code < 400:
                    raise DiscoveryError("discovery_redirect_rejected")
                if response.status_code in {404, 405}:
                    return "missing", []
                if response.status_code != 200:
                    return "http_error", []
                parts, size = [], 0
                for part in response.iter_bytes():
                    size += len(part)
                    if size > MAX_BYTES:
                        raise DiscoveryError("discovery_response_too_large")
                    parts.append(part)
                try:
                    body = json.loads(b"".join(parts))
                except (ValueError, UnicodeError):
                    return "malformed", []
                if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or body.get("id") != "secagent-discovery":
                    return "malformed", []
                result = body.get("result")
                tools = result.get("tools") if isinstance(result, dict) else None
                if (not isinstance(tools, list) or len(tools) > 100 or
                        any(not isinstance(item, dict) or _short(item.get("name")) is None
                            for item in tools)):
                    return "malformed", []
                names = [item["name"] for item in tools[:20]]
                return "advertised", list(dict.fromkeys(names))
        except httpx.TimeoutException:
            return "timeout", []
        except httpx.RequestError:
            return "connection_failure", []

    def _read_source(self, client: httpx.Client, origin: str, path: str) -> tuple[str, dict | None]:
        # Revalidate at the connection boundary. Only literal loopback IPs are
        # accepted; there is no DNS resolution or redirect destination switch.
        if path not in METADATA_PATHS:
            raise DiscoveryError("unsafe_discovery_destination")
        checked_origin, _, _ = canonical_input(origin + "/")
        if checked_origin != origin:
            raise DiscoveryError("unsafe_discovery_destination")
        try:
            with client.stream("GET", origin + path, headers={"Accept": "application/json"}) as response:
                if 300 <= response.status_code < 400:
                    raise DiscoveryError("discovery_redirect_rejected")
                if response.status_code in {404, 405}:
                    return "missing", None
                if response.status_code != 200:
                    return "http_error", None
                parts, size = [], 0
                for part in response.iter_bytes():
                    size += len(part)
                    if size > MAX_BYTES:
                        raise DiscoveryError("discovery_response_too_large")
                    parts.append(part)
                try:
                    body = json.loads(b"".join(parts))
                except (ValueError, UnicodeError):
                    return "malformed", None
                return ("advertised", body) if isinstance(body, dict) else ("malformed", None)
        except httpx.TimeoutException:
            return "timeout", None
        except httpx.RequestError:
            return "connection_failure", None

    def discover(self, request: DiscoveryRequest, *, allowed_aliases: set[str],
                 testcase_items: list[dict], text_case_ids: set[str]) -> dict:
        origin, input_path, canonical = canonical_input(request.url)
        if request.credential_alias and request.credential_alias not in allowed_aliases:
            raise DiscoveryError("unknown_credential_alias")
        sources, models, agent, advertised_tools, advertised_skills = [], [], None, [], []
        openapi_chat_path = None
        adapter_hint = (next((hint for provider in self.evidence_providers
            if (hint := getattr(provider, "preferred_protocol", lambda **_: None)(
                origin=origin, input_path=input_path)) is not None), None)
            if request.protocol_hint is None and input_path == "/" else None)
        mcp_mode = (request.protocol_hint == "mcp-jsonrpc" or
                    input_path in {"/mcp", "/jsonrpc"} or adapter_hint == "mcp-jsonrpc")
        client = httpx.Client(transport=self.transport, timeout=TIMEOUT_SECONDS,
                             follow_redirects=False, trust_env=False)
        try:
            if mcp_mode:
                status, advertised_tools = self._read_mcp_tools(client, canonical)
                sources.append({"url": canonical, "status": status,
                    "classification": "mcp_tools_list" if status == "advertised" else "unverified"})
            for path in (() if mcp_mode else METADATA_PATHS):
                status, body = self._read_source(client, origin, path)
                source = {"url": origin + path, "status": status,
                          "classification": "advertised_metadata" if status == "advertised" else "unverified"}
                sources.append(source)
                if status != "advertised" or body is None:
                    continue
                if path == "/v1/models":
                    data = body.get("data")
                    if isinstance(data, list) and len(data) <= 100:
                        models = list(dict.fromkeys(value for entry in data[:20]
                            if isinstance(entry, dict)
                            if (value := _short(entry.get("id"), SAFE_MODEL)) is not None))
                    else:
                        source["status"] = "malformed"
                        source["classification"] = "unverified"
                elif path == "/openapi.json":
                    paths = body.get("paths")
                    if isinstance(paths, dict):
                        openapi_chat_path = next((candidate for candidate in
                            ("/v1/chat/completions", "/chat/completions")
                            if isinstance(paths.get(candidate), dict) and
                            isinstance(paths[candidate].get("post"), dict)), None)
                    else:
                        source["status"] = "malformed"
                        source["classification"] = "unverified"
                else:
                    agent = _short(body.get("name"))
                    tools = body.get("tools")
                    skills = body.get("skills")
                    if isinstance(tools, list):
                        advertised_tools = [name for entry in tools[:20]
                            if isinstance(entry, dict)
                            if (name := _short(entry.get("name"))) is not None]
                    if isinstance(skills, list):
                        advertised_skills = [name for entry in skills[:20]
                            if isinstance(entry, dict)
                            if (name := _short(entry.get("name"))) is not None]
                    advertised_tools = list(dict.fromkeys(advertised_tools))[:20]
                    advertised_skills = list(dict.fromkeys(advertised_skills))[:20]
        finally:
            client.close()
        explicit_chat = input_path in {"/v1/chat/completions", "/chat/completions"}
        chat_path = input_path if explicit_chat else openapi_chat_path
        endpoint = canonical if mcp_mode and sources[0]["status"] == "advertised" else origin + chat_path if chat_path else None
        protocol_candidates = []
        if mcp_mode and endpoint:
            protocol_candidates.append({"id": "mcp-jsonrpc", "classification": "observed_tools_list",
                "source": canonical, "runtime_verified": False})
        elif endpoint:
            protocol_candidates.append({"id": "openai-chat", "classification":
                "operator_supplied" if explicit_chat else "advertised_metadata",
                "source": canonical if explicit_chat else origin + "/openapi.json",
                "runtime_verified": False})
        if any(row["url"].endswith("/openapi.json") and row["status"] == "advertised" for row in sources):
            protocol_candidates.append({"id": "openapi-http", "classification": "advertised_metadata",
                "source": origin + "/openapi.json", "runtime_verified": False})
        if agent:
            protocol_candidates.append({"id": "a2a", "classification": "advertised_metadata",
                "source": origin + "/.well-known/agent.json", "runtime_verified": False})
        target_id = "local-agent-" + str(urlsplit(origin).port)
        proposed = ({"id": target_id, "name": "Local AI Agent", "platform_id": "local-agent",
                     "platform_name": "Local Agent", "endpoint": endpoint,
                     "protocol": "mcp-jsonrpc" if mcp_mode else "openai-chat",
                     "model": "mcp-service" if mcp_mode else models[0] if models else "", "timeout_seconds": 30}
                    if endpoint else None)
        unknown = (["model", "tool_execution", "handler_receipt", "trace_completeness",
                    "agent_selected_action"] + ([] if endpoint else ["mcp_endpoint"])
                   if mcp_mode else
                   [field for field, known in (("runtime_chat_contract", False),
                    ("tool_execution", False), ("model", bool(models)),
                    ("chat_endpoint", bool(endpoint))) if not known])
        warnings = ["Metadata and operator input do not verify runtime behavior or execution authorization."]
        for condition, message in (("timeout", "A metadata request timed out."),
                                   ("connection_failure", "A metadata request could not connect."),
                                   ("malformed", "A metadata response was malformed."),
                                   ("http_error", "A metadata endpoint returned an HTTP error.")):
            if any(row["status"] == condition for row in sources):
                warnings.append(message)
        if not endpoint:
            warnings.append("No supported target endpoint was verified; configure the target manually.")
        if mcp_mode:
            warnings.append("MCP tools/list verifies tool metadata only; no tool was invoked or handler execution verified.")
        if request.credential_alias:
            warnings.append("Credential alias was recorded but no credential was sent during discovery.")
        if request.protocol_hint:
            warnings.append("Protocol hint is operator supplied; it does not verify a runtime protocol contract.")
        if adapter_hint:
            warnings.append("Adapter hint selected the MCP metadata probe; the tools/list response determines the proposal.")
        status = "metadata_found" if any(row["status"] == "advertised" for row in sources) else "manual_configuration_required"
        connection_status = ("reachable" if any(row["status"] in {"advertised", "missing", "malformed", "http_error"} for row in sources)
                             else "unavailable")
        evidence_candidates = []
        for provider in self.evidence_providers:
            evidence_candidates.extend(provider.candidates(origin=origin, endpoint=endpoint,
                protocol="mcp-jsonrpc" if mcp_mode else "openai-chat", connection_status=connection_status,
                tools=tuple(advertised_tools), models=tuple(models)))
        evidence_candidates = evidence_candidates[:20]
        recommendations = []
        for item in testcase_items:
            text_binding = item["id"] in text_case_ids
            recommendation = ("CONDITIONAL" if endpoint else "UNKNOWN") if text_binding else "UNSUPPORTED"
            recommendations.append({"testcase_id": item["id"],
                "asi_category": item["asi_category"], "status": recommendation,
                "reason": ("review_and_runtime_contract_required" if endpoint else "chat_endpoint_unknown")
                          if text_binding else "no_reviewed_execution_binding",
                "security_verdict": None})
        record = {"workflow_schema_version": "1.0.0", "discovery_id": uuid4().hex,
            "discovered_at": datetime.now(timezone.utc).isoformat(),
            "input_url": canonical, "canonical_endpoint": endpoint,
            "status": status, "connection_status": connection_status,
            "request_count": len(sources), "request_budget": MAX_REQUESTS,
            "metadata_sources": sources, "protocol_candidates": protocol_candidates,
            "evidence_candidates": evidence_candidates,
            "advertised_models": [{"id": model, "source": origin + "/v1/models",
                                   "classification": "advertised_metadata"} for model in models],
            "advertised_agent": ({"name": agent, "source": origin + "/.well-known/agent.json",
                                  "classification": "advertised_metadata"} if agent else None),
            "advertised_tools": [{"name": name, "source": canonical if mcp_mode else origin + "/.well-known/agent.json",
                                  "classification": "mcp_tools_list" if mcp_mode else "advertised_metadata"} for name in advertised_tools],
            "advertised_skills": [{"name": name, "source": origin + "/.well-known/agent.json",
                                   "classification": "advertised_metadata"} for name in advertised_skills],
            "possible_contracts": ([{"request": "mcp-tools-call-v1", "response": "mcp-jsonrpc-result-v1",
                                    "classification": "tools_list_only_action_unverified"}] if mcp_mode and endpoint else
                [{"request": "openai-chat-user-message-v1",
                                    "response": "choices.0.message.content",
                                    "classification": "advertised_or_operator_supplied_unverified"}] if endpoint else []),
            "unknown_fields": unknown, "warnings": warnings,
            "recommendations": recommendations,
            "proposed_profile": proposed, "credential_alias": request.credential_alias,
            "protocol_hint": request.protocol_hint,
            "adapter_protocol_hint": adapter_hint,
            "security_test_executed": False, "security_verdict": None,
            "profile_revision": None}
        self._save(record)
        return record

    def _path(self, discovery_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", discovery_id):
            raise DiscoveryError("invalid_discovery_id")
        return self.root / (discovery_id + ".json")

    def _save(self, record: dict):
        path = self._path(record["discovery_id"])
        temporary = self.root / ("." + record["discovery_id"] + "." + uuid4().hex)
        try:
            with temporary.open("x", encoding="utf-8") as stream:
                json.dump(record, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def load(self, discovery_id: str) -> dict:
        path = self._path(discovery_id)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 32768:
            raise DiscoveryError("discovery_record_not_found")
        return json.loads(path.read_text(encoding="utf-8"))

    def associate(self, discovery_id: str, profile: dict):
        record = self.validate_association(discovery_id, profile["endpoint"], profile["protocol"])
        record["saved_target_id"] = profile["id"]
        record["profile_revision"] = profile["profile_revision"]
        record["associated_at"] = datetime.now(timezone.utc).isoformat()
        self._save(record)

    def validate_association(self, discovery_id: str, endpoint: str, protocol: str) -> dict:
        record = self.load(discovery_id)
        if (record["proposed_profile"] is None or
                record["canonical_endpoint"] != endpoint or
                record["proposed_profile"]["protocol"] != protocol or
                record["profile_revision"] is not None):
            raise DiscoveryError("discovery_profile_mismatch")
        return record
