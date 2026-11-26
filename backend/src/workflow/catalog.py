"""Operator-selected catalog; constructs profiles offline, never invokes adapters."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import stat
from urllib.parse import urlsplit

from targets.runtime import build_runtime_target
from core.models import TargetProfile
from evaluators.contract import summarize_target_capabilities_and_scopes
from targets.validator import validate_target
from workflow.models import CatalogConfig, TargetDraft, ConnectionCheckResult


ROOT = Path(__file__).resolve().parents[3]


def safe_file(path: Path, root: Path) -> None:
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Outside repository scope")
    for part in (path, *path.parents):
        if part == root.parent:
            break
        if part.is_symlink() or getattr(part.stat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("Linked artifact")
    if not path.is_file() or path.stat().st_size > 262144:
        raise ValueError("Invalid artifact")


_OPTIONAL_EXTENSION_PRESET_FIELDS = ("http_config", "capability_states", "capability_provenance", "session_auth")


def serialize_preset_for_revision(preset, *, exclude=frozenset()):
    """Serialize Preset for revision hashing without altering legacy hashes when new optional fields are None."""
    dumped = preset.model_dump(exclude=set(exclude))
    for field_name in _OPTIONAL_EXTENSION_PRESET_FIELDS:
        if dumped.get(field_name) is None:
            dumped.pop(field_name, None)
    return dumped


def build_http_response_config_dict(http_config) -> dict:
    resp = {"text_path": http_config.response.text_path}
    if http_config.response.status_path:
        resp["status_path"] = http_config.response.status_path
    if http_config.response.complete_status_values:
        resp["complete_status_values"] = list(http_config.response.complete_status_values)
    if http_config.response.incomplete_status_values:
        resp["incomplete_status_values"] = list(http_config.response.incomplete_status_values)
    if http_config.response.correlation_id_path:
        resp["correlation_id_path"] = http_config.response.correlation_id_path
    if http_config.response.evidence_mapping is not None:
        resp["evidence_mapping"] = http_config.response.evidence_mapping.model_dump(exclude_none=True)
    return resp


def default_capability_states_for_preset(preset) -> dict[str, str]:
    if preset.protocol == "mcp-jsonrpc":
        base = {"mcp": "supported", "direct_tool_access": "supported"}
    elif preset.protocol == "http-json":
        base = {"response_behavior": "unverified", "chat": "unverified"}
    else:
        base = {"chat": "supported", "response_behavior": "supported"}
    if preset.capability_states:
        base.update(preset.capability_states)
    return base


class CatalogError(ValueError):
    pass


def read_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key.")
            result[key] = value
        return result
    def bad_constant(_):
        raise ValueError("Nonfinite JSON.")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=bad_constant)


def make_profile(preset, model, timeout, credential_env=None, *, session_auth=None):
    endpoint = preset.endpoint
    parts = urlsplit(endpoint)
    effective_session_auth = session_auth if session_auth is not None else getattr(preset, "session_auth", None)
    if credential_env is not None and effective_session_auth is not None:
        raise ValueError("Conflicting authentication configuration: cannot combine environment credential and session credential.")
    # Tighten the shared runtime builder for this web preset: no encoded path,
    # traversal, empty segments or parser ambiguities; no DNS resolution.
    if (not parts.path.startswith("/") or "%" in endpoint or "?" in endpoint or "#" in endpoint
            or any(s in {".", ".."} for s in parts.path.split("/")) or "//" in parts.path):
        raise ValueError("Invalid preset endpoint.")
    if preset.protocol == "mcp-jsonrpc":
        if effective_session_auth is not None:
            raise ValueError("session_auth is only valid for http-json targets.")
        if preset.id == "dvaa-toolbot-lab":
            if (endpoint != "http://127.0.0.1:17022/mcp"
                    or model != "toolbot-lab" or credential_env is not None):
                raise ValueError("Only the exact offline ToolBot Lab MCP profile is supported.")
        else:
            try:
                host = ipaddress.ip_address(parts.hostname or "")
                safe = (parts.scheme in {"http", "https"} and parts.port is not None
                    and host.is_loopback and parts.path in {"/", "/mcp", "/jsonrpc"}
                    and parts.username is None and parts.password is None)
            except ValueError:
                safe = False
            if not safe:
                raise ValueError("Generic MCP profile requires an exact loopback JSON-RPC endpoint.")
        headers = {"Content-Type": "application/json"}
        credential_refs = []
        if credential_env is not None:
            headers["Authorization"] = f"Bearer {{{{credential:{credential_env}}}}}"
            credential_refs.append(credential_env)
        profile = TargetProfile(id=preset.id, name=preset.name, target_type="ai_agent",
            interface={"type": "mcp", "adapter": "generic_mcp_jsonrpc", "config": {
                "url": endpoint, "timeout": timeout, "headers": headers}},
            capabilities=["tool_call"],
            capability_states=default_capability_states_for_preset(preset),
            observability=["tool_result"],
            credential_refs=credential_refs,
            metadata={"configuration_source": "operator_reviewed_offline_lab" if preset.id == "dvaa-toolbot-lab" else "operator_configured",
                      "protocol": "mcp-jsonrpc"})
    elif preset.protocol == "http-json":
        if preset.http_config is None:
            raise ValueError("http-json preset requires http_config.")
        try:
            host = ipaddress.ip_address(parts.hostname or "")
            safe = (
                parts.scheme in {"http", "https"}
                and (host.is_loopback or host.is_private)
                and not host.is_link_local
                and not host.is_multicast
                and not host.is_unspecified
                and parts.username is None
                and parts.password is None
            )
        except ValueError:
            safe = (parts.hostname or "").lower() == "localhost" and parts.username is None and parts.password is None
        if not safe:
            raise ValueError("HTTP JSON target requires an authorized local or private IP/localhost endpoint.")
        headers = {"Content-Type": "application/json"}
        for h_key, h_val in preset.http_config.headers.items():
            if h_key.lower() == "content-type":
                headers["Content-Type"] = h_val
            else:
                headers[h_key] = h_val
        credential_refs = []
        auth_source = "none"
        if credential_env is not None:
            if any(k.lower() == "authorization" for k in headers):
                raise ValueError("Conflicting Authorization header.")
            headers["Authorization"] = f"Bearer {{{{credential:{credential_env}}}}}"
            credential_refs.append(credential_env)
            auth_source = "env_alias"
        elif effective_session_auth is not None:
            auth_header = effective_session_auth.header_name
            if any(k.lower() == auth_header.lower() for k in headers):
                raise ValueError("Custom HTTP header conflicts with session authentication header.")
            if effective_session_auth.auth_type == "bearer":
                headers["Authorization"] = f"Bearer {{{{session_credential:{effective_session_auth.ref_id}}}}}"
            else:
                headers[auth_header] = f"{{{{session_credential:{effective_session_auth.ref_id}}}}}"
            credential_refs.append(effective_session_auth.ref_id)
            auth_source = "session_memory"
        obs = ["response"]
        if preset.http_config.response.evidence_mapping is not None:
            obs.append("inline_evidence")
        metadata = {
            "configuration_source": "operator_configured",
            "protocol": "http-json",
            "auth_source": auth_source,
        }
        if effective_session_auth is not None:
            metadata["session_credential_ref"] = effective_session_auth.ref_id
            metadata["session_auth_type"] = effective_session_auth.auth_type
            metadata["session_auth_header"] = effective_session_auth.header_name
        profile = TargetProfile(
            id=preset.id,
            name=preset.name,
            target_type="ai_agent",
            interface={
                "type": "http",
                "adapter": "generic_http",
                "config": {
                    "url": endpoint,
                    "method": preset.http_config.method,
                    "headers": headers,
                    "trust_env": False,
                    "body": dict(preset.http_config.body_template),
                    "response": build_http_response_config_dict(preset.http_config),
                },
            },
            capabilities=["http_json"],
            capability_states=default_capability_states_for_preset(preset),
            observability=obs,
            credential_refs=credential_refs,
            metadata=metadata,
        )
    else:
        if effective_session_auth is not None:
            raise ValueError("session_auth is only valid for http-json targets.")
        profile = build_runtime_target(endpoint, preset.id, protocol=preset.protocol,
            authorized_origin=f"{parts.scheme}://{parts.netloc}", model=model or "default",
            credential_env=credential_env, discover=False)
        if credential_env is not None:
            profile.interface.config["headers"]["Authorization"] = f"Bearer {{{{credential:{credential_env}}}}}"
        if preset.capability_states:
            profile = profile.model_copy(
                update={"capability_states": default_capability_states_for_preset(preset)}
            )
    profile.interface.config["timeout"] = timeout
    validate_target(profile)
    return profile


class TargetCatalog:
    def __init__(self, config: CatalogConfig):
        # Detach from caller containers; config is a startup snapshot.
        self._config = CatalogConfig.model_validate(config.model_dump())
        for preset in self._config.targets:
            make_profile(preset, preset.default_model, preset.timeout_default)
        self._targets = {p.id: p for p in self._config.targets}
        self._revisions = {p.id: hashlib.sha256(json.dumps({
            # New platform labels only group the UI; they grant no authority and
            # must not invalidate an otherwise unchanged execution profile.
            "policy": self._config.policy_ref,
            "preset": serialize_preset_for_revision(p, exclude={"platform_id", "platform_name"}),
            "credential_binding": self._config.credential_aliases.get(p.credential_alias),
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest() for p in self._config.targets}

    def _available(self, alias):
        if alias is None:
            return "not_required"
        return "available" if os.environ.get(self._config.credential_aliases[alias], "").strip() else "unavailable"

    def _preset_credential_status(self, preset) -> tuple[str, str]:
        if preset.credential_alias is not None:
            return self._available(preset.credential_alias), "env_alias"
        session_auth = getattr(preset, "session_auth", None)
        if session_auth is not None:
            store = getattr(self, "session_credentials", None)
            if store is None:
                return "unavailable", "session_memory"
            avail = store.availability(
                session_auth.ref_id,
                endpoint=preset.endpoint,
                scope_id=preset.id,
                scope_kind="target",
                expected_auth_type=session_auth.auth_type,
                expected_header_name=session_auth.header_name,
            )
            return avail, "session_memory"
        return "not_required", "none"

    def public_targets(self):
        rows = []
        for p in self._config.targets:
            cap_states = default_capability_states_for_preset(p)
            has_inline = bool(p.http_config and p.http_config.response.evidence_mapping is not None)
            req_mapping = (
                "mcp-tools-call-v1"
                if p.protocol == "mcp-jsonrpc"
                else ("http-json-template-v1" if p.protocol == "http-json" else "openai-chat-user-message-v1")
            )
            resp_parser = (
                "mcp-jsonrpc-result-v1"
                if p.protocol == "mcp-jsonrpc"
                else (p.http_config.response.text_path if p.protocol == "http-json" and p.http_config else "choices.0.message.content")
            )
            caps = ["tool_call"] if p.protocol == "mcp-jsonrpc" else (["http_json"] if p.protocol == "http-json" else ["chat"])
            cap_summary = summarize_target_capabilities_and_scopes(
                capability_states=cap_states,
                capabilities=caps,
                observability=["tool_result"] if p.protocol == "mcp-jsonrpc" else ["response"],
                has_inline_evidence=has_inline,
            )
            cred_availability, auth_source = self._preset_credential_status(p)
            row = {
                "id": p.id, "name": p.name,
                "platform_id": p.platform_id, "platform_name": p.platform_name,
                "profile_revision": self._revisions[p.id],
                "policy_ref": self._config.policy_ref,
                "authorization_status": "reviewed_for_offline_configuration" if p.reviewed else "review_required",
                "endpoint": p.endpoint, "protocol": p.protocol, "method": "POST",
                "models": list(p.models), "default_model": p.default_model or "",
                "timeout_min": p.timeout_min, "timeout_max": p.timeout_max, "timeout_default": p.timeout_default,
                "credential_alias": p.credential_alias, "credential_availability": cred_availability,
                "auth_source": auth_source,
                "request_mapping": req_mapping,
                "response_parser": resp_parser,
                "capabilities": caps,
                "capability_states": cap_states,
                "capability_provenance": dict(p.capability_provenance or {}),
                "capability_summary": cap_summary,
                "capability_basis": "configured_claim_not_probed",
                "connection_probe": {"status": "unsupported", "reason": "safe_probe_not_verified",
                                     "active_probe_authorized": False, "security_execution_authorized": False},
                "limitations": ["Offline configuration only; no target request is authorized or sent by this service.",
                                "Reachability and runtime protocol compatibility have not been checked."],
            }
            if p.session_auth is not None:
                row["session_auth"] = p.session_auth.model_dump(mode="json")
            if p.http_config is not None:
                row["http_config"] = p.http_config.model_dump(mode="json")
            rows.append(row)
        return rows

    def connection_check(self, selection):
        """Capability decision only: there is deliberately no network implementation."""
        p = self._targets.get(selection.target_id)
        if p is None:
            return ConnectionCheckResult(connection_status="rejected", reason="unknown_target"), 404
        if selection.profile_revision != self._revisions[p.id] or selection.policy_ref != self._config.policy_ref:
            return ConnectionCheckResult(connection_status="rejected", reason="stale_profile_or_policy"), 409
        if not p.reviewed:
            return ConnectionCheckResult(connection_status="requires_approval", reason="operator_review_required"), 403
        return ConnectionCheckResult(connection_status="unsupported", reason="safe_probe_not_verified"), 200

    def validate(self, draft: TargetDraft):
        p = self._targets.get(draft.target_id)
        if p is None:
            return ["unknown_target"]
        errors = []
        if not p.reviewed:
            errors.append("operator_review_required")
        if draft.profile_revision != self._revisions[p.id]:
            errors.append("stale_profile_revision")
        if draft.policy_ref != self._config.policy_ref:
            errors.append("policy_mismatch")
        if draft.endpoint != p.endpoint:
            errors.append("unauthorized_endpoint")
        expected_pair = (
            ("mcp-tools-call-v1", "mcp-jsonrpc-result-v1")
            if p.protocol == "mcp-jsonrpc"
            else (
                ("http-json-template-v1", p.http_config.response.text_path)
                if p.protocol == "http-json" and p.http_config is not None
                else ("openai-chat-user-message-v1", "choices.0.message.content")
            )
        )
        if draft.protocol != p.protocol or draft.method != "POST" or (
                draft.request_mapping, draft.response_parser) != expected_pair:
            errors.append("protocol_mapping_mismatch")
        if p.protocol == "http-json":
            if draft.model is not None and p.models and draft.model not in p.models:
                errors.append("model_not_approved")
        elif draft.model not in p.models:
            errors.append("model_not_approved")
        if not p.timeout_min <= draft.timeout_seconds <= p.timeout_max:
            errors.append("timeout_outside_policy")
        if draft.credential_alias != p.credential_alias:
            errors.append("credential_alias_mismatch")
        elif self._available(p.credential_alias) == "unavailable":
            errors.append("credential_unavailable")
        if not errors:
            make_profile(p, draft.model, draft.timeout_seconds,
                         self._config.credential_aliases.get(p.credential_alias))
        return errors


def load_catalog(path):
    try:
        p = Path(path)
        if not p.is_file() or p.is_symlink() or p.stat().st_size > 262144:
            raise ValueError("Invalid catalog file.")
        with p.open("rb") as stream:
            raw = stream.read(262145)
        if len(raw) > 262144:
            raise ValueError("Catalog too large.")
        return TargetCatalog(CatalogConfig.model_validate(read_json(raw)))
    except (OSError, ValueError, TypeError):
        raise CatalogError("Invalid operator target catalog; review its schema and endpoint policy.") from None
