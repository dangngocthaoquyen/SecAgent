"""Operator-selected catalog; constructs profiles offline, never invokes adapters."""
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from targets.runtime import build_runtime_target
from targets.validator import validate_target
from workflow.models import CatalogConfig, TargetDraft, ConnectionCheckResult


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


def make_profile(preset, model, timeout, credential_env=None):
    endpoint = preset.endpoint
    parts = urlsplit(endpoint)
    # Tighten the shared runtime builder for this web preset: no encoded path,
    # traversal, empty segments or parser ambiguities; no DNS resolution.
    if (not parts.path.startswith("/") or "%" in endpoint or "?" in endpoint or "#" in endpoint
            or any(s in {".", ".."} for s in parts.path.split("/")) or "//" in parts.path):
        raise ValueError("Invalid preset endpoint.")
    profile = build_runtime_target(endpoint, preset.id, protocol=preset.protocol,
        authorized_origin=f"{parts.scheme}://{parts.netloc}", model=model,
        credential_env=credential_env, discover=False)
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
            "preset": p.model_dump(exclude={"platform_id", "platform_name"}),
            "credential_binding": self._config.credential_aliases.get(p.credential_alias),
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest() for p in self._config.targets}

    def _available(self, alias):
        if alias is None:
            return "not_required"
        return "available" if os.environ.get(self._config.credential_aliases[alias], "").strip() else "unavailable"

    def public_targets(self):
        return [{"id": p.id, "name": p.name,
            "platform_id": p.platform_id, "platform_name": p.platform_name,
            "profile_revision": self._revisions[p.id],
            "policy_ref": self._config.policy_ref,
            "authorization_status": "reviewed_for_offline_configuration" if p.reviewed else "review_required",
            "endpoint": p.endpoint, "protocol": p.protocol, "method": "POST",
            "models": list(p.models), "default_model": p.default_model,
            "timeout_min": p.timeout_min, "timeout_max": p.timeout_max, "timeout_default": p.timeout_default,
            "credential_alias": p.credential_alias, "credential_availability": self._available(p.credential_alias),
            "request_mapping": "openai-chat-user-message-v1", "response_parser": "choices.0.message.content",
            "capabilities": ["chat"], "capability_basis": "configured_claim_not_probed",
            "connection_probe": {"status": "unsupported", "reason": "safe_probe_not_verified",
                                 "active_probe_authorized": False, "security_execution_authorized": False},
            "limitations": ["Offline configuration only; no target request is authorized or sent by this service.",
                            "Reachability and runtime protocol compatibility have not been checked."]}
            for p in self._config.targets]

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
        if draft.model not in p.models:
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
