"""Sanitized, bounded research provenance helpers for SecAgent runs and reports.

Design principles:
- Never persist credentials, API keys, Authorization headers, raw transport bodies,
  or raw sensitive tool arguments.
- Explicitly distinguish:
  * Reviewed Evaluation Policy (from ResponsePolicyStore)
  * Operator-declared Application Context (from ApplicationContextStore)
  * Effective Evaluation Context snapshot hash (effective_context_sha256) vs.
    full canonical Judge request hash (judge_request_sha256)
  * Configured Judge vs. actually invoked Judge (provider/model/skill/request hash
    recorded ONLY when semantic_invoked is True).
- Preserve unknown/unavailable metadata as None; never fabricate missing historical values.
"""

from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

RESEARCH_PROVENANCE_SCHEMA_VERSION = "1.0.0"
TOOL_INTENT_NORMALIZER_VERSION = "tool_intent.v1"
LEGACY_DSML_NORMALIZER_VERSION = "dsml_legacy.v1"
COMPLETION_SEMANTICS_VERSION = "response_completion.v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_POLICY_REVISION_KEYS: tuple[str, ...] = (
    "asi01_policy_revision_sha256",
    "asi02_policy_revision_sha256",
    "asi03_policy_revision_sha256",
    "asi03_contract_revision_sha256",
    "asi05_policy_revision_sha256",
)
_SENSITIVE_KEY_SUBSTRINGS: tuple[str, ...] = (
    "secret",
    "token",
    "password",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "private_key",
    "headers",
    "cookie",
)


def canonical_sha256(payload: Any) -> str:
    """Compute a deterministic lowercase SHA-256 hex digest over JSON-canonical data."""
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _safe_str(value: Any, *, max_len: int = 256) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    return cleaned[:max_len]


def _safe_sha256(value: Any) -> str | None:
    if isinstance(value, str) and _SHA256_RE.fullmatch(value.strip()):
        return value.strip()
    return None


def _sanitize_endpoint(raw_url: Any) -> str | None:
    """Strip userinfo, query, and fragment from a URL so secrets never leak."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        return None
    try:
        parsed = urlsplit(raw_url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = f"{host}:{parsed.port}" if parsed.port is not None else host
        return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    except ValueError:
        return None


def _is_sensitive_key(key: str) -> bool:
    low = key.lower()
    return any(part in low for part in _SENSITIVE_KEY_SUBSTRINGS)


def _strip_sensitive_fields(value: Any, *, depth: int = 0) -> Any:
    """Recursively omit sensitive keys while keeping bounded structural snapshots."""
    if depth > 6:
        return None
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for k, v in sorted(value.items(), key=lambda item: str(item[0])):
            key_str = str(k)
            if _is_sensitive_key(key_str):
                continue
            cleaned[key_str] = _strip_sensitive_fields(v, depth=depth + 1)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [_strip_sensitive_fields(item, depth=depth + 1) for item in value[:64]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def sanitize_target_config_snapshot(target: Any) -> dict[str, Any]:
    """Return a credential-free structural snapshot of a TargetProfile for hashing."""
    interface = getattr(target, "interface", None)
    cfg = getattr(interface, "config", None)
    cfg_dict = cfg if isinstance(cfg, Mapping) else {}

    safe_evidence_sources: list[dict[str, Any]] = []
    raw_sources = getattr(target, "evidence_sources", None) or []
    for spec in raw_sources:
        if isinstance(spec, Mapping):
            safe_evidence_sources.append({
                "id": _safe_str(spec.get("id")),
                "kind": _safe_str(spec.get("kind")),
                "provenance": _safe_str(spec.get("provenance")),
                "independent_verifier": bool(spec.get("independent_verifier", False)),
                "endpoint": _sanitize_endpoint(spec.get("url")),
            })

    cap_states = getattr(target, "capability_states", None)
    safe_caps = (
        {str(k): str(v) for k, v in sorted(cap_states.items())}
        if isinstance(cap_states, Mapping)
        else {}
    )
    cred_refs = getattr(target, "credential_refs", None) or []
    safe_cred_ref_names = sorted(
        str(name) for name in cred_refs if isinstance(name, str) and name.strip()
    )

    body_cfg = cfg_dict.get("body")
    body_template = cfg_dict.get("body_template")
    model_val = cfg_dict.get("model")
    if model_val is None and isinstance(body_cfg, Mapping):
        model_val = body_cfg.get("model")
    if model_val is None and isinstance(body_template, Mapping):
        model_val = body_template.get("model")

    raw_timeout = cfg_dict.get("timeout")
    if isinstance(raw_timeout, bool) or not isinstance(raw_timeout, (int, float)):
        raw_timeout = cfg_dict.get("timeout_seconds")
    timeout_val = (
        raw_timeout
        if not isinstance(raw_timeout, bool) and isinstance(raw_timeout, (int, float))
        else None
    )

    response_cfg = cfg_dict.get("response")
    safe_response_cfg = (
        _strip_sensitive_fields(response_cfg) if isinstance(response_cfg, Mapping) else None
    )
    safe_body_cfg = (
        _strip_sensitive_fields(body_cfg) if isinstance(body_cfg, Mapping) else None
    )
    safe_body_template = (
        _strip_sensitive_fields(body_template) if isinstance(body_template, Mapping) else None
    )

    return {
        "target_id": _safe_str(getattr(target, "id", None)),
        "target_name": _safe_str(getattr(target, "name", None)),
        "target_type": _safe_str(getattr(target, "target_type", None)),
        "interface_type": _safe_str(getattr(interface, "type", None)),
        "adapter": _safe_str(getattr(interface, "adapter", None)),
        "sanitized_endpoint": _sanitize_endpoint(cfg_dict.get("url")),
        "method": _safe_str(cfg_dict.get("method")),
        "model": _safe_str(model_val),
        "timeout": timeout_val,
        "body": safe_body_cfg,
        "body_template": safe_body_template,
        "response": safe_response_cfg,
        "trust_env": cfg_dict.get("trust_env") if isinstance(cfg_dict.get("trust_env"), bool) else None,
        "capability_states": safe_caps,
        "evidence_sources": safe_evidence_sources,
        "credential_ref_names": safe_cred_ref_names,
    }


def target_config_revision_sha256(target: Any) -> str | None:
    """Compute a deterministic SHA-256 over a credential-free TargetProfile snapshot."""
    if target is None:
        return None
    return canonical_sha256(sanitize_target_config_snapshot(target))


def extract_context_provenance(
    trusted_context: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Extract sanitized evaluation-context provenance keeping Policy & AppContext distinct."""
    if not isinstance(trusted_context, Mapping) or not trusted_context:
        return {
            "evaluation_scope": None,
            "context_source": "none",
            "reviewed_policy_id": None,
            "reviewed_policy_revision_sha256": None,
            "reviewed_policy_status": None,
            "application_context_id": None,
            "application_context_revision_sha256": None,
            "application_context_provenance": None,
            "effective_context_sha256": None,
        }

    eval_scope = _safe_str(trusted_context.get("evaluation_scope"))
    explicit_source = _safe_str(trusted_context.get("context_source"))

    app_ctx_rev = _safe_sha256(
        trusted_context.get("application_context_revision_sha256")
        or trusted_context.get("application_context_sha256")
    )
    app_ctx_id = _safe_str(trusted_context.get("application_context_id"))
    raw_policy_id = _safe_str(
        trusted_context.get("policy_id")
        or trusted_context.get("asi03_policy_id")
        or trusted_context.get("asi05_policy_id")
    )

    policy_rev: str | None = None
    for key in _POLICY_REVISION_KEYS:
        candidate = _safe_sha256(trusted_context.get(key))
        if candidate is not None:
            policy_rev = candidate
            break

    # Determine whether this context is backed by Application Context only vs Reviewed Policy.
    is_app_ctx_only = (
        explicit_source == "application_context"
        or (
            explicit_source is None
            and isinstance(raw_policy_id, str)
            and raw_policy_id.startswith("appctx-")
            and app_ctx_rev is not None
        )
    )

    if is_app_ctx_only:
        context_source = "application_context"
        reviewed_policy_id = None
        reviewed_policy_rev = None
        reviewed_policy_status = None
        if app_ctx_id is None and isinstance(raw_policy_id, str) and raw_policy_id.startswith("appctx-"):
            app_ctx_id = raw_policy_id
        app_ctx_prov = _safe_str(trusted_context.get("application_context_provenance")) or "operator_declared"
    else:
        reviewed_policy_id = _safe_str(trusted_context.get("reviewed_policy_id")) or raw_policy_id
        reviewed_policy_rev = _safe_sha256(trusted_context.get("reviewed_policy_revision_sha256")) or policy_rev
        has_reviewed_policy = (
            explicit_source in {"reviewed_policy", "reviewed_policy_with_application_context"}
            or reviewed_policy_id is not None
            or reviewed_policy_rev is not None
        )
        has_app_ctx = app_ctx_rev is not None or app_ctx_id is not None
        if has_reviewed_policy and has_app_ctx:
            context_source = "reviewed_policy_with_application_context"
        elif has_reviewed_policy:
            context_source = "reviewed_policy"
        else:
            context_source = "inline_trusted_context"

        raw_review_status = _safe_str(trusted_context.get("policy_review_status"))
        reviewed_policy_status = raw_review_status if has_reviewed_policy else None
        app_ctx_prov = (
            _safe_str(trusted_context.get("application_context_provenance")) or "operator_declared"
            if has_app_ctx
            else None
        )

    sanitized_ctx = _strip_sensitive_fields(trusted_context)
    effective_ctx_sha = canonical_sha256(sanitized_ctx)

    return {
        "evaluation_scope": eval_scope,
        "context_source": context_source,
        "reviewed_policy_id": reviewed_policy_id,
        "reviewed_policy_revision_sha256": reviewed_policy_rev,
        "reviewed_policy_status": reviewed_policy_status,
        "application_context_id": app_ctx_id,
        "application_context_revision_sha256": app_ctx_rev,
        "application_context_provenance": app_ctx_prov,
        "effective_context_sha256": effective_ctx_sha,
    }


def detect_tool_intent_normalizer(
    evidence: Sequence[Any] | None = None,
    *,
    adapter: str | None = None,
) -> str:
    """Identify which tool-intent normalization method produced or governed this observation."""
    for item in evidence or ():
        kind = getattr(item, "kind", None) if not isinstance(item, Mapping) else item.get("kind")
        if kind == "model_reported_tool_intent":
            data = getattr(item, "data", None) if not isinstance(item, Mapping) else item.get("data")
            if isinstance(data, Mapping) and data.get("observation_scope") == "model_response_text":
                return TOOL_INTENT_NORMALIZER_VERSION
            return LEGACY_DSML_NORMALIZER_VERSION
    if adapter in {"generic_http", "offline_stored"}:
        return TOOL_INTENT_NORMALIZER_VERSION
    return "none"


def build_case_research_provenance(
    *,
    testcase: Any,
    target: Any,
    test_input: Any,
    evaluation_mode: str,
    evaluation_strategy: str | None,
    semantic_enabled: bool,
    trusted_context: Mapping[str, Any] | None,
    diagnostic: Mapping[str, Any] | None,
    evidence: Sequence[Any] | None = None,
    judge_provider_name: str | None = None,
    judge_model_name: str | None = None,
    target_revision_sha256: str | None = None,
    dataset_metadata: Mapping[str, Any] | None = None,
    sent_payload_sha256: str | None = None,
) -> dict[str, Any]:
    """Build sanitized, per-case research provenance metadata for a Native Report."""
    ctx_prov = extract_context_provenance(trusted_context)
    adapter = _safe_str(getattr(getattr(target, "interface", None), "adapter", None))

    # Gather dataset provenance from test_input parameters/metadata + optional explicit override.
    ds_meta: dict[str, Any] = {}
    ti_params = getattr(test_input, "parameters", None)
    if isinstance(ti_params, Mapping):
        stored_rec = ti_params.get("stored_record")
        if isinstance(stored_rec, Mapping) and isinstance(stored_rec.get("provenance"), Mapping):
            ds_meta.update(stored_rec["provenance"])
    ti_meta = getattr(test_input, "metadata", None)
    if isinstance(ti_meta, Mapping) and isinstance(ti_meta.get("research_dataset_provenance"), Mapping):
        ds_meta.update(ti_meta["research_dataset_provenance"])
    if isinstance(dataset_metadata, Mapping):
        ds_meta.update(dataset_metadata)

    # Actual Judge metadata ONLY when Judge was actually invoked for this case.
    semantic_invoked = bool(diagnostic.get("semantic_invoked")) if isinstance(diagnostic, Mapping) else False
    if semantic_invoked and isinstance(diagnostic, Mapping):
        judge_block = {
            "invoked": True,
            "provider": _safe_str(judge_provider_name),
            "model": _safe_str(judge_model_name),
            "skill_version": _safe_str(diagnostic.get("skill_version")),
            "skill_sha256": _safe_sha256(diagnostic.get("skill_sha256")),
            "judge_request_sha256": _safe_sha256(diagnostic.get("request_sha256")),
        }
    else:
        judge_block = {
            "invoked": False,
            "provider": None,
            "model": None,
            "skill_version": None,
            "skill_sha256": None,
            "judge_request_sha256": None,
        }

    return {
        "schema_version": RESEARCH_PROVENANCE_SCHEMA_VERSION,
        "testcase_id": _safe_str(getattr(testcase, "id", None)),
        "category": _safe_str(getattr(testcase, "category", None)),
        "dataset": {
            "dataset_id": _safe_str(ds_meta.get("dataset_id")),
            "dataset_revision_sha256": _safe_sha256(
                ds_meta.get("dataset_revision_sha256") or ds_meta.get("source_file_sha256")
            ),
            "source_filename": _safe_str(ds_meta.get("source_filename")),
            "source_tool": _safe_str(ds_meta.get("source_tool")),
            "payload_ref": _safe_str(getattr(test_input, "payload_ref", None)),
            "sent_payload_sha256": _safe_sha256(sent_payload_sha256),
        },
        "target": {
            "target_id": _safe_str(getattr(target, "id", None)),
            "target_name": _safe_str(getattr(target, "name", None)),
            "adapter": adapter,
            "target_revision_sha256": _safe_sha256(target_revision_sha256),
            "target_config_sha256": target_config_revision_sha256(target),
        },
        "evaluation": {
            "evaluation_mode": _safe_str(evaluation_mode),
            "evaluation_strategy": _safe_str(evaluation_strategy),
            "semantic_enabled": bool(semantic_enabled),
            **ctx_prov,
        },
        "judge": judge_block,
        "normalization": {
            "tool_intent_normalizer": detect_tool_intent_normalizer(evidence, adapter=adapter),
            "completion_semantics_version": COMPLETION_SEMANTICS_VERSION,
        },
    }


def summarize_run_research_provenance(
    case_provenances: Sequence[Mapping[str, Any]],
    *,
    target: Any = None,
    target_revision_sha256: str | None = None,
    dataset_id: str | None = None,
    dataset_revision_sha256: str | None = None,
    dataset_name: str | None = None,
) -> dict[str, Any]:
    """Aggregate per-case research provenance accurately across single- or mixed-policy runs."""
    context_sources: set[str] = set()
    reviewed_policies_map: dict[tuple[str | None, str | None, str | None], dict[str, Any]] = {}
    app_contexts_map: dict[tuple[str | None, str | None], dict[str, Any]] = {}
    eval_modes: set[str] = set()
    eval_scopes: set[str] = set()
    normalizers: set[str] = set()
    providers_invoked: set[str] = set()
    models_invoked: set[str] = set()
    skill_versions: set[str] = set()
    skill_sha256s: set[str] = set()
    invoked_count = 0

    for prov in case_provenances:
        if not isinstance(prov, Mapping):
            continue
        ev = prov.get("evaluation")
        if isinstance(ev, Mapping):
            src = _safe_str(ev.get("context_source"))
            if src:
                context_sources.add(src)
            mode = _safe_str(ev.get("evaluation_mode"))
            if mode:
                eval_modes.add(mode)
            scope = _safe_str(ev.get("evaluation_scope"))
            if scope:
                eval_scopes.add(scope)
            rp_id = _safe_str(ev.get("reviewed_policy_id"))
            rp_rev = _safe_sha256(ev.get("reviewed_policy_revision_sha256"))
            if rp_id or rp_rev:
                cat = _safe_str(prov.get("category"))
                key = (rp_id, cat, rp_rev)
                reviewed_policies_map[key] = {
                    "policy_id": rp_id,
                    "category": cat,
                    "revision_sha256": rp_rev,
                }
            ac_id = _safe_str(ev.get("application_context_id"))
            ac_rev = _safe_sha256(ev.get("application_context_revision_sha256"))
            if ac_id or ac_rev:
                ac_key = (ac_id, ac_rev)
                app_contexts_map[ac_key] = {
                    "application_context_id": ac_id,
                    "revision_sha256": ac_rev,
                    "provenance": _safe_str(ev.get("application_context_provenance")) or "operator_declared",
                }
        judge = prov.get("judge")
        if isinstance(judge, Mapping) and judge.get("invoked") is True:
            invoked_count += 1
            p_name = _safe_str(judge.get("provider"))
            if p_name:
                providers_invoked.add(p_name)
            m_name = _safe_str(judge.get("model"))
            if m_name:
                models_invoked.add(m_name)
            s_ver = _safe_str(judge.get("skill_version"))
            if s_ver:
                skill_versions.add(s_ver)
            s_sha = _safe_sha256(judge.get("skill_sha256"))
            if s_sha:
                skill_sha256s.add(s_sha)
        norm = prov.get("normalization")
        if isinstance(norm, Mapping):
            t_norm = _safe_str(norm.get("tool_intent_normalizer"))
            if t_norm:
                normalizers.add(t_norm)

    reviewed_policies = sorted(
        reviewed_policies_map.values(),
        key=lambda row: (row.get("policy_id") or "", row.get("category") or ""),
    )
    application_contexts = sorted(
        app_contexts_map.values(),
        key=lambda row: (row.get("application_context_id") or "", row.get("revision_sha256") or ""),
    )

    non_empty_sources = context_sources - {"none"}
    if not non_empty_sources:
        policy_scope = "none"
    elif non_empty_sources == {"application_context"}:
        policy_scope = "application_context_only"
    elif len(reviewed_policies) == 1 and non_empty_sources <= {"reviewed_policy", "reviewed_policy_with_application_context"}:
        policy_scope = "single_reviewed_policy"
    else:
        policy_scope = "mixed"

    first_target = next(
        (p.get("target") for p in case_provenances if isinstance(p, Mapping) and isinstance(p.get("target"), Mapping)),
        None,
    )
    target_block = (
        {
            "target_id": _safe_str(getattr(target, "id", None)),
            "target_name": _safe_str(getattr(target, "name", None)),
            "adapter": _safe_str(getattr(getattr(target, "interface", None), "adapter", None)),
            "target_revision_sha256": _safe_sha256(target_revision_sha256),
            "target_config_sha256": target_config_revision_sha256(target),
        }
        if target is not None
        else (dict(first_target) if isinstance(first_target, Mapping) else None)
    )

    return {
        "schema_version": RESEARCH_PROVENANCE_SCHEMA_VERSION,
        "dataset": {
            "dataset_id": _safe_str(dataset_id),
            "dataset_revision_sha256": _safe_sha256(dataset_revision_sha256),
            "source_filename": _safe_str(dataset_name),
        },
        "target": target_block,
        "evaluation": {
            "evaluation_modes": sorted(eval_modes),
            "evaluation_scopes": sorted(eval_scopes),
            "context_sources": sorted(context_sources),
            "policy_scope": policy_scope,
            "reviewed_policies": reviewed_policies,
            "application_contexts": application_contexts,
        },
        "judge": {
            "invoked_case_count": invoked_count,
            "providers_invoked": sorted(providers_invoked),
            "models_invoked": sorted(models_invoked),
            "skill_versions": sorted(skill_versions),
            "skill_sha256s": sorted(skill_sha256s),
        },
        "normalization": {
            "tool_intent_normalizers": sorted(normalizers),
            "completion_semantics_version": COMPLETION_SEMANTICS_VERSION,
        },
    }
