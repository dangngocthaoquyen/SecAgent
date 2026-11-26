"""Generic Runner & ResponsePolicyStore routes connecting Web UI to `testing.generic_runner`."""

from __future__ import annotations

from collections import Counter
from contextlib import nullcontext
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import shutil
from threading import Event, RLock, Thread
from typing import Any
from uuid import uuid4

from flask import Response, jsonify, request
from pydantic import ValidationError

from core.models import TargetProfile, TestCase as CoreTestCase, TestInput as CoreTestInput
from core.models.provenance import (
    extract_context_provenance,
    summarize_run_research_provenance,
)
from evaluators.contract import (
    SCOPE_CAPABILITY_KEYS,
    assess_target_scope_compatibility,
    summarize_target_capabilities_and_scopes,
)
from integrations.external_evaluator.pi import PiEvaluatorConfig, PiEvaluatorProvider
from observers.evidence_collectors import (
    CollectedEvidenceOutput,
    CollectorDiagnostic,
    HttpCallbackCollector,
    _has_symlink_or_reparse,
)
from reporting.redaction import Redactor
from testing.evaluation_config import RunnerEvaluationConfig, _has_pi_auth_provider
from testing.generic_runner import (
    DispatchCheckpointError,
    _SEMANTIC_LABELS_BY_CATEGORY,
    build_blind_record_testcase,
    build_offline_target_profile,
    prepare_generic_case_pair,
    resolve_trusted_context_for_target_category,
    run_generic_cases,
)
from testing.offline_stored_import import CanonicalStoredRecordsAdapter, PromptfooReportAdapter, ImportContext
from testing.runner import Runner
from workflow.catalog import (
    build_http_response_config_dict,
    default_capability_states_for_preset,
    make_profile,
    read_json,
)
from workflow.session_credentials import SessionCredentialError
from workflow.dataset_models import infer_testcase_asi_code
from workflow.evidence_sources import EvidenceSourceError
from workflow.response_policies import (
    DEFAULT_EVALUATION_SCOPES,
    POLICY_REVISION_KEYS,
    ResponsePolicyDraft,
    ResponsePolicyStore,
    normalize_policy_category,
)

_ASI_CODE_BY_POLICY_CATEGORY: dict[str, str] = {
    "goal_hijacking": "ASI01",
    "tool_misuse": "ASI02",
    "identity_privilege_abuse": "ASI03",
    "unexpected_code_execution": "ASI05",
}

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_HEX32_RE = re.compile(r"^[a-f0-9]{32}$")
_MAX_WEB_CASES = 50


_CAPABILITY_TRUST_RANK: dict[str, int] = {
    "unsupported": 0,
    "unverified": 1,
    "supported": 2,
}


def _merge_authoritative_capability_states(
    saved_caps: dict[str, str],
    requested_caps: dict[str, str] | None,
) -> dict[str, str]:
    """Merge request capability_states without ever weakening saved managed restrictions.

    On a saved managed Target profile:
    - A saved 'unsupported' capability (or any sibling alias in the same scope
      capability group) can NEVER be upgraded to 'unverified' or 'supported'.
    - A saved 'unverified' capability can NEVER be upgraded to 'supported'.
    - An undeclared capability key in a scan request can only add 'unsupported' or
      'unverified', never fabricate 'supported'.
    """
    merged = dict(saved_caps)
    if not isinstance(requested_caps, dict):
        return merged

    def _group_min_rank(cap_key: str) -> int | None:
        ranks: list[int] = []
        if cap_key in merged and merged[cap_key] in _CAPABILITY_TRUST_RANK:
            ranks.append(_CAPABILITY_TRUST_RANK[merged[cap_key]])
        for alias_group in SCOPE_CAPABILITY_KEYS.values():
            if cap_key in alias_group:
                for sibling in alias_group:
                    if sibling in merged and merged[sibling] in _CAPABILITY_TRUST_RANK:
                        ranks.append(_CAPABILITY_TRUST_RANK[merged[sibling]])
        return min(ranks) if ranks else None

    for raw_key, raw_state in requested_caps.items():
        if not isinstance(raw_key, str) or not isinstance(raw_state, str):
            continue
        key = raw_key.strip()
        state = raw_state.strip().lower()
        if not key or state not in _CAPABILITY_TRUST_RANK:
            continue
        req_rank = _CAPABILITY_TRUST_RANK[state]
        group_ceiling = _group_min_rank(key)
        if key in merged:
            existing_rank = _CAPABILITY_TRUST_RANK.get(merged[key], 1)
            if req_rank < existing_rank and (group_ceiling is None or req_rank <= group_ceiling):
                merged[key] = state
        elif state != "supported" and (group_ceiling is None or req_rank <= group_ceiling):
            merged[key] = state
    return merged


_API_PRESERVED_VALUE_KEYS = Runner._PRESERVED_VALUE_KEYS | frozenset({
    "execution_status",
    "judge_recommendation",
    "judge_classification",
    "semantic_invoked",
    "provider_duration_ms",
    "response_complete",
    "source_eval_id",
    "source_timestamp",
    "source_filename",
})


_HEX64_RE = re.compile(r"^[a-f0-9]{64}$")
_EVENT_FINGERPRINT_RE = re.compile(r"^(?:sha256:)?[a-f0-9]{64}$")
_DYNAMIC_TRUSTED_ENUMS = frozenset({"provenance", "correlation_status", "correlation_strength"})


def _sanitize_for_api(
    value: Any,
    *,
    extra_secrets: tuple[str, ...] | list[str] = (),
    _key_name: str | None = None,
    _scrub_keys: bool = False,
) -> Any:
    cleaner = Redactor(extra_secrets)
    if isinstance(value, str):
        if _key_name is not None:
            if _scrub_keys:
                if _key_name in _DYNAMIC_TRUSTED_ENUMS:
                    return value
                if _key_name == "event_fingerprint" and _EVENT_FINGERPRINT_RE.fullmatch(value):
                    return value
                if _key_name in {"arguments_sha256", "observation_sha256"} and _HEX64_RE.fullmatch(value):
                    return value
            else:
                if _key_name in _API_PRESERVED_VALUE_KEYS:
                    return value
                if any(_key_name.endswith(sfx) for sfx in Runner._PRESERVED_VALUE_SUFFIXES) and _HEX64_RE.fullmatch(value):
                    return value
        return cleaner.clean(value, opaque=False, limit=max(4096, len(value) * 2))
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for k, v in value.items():
            if str(k).lower() in {"authorization", "api_key", "secret", "password", "access_token"}:
                continue
            next_scrub = _scrub_keys or (isinstance(k, str) and k in Runner._DYNAMIC_KEY_CONTAINERS)
            if (
                _scrub_keys
                and isinstance(k, str)
                and k not in _DYNAMIC_TRUSTED_ENUMS
                and k not in Runner._DYNAMIC_TRUSTED_DIGEST_KEYS
            ):
                clean_k = cleaner.clean(k, opaque=False, limit=256)
                if clean_k in out:
                    idx = 2
                    while f"{clean_k}#{idx}" in out:
                        idx += 1
                    clean_k = f"{clean_k}#{idx}"
            else:
                clean_k = k
            out[clean_k] = _sanitize_for_api(
                v,
                extra_secrets=extra_secrets,
                _key_name=k if isinstance(k, str) else None,
                _scrub_keys=next_scrub,
            )
        return out
    if isinstance(value, list):
        if not _scrub_keys and _key_name in _API_PRESERVED_VALUE_KEYS:
            return list(value)
        return [
            _sanitize_for_api(item, extra_secrets=extra_secrets, _key_name=None, _scrub_keys=_scrub_keys)
            for item in value
        ]
    return value


class _StaticDiagnosticCollector:
    """Read-only collector that surfaces pre-run evidence-source load errors without altering verdicts."""

    collector_id = "evidence_source_store"
    collector_kind = "evidence_source_store"

    def __init__(self, diagnostics: list[CollectorDiagnostic]) -> None:
        self._diagnostics = list(diagnostics)

    def collect(self, context: Any) -> CollectedEvidenceOutput:
        return CollectedEvidenceOutput(evidence=[], diagnostics=list(self._diagnostics))


class GenericRunService:
    """Thread-safe service bridging Web API with `testing.generic_runner` & `ResponsePolicyStore`."""

    def __init__(
        self,
        *,
        catalog: Any,
        dataset_repo: Any,
        inventory: Any,
        policy_store: ResponsePolicyStore,
        runs_root: Path,
        controlled_runs_root: Path | None = None,
        pi_config: PiEvaluatorConfig | None = None,
        judge_provider: Any = None,
        allowed_collector_roots: tuple[Path, ...] = (),
        application_contexts: Any = None,
        evidence_source_store: Any = None,
    ) -> None:
        self.catalog = catalog
        self.dataset_repo = dataset_repo
        self.inventory = inventory
        self.policy_store = policy_store
        self.runs_root = Path(runs_root).resolve()
        self.runs_root.mkdir(parents=True, exist_ok=True)
        self.controlled_runs_root = Path(controlled_runs_root).resolve() if controlled_runs_root else None
        self.pi_config = pi_config
        self.judge_provider = judge_provider
        self.allowed_collector_roots = tuple(
            Path(p).resolve()
            for p in allowed_collector_roots
            if not _has_symlink_or_reparse(Path(p))
        )
        self.application_contexts = application_contexts
        self.evidence_source_store = evidence_source_store
        self._active_target_counts: dict[str, int] = {}
        self._in_progress_runs: dict[str, Thread] = {}
        self._active_resumes_by_root: dict[str, str] = {}
        self._submissions_in_flight: dict[str, dict[str, Any]] = {}
        self.submission_wait_timeout: float = 30.0
        self._lock = RLock()

    def active_run_count(self, target_id: str) -> int:
        with self._lock:
            return self._active_target_counts.get(target_id, 0)

    def is_active_for_target(self, target_id: str) -> bool:
        with self._lock:
            return self._active_target_counts.get(target_id, 0) > 0

    def _acquire_target_run(self, target_id: str) -> None:
        with self._lock:
            self._active_target_counts[target_id] = self._active_target_counts.get(target_id, 0) + 1

    def _release_target_run(self, target_id: str) -> None:
        with self._lock:
            remaining = self._active_target_counts.get(target_id, 0) - 1
            if remaining > 0:
                self._active_target_counts[target_id] = remaining
            else:
                self._active_target_counts.pop(target_id, None)

    def judge_status(self) -> dict[str, Any]:
        if self.judge_provider is not None:
            return {
                "judge_configured": True,
                "credential_available": True,
                "judge_ready": True,
                "provider": getattr(self.judge_provider, "provider_name", None)
                or (self.pi_config.provider if self.pi_config else "configured_provider"),
                "model": getattr(self.judge_provider, "model_name", None)
                or (self.pi_config.model if self.pi_config else "configured_model"),
                "reason": "ready",
            }
        if os.environ.get("SECAGENT_JUDGE_SETUP_REASON") == "credential_missing":
            return {
                "judge_configured": True,
                "credential_available": False,
                "judge_ready": False,
                "provider": self.pi_config.provider if self.pi_config else "deepseek",
                "model": self.pi_config.model if self.pi_config else "deepseek-v4-flash",
                "reason": "credential_missing",
            }
        if self.pi_config is not None:
            exe = self.pi_config.executable
            exe_ok = Path(exe).is_file() or bool(shutil.which(exe))
            names = self.pi_config.credential_env
            if names:
                cred_ok = all(bool(os.environ.get(name)) for name in names)
            elif self.pi_config.use_pi_auth_file:
                cred_ok = _has_pi_auth_provider(self.pi_config.provider)
            else:
                cred_ok = False
            ready = bool(exe_ok and cred_ok)
            return {
                "judge_configured": True,
                "credential_available": cred_ok,
                "judge_ready": ready,
                "provider": self.pi_config.provider,
                "model": self.pi_config.model,
                "reason": "ready" if ready else ("credential_missing" if not cred_ok else "executable_missing"),
            }
        pi_exe = shutil.which("pi")
        auth_ok = _has_pi_auth_provider("deepseek")
        if pi_exe and auth_ok:
            return {
                "judge_configured": True,
                "credential_available": True,
                "judge_ready": True,
                "provider": "deepseek",
                "model": "deepseek-v4-flash",
                "reason": "ready",
            }
        return {
            "judge_configured": bool(pi_exe),
            "credential_available": bool(auth_ok),
            "judge_ready": False,
            "provider": "deepseek" if (pi_exe or auth_ok) else None,
            "model": "deepseek-v4-flash" if (pi_exe or auth_ok) else None,
            "reason": "credential_missing" if (pi_exe and not auth_ok) else "judge_configuration_missing",
        }

    def resolved_pi_config(self) -> PiEvaluatorConfig | None:
        if os.environ.get("SECAGENT_JUDGE_SETUP_REASON") == "credential_missing":
            return None
        if self.pi_config is not None:
            st = self.judge_status()
            return self.pi_config if st["judge_ready"] else None
        pi_exe = shutil.which("pi")
        if pi_exe and _has_pi_auth_provider("deepseek"):
            return PiEvaluatorConfig(
                executable=pi_exe,
                provider="deepseek",
                model="deepseek-v4-flash",
                timeout_seconds=60.0,
                max_output_bytes=65536,
                use_pi_auth_file=True,
            )
        return None

    def pi_judge_ready(self) -> bool:
        return bool(self.judge_status()["judge_ready"])

    def _resolve_saved_evidence_sources_with_diagnostics(
        self,
        target_id: str,
        *,
        for_execution: bool = False,
        mode: str = "live",
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        if self.evidence_source_store is None:
            return [], []
        if for_execution and mode == "offline":
            return [], []
        try:
            rows = self.evidence_source_store.list(target_id)
        except Exception as exc:
            err_code = (
                str(exc)
                if isinstance(exc, EvidenceSourceError)
                else f"evidence_source_load_error:{type(exc).__name__}"
            )
            return [], [
                {
                    "collector_id": "evidence_source_store",
                    "collector_kind": "evidence_source_store",
                    "status": "error",
                    "matched_count": 0,
                    "uncorrelated_count": 0,
                    "reason": f"Saved evidence sources could not be loaded ({err_code}).",
                }
            ]
        if not isinstance(rows, list):
            return [], []
        cred_env_map = getattr(getattr(self.evidence_source_store, "policy", None), "credential_env", {}) or {}
        specs: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if row.get("enabled") is not True or row.get("configuration_status") != "configured":
                continue
            endpoint = row.get("endpoint")
            if not isinstance(endpoint, str) or not endpoint.strip():
                continue
            headers: dict[str, str] = {"Accept": "application/json"}
            cred_ref = row.get("credential_ref")
            if isinstance(cred_ref, str) and cred_ref:
                env_var = cred_env_map.get(cred_ref)
                if isinstance(env_var, str) and env_var:
                    headers["Authorization"] = f"Bearer {{{{credential:{env_var}}}}}"
            raw_mapping = row.get("mapping")
            mapping_dict = dict(raw_mapping) if isinstance(raw_mapping, dict) else {}
            specs.append({
                "id": str(row.get("id") or "evidence_source"),
                "name": str(row.get("name") or "evidence_source"),
                "kind": "http_callback",
                "url": endpoint.strip(),
                "headers": headers,
                "timeout_seconds": float(row.get("timeout_seconds") or 5.0),
                "max_response_bytes": int(row.get("max_response_bytes") or 65536),
                "max_events": int(row.get("max_events") or 200),
                "mapping": mapping_dict,
                "provenance": "target_reported",
                "independent_verifier": False,
                "source_revision": row.get("revision"),
                "reported_semantics": row.get("semantics", "detector_reported"),
            })
        return specs, []

    def _resolve_saved_evidence_sources(
        self,
        target_id: str,
        *,
        for_execution: bool = False,
        mode: str = "live",
    ) -> list[dict[str, Any]]:
        specs, _ = self._resolve_saved_evidence_sources_with_diagnostics(
            target_id, for_execution=for_execution, mode=mode
        )
        return specs

    def _resolve_target(
        self,
        *,
        mode: str,
        target_id: str,
        target_profile_dict: dict[str, Any] | None = None,
        capability_states: dict[str, str] | None = None,
        evidence_sources: list[dict[str, Any]] | None = None,
        for_execution: bool = False,
    ) -> TargetProfile:
        resolved_evidence = (
            evidence_sources
            if evidence_sources is not None
            else self._resolve_saved_evidence_sources(target_id, for_execution=for_execution, mode=mode)
        )
        saved_preset = (
            self.catalog.get(target_id)
            if hasattr(self.catalog, "get")
            else getattr(self.catalog, "_targets", {}).get(target_id)
        )
        if target_profile_dict is not None:
            if saved_preset is not None and mode == "live":
                raise ValueError("generic_managed_target_override_forbidden")
            profile = TargetProfile.model_validate(target_profile_dict)
            if capability_states:
                profile = profile.model_copy(update={"capability_states": {**profile.capability_states, **capability_states}})
            if evidence_sources is not None:
                profile = profile.model_copy(update={"evidence_sources": evidence_sources})
            elif not profile.evidence_sources and resolved_evidence:
                profile = profile.model_copy(update={"evidence_sources": resolved_evidence})
            return profile

        if mode == "offline":
            return TargetProfile(
                id=target_id,
                name=f"Offline Stored Target ({target_id})",
                target_type="offline_stored",
                interface={"type": "offline", "adapter": "offline_stored", "config": {}},
                capabilities=["stored_response_replay"],
                capability_states={"stored_response_replay": "supported", **(capability_states or {})},
                evidence_sources=resolved_evidence,
            )

        preset = saved_preset
        if preset is None:
            raise ValueError("generic_target_not_found")

        cred_refs: list[str] = []
        headers: dict[str, str] = {"Content-Type": "application/json"}
        env_name: str | None = None
        if getattr(preset, "credential_alias", None):
            cat_cfg = getattr(self.catalog, "_config", None) or getattr(self.catalog, "config", None)
            aliases = getattr(cat_cfg, "credential_aliases", {}) or {}
            env_name = aliases.get(preset.credential_alias)
            if env_name:
                cred_refs.append(env_name)
                headers["Authorization"] = f"Bearer {{{{credential:{env_name}}}}}"

        if preset.protocol == "mcp-jsonrpc":
            iface_cfg: dict[str, Any] = {
                "url": preset.endpoint,
                "timeout": preset.timeout_default,
            }
            if cred_refs:
                iface_cfg["headers"] = headers
            iface = {"type": "mcp", "adapter": "generic_mcp_jsonrpc", "config": iface_cfg}
            default_caps = default_capability_states_for_preset(preset)
            observability = ["tool_result"]
            target_type = "mcp_server"
        elif preset.protocol == "http-json" and getattr(preset, "http_config", None) is not None:
            # Share the exact same TargetProfile & header construction with Test Connection.
            base_profile = make_profile(
                preset,
                preset.default_model,
                preset.timeout_default,
                credential_env=env_name,
                session_auth=getattr(preset, "session_auth", None),
            )
            default_caps = default_capability_states_for_preset(preset)
            return base_profile.model_copy(
                update={
                    "capabilities": list(getattr(preset, "capabilities", []) or base_profile.capabilities or [preset.protocol]),
                    "capability_states": _merge_authoritative_capability_states(default_caps, capability_states),
                    "evidence_sources": resolved_evidence,
                }
            )
        else:
            iface = {
                "type": "http",
                "adapter": "generic_http",
                "config": {
                    "url": preset.endpoint,
                    "method": "POST",
                    "timeout": preset.timeout_default,
                    "headers": headers,
                    "body": {
                        "model": preset.default_model,
                        "messages": [{"role": "user", "content": "{{input}}"}],
                    },
                    "response": {"text_path": "choices.0.message.content"},
                },
            }
            default_caps = default_capability_states_for_preset(preset)
            observability = ["response"]
            target_type = "llm_chat"

        return TargetProfile(
            id=preset.id,
            name=preset.name,
            target_type=target_type,
            interface=iface,
            capabilities=list(getattr(preset, "capabilities", []) or ([preset.protocol])),
            capability_states=_merge_authoritative_capability_states(default_caps, capability_states),
            observability=observability,
            credential_refs=cred_refs,
            evidence_sources=resolved_evidence,
        )

    def _extract_raw_cases(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        if isinstance(payload.get("cases"), list) and payload["cases"]:
            out_direct: list[dict[str, Any]] = []
            for row in payload["cases"]:
                if not isinstance(row, dict):
                    continue
                row_copy = dict(row)
                raw_prov = row_copy.get("provenance") if isinstance(row_copy.get("provenance"), dict) else {}
                src_tool = row_copy.get("source_tool") or raw_prov.get("source_tool")
                if isinstance(src_tool, str) and src_tool.strip():
                    row_copy["source_provenance"] = {
                        **{k: v for k, v in raw_prov.items() if isinstance(v, str)},
                        "source_tool": src_tool.strip(),
                    }
                out_direct.append(row_copy)
            return out_direct
        if payload.get("stored_payload") is not None:
            raw_obj = payload["stored_payload"]
            if isinstance(raw_obj, str):
                raw_obj = json.loads(raw_obj)
            ctx = ImportContext(
                source_filename="ui-upload.json",
                category=payload.get("asi_category"),
                target_id=payload.get("target_id"),
            )
            adapter = PromptfooReportAdapter() if PromptfooReportAdapter().supports(raw_obj) else CanonicalStoredRecordsAdapter()
            if not adapter.supports(raw_obj):
                raise ValueError("generic_invalid_stored_payload")
            extracted = adapter.extract(raw_obj, ctx)
            return [
                {
                    "case_id": rec.case_id or f"case-{idx + 1}",
                    "category": rec.category or payload.get("asi_category"),
                    "prompt": rec.prompt,
                    "stored_response": rec.stored_response,
                    "finish_reason": rec.finish_reason,
                    "response_complete": rec.response_complete,
                    "tool_calls": rec.tool_calls,
                    "response_id": rec.response_id,
                    "target_model": rec.target_model,
                    "source_provenance": {
                        "source_tool": rec.source_tool,
                        "adapter_name": adapter.name,
                        "source_filename": "ui-upload.json",
                        **({"source_eval_id": rec.source_eval_id} if rec.source_eval_id else {}),
                        **({"source_timestamp": rec.source_timestamp} if rec.source_timestamp else {}),
                        **({"provider_label": rec.provider_label} if rec.provider_label else {}),
                    },
                    **(
                        {"historical_verdict": rec.historical_verdict.model_dump(mode="json")}
                        if rec.historical_verdict is not None
                        else {}
                    ),
                }
                for idx, rec in enumerate(extracted)
            ]
        dataset_id = payload.get("dataset_id")
        if isinstance(dataset_id, str) and dataset_id:
            if self.dataset_repo is None:
                raise ValueError("dataset_not_found")
            env = self.dataset_repo.get_dataset(dataset_id)
            if env is None:
                raise ValueError("dataset_not_found")
            wanted = set(payload.get("testcase_ids") or [])
            fallback_cat = payload.get("asi_category")
            if isinstance(fallback_cat, str) and fallback_cat.strip().lower() in {"", "auto"}:
                fallback_cat = None
            src_meta = env.source_metadata if isinstance(env.source_metadata, dict) else {}
            adapter_name = src_meta.get("adapter_name")
            default_ds_source_tool = (
                "promptfoo_stored_report"
                if env.source_tool == "promptfoo_report" or adapter_name == "promptfoo"
                else ("canonical_stored_jsonl" if env.name.lower().endswith(".jsonl") and env.source_tool == "canonical_stored_json" else env.source_tool)
            )
            out = []
            for tc in env.testcases:
                if wanted and tc.internal_id not in wanted and tc.testcase_id not in wanted:
                    continue
                extra = tc.extra if isinstance(tc.extra, dict) else {}
                meta = tc.metadata if isinstance(tc.metadata, dict) else {}
                inferred_code = infer_testcase_asi_code(tc, fallback_run_id=env.run_id)
                row_cat = (
                    inferred_code
                    if inferred_code != "unmapped"
                    else (fallback_cat or "unmapped")
                )
                case_source_tool = (
                    extra.get("source_tool")
                    if isinstance(extra.get("source_tool"), str) and extra["source_tool"].strip()
                    else default_ds_source_tool
                )
                prov_meta: dict[str, Any] = {
                    "source_tool": case_source_tool,
                    "dataset_id": env.dataset_id,
                    "source_filename": env.name,
                    "source_file_sha256": env.file_sha256,
                }
                if isinstance(adapter_name, str) and adapter_name:
                    prov_meta["adapter_name"] = adapter_name
                if isinstance(extra.get("source_eval_id") or env.run_id, str):
                    prov_meta["source_eval_id"] = str(extra.get("source_eval_id") or env.run_id)
                if isinstance(extra.get("source_timestamp"), str):
                    prov_meta["source_timestamp"] = extra["source_timestamp"]
                if isinstance(extra.get("provider_label"), str):
                    prov_meta["provider_label"] = extra["provider_label"]

                out.append({
                    "case_id": tc.testcase_id,
                    "internal_id": tc.internal_id,
                    "category": row_cat,
                    "prompt": tc.prompt,
                    "stored_response": extra.get("stored_response") or extra.get("response_text"),
                    "finish_reason": extra.get("finish_reason"),
                    "response_complete": extra.get("response_complete"),
                    "tool_calls": extra.get("tool_calls", []),
                    "response_id": extra.get("response_id"),
                    "target_model": extra.get("target_model"),
                    "required_capability": meta.get("required_capability") or extra.get("required_capability"),
                    "tool_name": meta.get("tool_name") or extra.get("tool_name"),
                    "imported_assertions_count": len(tc.assertions) if isinstance(tc.assertions, list) else 0,
                    "source_provenance": prov_meta,
                    **(
                        {"historical_verdict": extra["historical_verdict"]}
                        if isinstance(extra.get("historical_verdict"), dict)
                        else {}
                    ),
                })
            return out
        raise ValueError("generic_cases_required")

    def _read_operator_app_context(self, target_id: str) -> dict[str, Any] | None:
        if self.application_contexts is None:
            return None
        try:
            row = self.application_contexts.read(target_id)
        except Exception:
            return None
        if not isinstance(row, dict) or row.get("provenance") != "operator_declared":
            return None
        return row

    def _current_target_revision(self, target_id: str) -> str | None:
        revs = getattr(self.catalog, "_revisions", None)
        if isinstance(revs, dict) and isinstance(revs.get(target_id), str):
            return revs[target_id]
        preset = self.catalog.get(target_id) if hasattr(self.catalog, "get") else None
        return getattr(preset, "profile_revision", None) if preset is not None else None

    def _resolve_category_trusted_context(
        self,
        *,
        target_id: str,
        norm_category: str,
        policy_id: str | None,
        mode: str = "live",
    ) -> tuple[dict[str, Any] | None, Any | None, str | None]:
        if not self.pi_judge_ready():
            return None, None, "judge_provider_unavailable"
        return resolve_trusted_context_for_target_category(
            target_id=target_id,
            norm_category=norm_category,
            policy_store=self.policy_store,
            policy_id=policy_id,
            app_ctx_row=self._read_operator_app_context(target_id),
            current_target_revision=self._current_target_revision(target_id),
            allow_generic_stored_fallback=(mode == "offline"),
        )

    def _resolve_reviewed_policy_for_rule_only(
        self,
        *,
        target_id: str,
        norm_category: str,
        policy_id: str | None,
        mode: str = "live",
    ) -> tuple[Any | None, str | None]:
        """Resolve an optional cryptographically reviewed policy for rule-only execution.

        Live targets strictly require policies reviewed for their exact target_id;
        generic-stored-target fallback is permitted only in explicit offline mode.
        """
        if self.policy_store is None:
            return (None, "policy_review_required") if policy_id else (None, None)
        allow_fallback = mode == "offline"
        allowed_targets = {target_id, "generic-stored-target"} if allow_fallback else {target_id}
        if policy_id:
            try:
                rec = self.policy_store.get(policy_id)
                if rec.target_id not in allowed_targets:
                    return None, "policy_review_required"
                reviewed = self.policy_store.require_reviewed(policy_id, target_id=rec.target_id)
            except (FileNotFoundError, ValueError):
                return None, "policy_review_required"
            if reviewed.category != norm_category:
                return None, "policy_category_mismatch"
            return reviewed, None
        candidates = [
            p for p in self.policy_store.list_for_target(target_id, category=norm_category)
            if p.review_status == "reviewed" and p.draft.evaluation_rules
        ]
        if not candidates and allow_fallback:
            candidates = [
                p for p in self.policy_store.list_for_target("generic-stored-target", category=norm_category)
                if p.review_status == "reviewed" and p.draft.evaluation_rules
            ]
        if not candidates:
            return None, None
        chosen = candidates[-1]
        try:
            return self.policy_store.require_reviewed(chosen.policy_id, target_id=chosen.target_id), None
        except ValueError:
            return None, "policy_review_required"

    def _build_cases(
        self,
        *,
        mode: str,
        target: TargetProfile,
        asi_category: str,
        raw_cases: list[dict[str, Any]],
        use_judge: bool,
        policy_id: str | None,
    ) -> tuple[list[tuple[CoreTestCase, CoreTestInput]], dict[str, Any]]:
        if len(raw_cases) > _MAX_WEB_CASES:
            raise ValueError("generic_too_many_cases")
        fallback_norm_cat: str | None = None
        if asi_category and asi_category.strip().lower() not in {"", "auto", "unmapped"}:
            fallback_norm_cat = normalize_policy_category(asi_category)

        context_cache: dict[str, tuple[dict[str, Any] | None, Any | None, str | None]] = {}
        if use_judge and fallback_norm_cat is not None:
            context_cache[fallback_norm_cat] = self._resolve_category_trusted_context(
                target_id=target.id,
                norm_category=fallback_norm_cat,
                policy_id=policy_id,
                mode=mode,
            )

        pairs: list[tuple[CoreTestCase, CoreTestInput]] = []
        preview_items: list[dict[str, Any]] = []
        asi_breakdown: dict[str, int] = {}
        reviewed_policies_seen: dict[tuple[str, str, str], dict[str, Any]] = {}
        app_contexts_seen: dict[tuple[str, str], dict[str, Any]] = {}
        context_sources_seen: set[str] = set()
        overall_blocker: str | None = None

        missing_live_cred = False
        if mode == "live":
            session_store = getattr(self.catalog, "session_credentials", None)
            target_url = str(target.interface.config.get("url") or "")
            target_meta = target.metadata if isinstance(target.metadata, dict) else {}
            for ref in (target.credential_refs or []):
                if not isinstance(ref, str) or not ref:
                    continue
                if ref.startswith("sess_"):
                    if session_store is None:
                        missing_live_cred = True
                        break
                    avail = session_store.availability(
                        ref,
                        endpoint=target_url,
                        scope_id=target.id,
                        scope_kind="target",
                        expected_auth_type=target_meta.get("session_auth_type"),
                        expected_header_name=target_meta.get("session_auth_header"),
                    )
                    if avail != "available":
                        missing_live_cred = True
                        break
                elif not os.environ.get(ref, "").strip():
                    missing_live_cred = True
                    break

        for idx, row in enumerate(raw_cases):
            case_id = str(row.get("case_id") or f"case-{idx + 1}")
            prompt = str(row.get("prompt") or "")
            if not prompt.strip():
                raise ValueError("generic_missing_prompt")

            raw_row_cat = str(row.get("category") or "").strip()
            row_cat: str | None = None
            if raw_row_cat and raw_row_cat.lower() not in {"auto", "unmapped"}:
                try:
                    row_cat = normalize_policy_category(raw_row_cat)
                except ValueError:
                    row_cat = None
            if row_cat is None:
                row_cat = fallback_norm_cat

            asi_code = _ASI_CODE_BY_POLICY_CATEGORY.get(row_cat, "unmapped") if row_cat else "unmapped"
            asi_breakdown[asi_code] = asi_breakdown.get(asi_code, 0) + 1

            req_cap = row.get("required_capability")
            cap_unsupported = (
                isinstance(req_cap, str)
                and bool(req_cap.strip())
                and target.capability_states.get(req_cap.strip()) == "unsupported"
            )
            mcp_tool_missing = (
                mode == "live"
                and target.interface.adapter == "generic_mcp_jsonrpc"
                and not (isinstance(row.get("tool_name"), str) and row.get("tool_name").strip())
            )
            is_unsupported = cap_unsupported or mcp_tool_missing

            stored_resp = row.get("stored_response")
            if mode == "offline" and not isinstance(stored_resp, str):
                raise ValueError("generic_stored_response_required_for_offline")

            row_blocker: str | None = None
            trusted_context: dict[str, Any] | None = None
            row_reviewed_policy: Any | None = None
            row_reviewed_rules: list[Any] = []
            if not is_unsupported:
                if missing_live_cred:
                    row_blocker = "credential_unavailable"
                elif row.get("rules") or row.get("evaluation_rules"):
                    row_blocker = "unreviewed_inline_rules_rejected"
                elif row_cat is None:
                    row_blocker = "unmapped_asi_category"
                elif use_judge:
                    if row_cat not in context_cache:
                        context_cache[row_cat] = self._resolve_category_trusted_context(
                            target_id=target.id,
                            norm_category=row_cat,
                            policy_id=policy_id,
                            mode=mode,
                        )
                    trusted_context, rev_pol, row_blocker = context_cache[row_cat]
                    row_reviewed_policy = rev_pol
                    if rev_pol is not None:
                        reviewed_policies_seen[(rev_pol.policy_id, rev_pol.category, rev_pol.revision_sha256)] = {
                            "policy_id": rev_pol.policy_id,
                            "category": rev_pol.category,
                            "revision_sha256": rev_pol.revision_sha256,
                        }
                        if self.policy_store is not None:
                            try:
                                row_reviewed_rules = self.policy_store.reviewed_rules(rev_pol)
                            except ValueError:
                                row_blocker = "invalid_evaluation_rule_contract"
                    if isinstance(trusted_context, dict):
                        ctx_prov = extract_context_provenance(trusted_context)
                        if ctx_prov["context_source"] != "none":
                            context_sources_seen.add(ctx_prov["context_source"])
                        if ctx_prov["application_context_id"] or ctx_prov["application_context_revision_sha256"]:
                            ac_id = ctx_prov["application_context_id"] or f"appctx-{target.id}"
                            ac_rev = ctx_prov["application_context_revision_sha256"] or ""
                            app_contexts_seen[(ac_id, ac_rev)] = {
                                "application_context_id": ac_id,
                                "revision_sha256": ac_rev or None,
                                "provenance": ctx_prov["application_context_provenance"] or "operator_declared",
                            }
                    if row_blocker is None and not self.pi_judge_ready():
                        row_blocker = "judge_provider_unavailable"
                else:
                    rev_pol, rule_blocker = self._resolve_reviewed_policy_for_rule_only(
                        target_id=target.id,
                        norm_category=row_cat,
                        policy_id=policy_id,
                        mode=mode,
                    )
                    if rule_blocker is not None:
                        row_blocker = rule_blocker
                    elif rev_pol is not None and self.policy_store is not None:
                        row_reviewed_policy = rev_pol
                        try:
                            row_reviewed_rules = self.policy_store.reviewed_rules(rev_pol)
                        except ValueError:
                            row_blocker = "invalid_evaluation_rule_contract"
                        else:
                            reviewed_policies_seen[(rev_pol.policy_id, rev_pol.category, rev_pol.revision_sha256)] = {
                                "policy_id": rev_pol.policy_id,
                                "category": rev_pol.category,
                                "revision_sha256": rev_pol.revision_sha256,
                            }
                            context_sources_seen.add("reviewed_policy")

                if row_blocker and overall_blocker is None:
                    overall_blocker = row_blocker

            scope_unsupported_reason: str | None = None
            if not is_unsupported and row_blocker is None:
                resolved_scope: str | None = None
                if isinstance(trusted_context, dict) and isinstance(trusted_context.get("evaluation_scope"), str):
                    resolved_scope = trusted_context["evaluation_scope"]
                elif row_reviewed_policy is not None and hasattr(row_reviewed_policy, "draft"):
                    resolved_scope = getattr(row_reviewed_policy.draft, "evaluation_scope", None)
                if resolved_scope:
                    has_inline = bool(
                        isinstance(target.interface.config.get("response"), dict)
                        and isinstance(target.interface.config["response"].get("evidence_mapping"), dict)
                    )
                    scope_compat = assess_target_scope_compatibility(
                        resolved_scope,
                        target.capability_states,
                        capabilities=target.capabilities,
                        evidence_sources=target.evidence_sources,
                        has_inline_evidence=has_inline,
                    )
                    if not scope_compat.admitted and scope_compat.capability_state == "unsupported":
                        is_unsupported = True
                        scope_unsupported_reason = scope_compat.reason

            item_status = "unsupported" if is_unsupported else ("blocked" if row_blocker else "ready")
            item_reason = (
                (
                    scope_unsupported_reason
                    if scope_unsupported_reason is not None
                    else ("mcp_tool_name_required" if mcp_tool_missing else "capability_unsupported")
                )
                if is_unsupported
                else row_blocker
            )

            if item_status == "ready":
                effective_cat = row_cat or "tool_misuse"
                active_ctx = trusted_context if (use_judge and trusted_context is not None and row_cat is not None) else None
                imp_assert_cnt = (
                    int(row.get("imported_assertions_count"))
                    if isinstance(row.get("imported_assertions_count"), int)
                    else (len(row["assertions"]) if isinstance(row.get("assertions"), list) else 0)
                )
                tc, ti = prepare_generic_case_pair(
                    mode=mode,  # type: ignore[arg-type]
                    target=target,
                    case_id=case_id,
                    norm_category=effective_cat,
                    prompt=prompt,
                    trusted_context=active_ctx,
                    reviewed_rules=row_reviewed_rules,
                    rule_origin="reviewed_policy" if row_reviewed_rules else "none",
                    reviewed_policy=row_reviewed_policy,
                    imported_assertions_count=imp_assert_cnt,
                    stored_response=stored_resp,
                    finish_reason=row.get("finish_reason"),
                    response_complete=row.get("response_complete"),
                    tool_calls=row.get("tool_calls"),
                    response_id=row.get("response_id"),
                    target_model=row.get("target_model"),
                    required_capability=req_cap if isinstance(req_cap, str) else None,
                    tool_name=row.get("tool_name") if isinstance(row.get("tool_name"), str) else None,
                    source_provenance=row.get("source_provenance") if isinstance(row.get("source_provenance"), dict) else None,
                )
                if isinstance(row.get("historical_verdict"), dict):
                    ti.metadata["isolated_historical_verdict"] = row["historical_verdict"]
                if isinstance(row.get("source_provenance"), dict):
                    ti.metadata["research_dataset_provenance"] = dict(row["source_provenance"])
                pairs.append((tc, ti))

            preview_items.append({
                "case_id": case_id,
                "category": row_cat or "unmapped",
                "asi_code": asi_code,
                "status": item_status,
                "reason": item_reason,
                "has_stored_response": isinstance(stored_resp, str) and len(stored_resp) > 0,
                "prompt_preview": Redactor().clean(prompt, opaque=False, limit=180),
            })

        ready_count = len(pairs)
        skipped_cases = [
            {
                "case_id": item["case_id"],
                "category": item["category"],
                "asi_code": item["asi_code"],
                "status": item["status"],
                "reason": item["reason"],
            }
            for item in preview_items
            if item["status"] != "ready"
        ]
        if overall_blocker is None and ready_count == 0:
            overall_blocker = "generic_no_executable_cases"
        has_stored = bool(preview_items) and all(i["has_stored_response"] for i in preview_items)
        reviewed_policies_list = sorted(
            reviewed_policies_seen.values(),
            key=lambda item: (item["policy_id"], item["category"]),
        )
        app_contexts_list = sorted(
            app_contexts_seen.values(),
            key=lambda item: (item["application_context_id"], item.get("revision_sha256") or ""),
        )
        has_app_only = "application_context" in context_sources_seen
        if not use_judge:
            if overall_blocker is not None:
                resolved_policy_id = policy_id
                resolved_policy_rev = None
                resolved_policy_status = "missing_or_draft"
                resolved_context_source = "none"
            elif len(reviewed_policies_list) == 1:
                resolved_policy_id = reviewed_policies_list[0]["policy_id"]
                resolved_policy_rev = reviewed_policies_list[0]["revision_sha256"]
                resolved_policy_status = "reviewed"
                resolved_context_source = "reviewed_policy"
            elif len(reviewed_policies_list) > 1:
                resolved_policy_id = None
                resolved_policy_rev = None
                resolved_policy_status = "mixed"
                resolved_context_source = "mixed"
            else:
                resolved_policy_id = None
                resolved_policy_rev = None
                resolved_policy_status = "not_required"
                resolved_context_source = "none"
        elif overall_blocker is not None:
            resolved_policy_id = reviewed_policies_list[0]["policy_id"] if len(reviewed_policies_list) == 1 and not has_app_only else policy_id
            resolved_policy_rev = reviewed_policies_list[0]["revision_sha256"] if len(reviewed_policies_list) == 1 and not has_app_only else None
            resolved_policy_status = "missing_or_draft"
            resolved_context_source = (
                "mixed" if len(context_sources_seen) > 1 else (next(iter(context_sources_seen), "none"))
            )
        elif len(reviewed_policies_list) == 1 and not has_app_only:
            resolved_policy_id = reviewed_policies_list[0]["policy_id"]
            resolved_policy_rev = reviewed_policies_list[0]["revision_sha256"]
            resolved_policy_status = "reviewed"
            resolved_context_source = (
                "reviewed_policy_with_application_context"
                if "reviewed_policy_with_application_context" in context_sources_seen
                else "reviewed_policy"
            )
        elif not reviewed_policies_list and has_app_only:
            resolved_policy_id = None
            resolved_policy_rev = None
            resolved_policy_status = "application_context_only"
            resolved_context_source = "application_context"
        elif len(reviewed_policies_list) > 1 or (reviewed_policies_list and has_app_only):
            resolved_policy_id = None
            resolved_policy_rev = None
            resolved_policy_status = "mixed"
            resolved_context_source = "mixed"
        else:
            resolved_policy_id = policy_id
            resolved_policy_rev = None
            resolved_policy_status = "missing_or_draft"
            resolved_context_source = "none"

        single_app_ctx = app_contexts_list[0] if len(app_contexts_list) == 1 else None
        return pairs, {
            "selected_cases": len(preview_items),
            "executed_cases": ready_count,
            "total_cases": len(preview_items),
            "asi_breakdown": asi_breakdown,
            "has_stored_responses": has_stored,
            "available_modes": ["live", "offline"] if has_stored else ["live"],
            "ready_count": ready_count,
            "blocked_count": sum(1 for i in preview_items if i["status"] == "blocked"),
            "unsupported_count": sum(1 for i in preview_items if i["status"] == "unsupported"),
            "skipped_count": len(skipped_cases),
            "skipped_cases": skipped_cases,
            "target_request_budget": 0 if mode == "offline" else ready_count,
            "judge_request_budget": ready_count if use_judge else 0,
            "policy_id": resolved_policy_id,
            "policy_revision_sha256": resolved_policy_rev,
            "policy_review_status": resolved_policy_status,
            "context_source": resolved_context_source,
            "application_context_id": single_app_ctx["application_context_id"] if single_app_ctx else None,
            "application_context_revision_sha256": single_app_ctx["revision_sha256"] if single_app_ctx else None,
            "reviewed_policies": reviewed_policies_list,
            "application_contexts": app_contexts_list,
            "blocker": overall_blocker,
            "items": preview_items,
        }

    def _resolve_target_auth_binding(self, *, mode: str, target: TargetProfile) -> dict[str, Any]:
        target_rev = self._current_target_revision(target.id)
        if mode == "offline":
            return {
                "target_revision_sha256": target_rev,
                "auth_source": "none",
                "session_credential_ref": None,
                "session_credential_generation": None,
                "session_auth_type": None,
                "session_auth_header": None,
            }
        session_refs = [
            ref for ref in (target.credential_refs or [])
            if isinstance(ref, str) and ref.startswith("sess_")
        ]
        if session_refs:
            ref = session_refs[0]
            target_url = str(target.interface.config.get("url") or "")
            target_meta = target.metadata if isinstance(target.metadata, dict) else {}
            session_store = getattr(self.catalog, "session_credentials", None)
            gen: str | None = None
            if session_store is not None:
                avail = session_store.availability(
                    ref,
                    endpoint=target_url,
                    scope_id=target.id,
                    scope_kind="target",
                    expected_auth_type=target_meta.get("session_auth_type"),
                    expected_header_name=target_meta.get("session_auth_header"),
                )
                if avail == "available":
                    gen = session_store.generation(
                        ref,
                        endpoint=target_url,
                        scope_id=target.id,
                        scope_kind="target",
                    )
            return {
                "target_revision_sha256": target_rev,
                "auth_source": "session_memory",
                "session_credential_ref": ref,
                "session_credential_generation": gen,
                "session_auth_type": target_meta.get("session_auth_type"),
                "session_auth_header": target_meta.get("session_auth_header"),
            }
        if target.credential_refs:
            return {
                "target_revision_sha256": target_rev,
                "auth_source": "env_alias",
                "session_credential_ref": None,
                "session_credential_generation": None,
                "session_auth_type": None,
                "session_auth_header": None,
            }
        return {
            "target_revision_sha256": target_rev,
            "auth_source": "none",
            "session_credential_ref": None,
            "session_credential_generation": None,
            "session_auth_type": None,
            "session_auth_header": None,
        }

    def preview_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        mode = payload.get("mode", "offline")
        if mode not in {"live", "offline"}:
            raise ValueError("generic_invalid_mode")
        target_id = str(payload.get("target_id") or "").strip()
        if not target_id or not _ID_RE.fullmatch(target_id):
            raise ValueError("generic_invalid_target_id")
        asi_category = str(payload.get("asi_category") or ("auto" if payload.get("dataset_id") else "")).strip()
        if not asi_category:
            raise ValueError("generic_asi_category_required")
        use_judge = bool(payload.get("use_judge", False))
        policy_id = payload.get("policy_id")
        target = self._resolve_target(
            mode=mode,
            target_id=target_id,
            target_profile_dict=payload.get("target_profile"),
            capability_states=payload.get("capability_states"),
            evidence_sources=payload.get("evidence_sources"),
            for_execution=True,
        )
        auth_binding = self._resolve_target_auth_binding(mode=mode, target=target)
        raw_sources = payload.get("evidence_sources")
        evidence_source_diagnostics: list[dict[str, Any]] = []
        if isinstance(raw_sources, list):
            configured_evidence_source_count = len([s for s in raw_sources if isinstance(s, dict)])
        else:
            configured_specs, evidence_source_diagnostics = self._resolve_saved_evidence_sources_with_diagnostics(
                target_id,
                for_execution=False,
                mode=mode,
            )
            configured_evidence_source_count = len(configured_specs)
        active_evidence_source_count = len(target.evidence_sources)
        raw_cases = self._extract_raw_cases(payload)
        _, preview_meta = self._build_cases(
            mode=mode,
            target=target,
            asi_category=asi_category,
            raw_cases=raw_cases,
            use_judge=use_judge,
            policy_id=policy_id,
        )
        dataset_id = payload.get("dataset_id")
        dataset_name = None
        if isinstance(dataset_id, str) and dataset_id and self.dataset_repo is not None:
            env = self.dataset_repo.get_dataset(dataset_id)
            if env is not None:
                dataset_name = env.name
        has_inline_ev = bool(
            isinstance(target.interface.config.get("response"), dict)
            and isinstance(target.interface.config["response"].get("evidence_mapping"), dict)
        )
        capability_summary = summarize_target_capabilities_and_scopes(
            capability_states=target.capability_states,
            capabilities=target.capabilities,
            observability=target.observability,
            evidence_sources=target.evidence_sources,
            has_inline_evidence=has_inline_ev,
        )
        if evidence_source_diagnostics:
            capability_summary["limitations"] = list(capability_summary.get("limitations") or []) + [
                d["reason"] for d in evidence_source_diagnostics if isinstance(d.get("reason"), str)
            ]
        return {
            "workflow_schema_version": "1.0.0",
            "mode": mode,
            "target_id": target.id,
            "target_name": target.name,
            "target_revision_sha256": auth_binding["target_revision_sha256"],
            "auth_source": auth_binding["auth_source"],
            "session_credential_generation": auth_binding["session_credential_generation"],
            "session_auth_type": auth_binding["session_auth_type"],
            "session_auth_header": auth_binding["session_auth_header"],
            "dataset_id": dataset_id,
            "dataset_name": dataset_name,
            "asi_category": asi_category,
            "use_judge": use_judge,
            "pi_judge_ready": self.pi_judge_ready(),
            "judge_status": self.judge_status(),
            "capability_states": target.capability_states,
            "capability_summary": capability_summary,
            "evidence_source_count": active_evidence_source_count,
            "active_evidence_source_count": active_evidence_source_count,
            "configured_evidence_source_count": configured_evidence_source_count,
            "evidence_source_diagnostics": evidence_source_diagnostics,
            **preview_meta,
        }

    def _persist_controlled_run_summary(
        self,
        *,
        item: dict[str, Any],
        report_path: Path,
        report_bytes: bytes,
        report_doc: dict[str, Any],
        ev_block: dict[str, Any],
        exec_block: dict[str, Any],
        run_id: str,
        dataset_id: str | None,
        dataset_name: str | None,
        target_id: str,
        mode: str,
    ) -> None:
        if self.controlled_runs_root is None:
            return
        case_run_dir = self.controlled_runs_root / item["run_id"]
        case_run_dir.mkdir(parents=True, exist_ok=True)
        sec_name = report_path.name
        sec_target = case_run_dir / sec_name
        sec_tmp = case_run_dir / f".{sec_name}.{secrets.token_hex(4)}.tmp"
        sec_tmp.write_bytes(report_bytes)
        os.replace(sec_tmp, sec_target)
        run_sum = {
            "run_id": item["run_id"],
            "native_execution_id": ev_block.get("run_id") or item["run_id"],
            "generic_run_id": run_id,
            "dataset_id": dataset_id,
            "dataset_name": dataset_name,
            "testcase_id": report_doc.get("testcase_id") or item["case_id"],
            "target_id": report_doc.get("target_id") or target_id,
            "target_request_count": 0 if mode == "offline" else (1 if exec_block else 0),
            "report_persisted": True,
            "report_file": sec_name,
            "report_sha256": sha256(report_bytes).hexdigest(),
        }
        sum_target = case_run_dir / "run-summary.json"
        sum_tmp = case_run_dir / f".run-summary-{secrets.token_hex(4)}.tmp"
        sum_tmp.write_text(json.dumps(run_sum, indent=2) + "\n", encoding="utf-8")
        os.replace(sum_tmp, sum_target)

    def _write_run_record(self, run_dir: Path, record: dict[str, Any]) -> None:
        with self._lock:
            run_dir.mkdir(parents=True, exist_ok=True)
            target_file = run_dir / "generic-run.json"
            tmp_file = run_dir / f".generic-run-{secrets.token_hex(6)}.tmp"
            data = (json.dumps(record, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
            tmp_file.write_bytes(data)
            last_err: OSError | None = None
            for _ in range(10):
                try:
                    os.replace(tmp_file, target_file)
                    return
                except OSError as exc:
                    last_err = exc
                    import time
                    time.sleep(0.005)
            try:
                tmp_file.unlink(missing_ok=True)
            except OSError:
                pass
            raise OSError("generic_run_atomic_write_failed") from last_err

    @staticmethod
    def _submission_fingerprint(payload: dict[str, Any], mode: str, target_id: str, asi_category: str, use_judge: bool) -> str:
        canonical = {
            "mode": mode,
            "target_id": target_id,
            "asi_category": asi_category,
            "use_judge": use_judge,
            "policy_id": payload.get("policy_id"),
            "dataset_id": payload.get("dataset_id"),
            "testcase_ids": list(payload.get("testcase_ids") or []),
            "cases": payload.get("cases"),
            "stored_payload": payload.get("stored_payload"),
            "target_profile": payload.get("target_profile"),
            "capability_states": payload.get("capability_states"),
            "evidence_sources": payload.get("evidence_sources"),
            "allowed_collector_roots": payload.get("allowed_collector_roots"),
            "expected_target_revision": payload.get("expected_target_revision"),
            "expected_session_credential_generation": payload.get("expected_session_credential_generation"),
        }
        if payload.get("continuation_of_run_id") or payload.get("expected_resume_digest"):
            canonical["continuation_of_run_id"] = payload.get("continuation_of_run_id")
            canonical["expected_resume_digest"] = payload.get("expected_resume_digest")
        return sha256(json.dumps(canonical, sort_keys=True, default=str).encode("utf-8")).hexdigest()

    def _build_judge_metadata(
        self,
        *,
        use_judge: bool,
        run_status: str,
        cases: list[dict[str, Any]],
        pi_cfg: PiEvaluatorConfig | None = None,
        is_historical: bool = False,
        recorded_provider: str | None = None,
        recorded_model: str | None = None,
    ) -> dict[str, Any]:
        j_stat = self.judge_status()
        if is_historical:
            provider_name = recorded_provider
            model_name = recorded_model
        else:
            provider_name = (
                recorded_provider
                or (pi_cfg.provider if (use_judge and pi_cfg is not None) else None)
                or (j_stat.get("provider") if use_judge else None)
            )
            model_name = (
                recorded_model
                or (pi_cfg.model if (use_judge and pi_cfg is not None) else None)
                or (j_stat.get("model") if use_judge else None)
            )
        if not use_judge:
            return {
                "mode": "rule_only",
                "judge_configured": j_stat["judge_configured"],
                "credential_available": j_stat["credential_available"],
                "judge_ready": j_stat["judge_ready"],
                "provider": None,
                "model": None,
                "invocation_status": "not_requested",
                "request_count": 0,
                "success_count": 0,
                "failure_count": 0,
                "error_categories": [],
            }
        attempted = 0
        succeeded = 0
        failed = 0
        unverified_output_count = 0
        errors: set[str] = set()
        for c in cases:
            if not isinstance(c, dict):
                continue
            invoked = c.get("semantic_invoked")
            raw_fault = c.get("provider_fault_code")
            fault = getattr(raw_fault, "value", raw_fault)
            val_status = c.get("json_validation_status")
            has_judge_output = bool(c.get("judge_classification") or c.get("judge_reason"))
            blocked_fault = fault in {"budget_exhausted", "judge_disabled", "skill_unavailable", "skill_mismatch"}
            if invoked is True or (bool(fault) and not blocked_fault):
                attempted += 1
                if fault or val_status == "provider_fault":
                    failed += 1
                    errors.add(str(fault or "provider_fault"))
                elif val_status in {"valid", None} and (has_judge_output or val_status == "valid"):
                    succeeded += 1
                else:
                    failed += 1
                    errors.add(str(val_status or "invalid_judge_output"))
            elif blocked_fault:
                errors.add(str(fault))
            elif has_judge_output:
                unverified_output_count += 1
        if run_status in {"preparing", "running"} and attempted == 0:
            inv_status = "running"
        elif attempted == 0 and unverified_output_count > 0:
            inv_status = "unknown_unverified"
        elif attempted == 0:
            inv_status = "not_invoked"
        elif failed == 0 and unverified_output_count == 0:
            inv_status = "succeeded"
        elif succeeded > 0:
            inv_status = "partial_failure"
        else:
            inv_status = "failed"
        return {
            "mode": "hybrid",
            "judge_configured": j_stat["judge_configured"],
            "credential_available": j_stat["credential_available"],
            "judge_ready": j_stat["judge_ready"],
            "provider": provider_name,
            "model": model_name,
            "invocation_status": inv_status,
            "request_count": attempted,
            "success_count": succeeded,
            "failure_count": failed,
            "error_categories": sorted(errors),
        }

    def _verify_completion_invariants(
        self,
        *,
        run_id: str,
        record: dict[str, Any],
        expected_cases_count: int,
    ) -> None:
        cases = record.get("cases")
        if not isinstance(cases, list) or len(cases) != expected_cases_count:
            raise RuntimeError("completion_invariant_case_count_mismatch")
        if record.get("executed_cases") != expected_cases_count or record.get("total_cases") != expected_cases_count:
            raise RuntimeError("completion_invariant_executed_count_mismatch")
        v_counts = record.get("verdict_counts")
        if not isinstance(v_counts, dict) or sum(int(v) for v in v_counts.values()) != expected_cases_count:
            raise RuntimeError("completion_invariant_verdict_sum_mismatch")
        actual_verdicts: Counter[str] = Counter()
        for c in cases:
            if not isinstance(c, dict) or not isinstance(c.get("verdict"), str):
                raise RuntimeError("completion_invariant_invalid_case_entry")
            actual_verdicts[c["verdict"]] += 1
            c_case_id = str(c.get("case_id") or "")
            c_run_id = str(c.get("run_id") or "")
            if not c_case_id or not c_run_id:
                raise RuntimeError("completion_invariant_case_identity_missing")
            r_path_str = c.get("report_path")
            if not isinstance(r_path_str, str) or not r_path_str.strip():
                raise RuntimeError("completion_invariant_native_report_missing")
            r_path = Path(r_path_str)
            if not r_path.is_file():
                raise RuntimeError("completion_invariant_native_report_missing")
            try:
                raw_rep = r_path.read_bytes()
            except OSError as exc:
                raise RuntimeError("completion_invariant_native_report_unreadable") from exc
            if not raw_rep:
                raise RuntimeError("completion_invariant_native_report_empty")
            try:
                rep_doc = json.loads(raw_rep.decode("utf-8"))
            except Exception as exc:
                raise RuntimeError("completion_invariant_native_report_corrupted") from exc
            if not isinstance(rep_doc, dict):
                raise RuntimeError("completion_invariant_native_report_invalid")
            ev_b = rep_doc.get("evaluation")
            if not isinstance(ev_b, dict):
                raise RuntimeError("completion_invariant_native_report_evaluation_missing")
            rep_tc_id = rep_doc.get("testcase_id") or (rep_doc.get("testcase") or {}).get("testcase_id")
            if rep_tc_id != c_case_id:
                raise RuntimeError("completion_invariant_native_report_testcase_mismatch")
            if ev_b.get("run_id") != c_run_id:
                raise RuntimeError("completion_invariant_native_report_run_id_mismatch")
            rep_generic_id = rep_doc.get("generic_run_id") or ev_b.get("generic_run_id")
            if rep_generic_id is not None and rep_generic_id != run_id:
                raise RuntimeError("completion_invariant_native_report_generic_run_mismatch")
            rep_sha = sha256(raw_rep).hexdigest()
            if self.controlled_runs_root is not None:
                sum_path = self.controlled_runs_root / c_run_id / "run-summary.json"
                if not sum_path.is_file():
                    raise RuntimeError("completion_invariant_run_summary_missing")
                try:
                    sum_doc = json.loads(sum_path.read_text(encoding="utf-8"))
                except Exception as exc:
                    raise RuntimeError("completion_invariant_run_summary_corrupted") from exc
                if not isinstance(sum_doc, dict):
                    raise RuntimeError("completion_invariant_run_summary_invalid")
                if (
                    sum_doc.get("run_id") != c_run_id
                    or sum_doc.get("generic_run_id") != run_id
                    or sum_doc.get("testcase_id") != c_case_id
                ):
                    raise RuntimeError("completion_invariant_run_summary_link_mismatch")
                if sum_doc.get("report_sha256") != rep_sha:
                    raise RuntimeError("completion_invariant_report_sha256_mismatch")
                rep_file = sum_doc.get("report_file")
                ctrl_rep_path = (
                    (self.controlled_runs_root / c_run_id / rep_file)
                    if isinstance(rep_file, str) and rep_file
                    else None
                )
                if ctrl_rep_path is None or not ctrl_rep_path.is_file():
                    raise RuntimeError("completion_invariant_controlled_report_missing")
                if sha256(ctrl_rep_path.read_bytes()).hexdigest() != rep_sha:
                    raise RuntimeError("completion_invariant_controlled_report_sha256_mismatch")
        if dict(sorted(actual_verdicts.items())) != dict(sorted((k, int(v)) for k, v in v_counts.items() if int(v) > 0)):
            raise RuntimeError("completion_invariant_verdict_distribution_mismatch")

    def start_run(
        self,
        payload: dict[str, Any],
        *,
        _continuation_meta: dict[str, Any] | None = None,
        _owns_root_lock: str | None = None,
    ) -> dict[str, Any]:
        if payload.get("authorization_confirmed") is not True:
            raise ValueError("generic_authorization_required")
        mode = payload.get("mode", "offline")
        if mode not in {"live", "offline"}:
            raise ValueError("generic_invalid_mode")
        target_id = str(payload.get("target_id") or "").strip()
        if not target_id or not _ID_RE.fullmatch(target_id):
            raise ValueError("generic_invalid_target_id")
        asi_category = str(payload.get("asi_category") or ("auto" if payload.get("dataset_id") else "")).strip()
        use_judge = bool(payload.get("use_judge", False))
        policy_id = payload.get("policy_id")
        async_execution = bool(payload.get("async_execution", False))
        submission_id_raw = payload.get("submission_id")
        submission_id: str | None = None
        if submission_id_raw is not None:
            submission_id = str(submission_id_raw).strip()
            if not _HEX32_RE.fullmatch(submission_id):
                raise ValueError("generic_invalid_submission_id")

        expected_target_revision = payload.get("expected_target_revision")
        if expected_target_revision is not None:
            if not isinstance(expected_target_revision, str) or not _HEX64_RE.fullmatch(expected_target_revision):
                raise ValueError("generic_target_revision_stale")
        expected_session_gen = payload.get("expected_session_credential_generation")
        if expected_session_gen is not None:
            if not isinstance(expected_session_gen, str) or not _HEX32_RE.fullmatch(expected_session_gen):
                raise ValueError("generic_session_credential_stale")

        fingerprint = (
            self._submission_fingerprint(payload, mode, target_id, asi_category, use_judge)
            if submission_id
            else None
        )
        submissions_dir = self.runs_root / "submissions"
        in_flight_owner = False
        in_flight_entry: dict[str, Any] | None = None
        if submission_id and fingerprint:
            existing_id_to_return: str | None = None
            worker_to_join: Thread | None = None
            wait_entry: dict[str, Any] | None = None
            with self._lock:
                sub_file = submissions_dir / f"{submission_id}.json"
                if sub_file.is_file():
                    try:
                        sub_doc = json.loads(sub_file.read_text(encoding="utf-8"))
                    except Exception:
                        sub_doc = {}
                    if sub_doc.get("request_fingerprint") != fingerprint:
                        raise ValueError("generic_submission_conflict")
                    existing_id_to_return = str(sub_doc.get("generic_run_id") or "")
                    worker_to_join = self._in_progress_runs.get(existing_id_to_return)
                elif submission_id in self._submissions_in_flight:
                    wait_entry = self._submissions_in_flight[submission_id]
                    if wait_entry.get("fingerprint") != fingerprint:
                        raise ValueError("generic_submission_conflict")
                else:
                    in_flight_entry = {
                        "fingerprint": fingerprint,
                        "event": Event(),
                        "run_id": None,
                        "error": None,
                    }
                    self._submissions_in_flight[submission_id] = in_flight_entry
                    in_flight_owner = True

            if existing_id_to_return is not None:
                if not existing_id_to_return:
                    raise ValueError("generic_submission_record_unavailable")
                if not async_execution and worker_to_join is not None and worker_to_join.is_alive():
                    worker_to_join.join(timeout=300)
                existing_record = self.get_run(existing_id_to_return)
                if existing_record is not None:
                    return existing_record
                raise ValueError("generic_submission_record_unavailable")

            if wait_entry is not None:
                signaled = wait_entry["event"].wait(timeout=self.submission_wait_timeout)
                if not signaled:
                    raise ValueError("generic_submission_in_progress")
                if wait_entry.get("error") is not None:
                    err = wait_entry["error"]
                    if isinstance(err, ValueError):
                        raise err
                    raise ValueError("generic_submission_init_failed") from err
                waited_id = str(wait_entry.get("run_id") or "")
                if not waited_id:
                    raise ValueError("generic_submission_init_failed")
                with self._lock:
                    w_thread = self._in_progress_runs.get(waited_id)
                if not async_execution and w_thread is not None and w_thread.is_alive():
                    w_thread.join(timeout=300)
                waited_record = self.get_run(waited_id)
                if waited_record is not None:
                    return waited_record
                raise ValueError("generic_submission_record_unavailable")

        if submission_id and not in_flight_owner:
            raise ValueError("generic_submission_in_progress")

        tracked_ids: tuple[str, ...] = ()
        released = False
        try:
            cat_lock = getattr(self.catalog, "_lock", None)
            session_resolver = None
            session_secrets: list[str] = []
            with (cat_lock if cat_lock is not None else nullcontext()), self._lock:
                target = self._resolve_target(
                    mode=mode,
                    target_id=target_id,
                    target_profile_dict=payload.get("target_profile"),
                    capability_states=payload.get("capability_states"),
                    evidence_sources=payload.get("evidence_sources"),
                    for_execution=True,
                )
                auth_binding = self._resolve_target_auth_binding(mode=mode, target=target)
                current_target_rev = auth_binding["target_revision_sha256"]
                if expected_target_revision is not None and current_target_rev is not None:
                    if expected_target_revision != current_target_rev:
                        raise ValueError("generic_target_revision_stale")

                # Snapshot & validate session-memory credential generation and target revision
                # under lock BEFORE acquiring run or sending any target request.
                if mode == "live" and auth_binding["auth_source"] == "session_memory":
                    session_store = getattr(self.catalog, "session_credentials", None)
                    if session_store is None:
                        raise ValueError("credential_unavailable")
                    current_gen = auth_binding["session_credential_generation"]
                    if not current_gen:
                        raise ValueError("credential_unavailable")
                    if not expected_session_gen:
                        raise ValueError("generic_session_credential_authorization_required")
                    if expected_session_gen != current_gen:
                        raise ValueError("generic_session_credential_stale")
                    if current_target_rev is not None and not expected_target_revision:
                        raise ValueError("generic_target_revision_stale")
                    target_url = str(target.interface.config.get("url") or "")
                    target_meta = target.metadata if isinstance(target.metadata, dict) else {}
                    resolved_map: dict[str, str] = {}
                    for ref in (target.credential_refs or []):
                        if not isinstance(ref, str) or not ref.startswith("sess_"):
                            continue
                        try:
                            _, raw_secret, variants = session_store.resolve(
                                ref,
                                endpoint=target_url,
                                scope_id=target.id,
                                scope_kind="target",
                                expected_auth_type=target_meta.get("session_auth_type"),
                                expected_header_name=target_meta.get("session_auth_header"),
                            )
                        except SessionCredentialError as exc:
                            raise ValueError("credential_unavailable") from exc
                        resolved_map[ref] = raw_secret
                        for variant in variants:
                            if variant not in session_secrets:
                                session_secrets.append(variant)

                    def _resolve_scan_session_cred(ref_id: str, _snap=dict(resolved_map)) -> str | None:
                        return _snap.get(ref_id)

                    session_resolver = _resolve_scan_session_cred
                elif expected_session_gen is not None:
                    # Authorization was bound to a session credential generation, but target is no longer session-backed.
                    raise ValueError("generic_session_credential_stale")

                tracked_ids = tuple(dict.fromkeys((target_id, target.id)))
                for tid in tracked_ids:
                    self._acquire_target_run(tid)

            raw_cases = self._extract_raw_cases(payload)
            pairs, preview_meta = self._build_cases(
                mode=mode,
                target=target,
                asi_category=asi_category,
                raw_cases=raw_cases,
                use_judge=use_judge,
                policy_id=policy_id,
            )
            if preview_meta["blocker"]:
                raise ValueError(preview_meta["blocker"])

            eval_cfg = RunnerEvaluationConfig()
            provider = None
            pi_cfg = None
            if use_judge:
                pi_cfg = self.resolved_pi_config()
                if self.judge_provider is not None:
                    provider = self.judge_provider
                    eval_cfg = RunnerEvaluationConfig(
                        mode="hybrid",
                        judge_enabled=True,
                        max_judge_calls=max(1, len(pairs)),
                        require_complete_response_for_semantic=True,
                    )
                elif pi_cfg is not None:
                    provider = PiEvaluatorProvider(pi_cfg)
                    eval_cfg = RunnerEvaluationConfig(
                        mode="hybrid",
                        judge_enabled=True,
                        allow_live_judge=True,
                        max_judge_calls=max(1, len(pairs)),
                        pi=pi_cfg,
                        require_complete_response_for_semantic=True,
                    )
                else:
                    raise ValueError("judge_provider_unavailable")

            run_id = uuid4().hex
            run_dir = self.runs_root / run_id
            allowed_endpoints: list[str] = []
            if target.interface.config.get("url"):
                allowed_endpoints.append(str(target.interface.config["url"]))
            for spec in target.evidence_sources:
                if isinstance(spec, dict) and spec.get("url"):
                    allowed_endpoints.append(str(spec["url"]))

            extra_roots: list[Path] = list(self.allowed_collector_roots)
            requested_roots = payload.get("allowed_collector_roots")
            if requested_roots is not None:
                if not isinstance(requested_roots, list):
                    raise ValueError("generic_collector_root_not_allowed")
                for root_str in requested_roots:
                    if not isinstance(root_str, str) or not root_str.strip():
                        raise ValueError("generic_collector_root_not_allowed")
                    if not self.allowed_collector_roots:
                        raise ValueError("generic_collector_root_not_allowed")
                    raw_path = Path(root_str.strip())
                    if not raw_path.is_absolute() or not raw_path.exists() or not raw_path.is_dir():
                        raise ValueError("generic_collector_root_not_allowed")
                    candidate = raw_path.resolve()
                    matched_base = next(
                        (base for base in self.allowed_collector_roots if candidate.is_relative_to(base)),
                        None,
                    )
                    if matched_base is None or _has_symlink_or_reparse(raw_path, stop_at=matched_base):
                        raise ValueError("generic_collector_root_not_allowed")
                    if candidate not in extra_roots:
                        extra_roots.append(candidate)

            ev_transport = getattr(self.evidence_source_store, "transport", None)
            injected_collectors: list[Any] = []
            ev_store_diagnostics: list[dict[str, Any]] = []
            if payload.get("evidence_sources") is None and mode != "offline":
                _, ev_store_diagnostics = self._resolve_saved_evidence_sources_with_diagnostics(
                    target_id,
                    for_execution=True,
                    mode=mode,
                )
                if ev_store_diagnostics:
                    injected_collectors.append(
                        _StaticDiagnosticCollector(
                            [
                                CollectorDiagnostic(
                                    collector_id=str(d["collector_id"]),
                                    collector_kind=str(d["collector_kind"]),
                                    status="error",
                                    reason=str(d["reason"]),
                                )
                                for d in ev_store_diagnostics
                            ]
                        )
                    )
            run_target = target
            if ev_transport is not None and any(
                isinstance(s, dict) and s.get("kind") == "http_callback" for s in target.evidence_sources
            ):
                remaining_specs = []
                for spec in target.evidence_sources:
                    if isinstance(spec, dict) and spec.get("kind") == "http_callback" and spec.get("url"):
                        injected_collectors.append(
                            HttpCallbackCollector(
                                collector_id=str(spec.get("id") or "http_callback"),
                                url=str(spec["url"]),
                                headers=spec.get("headers") if isinstance(spec.get("headers"), dict) else None,
                                timeout_seconds=float(spec.get("timeout_seconds") or 5.0),
                                provenance="target_reported",
                                independent_verifier=False,
                                mapping=spec.get("mapping") if isinstance(spec.get("mapping"), dict) else None,
                                max_response_bytes=int(spec.get("max_response_bytes") or 65536),
                                max_events=int(spec.get("max_events") or 200),
                                transport=ev_transport,
                            )
                        )
                    else:
                        remaining_specs.append(spec)
                run_target = target.model_copy(update={"evidence_sources": remaining_specs})

            dataset_id = payload.get("dataset_id") if isinstance(payload.get("dataset_id"), str) else None
            dataset_name = None
            dataset_revision_sha256 = None
            if dataset_id and self.dataset_repo is not None:
                env = self.dataset_repo.get_dataset(dataset_id)
                if env is not None:
                    dataset_name = env.name
                    dataset_revision_sha256 = env.file_sha256
            target_revision_sha256 = self._current_target_revision(target.id)
            run_dataset_metadata = (
                {
                    "dataset_id": dataset_id,
                    "dataset_revision_sha256": dataset_revision_sha256,
                    "source_filename": dataset_name,
                }
                if dataset_id
                else None
            )

            started_at = datetime.now(timezone.utc).isoformat()
            case_statuses = [
                {
                    "case_id": item["case_id"],
                    "category": item["category"],
                    "asi_code": item["asi_code"],
                    "status": "queued" if item["status"] == "ready" else item["status"],
                    "stage": "queued" if item["status"] == "ready" else "skipped",
                    "verdict": None,
                    "reason": item["reason"],
                    "evidence_level": None,
                    "run_id": None,
                }
                for item in preview_meta["items"]
            ]
            record: dict[str, Any] = {
                "workflow_schema_version": "1.0.0",
                "generic_run_id": run_id,
                "submission_id": submission_id,
                "status": "running",
                "started_at": started_at,
                "completed_at": None,
                "mode": mode,
                "target_id": target.id,
                "target_name": target.name,
                "target_revision_sha256": target_revision_sha256,
                "authentication_provenance": {
                    "auth_source": auth_binding["auth_source"],
                    "session_auth_type": auth_binding["session_auth_type"],
                    "session_auth_header": auth_binding["session_auth_header"],
                    "session_credential_generation": auth_binding["session_credential_generation"],
                    "identity_verified": False,
                },
                "dataset_id": dataset_id,
                "dataset_name": dataset_name,
                "dataset_revision_sha256": dataset_revision_sha256,
                "asi_category": asi_category,
                "use_judge": use_judge,
                "policy_id": preview_meta["policy_id"],
                "policy_revision_sha256": preview_meta["policy_revision_sha256"],
                "policy_review_status": preview_meta["policy_review_status"],
                "context_source": preview_meta["context_source"],
                "application_context_id": preview_meta["application_context_id"],
                "application_context_revision_sha256": preview_meta["application_context_revision_sha256"],
                "reviewed_policies": preview_meta["reviewed_policies"],
                "application_contexts": preview_meta["application_contexts"],
                "research_provenance": summarize_run_research_provenance(
                    [],
                    target=target,
                    target_revision_sha256=target_revision_sha256,
                    dataset_id=dataset_id,
                    dataset_revision_sha256=dataset_revision_sha256,
                    dataset_name=dataset_name,
                ),
                "capability_states": target.capability_states,
                "selected_cases": len(preview_meta["items"]),
                "ready_count": len(pairs),
                "executed_cases": 0,
                "total_cases": len(pairs),
                "skipped_count": len(preview_meta["skipped_cases"]),
                "skipped_cases": preview_meta["skipped_cases"],
                "progress_percent": 0,
                "current_case_id": pairs[0][0].id if pairs else None,
                "current_stage": "queued",
                "target_request_budget": preview_meta["target_request_budget"],
                "target_requests_used": 0,
                "judge_request_budget": preview_meta["judge_request_budget"],
                "judge_requests_used": 0,
                "verdict_counts": {},
                "evidence_summary": {},
                "evidence_source_diagnostics": ev_store_diagnostics,
                "judge_metadata": self._build_judge_metadata(
                    use_judge=use_judge,
                    run_status="running",
                    cases=[],
                    pi_cfg=pi_cfg,
                ),
                "case_statuses": case_statuses,
                "events": [{"at": started_at, "stage": "run_started", "case_id": None}],
                "cases": [],
                **(
                    {
                        "continuation_of_run_id": _continuation_meta["parent_run_id"],
                        "root_run_id": _continuation_meta["root_run_id"],
                        "resume_metadata": dict(_continuation_meta),
                    }
                    if isinstance(_continuation_meta, dict)
                    else {}
                ),
            }
            with self._lock:
                # Register in-progress run BEFORE writing generic-run.json to disk so get_run/list_runs never see a false orphan
                self._in_progress_runs[run_id] = Thread(name=f"init-{run_id[:8]}")
                if _owns_root_lock:
                    self._active_resumes_by_root[_owns_root_lock] = run_id
            try:
                self._write_run_record(run_dir, record)
                if submission_id and fingerprint:
                    with self._lock:
                        submissions_dir.mkdir(parents=True, exist_ok=True)
                        sub_path = submissions_dir / f"{submission_id}.json"
                        sub_tmp = submissions_dir / f".sub-{secrets.token_hex(6)}.tmp"
                        sub_tmp.write_text(
                            json.dumps(
                                {
                                    "submission_id": submission_id,
                                    "generic_run_id": run_id,
                                    "request_fingerprint": fingerprint,
                                    "created_at": started_at,
                                },
                                indent=2,
                            )
                            + "\n",
                            encoding="utf-8",
                        )
                        os.replace(sub_tmp, sub_path)
                        if in_flight_entry is not None:
                            in_flight_entry["run_id"] = run_id
            except Exception:
                with self._lock:
                    self._in_progress_runs.pop(run_id, None)
                raise

            if in_flight_owner and in_flight_entry is not None:
                in_flight_entry["event"].set()

            enriched_cases: list[dict[str, Any]] = []
            verdict_counter: Counter[str] = Counter()
            evidence_counter: Counter[str] = Counter()

            def _on_progress(evt: dict[str, Any]) -> None:
                now_iso = datetime.now(timezone.utc).isoformat()
                ev_type = evt.get("event")
                cid = str(evt.get("case_id") or "")
                if ev_type in {"case_started", "case_stage"}:
                    stage_name = str(evt.get("stage") or "running")
                    is_pre_dispatch = ev_type == "case_started" or stage_name == "sending_request_to_target"
                    with self._lock:
                        record["current_case_id"] = cid
                        record["current_stage"] = stage_name
                        for row in record["case_statuses"]:
                            if row["case_id"] == cid and row["status"] in {"queued", "running"}:
                                row["status"] = "running"
                                row["stage"] = stage_name
                                break
                        record["events"] = (
                            record["events"] + [{"at": now_iso, "stage": stage_name, "case_id": cid}]
                        )[-120:]
                    try:
                        self._write_run_record(run_dir, record)
                    except OSError as exc:
                        if is_pre_dispatch:
                            raise DispatchCheckpointError("dispatch_checkpoint_write_failed") from exc
                elif ev_type == "case_completed":
                    idx = int(evt.get("index", len(enriched_cases)))
                    item = evt["case_summary"]
                    report_path = Path(item["report_path"])
                    report_bytes = evt.get("report_bytes") or report_path.read_bytes()
                    report_doc = evt.get("report_doc") or json.loads(report_bytes.decode("utf-8"))
                    ev_block = report_doc.get("evaluation") or {}
                    obs_block = ev_block.get("observation") or {}
                    exec_block = ev_block.get("execution") or {}
                    judge_block = ev_block.get("judge") or {}

                    self._persist_controlled_run_summary(
                        item=item,
                        report_path=report_path,
                        report_bytes=report_bytes,
                        report_doc=report_doc,
                        ev_block=ev_block,
                        exec_block=exec_block,
                        run_id=run_id,
                        dataset_id=dataset_id,
                        dataset_name=dataset_name,
                        target_id=target.id,
                        mode=mode,
                    )

                    pair_ti = pairs[idx][1] if idx < len(pairs) else evt.get("test_input")
                    stored_rec = pair_ti.parameters.get("stored_record") if pair_ti is not None else None
                    source_prov = (
                        stored_rec.get("provenance")
                        if isinstance(stored_rec, dict) and isinstance(stored_rec.get("provenance"), dict)
                        else None
                    )
                    hist_verdict = pair_ti.metadata.get("isolated_historical_verdict") if pair_ti is not None else None
                    exec_status = "succeeded" if exec_block.get("success") else "failed" if exec_block else "skipped"
                    ev_level = item.get("evidence_level")
                    prov_block = ev_block.get("research_provenance") if isinstance(ev_block.get("research_provenance"), dict) else {}
                    prov_eval = prov_block.get("evaluation") if isinstance(prov_block.get("evaluation"), dict) else {}
                    prov_judge = prov_block.get("judge") if isinstance(prov_block.get("judge"), dict) else {}
                    enriched_case = _sanitize_for_api({
                        "case_id": item["case_id"],
                        "run_id": item["run_id"],
                        "category": item["category"],
                        "prompt": pair_ti.prompt if pair_ti is not None else "",
                        "response_text": obs_block.get("response_text"),
                        "response_complete": obs_block.get("response_complete"),
                        "verdict": item["verdict"],
                        "reason": item["reason"],
                        "decision_source": prov_eval.get("decision_source"),
                        "deterministic_verdict": prov_eval.get("deterministic_verdict"),
                        "effective_deterministic_verdict": prov_eval.get("effective_deterministic_verdict"),
                        "deterministic_matched_rule_id": prov_eval.get("deterministic_matched_rule_id"),
                        "deterministic_matched_rule_type": prov_eval.get("deterministic_matched_rule_type"),
                        "matched_rule_id": prov_eval.get("matched_rule_id"),
                        "matched_rule_type": prov_eval.get("matched_rule_type"),
                        "downgrade_reason": prov_eval.get("downgrade_reason"),
                        "judge_recommendation": prov_judge.get("recommendation"),
                        "judge_reason": judge_block.get("judge_reason"),
                        "judge_classification": judge_block.get("classification"),
                        "semantic_invoked": bool(judge_block.get("semantic_invoked")),
                        "provider_fault_code": getattr(
                            judge_block.get("provider_fault_code"),
                            "value",
                            judge_block.get("provider_fault_code"),
                        ),
                        "json_validation_status": judge_block.get("json_validation_status"),
                        "provider_duration_ms": judge_block.get("provider_duration_ms"),
                        "evidence_level": ev_level,
                        "provenance_tiers": item["provenance_tiers"],
                        "execution_status": exec_status,
                        "collector_diagnostics": item["collector_diagnostics"],
                        "evidence": obs_block.get("evidence", []),
                        "research_provenance": ev_block.get("research_provenance"),
                        **({"source_provenance": source_prov} if source_prov is not None else {}),
                        **({"historical_verdict": hist_verdict} if isinstance(hist_verdict, dict) else {}),
                        "report_path": str(report_path),
                    }, extra_secrets=session_secrets)
                    with self._lock:
                        enriched_cases.append(enriched_case)
                        verdict_counter[item["verdict"]] += 1
                        if isinstance(ev_level, str) and ev_level:
                            evidence_counter[ev_level] += 1
                        if mode == "live" and exec_block:
                            record["target_requests_used"] = int(record.get("target_requests_used", 0)) + 1
                        if bool(judge_block.get("semantic_invoked")):
                            record["judge_requests_used"] = int(record.get("judge_requests_used", 0)) + 1
                        record["cases"] = list(enriched_cases)
                        record["executed_cases"] = len(enriched_cases)
                        # Keep total_cases equal to ready executable count (len(pairs)), never overwrite with partial executed count
                        record["total_cases"] = len(pairs)
                        record["verdict_counts"] = dict(sorted(verdict_counter.items()))
                        record["evidence_summary"] = dict(sorted(evidence_counter.items()))
                        record["progress_percent"] = int(round((len(enriched_cases) / max(1, len(pairs))) * 100))
                        for row in record["case_statuses"]:
                            if row["case_id"] == cid:
                                row["status"] = "error" if item["verdict"] == "ERROR" else "completed"
                                row["stage"] = "completed"
                                row["verdict"] = item["verdict"]
                                row["reason"] = item["reason"]
                                row["evidence_level"] = ev_level
                                row["run_id"] = item["run_id"]
                                break
                        record["judge_metadata"] = self._build_judge_metadata(
                            use_judge=use_judge,
                            run_status="running",
                            cases=enriched_cases,
                            pi_cfg=pi_cfg,
                        )
                        record["events"] = (
                            record["events"]
                            + [{"at": now_iso, "stage": "case_completed", "case_id": cid, "verdict": item["verdict"]}]
                        )[-120:]
                    self._write_run_record(run_dir, record)

            def _execute_worker() -> None:
                try:
                    summary = run_generic_cases(
                        mode=mode,
                        target=run_target,
                        cases=pairs,
                        output_dir=run_dir,
                        evaluation_config=eval_cfg,
                        judge_provider=provider,
                        collectors=tuple(injected_collectors),
                        allowed_collector_roots=tuple(extra_roots),
                        allowed_collector_endpoints=tuple(allowed_endpoints),
                        generic_run_id=run_id,
                        case_progress_callback=_on_progress,
                        target_revision_sha256=target_revision_sha256,
                        dataset_metadata=run_dataset_metadata,
                        credential_resolver=session_resolver,
                        extra_sensitive_values=tuple(session_secrets),
                    )
                    done_iso = datetime.now(timezone.utc).isoformat()
                    with self._lock:
                        record["executed_cases"] = len(record["cases"])
                        record["total_cases"] = len(pairs)
                        record["verdict_counts"] = summary["verdict_counts"]
                        if isinstance(summary.get("research_provenance"), dict):
                            record["research_provenance"] = summary["research_provenance"]
                        self._verify_completion_invariants(
                            run_id=run_id,
                            record=record,
                            expected_cases_count=len(pairs),
                        )
                        record["status"] = "completed"
                        record["completed_at"] = done_iso
                        record["current_case_id"] = None
                        record["current_stage"] = "completed"
                        record["progress_percent"] = 100
                        record["judge_metadata"] = self._build_judge_metadata(
                            use_judge=use_judge,
                            run_status="completed",
                            cases=record["cases"],
                            pi_cfg=pi_cfg,
                        )
                        record["events"] = (
                            record["events"] + [{"at": done_iso, "stage": "completed", "case_id": None}]
                        )[-120:]
                    self._write_run_record(run_dir, record)
                except Exception as exc:
                    fail_iso = datetime.now(timezone.utc).isoformat()
                    err_code = (
                        "dispatch_checkpoint_write_failed"
                        if isinstance(exc, DispatchCheckpointError)
                        else (
                            "persistence_integrity_failed"
                            if isinstance(exc, (OSError, RuntimeError))
                            else "runner_execution_failed"
                        )
                    )
                    with self._lock:
                        record["status"] = "failed"
                        record["completed_at"] = fail_iso
                        record["current_stage"] = "failed"
                        record["error_code"] = err_code
                        record["executed_cases"] = len(record["cases"])
                        record["total_cases"] = len(pairs)
                        record["progress_percent"] = int(round((len(record["cases"]) / max(1, len(pairs))) * 100))
                        record["judge_metadata"] = self._build_judge_metadata(
                            use_judge=use_judge,
                            run_status="failed",
                            cases=record["cases"],
                            pi_cfg=pi_cfg,
                        )
                    try:
                        self._write_run_record(run_dir, record)
                    except OSError:
                        pass
                finally:
                    with self._lock:
                        self._in_progress_runs.pop(run_id, None)
                        if _owns_root_lock and self._active_resumes_by_root.get(_owns_root_lock) in {run_id, "reserving"}:
                            self._active_resumes_by_root.pop(_owns_root_lock, None)
                    for tid in tracked_ids:
                        self._release_target_run(tid)

            if async_execution:
                worker_thread = Thread(target=_execute_worker, name=f"secagent-generic-run-{run_id[:8]}", daemon=True)
                with self._lock:
                    self._in_progress_runs[run_id] = worker_thread
                released = True
                worker_thread.start()
                with self._lock:
                    snap = dict(record)
                if isinstance(_continuation_meta, dict):
                    return self._enrich_loaded_run(run_id, snap, run_dir, is_in_progress=True)
                return snap

            released = True
            _execute_worker()
            return self.get_run(run_id) or record
        except Exception as exc:
            if in_flight_owner and in_flight_entry is not None:
                with self._lock:
                    in_flight_entry["error"] = exc
                    if submission_id:
                        self._submissions_in_flight.pop(submission_id, None)
                in_flight_entry["event"].set()
            raise
        finally:
            if in_flight_owner and submission_id:
                with self._lock:
                    self._submissions_in_flight.pop(submission_id, None)
                    if in_flight_entry is not None and not in_flight_entry["event"].is_set():
                        in_flight_entry["event"].set()
            if not released:
                if _owns_root_lock:
                    with self._lock:
                        self._active_resumes_by_root.pop(_owns_root_lock, None)
                for tid in tracked_ids:
                    self._release_target_run(tid)

    def _enrich_loaded_run(
        self,
        run_id: str,
        raw: dict[str, Any],
        run_dir: Path,
        *,
        is_in_progress: bool | None = None,
    ) -> dict[str, Any]:
        record = dict(raw)
        if is_in_progress is None:
            with self._lock:
                is_in_progress = run_id in self._in_progress_runs
        raw_status = record.get("status")
        if raw_status in {"preparing", "running"} and not is_in_progress:
            record["status"] = "interrupted"
            record["current_stage"] = "interrupted"
            record["interrupted_reason"] = "process_restarted_before_completion"
            try:
                self._write_run_record(run_dir, record)
            except OSError:
                pass
        elif not isinstance(raw_status, str) or not raw_status:
            record["status"] = "completed"

        cases = record.get("cases") if isinstance(record.get("cases"), list) else []
        skipped_cases = record.get("skipped_cases") if isinstance(record.get("skipped_cases"), list) else []
        executed_count = int(record.get("executed_cases") if isinstance(record.get("executed_cases"), int) else len(cases))
        skipped_count = int(record.get("skipped_count") if isinstance(record.get("skipped_count"), int) else len(skipped_cases))
        selected_count = int(
            record.get("selected_cases")
            if isinstance(record.get("selected_cases"), int)
            else (executed_count + skipped_count)
        )
        ready_count = int(
            record.get("ready_count")
            if isinstance(record.get("ready_count"), int)
            else max(executed_count, selected_count - skipped_count)
        )
        record["selected_cases"] = selected_count
        record["ready_count"] = ready_count
        record["executed_cases"] = executed_count
        record["total_cases"] = ready_count if record["status"] in {"preparing", "running", "failed", "interrupted", "cancelled"} else int(record.get("total_cases") or executed_count)
        record["skipped_count"] = skipped_count
        record["skipped_cases"] = skipped_cases

        if "progress_percent" not in record or record["status"] in {"failed", "interrupted", "cancelled"}:
            record["progress_percent"] = (
                100
                if (record["status"] == "completed" and executed_count >= ready_count and ready_count > 0)
                else int(round((executed_count / max(1, ready_count)) * 100))
            )

        if not isinstance(record.get("evidence_summary"), dict) or not record["evidence_summary"]:
            ev_counts: Counter[str] = Counter()
            for c in cases:
                if isinstance(c, dict) and isinstance(c.get("evidence_level"), str) and c["evidence_level"]:
                    ev_counts[c["evidence_level"]] += 1
            record["evidence_summary"] = dict(sorted(ev_counts.items()))

        enriched_hist_cases: list[dict[str, Any]] = []
        for c in cases:
            if not isinstance(c, dict):
                continue
            c_copy = dict(c)
            if "semantic_invoked" not in c_copy:
                r_path_str = c_copy.get("report_path")
                c_run_id = c_copy.get("run_id")
                c_case_id = c_copy.get("case_id")
                if (
                    isinstance(r_path_str, str)
                    and r_path_str
                    and isinstance(c_run_id, str)
                    and c_run_id
                    and self.controlled_runs_root is not None
                ):
                    r_path = Path(r_path_str)
                    sum_p = self.controlled_runs_root / c_run_id / "run-summary.json"
                    if r_path.is_file() and sum_p.is_file():
                        try:
                            raw_rep = r_path.read_bytes()
                            sum_d = json.loads(sum_p.read_text(encoding="utf-8"))
                            expected_sha = sum_d.get("report_sha256") if isinstance(sum_d, dict) else None
                            hash_ok = (
                                isinstance(sum_d, dict)
                                and sum_d.get("run_id") == c_run_id
                                and sum_d.get("generic_run_id") in {None, run_id}
                                and sum_d.get("testcase_id") in {None, c_case_id}
                                and isinstance(expected_sha, str)
                                and expected_sha == sha256(raw_rep).hexdigest()
                            )
                            if hash_ok:
                                rep_doc = json.loads(raw_rep.decode("utf-8"))
                                ev_b = rep_doc.get("evaluation") or {}
                                j_b = ev_b.get("judge")
                                if (
                                    rep_doc.get("testcase_id") == c_case_id
                                    and ev_b.get("run_id") == c_run_id
                                    and isinstance(j_b, dict)
                                    and isinstance(j_b.get("semantic_invoked"), bool)
                                ):
                                    c_copy["semantic_invoked"] = j_b["semantic_invoked"]
                                    c_copy["provider_fault_code"] = j_b.get("provider_fault_code")
                                    c_copy["json_validation_status"] = j_b.get("json_validation_status")
                                    c_copy["provider_duration_ms"] = j_b.get("provider_duration_ms")
                        except Exception:
                            pass
            enriched_hist_cases.append(c_copy)
        cases = enriched_hist_cases
        record["cases"] = cases

        if not record.get("started_at") and cases:
            first_path = cases[0].get("report_path") if isinstance(cases[0], dict) else None
            if isinstance(first_path, str):
                p = Path(first_path)
                if p.is_file():
                    try:
                        doc = json.loads(p.read_text(encoding="utf-8"))
                        record["started_at"] = doc.get("timestamp") or (doc.get("evaluation") or {}).get("timestamp")
                    except Exception:
                        pass
        if not record.get("completed_at") and record["status"] == "completed" and cases:
            last_path = cases[-1].get("report_path") if isinstance(cases[-1], dict) else None
            if isinstance(last_path, str):
                p = Path(last_path)
                if p.is_file():
                    try:
                        doc = json.loads(p.read_text(encoding="utf-8"))
                        record["completed_at"] = doc.get("timestamp") or (doc.get("evaluation") or {}).get("timestamp")
                    except Exception:
                        pass

        if not isinstance(record.get("judge_metadata"), dict):
            record["judge_metadata"] = self._build_judge_metadata(
                use_judge=bool(record.get("use_judge")),
                run_status=str(record["status"]),
                cases=cases,
                pi_cfg=None,
                is_historical=True,
            )

        if not isinstance(record.get("case_statuses"), list):
            reconstructed = [
                {
                    "case_id": c.get("case_id"),
                    "category": c.get("category"),
                    "asi_code": _ASI_CODE_BY_POLICY_CATEGORY.get(str(c.get("category") or ""), str(c.get("category") or "")),
                    "status": "error" if c.get("verdict") == "ERROR" else "completed",
                    "stage": "completed",
                    "verdict": c.get("verdict"),
                    "reason": c.get("reason"),
                    "evidence_level": c.get("evidence_level"),
                    "run_id": c.get("run_id"),
                }
                for c in cases
                if isinstance(c, dict)
            ] + [
                {
                    "case_id": s.get("case_id"),
                    "category": s.get("category"),
                    "asi_code": s.get("asi_code") or s.get("category"),
                    "status": s.get("status", "unsupported"),
                    "stage": "skipped",
                    "verdict": None,
                    "reason": s.get("reason"),
                    "evidence_level": None,
                    "run_id": None,
                }
                for s in skipped_cases
                if isinstance(s, dict)
            ]
            record["case_statuses"] = reconstructed
        lineage_info = self._scan_lineage(run_id)
        record["child_run_ids"] = lineage_info["child_run_ids"]
        is_multi_session = len(lineage_info["lineage_run_ids"]) > 1 or bool(record.get("continuation_of_run_id"))
        if (
            is_multi_session
            or record.get("status") == "interrupted"
            or (record.get("status") == "completed" and int((record.get("verdict_counts") or {}).get("ERROR", 0)) > 0)
        ):
            cls = self._classify_resume_cases(raw, lineage_info)
            unified = self._build_unified_lineage_view(run_id, raw, record, lineage_info, cls)
            record["lineage_summary"] = unified["lineage_summary"]
            if is_multi_session:
                record["unified_lineage"] = unified["unified_lineage"]
        return record

    def _build_unified_lineage_view(
        self,
        run_id: str,
        raw: dict[str, Any],
        current_record: dict[str, Any],
        lineage_info: dict[str, Any],
        cls: dict[str, Any],
    ) -> dict[str, Any]:
        """Build read-only unified logical scan summary & deduplicated lineage view without mutating disk records."""
        lineage_docs: list[tuple[str, dict[str, Any]]] = list(lineage_info.get("lineage_docs") or [])
        if not lineage_docs:
            lineage_docs = [(run_id, raw)]
        root_id = str(lineage_info["root_run_id"])
        root_doc = lineage_info.get("root_doc") if isinstance(lineage_info.get("root_doc"), dict) else raw
        active_id = lineage_info.get("active_lineage_run_id")

        with self._lock:
            in_progress_ids = set(self._in_progress_runs.keys())

        sessions: list[dict[str, Any]] = []
        unified_cases_by_id: dict[str, dict[str, Any]] = {}
        active_case_status_by_id: dict[str, dict[str, Any]] = {}
        active_session_doc: dict[str, Any] | None = None
        total_target_req_used: int = 0
        saw_target_req_used = False
        total_judge_req_used: int = 0
        saw_judge_req_used = False
        recorded_judge_provider: str | None = None
        recorded_judge_model: str | None = None
        saw_any_judge_metadata = False

        for idx, (rid, doc) in enumerate(lineage_docs, start=1):
            raw_st = str(doc.get("status") or "completed")
            if rid in in_progress_ids:
                sess_status = "running"
            elif raw_st in {"preparing", "running"}:
                sess_status = "interrupted"
            else:
                sess_status = raw_st

            sess_cases = doc.get("cases") if isinstance(doc.get("cases"), list) else []
            sess_vc = doc.get("verdict_counts") if isinstance(doc.get("verdict_counts"), dict) else {}
            if not sess_vc and sess_cases:
                c_cnt: Counter[str] = Counter()
                for c in sess_cases:
                    if isinstance(c, dict) and isinstance(c.get("verdict"), str):
                        c_cnt[c["verdict"]] += 1
                sess_vc = dict(sorted(c_cnt.items()))

            sess_t_used = (
                int(doc["target_requests_used"])
                if isinstance(doc.get("target_requests_used"), int) and not isinstance(doc.get("target_requests_used"), bool)
                else None
            )
            sess_t_budget = (
                int(doc["target_request_budget"])
                if isinstance(doc.get("target_request_budget"), int) and not isinstance(doc.get("target_request_budget"), bool)
                else None
            )
            sess_j_used = (
                int(doc["judge_requests_used"])
                if isinstance(doc.get("judge_requests_used"), int) and not isinstance(doc.get("judge_requests_used"), bool)
                else None
            )
            sess_j_budget = (
                int(doc["judge_request_budget"])
                if isinstance(doc.get("judge_request_budget"), int) and not isinstance(doc.get("judge_request_budget"), bool)
                else None
            )
            sess_jm = doc.get("judge_metadata") if isinstance(doc.get("judge_metadata"), dict) else None
            if sess_jm is not None:
                saw_any_judge_metadata = True
                if not recorded_judge_provider and isinstance(sess_jm.get("provider"), str) and sess_jm["provider"].strip():
                    recorded_judge_provider = sess_jm["provider"].strip()
                if not recorded_judge_model and isinstance(sess_jm.get("model"), str) and sess_jm["model"].strip():
                    recorded_judge_model = sess_jm["model"].strip()

            if sess_t_used is not None:
                total_target_req_used += sess_t_used
                saw_target_req_used = True
            if sess_j_used is not None:
                total_judge_req_used += sess_j_used
                saw_judge_req_used = True

            sessions.append({
                "session_index": idx,
                "generic_run_id": rid,
                "continuation_of_run_id": doc.get("continuation_of_run_id"),
                "status": sess_status,
                "started_at": doc.get("started_at"),
                "completed_at": doc.get("completed_at") if sess_status not in {"preparing", "running"} else None,
                "selected_cases": int(doc.get("selected_cases") or len(sess_cases)),
                "ready_count": int(doc.get("ready_count") or doc.get("total_cases") or len(sess_cases)),
                "executed_cases": len(sess_cases),
                "verdict_counts": sess_vc,
                "target_requests_used": sess_t_used,
                "target_request_budget": sess_t_budget,
                "judge_requests_used": sess_j_used,
                "judge_request_budget": sess_j_budget,
                "judge_metadata": sess_jm,
                "error_code": doc.get("error_code"),
                "interrupted_reason": (
                    doc.get("interrupted_reason")
                    or ("process_restarted_before_completion" if sess_status == "interrupted" else None)
                ),
            })

            if rid == active_id or (rid == run_id and sess_status in {"preparing", "running"}):
                active_session_doc = doc
                for cs in doc.get("case_statuses") or []:
                    if isinstance(cs, dict) and isinstance(cs.get("case_id"), str):
                        active_case_status_by_id[cs["case_id"]] = cs

            for c in sess_cases:
                if not isinstance(c, dict):
                    continue
                cid = c.get("case_id")
                verdict = c.get("verdict")
                if not isinstance(cid, str) or not cid or not isinstance(verdict, str) or not verdict:
                    continue
                if cid not in unified_cases_by_id:
                    c_copy = dict(c)
                    c_copy["source_generic_run_id"] = rid
                    c_copy["session_index"] = idx
                    unified_cases_by_id[cid] = c_copy

        # R05: Strictly enforce validated root testcase scope & checkpoint integrity.
        # Never append out-of-scope cases into cumulative counts or report verified completion for an invalid lineage.
        state_incomplete = bool(cls.get("state_incomplete"))
        root_selected_ids: list[str] = list(cls.get("root_selected_ids") or [])
        root_selected_set: set[str] = set(root_selected_ids)

        out_of_scope_case_ids: list[str] = []
        if root_selected_set:
            out_of_scope_case_ids = sorted(cid for cid in unified_cases_by_id if cid not in root_selected_set)
            if out_of_scope_case_ids:
                state_incomplete = True

        ordered_case_ids: list[str] = []
        if root_selected_ids:
            seen_cids: set[str] = set()
            for cid in root_selected_ids:
                if cid in unified_cases_by_id and cid not in seen_cids:
                    ordered_case_ids.append(cid)
                    seen_cids.add(cid)
        elif not state_incomplete:
            ordered_case_ids = list(unified_cases_by_id.keys())

        unified_cases = [unified_cases_by_id[cid] for cid in ordered_case_ids]

        verdict_counter: Counter[str] = Counter()
        evidence_counter: Counter[str] = Counter()
        for c in unified_cases:
            verdict_counter[str(c["verdict"])] += 1
            ev_lvl = c.get("evidence_level")
            if isinstance(ev_lvl, str) and ev_lvl:
                evidence_counter[ev_lvl] += 1
        unified_verdict_counts = dict(sorted(verdict_counter.items()))
        unified_evidence_summary = dict(sorted(evidence_counter.items()))

        root_skipped_cases = root_doc.get("skipped_cases") if isinstance(root_doc.get("skipped_cases"), list) else []
        root_skipped_count = (
            int(root_doc["skipped_count"])
            if isinstance(root_doc.get("skipped_count"), int) and not isinstance(root_doc.get("skipped_count"), bool)
            else len(root_skipped_cases)
        )
        orig_selected = int(lineage_info.get("original_selected_cases") or len(root_selected_ids) or 0)
        root_ready_count = (
            int(root_doc["ready_count"])
            if isinstance(root_doc.get("ready_count"), int) and not isinstance(root_doc.get("ready_count"), bool)
            else max(0, orig_selected - root_skipped_count)
        )
        executed_unique = len(unified_cases)

        integrity_status = "invalid_checkpoint" if state_incomplete else "valid"
        integrity_warning: str | None = None
        if state_incomplete:
            if out_of_scope_case_ids:
                integrity_warning = (
                    f"Lineage checkpoint integrity failed (resume_state_incomplete): out-of-scope testcase(s) detected "
                    f"({', '.join(out_of_scope_case_ids[:10])}). Unified completion and export are blocked; inspect individual session reports."
                )
            else:
                integrity_warning = (
                    "Lineage checkpoint integrity failed (resume_state_incomplete): persisted testcase state is incomplete or inconsistent. "
                    "Unified completion and export are blocked; inspect individual session reports."
                )

        # Authoritative logical status distinguishing execution completion from evaluation errors and invalid checkpoints.
        latest_sess = sessions[-1] if sessions else None
        if state_incomplete:
            if active_id is not None:
                logical_status = "running"
            elif any(s["status"] == "interrupted" for s in sessions):
                logical_status = "interrupted"
            else:
                logical_status = "failed"
        elif active_id is not None:
            logical_status = "running"
        elif root_ready_count > 0 and executed_unique >= root_ready_count:
            logical_status = "completed_with_errors" if int(unified_verdict_counts.get("ERROR", 0)) > 0 else "completed"
        elif latest_sess and latest_sess["status"] in {"interrupted", "cancelled", "failed"}:
            logical_status = latest_sess["status"]
        elif any(s["status"] == "interrupted" for s in sessions):
            logical_status = "interrupted"
        else:
            logical_status = str(current_record.get("status") or "failed")

        has_remaining_cases = len(cls["pending_case_ids"]) > 0 or len(cls["uncertain_case_ids"]) > 0
        interrupted_sessions = [s["generic_run_id"] for s in sessions if s["status"] == "interrupted"]
        resumable_run_id: str | None = None
        if active_id is None and not state_incomplete and has_remaining_cases and interrupted_sessions:
            resumable_run_id = run_id if run_id in interrupted_sessions else interrupted_sessions[-1]

        has_resumable_work = resumable_run_id is not None

        # R04: Aggregated Judge metadata across deduplicated unified_cases (consistent from root or continuation).
        root_use_judge = bool(root_doc.get("use_judge", current_record.get("use_judge")))
        root_mode = str(root_doc.get("mode", current_record.get("mode") or "live"))
        has_per_case_judge_signal = any(
            isinstance(c, dict)
            and (
                "semantic_invoked" in c
                or c.get("judge_classification") is not None
                or c.get("judge_reason") is not None
                or c.get("provider_fault_code") is not None
            )
            for c in unified_cases
        )
        if not root_use_judge:
            unified_judge_metadata = self._build_judge_metadata(
                use_judge=False,
                run_status="running" if active_id is not None else "completed",
                cases=unified_cases,
                pi_cfg=None,
                is_historical=True,
            )
        elif has_per_case_judge_signal or saw_any_judge_metadata:
            unified_judge_metadata = self._build_judge_metadata(
                use_judge=True,
                run_status="running" if active_id is not None else "completed",
                cases=unified_cases,
                pi_cfg=None,
                is_historical=True,
                recorded_provider=recorded_judge_provider,
                recorded_model=recorded_judge_model,
            )
        else:
            unified_judge_metadata = None

        # Distinguish missing request counter metadata (None) from recorded zero (0).
        cumulative_target_requests_used: int | None = (
            total_target_req_used if saw_target_req_used else (0 if root_mode == "offline" else None)
        )
        cumulative_judge_requests_used: int | None = (
            total_judge_req_used
            if saw_judge_req_used
            else (
                int(unified_judge_metadata["request_count"])
                if isinstance(unified_judge_metadata, dict)
                else (0 if not root_use_judge else None)
            )
        )

        # Resolve active/latest session live progress details (CurrentTestcase & BudgetUsage).
        latest_doc = lineage_docs[-1][1] if lineage_docs else raw
        live_doc = active_session_doc if active_session_doc is not None else latest_doc
        active_sess_summary = (
            next((s for s in sessions if s["generic_run_id"] == active_id), None)
            if active_id is not None
            else latest_sess
        )
        active_current_case_id = live_doc.get("current_case_id") if active_id is not None else None
        active_current_stage = (
            live_doc.get("current_stage") if active_id is not None else logical_status
        )
        active_session_events = (
            live_doc.get("events") if isinstance(live_doc.get("events"), list) else []
        )

        # Unified case_statuses across ALL originally selected testcases in root order.
        root_row_by_id = {
            row["case_id"]: row
            for row in (root_doc.get("case_statuses") or [])
            if isinstance(row, dict) and isinstance(row.get("case_id"), str)
        }
        uncertain_set = set(cls["uncertain_case_ids"])
        skipped_set = set(cls["skipped_case_ids"])
        unified_case_statuses: list[dict[str, Any]] = []
        for cid in root_selected_ids:
            base_row = root_row_by_id.get(cid) or {}
            cat = base_row.get("category")
            asi_code = base_row.get("asi_code") or _ASI_CODE_BY_POLICY_CATEGORY.get(str(cat or ""), str(cat or ""))
            if cid in unified_cases_by_id:
                c = unified_cases_by_id[cid]
                unified_case_statuses.append({
                    "case_id": cid,
                    "category": c.get("category") or cat,
                    "asi_code": _ASI_CODE_BY_POLICY_CATEGORY.get(str(c.get("category") or ""), asi_code),
                    "status": "error" if c.get("verdict") == "ERROR" else "completed",
                    "stage": "completed",
                    "verdict": c.get("verdict"),
                    "reason": c.get("reason"),
                    "evidence_level": c.get("evidence_level"),
                    "run_id": c.get("run_id"),
                    "source_generic_run_id": c.get("source_generic_run_id"),
                    "session_index": c.get("session_index"),
                })
            elif cid in active_case_status_by_id and active_case_status_by_id[cid].get("status") == "running":
                ar = active_case_status_by_id[cid]
                unified_case_statuses.append({
                    "case_id": cid,
                    "category": ar.get("category") or cat,
                    "asi_code": ar.get("asi_code") or asi_code,
                    "status": "running",
                    "stage": ar.get("stage") or "running",
                    "verdict": None,
                    "reason": ar.get("reason"),
                    "evidence_level": None,
                    "run_id": None,
                    "source_generic_run_id": active_id or run_id,
                })
            elif cid in skipped_set:
                unified_case_statuses.append({
                    "case_id": cid,
                    "category": cat,
                    "asi_code": asi_code,
                    "status": base_row.get("status", "unsupported"),
                    "stage": "skipped",
                    "verdict": None,
                    "reason": base_row.get("reason"),
                    "evidence_level": None,
                    "run_id": None,
                })
            elif cid in uncertain_set:
                unified_case_statuses.append({
                    "case_id": cid,
                    "category": cat,
                    "asi_code": asi_code,
                    "status": "queued",
                    "stage": "interrupted",
                    "verdict": None,
                    "reason": "Interrupted in-flight before result was recorded",
                    "evidence_level": None,
                    "run_id": None,
                })
            else:
                unified_case_statuses.append({
                    "case_id": cid,
                    "category": cat,
                    "asi_code": asi_code,
                    "status": "queued",
                    "stage": "queued",
                    "verdict": None,
                    "reason": None,
                    "evidence_level": None,
                    "run_id": None,
                })

        progress_pct = (
            100
            if (not state_incomplete and logical_status in {"completed", "completed_with_errors"} and root_ready_count > 0)
            else int(round((executed_unique / max(1, root_ready_count)) * 100)) if root_ready_count > 0 else 0
        )
        started_at = root_doc.get("started_at") or (sessions[0]["started_at"] if sessions else None)
        completed_at = None if (active_id is not None or state_incomplete) else (latest_sess["completed_at"] if latest_sess else None)

        lineage_summary = {
            "root_run_id": root_id,
            "parent_run_id": lineage_info["parent_run_id"],
            "child_run_ids": lineage_info["child_run_ids"],
            "lineage_run_ids": lineage_info["lineage_run_ids"],
            "latest_run_id": sessions[-1]["generic_run_id"] if sessions else run_id,
            "active_lineage_run_id": active_id,
            "resumable_run_id": resumable_run_id,
            "logical_status": logical_status,
            "integrity_status": integrity_status,
            "integrity_warning": integrity_warning,
            "session_count": len(sessions),
            "resume_count": max(0, len(sessions) - 1),
            "started_at": started_at,
            "completed_at": completed_at,
            "original_selected_cases": orig_selected,
            "ready_count": root_ready_count,
            "skipped_count": root_skipped_count,
            "lineage_completed_count": executed_unique,
            "lineage_verdict_counts": unified_verdict_counts,
            "remaining_pending_count": len(cls["pending_case_ids"]),
            "remaining_uncertain_count": len(cls["uncertain_case_ids"]),
            "has_resumable_work": has_resumable_work,
        }

        unified_lineage = {
            "logical_scan_id": root_id,
            "root_run_id": root_id,
            "latest_run_id": sessions[-1]["generic_run_id"] if sessions else run_id,
            "active_session_run_id": active_id,
            "resumable_run_id": resumable_run_id,
            "logical_status": logical_status,
            "integrity_status": integrity_status,
            "integrity_warning": integrity_warning,
            "out_of_scope_case_ids": out_of_scope_case_ids,
            "execution_completed": (
                not state_incomplete
                and root_ready_count > 0
                and executed_unique >= root_ready_count
                and active_id is None
            ),
            "has_evaluation_errors": int(unified_verdict_counts.get("ERROR", 0)) > 0,
            "started_at": started_at,
            "completed_at": completed_at,
            "session_count": len(sessions),
            "resume_count": max(0, len(sessions) - 1),
            "selected_cases": orig_selected,
            "ready_count": root_ready_count,
            "executed_cases": executed_unique,
            "skipped_count": root_skipped_count,
            "skipped_cases": root_skipped_cases,
            "progress_percent": progress_pct,
            "verdict_counts": unified_verdict_counts,
            "evidence_summary": unified_evidence_summary,
            "judge_metadata": unified_judge_metadata,
            "target_requests_used": cumulative_target_requests_used,
            "judge_requests_used": cumulative_judge_requests_used,
            "current_case_id": active_current_case_id,
            "current_stage": active_current_stage,
            "active_session_started_at": active_sess_summary["started_at"] if active_sess_summary else None,
            "active_session_target_requests_used": active_sess_summary["target_requests_used"] if active_sess_summary else None,
            "active_session_target_request_budget": active_sess_summary["target_request_budget"] if active_sess_summary else None,
            "active_session_judge_requests_used": active_sess_summary["judge_requests_used"] if active_sess_summary else None,
            "active_session_judge_request_budget": active_sess_summary["judge_request_budget"] if active_sess_summary else None,
            "active_session_events": active_session_events,
            "sessions": sessions,
            "case_statuses": unified_case_statuses,
            "cases": unified_cases,
        }
        return {"lineage_summary": lineage_summary, "unified_lineage": unified_lineage}

    def get_unified_report(self, run_id: str) -> dict[str, Any] | None:
        """Build a read-only unified lineage report JSON without modifying historical artifacts."""
        record = self.get_run(run_id)
        if record is None:
            return None
        raw = self._read_raw_run_disk(run_id)
        if raw is None:
            return None
        lineage_info = self._scan_lineage(run_id)
        cls = self._classify_resume_cases(raw, lineage_info)
        built = self._build_unified_lineage_view(run_id, raw, record, lineage_info, cls)
        ul = built["unified_lineage"]
        if ul.get("integrity_status") != "valid":
            raise ValueError("unified_report_integrity_failed")
        root_doc = lineage_info.get("root_doc") if isinstance(lineage_info.get("root_doc"), dict) else raw
        return {
            "workflow_schema_version": "1.0.0",
            "report_kind": "unified_generic_scan_lineage",
            "logical_scan_id": ul["logical_scan_id"],
            "root_run_id": ul["root_run_id"],
            "requested_run_id": run_id,
            "latest_run_id": ul["latest_run_id"],
            "logical_status": ul["logical_status"],
            "integrity_status": ul["integrity_status"],
            "execution_completed": ul["execution_completed"],
            "has_evaluation_errors": ul["has_evaluation_errors"],
            "mode": root_doc.get("mode", record.get("mode")),
            "target_id": root_doc.get("target_id", record.get("target_id")),
            "target_name": root_doc.get("target_name", record.get("target_name")),
            "target_revision_sha256": root_doc.get("target_revision_sha256"),
            "dataset_id": root_doc.get("dataset_id", record.get("dataset_id")),
            "dataset_name": root_doc.get("dataset_name", record.get("dataset_name")),
            "dataset_revision_sha256": root_doc.get("dataset_revision_sha256"),
            "asi_category": root_doc.get("asi_category", record.get("asi_category")),
            "use_judge": bool(root_doc.get("use_judge", record.get("use_judge"))),
            "started_at": ul["started_at"],
            "completed_at": ul["completed_at"],
            "selected_cases": ul["selected_cases"],
            "ready_count": ul["ready_count"],
            "skipped_count": ul["skipped_count"],
            "recorded_outcomes": ul["executed_cases"],
            "verdict_counts": ul["verdict_counts"],
            "evidence_summary": ul["evidence_summary"],
            "target_requests_used": ul["target_requests_used"],
            "judge_requests_used": ul["judge_requests_used"],
            "judge_metadata": ul["judge_metadata"],
            "session_count": ul["session_count"],
            "resume_count": ul["resume_count"],
            "sessions": ul["sessions"],
            "skipped_cases": ul["skipped_cases"],
            "cases": ul["cases"],
        }

    def _read_raw_run_disk(self, run_id: str) -> dict[str, Any] | None:
        if not _HEX32_RE.fullmatch(run_id):
            return None
        path = self.runs_root / run_id / "generic-run.json"
        with self._lock:
            if not path.is_file():
                return None
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return None
        return raw if isinstance(raw, dict) else None

    def _scan_lineage(self, run_id: str, *, ignore_root_lock: bool = False) -> dict[str, Any]:
        raw_by_id: dict[str, dict[str, Any]] = {}
        with self._lock:
            if self.runs_root.is_dir():
                for entry in self.runs_root.iterdir():
                    if not entry.is_dir() or not _HEX32_RE.fullmatch(entry.name):
                        continue
                    path = entry / "generic-run.json"
                    if not path.is_file():
                        continue
                    try:
                        doc = json.loads(path.read_text(encoding="utf-8"))
                    except Exception:
                        continue
                    if isinstance(doc, dict):
                        raw_by_id[entry.name] = doc
            in_progress_ids = set(self._in_progress_runs.keys())
            active_resumes = dict(self._active_resumes_by_root)

        def _resolve_root(rid: str) -> str:
            cur = rid
            seen: set[str] = set()
            while cur in raw_by_id and cur not in seen:
                seen.add(cur)
                doc = raw_by_id[cur]
                explicit_root = doc.get("root_run_id")
                if isinstance(explicit_root, str) and _HEX32_RE.fullmatch(explicit_root):
                    return explicit_root
                parent = doc.get("continuation_of_run_id")
                if isinstance(parent, str) and _HEX32_RE.fullmatch(parent) and parent != cur:
                    cur = parent
                    continue
                break
            return cur

        root_id = _resolve_root(run_id)
        self_raw = raw_by_id.get(run_id) or {}
        parent_id = (
            self_raw.get("continuation_of_run_id")
            if isinstance(self_raw.get("continuation_of_run_id"), str)
            else None
        )
        lineage_ids = [rid for rid in raw_by_id if _resolve_root(rid) == root_id]
        lineage_ids.sort(key=lambda rid: (str(raw_by_id[rid].get("started_at") or ""), rid))
        child_ids = [
            rid
            for rid in lineage_ids
            if raw_by_id[rid].get("continuation_of_run_id") == run_id
        ]

        active_lineage_run_id: str | None = None
        for rid in lineage_ids:
            if rid in in_progress_ids:
                active_lineage_run_id = rid
                break
        if active_lineage_run_id is None and not ignore_root_lock:
            locked_val = active_resumes.get(root_id)
            if isinstance(locked_val, str) and locked_val:
                active_lineage_run_id = locked_val

        lineage_completed_by_case_id: dict[str, dict[str, Any]] = {}
        verdict_counter: Counter[str] = Counter()
        for rid in lineage_ids:
            doc = raw_by_id[rid]
            for c in doc.get("cases") or []:
                if not isinstance(c, dict):
                    continue
                cid = c.get("case_id")
                verdict = c.get("verdict")
                if not isinstance(cid, str) or not cid or not isinstance(verdict, str) or not verdict:
                    continue
                if cid not in lineage_completed_by_case_id:
                    lineage_completed_by_case_id[cid] = {
                        "case_id": cid,
                        "verdict": verdict,
                        "run_id": c.get("run_id"),
                        "generic_run_id": rid,
                        "report_path": c.get("report_path"),
                        "category": c.get("category"),
                    }
                    verdict_counter[verdict] += 1

        root_doc = raw_by_id.get(root_id)
        root_statuses = root_doc.get("case_statuses") if (isinstance(root_doc, dict) and isinstance(root_doc.get("case_statuses"), list)) else []
        orig_selected = (
            int(root_doc["selected_cases"])
            if isinstance(root_doc, dict) and isinstance(root_doc.get("selected_cases"), int) and not isinstance(root_doc.get("selected_cases"), bool)
            else len(root_statuses)
        )
        lineage_docs = [(rid, raw_by_id[rid]) for rid in lineage_ids]
        return {
            "root_run_id": root_id,
            "root_doc": root_doc,
            "parent_run_id": parent_id,
            "child_run_ids": child_ids,
            "lineage_run_ids": lineage_ids,
            "lineage_docs": lineage_docs,
            "active_lineage_run_id": active_lineage_run_id,
            "lineage_completed_by_case_id": lineage_completed_by_case_id,
            "lineage_verdict_counts": dict(sorted(verdict_counter.items())),
            "original_selected_cases": orig_selected,
        }

    @staticmethod
    def _validate_run_checkpoint(doc: dict[str, Any]) -> dict[str, Any]:
        """Validate a single persisted generic-run.json checkpoint fail-closed."""
        valid_statuses = {"queued", "running", "completed", "error", "unsupported", "blocked"}
        valid_verdicts = {"PASS", "FAIL", "INCONCLUSIVE", "ERROR"}

        if not isinstance(doc, dict):
            return {"valid": False}

        raw_statuses = doc.get("case_statuses")
        expected_selected = doc.get("selected_cases")
        if (
            not isinstance(raw_statuses, list)
            or not raw_statuses
            or not isinstance(expected_selected, int)
            or isinstance(expected_selected, bool)
            or expected_selected <= 0
        ):
            return {"valid": False}

        unique_ids: list[str] = []
        status_by_id: dict[str, dict[str, Any]] = {}
        for row in raw_statuses:
            if not isinstance(row, dict):
                return {"valid": False}
            cid = row.get("case_id")
            st = row.get("status")
            stage = row.get("stage")
            if (
                not isinstance(cid, str)
                or not cid
                or cid.strip() != cid
                or cid in status_by_id
                or not isinstance(st, str)
                or st not in valid_statuses
            ):
                return {"valid": False}
            if stage is not None and not isinstance(stage, str):
                return {"valid": False}
            unique_ids.append(cid)
            status_by_id[cid] = row

        if len(unique_ids) != expected_selected:
            return {"valid": False}

        raw_cases = doc.get("cases")
        if not isinstance(raw_cases, list):
            return {"valid": False}
        completed_in_doc: dict[str, dict[str, Any]] = {}
        for c in raw_cases:
            if not isinstance(c, dict):
                return {"valid": False}
            cid = c.get("case_id")
            verdict = c.get("verdict")
            if (
                not isinstance(cid, str)
                or not cid
                or cid.strip() != cid
                or cid in completed_in_doc
                or cid not in status_by_id
                or not isinstance(verdict, str)
                or verdict not in valid_verdicts
            ):
                return {"valid": False}
            completed_in_doc[cid] = c

        executed_cases = doc.get("executed_cases")
        if executed_cases is not None:
            if (
                not isinstance(executed_cases, int)
                or isinstance(executed_cases, bool)
                or executed_cases != len(raw_cases)
            ):
                return {"valid": False}

        skipped_ids: set[str] = set()
        raw_skipped = doc.get("skipped_cases")
        if raw_skipped is not None:
            if not isinstance(raw_skipped, list):
                return {"valid": False}
            for s in raw_skipped:
                if not isinstance(s, dict):
                    return {"valid": False}
                scid = s.get("case_id")
                if not isinstance(scid, str) or not scid or scid not in status_by_id:
                    return {"valid": False}
                skipped_ids.add(scid)

        dispatched_ids: set[str] = set()
        for cid, row in status_by_id.items():
            st = str(row["status"])
            stage = str(row.get("stage") or "")
            if st in {"unsupported", "blocked"} or stage == "skipped":
                skipped_ids.add(cid)
            elif st == "running":
                dispatched_ids.add(cid)
            elif st in {"completed", "error"} and cid not in completed_in_doc:
                # Status claims terminal completion without a persisted result -> uncertain, never pending.
                dispatched_ids.add(cid)
            elif st == "queued" and stage not in {"", "queued"}:
                dispatched_ids.add(cid)

        curr_cid = doc.get("current_case_id")
        if curr_cid is not None:
            if not isinstance(curr_cid, str) or not curr_cid or curr_cid not in status_by_id:
                return {"valid": False}
            curr_stage = str(doc.get("current_stage") or "")
            if curr_stage not in {"", "queued"}:
                dispatched_ids.add(curr_cid)

        raw_events = doc.get("events")
        if raw_events is not None:
            if not isinstance(raw_events, list):
                return {"valid": False}
            for ev in raw_events:
                if not isinstance(ev, dict):
                    return {"valid": False}
                ev_cid = ev.get("case_id")
                ev_stage = str(ev.get("stage") or "")
                if isinstance(ev_cid, str) and ev_cid:
                    if ev_cid not in status_by_id:
                        return {"valid": False}
                    if ev_stage not in {"", "queued", "skipped"}:
                        dispatched_ids.add(ev_cid)

        return {
            "valid": True,
            "unique_ids": unique_ids,
            "status_by_id": status_by_id,
            "skipped_ids": skipped_ids,
            "dispatched_ids": dispatched_ids,
            "completed_in_doc": completed_in_doc,
        }

    @classmethod
    def _classify_resume_cases(
        cls,
        parent_raw: dict[str, Any],
        lineage_info: dict[str, Any],
    ) -> dict[str, Any]:
        """Authoritatively classify cases across the entire root lineage in original root order."""
        root_doc = lineage_info.get("root_doc")
        lineage_docs: list[tuple[str, dict[str, Any]]] = list(lineage_info.get("lineage_docs") or [])
        if not isinstance(root_doc, dict):
            return {
                "completed_case_ids": [],
                "completed_cases_summary": [],
                "pending_case_ids": [],
                "uncertain_case_ids": [],
                "skipped_case_ids": [],
                "root_selected_ids": [],
                "state_incomplete": True,
            }

        root_chk = cls._validate_run_checkpoint(root_doc)
        if not root_chk["valid"]:
            return {
                "completed_case_ids": [],
                "completed_cases_summary": [],
                "pending_case_ids": [],
                "uncertain_case_ids": [],
                "skipped_case_ids": [],
                "root_selected_ids": [],
                "state_incomplete": True,
            }

        root_selected_ids: list[str] = list(root_chk["unique_ids"])
        root_selected_set: set[str] = set(root_selected_ids)
        root_skipped_ids: set[str] = set(root_chk["skipped_ids"])

        # Validate every lineage member checkpoint and aggregate completed & dispatched/uncertain states across the lineage.
        state_incomplete = False
        completed_map: dict[str, dict[str, Any]] = {}
        lineage_dispatched_ids: set[str] = set()

        parent_rid = str(parent_raw.get("generic_run_id") or "")
        docs_to_check = list(lineage_docs)
        if parent_rid and all(rid != parent_rid for rid, _ in docs_to_check):
            docs_to_check.append((parent_rid, parent_raw))

        for rid, doc in docs_to_check:
            chk = root_chk if doc is root_doc else cls._validate_run_checkpoint(doc)
            if not chk["valid"]:
                state_incomplete = True
                continue
            # Every continuation member's cases must remain strictly inside the root run's original scope.
            if not set(chk["unique_ids"]).issubset(root_selected_set):
                state_incomplete = True
                continue
            lineage_dispatched_ids.update(chk["dispatched_ids"])
            for cid, c in chk["completed_in_doc"].items():
                if cid not in completed_map:
                    completed_map[cid] = {
                        "case_id": cid,
                        "verdict": c["verdict"],
                        "run_id": c.get("run_id"),
                        "generic_run_id": rid,
                        "report_path": c.get("report_path"),
                        "category": c.get("category"),
                    }

        if state_incomplete:
            return {
                "completed_case_ids": [cid for cid in root_selected_ids if cid in completed_map],
                "completed_cases_summary": [completed_map[cid] for cid in root_selected_ids if cid in completed_map],
                "pending_case_ids": [],
                "uncertain_case_ids": [],
                "skipped_case_ids": [],
                "root_selected_ids": root_selected_ids,
                "state_incomplete": True,
            }

        completed_case_ids: list[str] = []
        completed_cases_summary: list[dict[str, Any]] = []
        pending_case_ids: list[str] = []
        uncertain_case_ids: list[str] = []
        skipped_case_ids: list[str] = []

        # Preserve exact original root testcase order.
        # Precedence across lineage: Completed > Uncertain (dispatched in ANY lineage run) > Skipped > Definitely Pending.
        for cid in root_selected_ids:
            if cid in completed_map:
                completed_case_ids.append(cid)
                completed_cases_summary.append(completed_map[cid])
            elif cid in lineage_dispatched_ids:
                uncertain_case_ids.append(cid)
            elif cid in root_skipped_ids:
                skipped_case_ids.append(cid)
            else:
                pending_case_ids.append(cid)

        return {
            "completed_case_ids": completed_case_ids,
            "completed_cases_summary": completed_cases_summary,
            "pending_case_ids": pending_case_ids,
            "uncertain_case_ids": uncertain_case_ids,
            "skipped_case_ids": skipped_case_ids,
            "root_selected_ids": root_selected_ids,
            "state_incomplete": False,
        }

    def preview_resume(
        self,
        parent_run_id: str,
        payload: dict[str, Any] | None = None,
        *,
        _ignore_root_lock: bool = False,
    ) -> dict[str, Any]:
        """Read-only Resume Preview for an interrupted Generic Scan run (0 Target / 0 Judge requests)."""
        if not _HEX32_RE.fullmatch(parent_run_id):
            raise ValueError("generic_run_not_found")
        parent_record = self.get_run(parent_run_id)
        parent_raw = self._read_raw_run_disk(parent_run_id)
        if parent_record is None or parent_raw is None:
            raise ValueError("generic_run_not_found")

        req = payload if isinstance(payload, dict) else {}
        lineage_info = self._scan_lineage(parent_run_id, ignore_root_lock=_ignore_root_lock)
        cls = self._classify_resume_cases(parent_raw, lineage_info)

        raw_inc = req.get("include_uncertain_case_ids")
        included_uncertain: list[str] = []
        if raw_inc is not None:
            if not isinstance(raw_inc, list) or not all(isinstance(x, str) and x.strip() for x in raw_inc):
                raise ValueError("generic_resume_invalid_uncertain_selection")
            uncertain_set = set(cls["uncertain_case_ids"])
            for x in raw_inc:
                cid = x.strip()
                if cid not in uncertain_set:
                    raise ValueError("generic_resume_invalid_uncertain_selection")
                if cid not in included_uncertain:
                    included_uncertain.append(cid)

        pending_case_ids: list[str] = list(cls["pending_case_ids"])
        uncertain_case_ids: list[str] = list(cls["uncertain_case_ids"])
        selected_set = set(pending_case_ids) | set(included_uncertain)
        root_selected_ids: list[str] = list(cls.get("root_selected_ids") or [])
        selected_resume_case_ids: list[str] = (
            [cid for cid in root_selected_ids if cid in selected_set]
            if root_selected_ids
            else (list(pending_case_ids) + [cid for cid in included_uncertain if cid not in pending_case_ids])
        )

        blockers: list[str] = []

        def _add_blocker(code: str) -> None:
            if code and code not in blockers:
                blockers.append(code)

        if parent_record.get("status") != "interrupted":
            _add_blocker("generic_resume_not_interrupted")
        if lineage_info["active_lineage_run_id"] is not None:
            _add_blocker("generic_resume_already_active")
        if cls["state_incomplete"]:
            _add_blocker("resume_state_incomplete")
        if not cls["state_incomplete"] and not pending_case_ids and not uncertain_case_ids:
            _add_blocker("generic_resume_no_remaining_cases")

        mode = str(parent_raw.get("mode") or "offline")
        target_id = str(parent_raw.get("target_id") or "")
        asi_category = str(parent_raw.get("asi_category") or "auto")
        use_judge = bool(parent_raw.get("use_judge", False))
        policy_id = parent_raw.get("policy_id")
        parent_cap_states = (
            parent_raw.get("capability_states")
            if isinstance(parent_raw.get("capability_states"), dict)
            else None
        )
        dataset_id = parent_raw.get("dataset_id") if isinstance(parent_raw.get("dataset_id"), str) else None
        dataset_name = parent_raw.get("dataset_name")
        parent_dataset_rev = parent_raw.get("dataset_revision_sha256")
        dataset_consistent = False
        env = None
        if not dataset_id or self.dataset_repo is None:
            _add_blocker("resume_dataset_not_found")
        else:
            env = self.dataset_repo.get_dataset(dataset_id)
            if env is None:
                _add_blocker("resume_dataset_not_found")
            else:
                dataset_name = env.name
                available_tc_ids = {tc.testcase_id for tc in env.testcases}
                needed_ids = list(dict.fromkeys(pending_case_ids + uncertain_case_ids))
                if not isinstance(parent_dataset_rev, str) or not _HEX64_RE.fullmatch(parent_dataset_rev):
                    _add_blocker("resume_dataset_revision_missing")
                else:
                    rev_ok = env.file_sha256 == parent_dataset_rev
                    ids_ok = all(cid in available_tc_ids for cid in needed_ids)
                    if not rev_ok or not ids_ok:
                        _add_blocker("resume_dataset_mismatch")
                    else:
                        dataset_consistent = True

        target = None
        target_name = str(parent_raw.get("target_name") or target_id)
        target_consistent = False
        auth_binding: dict[str, Any] = {
            "target_revision_sha256": None,
            "auth_source": "none",
            "session_credential_ref": None,
            "session_credential_generation": None,
            "session_auth_type": None,
            "session_auth_header": None,
        }
        credential_availability = "not_required"
        try:
            target = self._resolve_target(
                mode=mode,
                target_id=target_id,
                capability_states=parent_cap_states,
                for_execution=True,
            )
            target_name = target.name
            auth_binding = self._resolve_target_auth_binding(mode=mode, target=target)
            parent_target_rev = parent_raw.get("target_revision_sha256")
            if mode == "live":
                if not isinstance(parent_target_rev, str) or not _HEX64_RE.fullmatch(parent_target_rev):
                    _add_blocker("resume_target_revision_missing")
                elif auth_binding["target_revision_sha256"] != parent_target_rev:
                    _add_blocker("resume_target_configuration_changed")
                else:
                    target_consistent = True
            else:
                target_consistent = True

            if mode == "live":
                if auth_binding["auth_source"] == "session_memory":
                    credential_availability = (
                        "available" if auth_binding["session_credential_generation"] else "unavailable"
                    )
                elif auth_binding["auth_source"] == "env_alias":
                    credential_availability = (
                        "available"
                        if all(bool(os.environ.get(ref)) for ref in (target.credential_refs or []))
                        else "unavailable"
                    )
                else:
                    credential_availability = "not_required"
                if credential_availability == "unavailable":
                    _add_blocker("credential_unavailable")
        except ValueError as exc:
            if str(exc) == "generic_target_not_found":
                _add_blocker("resume_target_not_found")
            else:
                _add_blocker("resume_target_configuration_changed")

        config_consistent = dataset_consistent and target_consistent

        # R02: Bind & validate Judge provider/model consistency for Hybrid runs.
        current_judge_status = self.judge_status()
        curr_judge_provider = current_judge_status.get("provider") if use_judge else None
        curr_judge_model = current_judge_status.get("model") if use_judge else None
        orig_judge_provider: str | None = None
        orig_judge_model: str | None = None
        if use_judge:
            root_doc = lineage_info.get("root_doc") if isinstance(lineage_info.get("root_doc"), dict) else None
            parent_jm = parent_raw.get("judge_metadata") if isinstance(parent_raw.get("judge_metadata"), dict) else {}
            root_jm = root_doc.get("judge_metadata") if (isinstance(root_doc, dict) and isinstance(root_doc.get("judge_metadata"), dict)) else {}
            raw_jp = parent_jm.get("provider") or root_jm.get("provider")
            raw_jm = parent_jm.get("model") or root_jm.get("model")
            orig_judge_provider = raw_jp.strip() if isinstance(raw_jp, str) and raw_jp.strip() else None
            orig_judge_model = raw_jm.strip() if isinstance(raw_jm, str) and raw_jm.strip() else None
            if not orig_judge_provider or not orig_judge_model:
                config_consistent = False
                _add_blocker("resume_judge_configuration_missing")
            elif current_judge_status.get("judge_ready") and (
                curr_judge_provider != orig_judge_provider or curr_judge_model != orig_judge_model
            ):
                config_consistent = False
                _add_blocker("resume_judge_configuration_changed")

        preview_meta: dict[str, Any] | None = None
        target_request_budget = 0
        judge_request_budget = 0
        probe_case_ids = selected_resume_case_ids if selected_resume_case_ids else list(uncertain_case_ids)
        if env is not None and target is not None and dataset_consistent and probe_case_ids:
            try:
                raw_cases = self._extract_raw_cases({"dataset_id": dataset_id, "testcase_ids": probe_case_ids})
                _, preview_meta = self._build_cases(
                    mode=mode,
                    target=target,
                    asi_category=asi_category,
                    raw_cases=raw_cases,
                    use_judge=use_judge,
                    policy_id=policy_id,
                )

                # R02: Strict Policy consistency (distinguish legitimate None absence vs missing history vs drift).
                has_hist_policy_rev = "policy_revision_sha256" in parent_raw
                hist_policy_id = parent_raw.get("policy_id")
                hist_policy_rev = parent_raw.get("policy_revision_sha256")
                curr_policy_id = preview_meta.get("policy_id")
                curr_policy_rev = preview_meta.get("policy_revision_sha256")
                if hist_policy_id is not None and (
                    not isinstance(hist_policy_rev, str) or not _HEX64_RE.fullmatch(hist_policy_rev)
                ):
                    config_consistent = False
                    _add_blocker("resume_configuration_incomplete")
                elif not has_hist_policy_rev:
                    if curr_policy_rev is not None or curr_policy_id is not None or use_judge:
                        config_consistent = False
                        _add_blocker("resume_configuration_incomplete")
                else:
                    if hist_policy_rev is not None and (
                        not isinstance(hist_policy_rev, str) or not _HEX64_RE.fullmatch(hist_policy_rev)
                    ):
                        config_consistent = False
                        _add_blocker("resume_configuration_incomplete")
                    elif (
                        (hist_policy_rev is None) != (curr_policy_rev is None)
                        or hist_policy_rev != curr_policy_rev
                        or hist_policy_id != curr_policy_id
                    ):
                        config_consistent = False
                        _add_blocker("resume_policy_changed")
                    elif isinstance(parent_raw.get("reviewed_policies"), list):
                        hist_by_cat = {
                            p.get("category"): (p.get("policy_id"), p.get("revision_sha256"))
                            for p in parent_raw["reviewed_policies"]
                            if isinstance(p, dict) and p.get("category")
                        }
                        curr_by_cat = {
                            p.get("category"): (p.get("policy_id"), p.get("revision_sha256"))
                            for p in (preview_meta.get("reviewed_policies") or [])
                            if isinstance(p, dict) and p.get("category")
                        }
                        rem_cats = {
                            item.get("category")
                            for item in (preview_meta.get("items") or [])
                            if isinstance(item, dict) and item.get("category")
                        }
                        for cat in rem_cats:
                            if hist_by_cat.get(cat) != curr_by_cat.get(cat):
                                config_consistent = False
                                _add_blocker("resume_policy_changed")
                                break

                # R02: Strict Application Context consistency (detect absent->configured, configured->absent, revision change, or missing history).
                has_hist_ctx_rev = "application_context_revision_sha256" in parent_raw
                hist_ctx_id = parent_raw.get("application_context_id")
                hist_ctx_rev = parent_raw.get("application_context_revision_sha256")
                curr_ctx_id = preview_meta.get("application_context_id")
                curr_ctx_rev = preview_meta.get("application_context_revision_sha256")
                if hist_ctx_id is not None and (
                    not isinstance(hist_ctx_rev, str) or not _HEX64_RE.fullmatch(hist_ctx_rev)
                ):
                    config_consistent = False
                    _add_blocker("resume_configuration_incomplete")
                elif not has_hist_ctx_rev:
                    if curr_ctx_rev is not None or curr_ctx_id is not None or use_judge:
                        config_consistent = False
                        _add_blocker("resume_configuration_incomplete")
                else:
                    if hist_ctx_rev is not None and (
                        not isinstance(hist_ctx_rev, str) or not _HEX64_RE.fullmatch(hist_ctx_rev)
                    ):
                        config_consistent = False
                        _add_blocker("resume_configuration_incomplete")
                    elif (
                        (hist_ctx_rev is None) != (curr_ctx_rev is None)
                        or hist_ctx_rev != curr_ctx_rev
                        or ("application_context_id" in parent_raw and hist_ctx_id != curr_ctx_id)
                    ):
                        config_consistent = False
                        _add_blocker("resume_application_context_changed")

                if preview_meta.get("blocker"):
                    _add_blocker(str(preview_meta["blocker"]))
                if selected_resume_case_ids:
                    ready_n = int(preview_meta.get("ready_count") or 0)
                    target_request_budget = ready_n if mode == "live" else 0
                    judge_request_budget = ready_n if use_judge else 0
            except ValueError as exc:
                _add_blocker(str(exc))

        if not selected_resume_case_ids and uncertain_case_ids:
            _add_blocker("generic_resume_no_cases_selected")

        blocker = blockers[0] if blockers else None
        eligible = blocker is None and len(selected_resume_case_ids) > 0

        warnings: list[str] = []
        if mode == "live":
            warnings.append(
                "Stateful target notice: previously completed or interrupted testcases may have modified target application state. Restarting containers or services does not automatically restore baseline state."
            )
        if uncertain_case_ids:
            if included_uncertain:
                warnings.append(
                    f"Uncertain in-flight testcase(s) opted in ({', '.join(included_uncertain)}): the previous request may already have executed on the target before interruption. Verify remote execution state before confirming."
                )
            else:
                warnings.append(
                    f"Uncertain in-flight testcase(s) excluded by default ({', '.join(uncertain_case_ids)}): execution started before interruption with no completed result. Opt in explicitly only after checking target state."
                )

        digest_material = {
            "parent_run_id": parent_run_id,
            "root_run_id": lineage_info["root_run_id"],
            "mode": mode,
            "target_id": target_id,
            "target_revision_sha256": auth_binding["target_revision_sha256"],
            "dataset_id": dataset_id,
            "dataset_revision_sha256": env.file_sha256 if env is not None else parent_dataset_rev,
            "asi_category": asi_category,
            "use_judge": use_judge,
            "judge_provider": curr_judge_provider if use_judge else None,
            "judge_model": curr_judge_model if use_judge else None,
            "policy_id": preview_meta.get("policy_id") if preview_meta else policy_id,
            "policy_revision_sha256": preview_meta.get("policy_revision_sha256") if preview_meta else parent_raw.get("policy_revision_sha256"),
            "application_context_id": preview_meta.get("application_context_id") if preview_meta else parent_raw.get("application_context_id"),
            "application_context_revision_sha256": preview_meta.get("application_context_revision_sha256") if preview_meta else parent_raw.get("application_context_revision_sha256"),
            "selected_resume_case_ids": selected_resume_case_ids,
            "included_uncertain_case_ids": included_uncertain,
            "session_credential_generation": auth_binding["session_credential_generation"],
        }
        resume_digest = sha256(json.dumps(digest_material, sort_keys=True, default=str).encode("utf-8")).hexdigest()

        return {
            "workflow_schema_version": "1.0.0",
            "parent_run_id": parent_run_id,
            "root_run_id": lineage_info["root_run_id"],
            "parent_status": parent_record.get("status"),
            "original_selected_cases": lineage_info["original_selected_cases"],
            "completed_count": len(cls["completed_case_ids"]),
            "completed_case_ids": cls["completed_case_ids"],
            "completed_cases_summary": cls["completed_cases_summary"],
            "pending_case_ids": pending_case_ids,
            "uncertain_case_ids": uncertain_case_ids,
            "included_uncertain_case_ids": included_uncertain,
            "skipped_case_ids": cls["skipped_case_ids"],
            "selected_resume_case_ids": selected_resume_case_ids,
            "target_id": target_id,
            "target_name": target_name,
            "target_revision_sha256": auth_binding["target_revision_sha256"],
            "target_ready": target_consistent and credential_availability != "unavailable",
            "auth_source": auth_binding["auth_source"],
            "credential_availability": credential_availability,
            "session_credential_generation": auth_binding["session_credential_generation"],
            "session_auth_type": auth_binding["session_auth_type"],
            "session_auth_header": auth_binding["session_auth_header"],
            "dataset_id": dataset_id,
            "dataset_name": dataset_name,
            "dataset_consistent": dataset_consistent,
            "config_consistent": config_consistent,
            "mode": mode,
            "asi_category": asi_category,
            "use_judge": use_judge,
            "original_judge_provider": orig_judge_provider,
            "original_judge_model": orig_judge_model,
            "current_judge_provider": curr_judge_provider,
            "current_judge_model": curr_judge_model,
            "judge_status": current_judge_status,
            "target_request_budget": target_request_budget,
            "judge_request_budget": judge_request_budget,
            "resume_digest": resume_digest,
            "eligible": eligible,
            "blocker": blocker,
            "blockers": blockers,
            "warnings": warnings,
        }

    def start_resume(self, parent_run_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Start a linked continuation run for an interrupted Generic Scan run."""
        if not isinstance(payload, dict):
            raise ValueError("generic_run_rejected")
        if payload.get("authorization_confirmed") is not True:
            raise ValueError("generic_authorization_required")
        if not _HEX32_RE.fullmatch(parent_run_id):
            raise ValueError("generic_run_not_found")
        parent_raw = self._read_raw_run_disk(parent_run_id)
        if parent_raw is None:
            raise ValueError("generic_run_not_found")

        expected_resume_digest = payload.get("expected_resume_digest")
        if not isinstance(expected_resume_digest, str) or not _HEX64_RE.fullmatch(expected_resume_digest):
            raise ValueError("generic_resume_digest_stale")

        raw_inc = payload.get("include_uncertain_case_ids")
        include_uncertain: list[str] = []
        if raw_inc is not None:
            if not isinstance(raw_inc, list) or not all(isinstance(x, str) and x.strip() for x in raw_inc):
                raise ValueError("generic_resume_invalid_uncertain_selection")
            include_uncertain = list(dict.fromkeys(x.strip() for x in raw_inc))
        if include_uncertain and payload.get("uncertain_reexecution_confirmed") is not True:
            raise ValueError("generic_resume_uncertain_confirmation_required")

        submission_id_raw = payload.get("submission_id")
        submission_id: str | None = None
        if submission_id_raw is not None:
            submission_id = str(submission_id_raw).strip()
            if not _HEX32_RE.fullmatch(submission_id):
                raise ValueError("generic_invalid_submission_id")
            sub_file = self.runs_root / "submissions" / f"{submission_id}.json"
            with self._lock:
                has_sub = sub_file.is_file()
            if has_sub:
                try:
                    sub_doc = json.loads(sub_file.read_text(encoding="utf-8"))
                except Exception as exc:
                    raise ValueError("generic_submission_record_unavailable") from exc
                existing_id = str(sub_doc.get("generic_run_id") or "")
                existing_rec = self.get_run(existing_id) if existing_id else None
                if existing_rec is None:
                    raise ValueError("generic_submission_record_unavailable")
                ex_meta = existing_rec.get("resume_metadata") if isinstance(existing_rec.get("resume_metadata"), dict) else {}
                if (
                    existing_rec.get("continuation_of_run_id") != parent_run_id
                    or ex_meta.get("resume_digest") != expected_resume_digest
                ):
                    raise ValueError("generic_submission_conflict")
                return existing_rec

        lineage_info = self._scan_lineage(parent_run_id)
        root_run_id = lineage_info["root_run_id"]

        with self._lock:
            if lineage_info["active_lineage_run_id"] is not None or root_run_id in self._active_resumes_by_root:
                raise ValueError("generic_resume_already_active")
            self._active_resumes_by_root[root_run_id] = "reserving"

        lock_transferred = False
        try:
            preview = self.preview_resume(
                parent_run_id,
                {"include_uncertain_case_ids": include_uncertain},
                _ignore_root_lock=True,
            )
            if preview["mode"] == "live" and payload.get("stateful_target_acknowledged") is not True:
                raise ValueError("generic_resume_stateful_acknowledgement_required")
            if preview["blocker"] is not None or not preview["eligible"]:
                raise ValueError(preview["blocker"] or "generic_resume_not_eligible")
            if expected_resume_digest != preview["resume_digest"]:
                raise ValueError("generic_resume_digest_stale")

            expected_target_revision = (
                payload.get("expected_target_revision")
                if "expected_target_revision" in payload
                else preview["target_revision_sha256"]
            )
            expected_session_gen = (
                payload.get("expected_session_credential_generation")
                if "expected_session_credential_generation" in payload
                else preview["session_credential_generation"]
            )
            start_payload: dict[str, Any] = {
                "authorization_confirmed": True,
                "mode": preview["mode"],
                "target_id": preview["target_id"],
                "dataset_id": preview["dataset_id"],
                "testcase_ids": list(preview["selected_resume_case_ids"]),
                "asi_category": preview["asi_category"],
                "use_judge": preview["use_judge"],
                "policy_id": parent_raw.get("policy_id"),
                "capability_states": parent_raw.get("capability_states"),
                "async_execution": bool(payload.get("async_execution", False)),
                "expected_target_revision": expected_target_revision,
                "expected_session_credential_generation": expected_session_gen,
                "continuation_of_run_id": parent_run_id,
                "expected_resume_digest": preview["resume_digest"],
            }
            if submission_id is not None:
                start_payload["submission_id"] = submission_id

            continuation_meta = {
                "parent_run_id": parent_run_id,
                "root_run_id": preview["root_run_id"],
                "original_selected_cases": preview["original_selected_cases"],
                "preserved_completed_case_ids": list(preview["completed_case_ids"]),
                "resumed_pending_case_ids": list(preview["pending_case_ids"]),
                "uncertain_case_ids": list(preview["uncertain_case_ids"]),
                "included_uncertain_case_ids": list(preview["included_uncertain_case_ids"]),
                "excluded_uncertain_case_ids": [
                    cid
                    for cid in preview["uncertain_case_ids"]
                    if cid not in preview["included_uncertain_case_ids"]
                ],
                "skipped_case_ids": list(preview["skipped_case_ids"]),
                "selected_resume_case_ids": list(preview["selected_resume_case_ids"]),
                "resume_digest": preview["resume_digest"],
                "stateful_target_acknowledged": bool(payload.get("stateful_target_acknowledged")),
                "uncertain_reexecution_confirmed": bool(payload.get("uncertain_reexecution_confirmed")),
            }
            return self.start_run(
                start_payload,
                _continuation_meta=continuation_meta,
                _owns_root_lock=root_run_id,
            )
        finally:
            with self._lock:
                if self._active_resumes_by_root.get(root_run_id) == "reserving":
                    self._active_resumes_by_root.pop(root_run_id, None)

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        if not _HEX32_RE.fullmatch(run_id):
            return None
        run_dir = self.runs_root / run_id
        path = run_dir / "generic-run.json"
        with self._lock:
            if not path.is_file():
                return None
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return None
            is_in_progress = run_id in self._in_progress_runs
        if not isinstance(raw, dict):
            return None
        return self._enrich_loaded_run(run_id, raw, run_dir, is_in_progress=is_in_progress)

    def get_run_by_submission(self, submission_id: str) -> dict[str, Any] | None:
        if not _HEX32_RE.fullmatch(submission_id):
            return None
        sub_path = self.runs_root / "submissions" / f"{submission_id}.json"
        with self._lock:
            in_flight = self._submissions_in_flight.get(submission_id)
            has_file = sub_path.is_file()
        if not has_file:
            if in_flight is not None:
                in_flight_run_id = str(in_flight.get("run_id") or "")
                if in_flight_run_id:
                    rec = self.get_run(in_flight_run_id)
                    if rec is not None:
                        return rec
                raise ValueError("generic_submission_in_progress")
            return None
        try:
            sub_doc = json.loads(sub_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ValueError("generic_submission_record_unavailable") from exc
        run_id = str(sub_doc.get("generic_run_id") or "")
        if not run_id:
            raise ValueError("generic_submission_record_unavailable")
        record = self.get_run(run_id)
        if record is None:
            raise ValueError("generic_submission_record_unavailable")
        return record

    def list_runs(self) -> list[dict[str, Any]]:
        if not self.runs_root.is_dir():
            return []
        summaries: list[dict[str, Any]] = []
        for entry in sorted(self.runs_root.iterdir(), key=lambda p: p.name):
            if not entry.is_dir() or not _HEX32_RE.fullmatch(entry.name):
                continue
            rec = self.get_run(entry.name)
            if rec is None:
                continue
            cases = rec.get("cases") if isinstance(rec.get("cases"), list) else []
            skipped = rec.get("skipped_cases") if isinstance(rec.get("skipped_cases"), list) else []
            asi_codes: set[str] = set()
            tc_ids: list[str] = []
            for c in cases:
                if isinstance(c, dict):
                    if isinstance(c.get("case_id"), str):
                        tc_ids.append(c["case_id"])
                    cat_str = str(c.get("category") or "")
                    asi_codes.add(_ASI_CODE_BY_POLICY_CATEGORY.get(cat_str, cat_str))
            for s in skipped:
                if isinstance(s, dict):
                    if isinstance(s.get("case_id"), str):
                        tc_ids.append(s["case_id"])
                    code_str = str(s.get("asi_code") or s.get("category") or "")
                    asi_codes.add(_ASI_CODE_BY_POLICY_CATEGORY.get(code_str, code_str))
            summaries.append({
                "generic_run_id": rec.get("generic_run_id") or entry.name,
                "status": rec.get("status", "completed"),
                "started_at": rec.get("started_at"),
                "completed_at": rec.get("completed_at"),
                "mode": rec.get("mode", "live"),
                "target_id": rec.get("target_id"),
                "target_name": rec.get("target_name"),
                "dataset_id": rec.get("dataset_id"),
                "dataset_name": rec.get("dataset_name"),
                "asi_category": rec.get("asi_category", "auto"),
                "asi_categories": sorted(c for c in asi_codes if c),
                "testcase_ids": tc_ids,
                "use_judge": bool(rec.get("use_judge")),
                "selected_cases": rec.get("selected_cases", len(cases)),
                "ready_count": rec.get("ready_count", len(cases)),
                "executed_cases": rec.get("executed_cases", len(cases)),
                "total_cases": rec.get("total_cases", len(cases)),
                "skipped_count": rec.get("skipped_count", 0),
                "progress_percent": rec.get("progress_percent", 100),
                "verdict_counts": rec.get("verdict_counts") or {},
                "evidence_summary": rec.get("evidence_summary") or {},
                "judge_metadata": rec.get("judge_metadata"),
                "case_run_ids": [c.get("run_id") for c in cases if isinstance(c, dict) and isinstance(c.get("run_id"), str)],
                "continuation_of_run_id": rec.get("continuation_of_run_id"),
                "root_run_id": rec.get("root_run_id"),
                "child_run_ids": rec.get("child_run_ids") or [],
                "lineage_summary": rec.get("lineage_summary"),
            })
        summaries.sort(key=lambda r: (str(r.get("started_at") or ""), str(r.get("generic_run_id") or "")), reverse=True)
        return summaries


def register_generic_runner_routes(app, ctx) -> None:
    """Register ResponsePolicyStore and Generic Live/Offline Runner API routes."""
    service: GenericRunService = ctx.generic_run_service
    nonce = ctx.nonce
    fail = ctx.fail
    operator_authorized = ctx.operator_authorized

    def auth():
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        supplied = request.headers.get("X-SecAgent-Validation", "")
        if not secrets.compare_digest(supplied, nonce):
            return fail("validation_nonce_required", 403)
        return None

    @app.get("/api/testing/response-policies/target/<target_id>")
    def generic_policy_list(target_id):
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        if not _ID_RE.fullmatch(target_id):
            return fail("generic_invalid_target_id", 400)
        policies = [p.model_dump(mode="json") for p in service.policy_store.list_for_target(target_id)]
        return jsonify(workflow_schema_version="1.0.0", target_id=target_id, policies=policies)

    @app.post("/api/testing/response-policies/drafts")
    def generic_policy_draft():
        denied = auth()
        if denied:
            return denied
        try:
            draft = ResponsePolicyDraft.model_validate(read_json(request.get_data()))
            saved = service.policy_store.save_draft(draft)
            return jsonify(workflow_schema_version="1.0.0", policy=saved.model_dump(mode="json")), 201
        except (ValidationError, ValueError):
            return fail("generic_policy_invalid", 400)

    @app.post("/api/testing/response-policies/<policy_id>/review")
    def generic_policy_review(policy_id):
        denied = auth()
        if denied:
            return denied
        try:
            body = read_json(request.get_data())
            if body.get("review_confirmed") is not True:
                return fail("generic_policy_review_rejected", 409)
            reviewer = str(body.get("reviewer") or "").strip()
            expected_rev = str(body.get("expected_revision_sha256") or "").strip()
            updated = service.policy_store.review(
                policy_id,
                reviewer=reviewer,
                expected_revision_sha256=expected_rev,
            )
            return jsonify(workflow_schema_version="1.0.0", policy=updated.model_dump(mode="json"))
        except FileNotFoundError:
            return fail("generic_policy_not_found", 404)
        except (ValueError, KeyError, TypeError):
            return fail("generic_policy_review_rejected", 409)

    @app.get("/api/testing/generic-runs")
    def generic_run_list():
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        return jsonify(workflow_schema_version="1.0.0", runs=service.list_runs())

    @app.post("/api/testing/generic-runs/preview")
    def generic_run_preview():
        denied = auth()
        if denied:
            return denied
        try:
            payload = read_json(request.get_data())
            return jsonify(service.preview_run(payload))
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            code = str(exc) if str(exc).startswith(("generic_", "policy_", "judge_", "dataset_", "unmapped_", "application_context_", "unverified_", "unreviewed_", "invalid_evaluation_rule_")) else "generic_preview_invalid"
            return fail(code, 400)

    @app.post("/api/testing/generic-runs/start")
    def generic_run_start():
        denied = auth()
        if denied:
            return denied
        try:
            payload = read_json(request.get_data())
            record = service.start_run(payload)
            status_code = 202 if payload.get("async_execution") is True and record.get("status") in {"preparing", "running"} else 201
            return jsonify(record), status_code
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            code = str(exc) if (str(exc) == "credential_unavailable" or str(exc).startswith(("generic_", "policy_", "judge_", "dataset_", "unmapped_", "application_context_", "unverified_", "unreviewed_", "invalid_evaluation_rule_"))) else "generic_run_rejected"
            status = 409 if code in {
                "credential_unavailable",
                "generic_session_credential_stale",
                "generic_session_credential_authorization_required",
                "generic_target_revision_stale",
                "policy_review_required",
                "policy_category_mismatch",
                "judge_provider_unavailable",
                "unmapped_asi_category",
                "application_context_stale",
                "unverified_discovery_metadata_rejected",
                "unreviewed_inline_rules_rejected",
                "invalid_evaluation_rule_contract",
                "generic_no_executable_cases",
                "generic_submission_conflict",
                "generic_submission_in_progress",
                "generic_submission_init_failed",
                "generic_submission_record_unavailable",
            } else 400
            return fail(code, status)

    @app.post("/api/testing/generic-runs/<run_id>/resume/preview")
    def generic_run_resume_preview(run_id):
        denied = auth()
        if denied:
            return denied
        try:
            raw_bytes = request.get_data()
            payload = read_json(raw_bytes) if raw_bytes else {}
            return jsonify(service.preview_resume(run_id, payload))
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            code = str(exc)
            if code == "generic_run_not_found":
                return fail(code, 404)
            if code.startswith(("generic_resume_", "resume_")):
                return fail(code, 400)
            return fail("generic_preview_invalid", 400)

    @app.post("/api/testing/generic-runs/<run_id>/resume/start")
    def generic_run_resume_start(run_id):
        denied = auth()
        if denied:
            return denied
        try:
            payload = read_json(request.get_data())
            record = service.start_resume(run_id, payload)
            status_code = 202 if payload.get("async_execution") is True and record.get("status") in {"preparing", "running"} else 201
            return jsonify(record), status_code
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            code = str(exc)
            if code == "generic_run_not_found":
                return fail(code, 404)
            known = (
                code == "credential_unavailable"
                or code.startswith((
                    "generic_",
                    "resume_",
                    "policy_",
                    "judge_",
                    "dataset_",
                    "unmapped_",
                    "application_context_",
                    "unverified_",
                    "unreviewed_",
                    "invalid_evaluation_rule_",
                ))
            )
            err_code = code if known else "generic_run_rejected"
            status = 409 if err_code in {
                "credential_unavailable",
                "generic_session_credential_stale",
                "generic_session_credential_authorization_required",
                "generic_target_revision_stale",
                "generic_resume_not_interrupted",
                "generic_resume_already_active",
                "generic_resume_no_remaining_cases",
                "generic_resume_no_cases_selected",
                "generic_resume_uncertain_confirmation_required",
                "generic_resume_stateful_acknowledgement_required",
                "generic_resume_digest_stale",
                "generic_resume_not_eligible",
                "resume_state_incomplete",
                "resume_dataset_not_found",
                "resume_dataset_revision_missing",
                "resume_dataset_mismatch",
                "resume_target_not_found",
                "resume_target_revision_missing",
                "resume_target_configuration_changed",
                "resume_judge_configuration_missing",
                "resume_judge_configuration_changed",
                "resume_configuration_incomplete",
                "resume_policy_changed",
                "resume_application_context_changed",
                "policy_review_required",
                "policy_category_mismatch",
                "judge_provider_unavailable",
                "unmapped_asi_category",
                "application_context_stale",
                "unverified_discovery_metadata_rejected",
                "unreviewed_inline_rules_rejected",
                "invalid_evaluation_rule_contract",
                "generic_no_executable_cases",
                "generic_submission_conflict",
                "generic_submission_in_progress",
                "generic_submission_init_failed",
                "generic_submission_record_unavailable",
            } else 400
            return fail(err_code, status)

    @app.get("/api/testing/generic-runs/submission/<submission_id>")
    def generic_run_by_submission(submission_id):
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        try:
            record = service.get_run_by_submission(submission_id)
        except ValueError as exc:
            code = str(exc) if str(exc).startswith("generic_submission_") else "generic_submission_record_unavailable"
            return fail(code, 409)
        if record is None:
            return fail("generic_run_not_found", 404)
        return jsonify(record)

    @app.get("/api/testing/generic-runs/<run_id>")
    def generic_run_read(run_id):
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        record = service.get_run(run_id)
        if record is None:
            return fail("generic_run_not_found", 404)
        return jsonify(record)

    @app.get("/api/testing/generic-runs/<run_id>/report.json")
    def generic_run_export(run_id):
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        record = service.get_run(run_id)
        if record is None:
            return fail("generic_run_not_found", 404)
        raw = (json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
        return Response(
            raw,
            mimetype="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="secagent-generic-run-{run_id}.json"',
                "X-SecAgent-Export-Schema": "1.0.0",
            },
        )

    @app.get("/api/testing/generic-runs/<run_id>/unified-report.json")
    def generic_run_unified_export(run_id):
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        try:
            report = service.get_unified_report(run_id)
        except ValueError as exc:
            if str(exc) == "unified_report_integrity_failed":
                return fail("unified_report_integrity_failed", 409)
            return fail("generic_run_rejected", 400)
        if report is None:
            return fail("generic_run_not_found", 404)
        logical_id = str(report.get("logical_scan_id") or run_id)
        raw = (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
        return Response(
            raw,
            mimetype="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="secagent-unified-scan-{logical_id}.json"',
                "X-SecAgent-Export-Schema": "1.0.0",
            },
        )
