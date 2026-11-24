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
from integrations.external_evaluator.pi import PiEvaluatorConfig, PiEvaluatorProvider
from observers.evidence_collectors import HttpCallbackCollector, _has_symlink_or_reparse
from reporting.redaction import Redactor
from testing.evaluation_config import RunnerEvaluationConfig, _has_pi_auth_provider
from testing.generic_runner import (
    _SEMANTIC_LABELS_BY_CATEGORY,
    build_blind_record_testcase,
    build_offline_target_profile,
    prepare_generic_case_pair,
    resolve_trusted_context_for_target_category,
    run_generic_cases,
)
from testing.offline_stored_import import CanonicalStoredRecordsAdapter, PromptfooReportAdapter, ImportContext
from testing.runner import Runner
from workflow.catalog import read_json
from workflow.dataset_models import infer_testcase_asi_code
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


def _sanitize_for_api(value: Any) -> Any:
    if isinstance(value, str):
        return Redactor().clean(value, opaque=False, limit=max(4096, len(value) * 2))
    if isinstance(value, dict):
        return {
            k: _sanitize_for_api(v)
            for k, v in value.items()
            if str(k).lower() not in {"authorization", "api_key", "secret", "password", "access_token"}
        }
    if isinstance(value, list):
        return [_sanitize_for_api(item) for item in value]
    return value


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

    def _resolve_saved_evidence_sources(
        self,
        target_id: str,
        *,
        for_execution: bool = False,
        mode: str = "live",
    ) -> list[dict[str, Any]]:
        if self.evidence_source_store is None:
            return []
        if for_execution and mode == "offline":
            return []
        try:
            rows = self.evidence_source_store.list(target_id)
        except Exception:
            return []
        if not isinstance(rows, list):
            return []
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
            specs.append({
                "id": str(row.get("id") or "evidence_source"),
                "name": str(row.get("name") or "evidence_source"),
                "kind": "http_callback",
                "url": endpoint.strip(),
                "headers": headers,
                "timeout_seconds": float(row.get("timeout_seconds") or 5.0),
                "provenance": "target_reported",
                "independent_verifier": False,
                "source_revision": row.get("revision"),
                "reported_semantics": row.get("semantics", "detector_reported"),
            })
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
        if target_profile_dict is not None:
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

        preset = (
            self.catalog.get(target_id)
            if hasattr(self.catalog, "get")
            else getattr(self.catalog, "_targets", {}).get(target_id)
        )
        if preset is None:
            raise ValueError("generic_target_not_found")

        cred_refs: list[str] = []
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if getattr(preset, "credential_alias", None):
            aliases = getattr(getattr(self.catalog, "config", None), "credential_aliases", {})
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
            default_caps = {"mcp": "supported"}
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
            default_caps = {"chat": "supported"}

        return TargetProfile(
            id=preset.id,
            name=preset.name,
            target_type="llm_chat" if preset.protocol == "openai-chat" else "mcp_server",
            interface=iface,
            capabilities=list(getattr(preset, "capabilities", []) or ([preset.protocol])),
            capability_states={**default_caps, **(capability_states or {})},
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
                    "finish_reason": extra.get("finish_reason", "stop"),
                    "response_complete": extra.get("response_complete"),
                    "tool_calls": extra.get("tool_calls", []),
                    "response_id": extra.get("response_id"),
                    "target_model": extra.get("target_model"),
                    "required_capability": meta.get("required_capability") or extra.get("required_capability"),
                    "tool_name": meta.get("tool_name") or extra.get("tool_name"),
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
        )

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
            )

        pairs: list[tuple[CoreTestCase, CoreTestInput]] = []
        preview_items: list[dict[str, Any]] = []
        asi_breakdown: dict[str, int] = {}
        first_reviewed_policy = None
        overall_blocker: str | None = None

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
            if not is_unsupported:
                if row_cat is None:
                    row_blocker = "unmapped_asi_category"
                elif use_judge:
                    if row_cat not in context_cache:
                        context_cache[row_cat] = self._resolve_category_trusted_context(
                            target_id=target.id,
                            norm_category=row_cat,
                            policy_id=policy_id,
                        )
                    trusted_context, rev_pol, row_blocker = context_cache[row_cat]
                    if rev_pol is not None and first_reviewed_policy is None:
                        first_reviewed_policy = rev_pol
                    if row_blocker is None and not self.pi_judge_ready():
                        row_blocker = "judge_provider_unavailable"

                if row_blocker and overall_blocker is None:
                    overall_blocker = row_blocker

            item_status = "unsupported" if is_unsupported else ("blocked" if row_blocker else "ready")
            item_reason = (
                ("mcp_tool_name_required" if mcp_tool_missing else "capability_unsupported")
                if is_unsupported
                else row_blocker
            )

            if item_status == "ready":
                effective_cat = row_cat or "tool_misuse"
                active_ctx = trusted_context if (use_judge and trusted_context is not None and row_cat is not None) else None
                tc, ti = prepare_generic_case_pair(
                    mode=mode,  # type: ignore[arg-type]
                    target=target,
                    case_id=case_id,
                    norm_category=effective_cat,
                    prompt=prompt,
                    trusted_context=active_ctx,
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
            "policy_id": first_reviewed_policy.policy_id if first_reviewed_policy else policy_id,
            "policy_revision_sha256": first_reviewed_policy.revision_sha256 if first_reviewed_policy else None,
            "policy_review_status": (
                first_reviewed_policy.review_status
                if first_reviewed_policy
                else ("reviewed" if (use_judge and not overall_blocker) else ("missing_or_draft" if use_judge else "not_required"))
            ),
            "blocker": overall_blocker,
            "items": preview_items,
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
        raw_sources = payload.get("evidence_sources")
        if isinstance(raw_sources, list):
            configured_evidence_source_count = len([s for s in raw_sources if isinstance(s, dict)])
        else:
            configured_evidence_source_count = len(
                self._resolve_saved_evidence_sources(
                    target_id,
                    for_execution=False,
                    mode=mode,
                )
            )
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
        return {
            "workflow_schema_version": "1.0.0",
            "mode": mode,
            "target_id": target.id,
            "target_name": target.name,
            "dataset_id": dataset_id,
            "dataset_name": dataset_name,
            "asi_category": asi_category,
            "use_judge": use_judge,
            "pi_judge_ready": self.pi_judge_ready(),
            "judge_status": self.judge_status(),
            "capability_states": target.capability_states,
            "evidence_source_count": active_evidence_source_count,
            "active_evidence_source_count": active_evidence_source_count,
            "configured_evidence_source_count": configured_evidence_source_count,
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
        }
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
            fault = c.get("provider_fault_code")
            val_status = c.get("json_validation_status")
            has_judge_output = bool(c.get("judge_classification") or c.get("judge_reason"))
            if invoked is True or bool(fault):
                attempted += 1
                if fault or val_status == "provider_fault":
                    failed += 1
                    errors.add(str(fault or "provider_fault"))
                elif val_status in {"valid", None} and (has_judge_output or val_status == "valid"):
                    succeeded += 1
                else:
                    failed += 1
                    errors.add(str(val_status or "invalid_judge_output"))
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

    def start_run(self, payload: dict[str, Any]) -> dict[str, Any]:
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
            with (cat_lock if cat_lock is not None else nullcontext()), self._lock:
                target = self._resolve_target(
                    mode=mode,
                    target_id=target_id,
                    target_profile_dict=payload.get("target_profile"),
                    capability_states=payload.get("capability_states"),
                    evidence_sources=payload.get("evidence_sources"),
                    for_execution=True,
                )
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
            injected_collectors = []
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
                                transport=ev_transport,
                            )
                        )
                    else:
                        remaining_specs.append(spec)
                run_target = target.model_copy(update={"evidence_sources": remaining_specs})

            dataset_id = payload.get("dataset_id") if isinstance(payload.get("dataset_id"), str) else None
            dataset_name = None
            if dataset_id and self.dataset_repo is not None:
                env = self.dataset_repo.get_dataset(dataset_id)
                if env is not None:
                    dataset_name = env.name

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
                "dataset_id": dataset_id,
                "dataset_name": dataset_name,
                "asi_category": asi_category,
                "use_judge": use_judge,
                "policy_id": preview_meta["policy_id"],
                "policy_revision_sha256": preview_meta["policy_revision_sha256"],
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
                "judge_metadata": self._build_judge_metadata(
                    use_judge=use_judge,
                    run_status="running",
                    cases=[],
                    pi_cfg=pi_cfg,
                ),
                "case_statuses": case_statuses,
                "events": [{"at": started_at, "stage": "run_started", "case_id": None}],
                "cases": [],
            }
            with self._lock:
                # Register in-progress run BEFORE writing generic-run.json to disk so get_run/list_runs never see a false orphan
                self._in_progress_runs[run_id] = Thread(name=f"init-{run_id[:8]}")
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
                    except OSError:
                        pass
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
                    enriched_case = _sanitize_for_api({
                        "case_id": item["case_id"],
                        "run_id": item["run_id"],
                        "category": item["category"],
                        "prompt": pair_ti.prompt if pair_ti is not None else "",
                        "response_text": obs_block.get("response_text"),
                        "response_complete": obs_block.get("response_complete"),
                        "verdict": item["verdict"],
                        "reason": item["reason"],
                        "judge_reason": judge_block.get("judge_reason"),
                        "judge_classification": judge_block.get("classification"),
                        "semantic_invoked": bool(judge_block.get("semantic_invoked")),
                        "provider_fault_code": judge_block.get("provider_fault_code"),
                        "json_validation_status": judge_block.get("json_validation_status"),
                        "provider_duration_ms": judge_block.get("provider_duration_ms"),
                        "evidence_level": ev_level,
                        "provenance_tiers": item["provenance_tiers"],
                        "execution_status": exec_status,
                        "collector_diagnostics": item["collector_diagnostics"],
                        "evidence": obs_block.get("evidence", []),
                        **({"source_provenance": source_prov} if source_prov is not None else {}),
                        **({"historical_verdict": hist_verdict} if isinstance(hist_verdict, dict) else {}),
                        "report_path": str(report_path),
                    })
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
                    )
                    done_iso = datetime.now(timezone.utc).isoformat()
                    with self._lock:
                        record["executed_cases"] = len(record["cases"])
                        record["total_cases"] = len(pairs)
                        record["verdict_counts"] = summary["verdict_counts"]
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
                        "persistence_integrity_failed"
                        if isinstance(exc, (OSError, RuntimeError))
                        else "runner_execution_failed"
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
                    for tid in tracked_ids:
                        self._release_target_run(tid)

            if async_execution:
                worker_thread = Thread(target=_execute_worker, name=f"secagent-generic-run-{run_id[:8]}", daemon=True)
                with self._lock:
                    self._in_progress_runs[run_id] = worker_thread
                released = True
                worker_thread.start()
                with self._lock:
                    return dict(record)

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
        return record

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
            code = str(exc) if str(exc).startswith(("generic_", "policy_", "judge_", "dataset_", "unmapped_", "application_context_", "unverified_")) else "generic_preview_invalid"
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
            code = str(exc) if str(exc).startswith(("generic_", "policy_", "judge_", "dataset_", "unmapped_", "application_context_", "unverified_")) else "generic_run_rejected"
            status = 409 if code in {
                "policy_review_required",
                "policy_category_mismatch",
                "judge_provider_unavailable",
                "unmapped_asi_category",
                "application_context_stale",
                "unverified_discovery_metadata_rejected",
                "generic_no_executable_cases",
                "generic_submission_conflict",
                "generic_submission_in_progress",
                "generic_submission_init_failed",
                "generic_submission_record_unavailable",
            } else 400
            return fail(code, status)

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
