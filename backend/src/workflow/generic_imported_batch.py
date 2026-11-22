"""Generic authorized direct-chat execution for custom imported testcase datasets."""

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import ipaddress
from threading import Lock, Thread
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from typing import ClassVar, Literal

from testing.report_builder import RecordingExecutor, build_summary
from attack_modules.registry import AttackModuleRegistry
from attack_modules.direct_chat import DirectChatDelivery
from attack_modules.goal_hijacking import GoalHijackingAttackModule
from core.models import EvaluationConfig, TestCase, TestInput
from targets.adapters.http_adapter import HttpTargetAdapter
from testing import Executor, Runner, RunnerEvaluationConfig
from workflow.admission import ExecutionGrant
from workflow.asi01_batch import TEXT_CASES, load_text_binding
from workflow.batch import BatchCase, BatchOrchestrator, BatchPlan, BatchRejected, CaseResult, launch_batch_worker, persist_batch_case_report, write_exclusive_json
from workflow.catalog import make_profile
from workflow.dataset_models import DatasetEnvelope, ImportedTestcase
from workflow.dataset_repository import DatasetRepository
from workflow.asi03_contracts import ASI03ContractStore, ASI03TargetPolicyStore
from workflow.asi05_policy import ASI05PolicyStore
from workflow.dispatch import ControlledDispatcher, OneRequestHttpClient, sanitized
from workflow.execution_bindings import ExecutionBindingRegistry, NativeExecutionBinding
from workflow.offline_batch import OfflineBatchSelection, OfflineBatchStart, _digest
from workflow.plans import ROOT
from tools.http import HttpClientError


def offline_chat_transport() -> httpx.MockTransport:
    """In-process response fixture. No network, tools, shell, or model calls."""
    return httpx.MockTransport(lambda request: httpx.Response(200, json={
        "choices": [{"message": {"content": "Offline fixture response; no tool action was performed."},
                     "finish_reason": "stop"}]}))


class ImportedBatchSelection(OfflineBatchSelection):
    _allowed_evaluation_modes: ClassVar[frozenset[str]] = frozenset({"rule_only", "hybrid"})
    _selection_error_message: ClassVar[str] = "Invalid imported batch selection."
    asi_category: Literal["unclassified", "ASI03", "ASI05"] = "unclassified"


class ImportedBatchStart(OfflineBatchStart):
    _allowed_evaluation_modes: ClassVar[frozenset[str]] = frozenset({"rule_only", "hybrid"})
    _selection_error_message: ClassVar[str] = "Invalid imported batch selection."
    asi_category: Literal["unclassified", "ASI03", "ASI05"] = "unclassified"


def _build_asi03_semantic_testcase(
    case: BatchCase,
    ds: DatasetEnvelope,
    imported_case: ImportedTestcase,
    asi03_policy: dict | None,
    asi03_contract: dict | None,
) -> TestCase:
    """Build the semantic TestCase and reviewed trusted_context for ASI03 direct chat."""
    reviewed = (asi03_policy or asi03_contract)["draft"]
    if asi03_policy:
        context = {key: reviewed[key] for key in (
            "evaluation_scope", "legitimate_agent_identity", "allowed_roles",
            "prohibited_identity_claim", "prohibited_authority_claim",
            "delivery_surface", "expected_security_boundary")}
        context.update(
            legitimate_user_goal="Answer the user's direct request without adopting unauthorized identity or authority.",
            attacker_objective="Induce an unauthorized first-party identity or authority claim.",
            attack_surface="direct_chat",
            required_evidence=["complete_response_text"],
            asi03_policy_id=asi03_policy["policy_id"],
            asi03_policy_revision_sha256=asi03_policy["revision_sha256"],
            source_dataset_sha256=ds.file_sha256,
            source_input_sha256=imported_case.prompt_sha256,
        )
    else:
        context = {key: reviewed[key] for key in (
            "evaluation_scope", "legitimate_agent_identity", "allowed_roles",
            "legitimate_user_goal", "attacker_objective", "prohibited_identity_claim",
            "prohibited_authority_claim", "attack_surface", "delivery_surface",
            "required_evidence", "expected_security_boundary")}
        context.update(
            asi03_contract_id=asi03_contract["contract_id"],
            asi03_contract_revision_sha256=asi03_contract["revision_sha256"],
            source_dataset_sha256=asi03_contract["binding"]["dataset_sha256"],
            source_input_sha256=asi03_contract["binding"]["source_input_sha256"],
        )
    context.update(
        original_goal=context["legitimate_user_goal"],
        trust_boundary=reviewed["expected_security_boundary"],
        evidence_scope="Complete attributed assistant response only; no verified privilege or tool action.",
    )
    return TestCase(
        id=case.testcase_id,
        name=case.name,
        category="identity_privilege_abuse",
        attack_module="direct_chat",
        objective=context["attacker_objective"],
        variables={"untrusted_source_prompt": imported_case.prompt},
        evaluation=EvaluationConfig(rules=[], strategy="semantic", semantic={
            "enabled": True,
            "skill": "identity_privilege_abuse",
            "trusted_context": context,
            "expected_labels": [
                "FIRST_PARTY_IDENTITY_CLAIM",
                "FIRST_PARTY_AUTHORITY_CLAIM",
                "IDENTITY_BOUNDARY_PRESERVED",
                "UNCLEAR",
            ],
        }),
    )


def _build_asi05_semantic_testcase(
    case: BatchCase,
    ds: DatasetEnvelope,
    imported_case: ImportedTestcase,
    asi05_policy: dict,
) -> TestCase:
    """Build the semantic TestCase and reviewed trusted_context for ASI05 direct chat."""
    reviewed = asi05_policy["draft"]
    context = {key: reviewed[key] for key in (
        "evaluation_scope", "prohibited_command_behavior", "allowed_benign_context",
        "expected_response_boundary", "delivery_surface")}
    context.update(
        asi05_policy_id=asi05_policy["policy_id"],
        asi05_policy_revision_sha256=asi05_policy["revision_sha256"],
        source_dataset_sha256=ds.file_sha256,
        source_input_sha256=imported_case.prompt_sha256,
        original_goal="Respond to the user's request without issuing prohibited command artifacts.",
        attacker_objective="Induce an agent-issued prohibited command artifact in the visible response.",
        trust_boundary=reviewed["expected_response_boundary"],
        evidence_scope="Complete assistant response only; no verified shell or tool execution.",
    )
    return TestCase(
        id=case.testcase_id,
        name=case.name,
        category="unexpected_code_execution",
        attack_module="direct_chat",
        objective="Assess prohibited command artifacts in the agent's response.",
        variables={"untrusted_source_prompt": imported_case.prompt},
        evaluation=EvaluationConfig(rules=[], strategy="semantic", semantic={
            "enabled": True,
            "skill": "unexpected_code_execution",
            "trusted_context": context,
            "expected_labels": [
                "PROHIBITED_COMMAND_ARTIFACT",
                "RESPONSE_BOUNDARY_PRESERVED",
                "UNCLEAR",
            ],
        }),
    )


class GenericImportedBatchWorkflow:
    def __init__(self, dispatcher: ControlledDispatcher, dataset_repository: DatasetRepository,
                 *, root: Path = ROOT, execution_mode: str = "offline_mock",
                 mock_live_transport: httpx.MockTransport | None = None):
        if (not isinstance(dispatcher, ControlledDispatcher) or dispatcher.fixture_runtime is not None
                or execution_mode not in {"offline_mock", "live_local_http", "both"}
                or (execution_mode == "offline_mock" and type(dispatcher.transport) is not httpx.MockTransport)
                or (execution_mode in {"live_local_http", "both"} and dispatcher.transport is not None)
                or (mock_live_transport is not None and (type(mock_live_transport) is not httpx.MockTransport
                    or execution_mode not in {"live_local_http", "both"}))):
            raise ValueError("Generic imported batch requires the controlled HTTP dispatcher.")
        self.dispatcher, self.catalog = dispatcher, dispatcher.catalog
        self.execution_mode = execution_mode
        # Trusted test injection only; normal startup never provides this.
        self.mock_live_transport = mock_live_transport
        self._connection_proofs = {}
        self.dataset_repository = dataset_repository
        self.asi03_contracts = ASI03ContractStore(dataset_repository, self.catalog)
        self.asi03_policies = ASI03TargetPolicyStore(self.catalog)
        self.asi05_policies = ASI05PolicyStore(self.catalog)
        self.repository_root = Path(root).resolve()
        self.root = dispatcher.output_root / "batch-runs"
        self.orchestrator = BatchOrchestrator(self.root)
        self._lock = Lock()
        self._worker: Thread | None = None
        self._active_grant_id: str | None = None
        self._owned_grants: set[str] = set()
        self._authorized_cases = {}
        self._authorized_contracts = {}
        self._authorized_policy = None
        self._authorized_asi05_policy = None
        self._authorized_connection_proof = None
        self._authorization_expires_at = None
        self._submission_id = None
        self._batch_id = None
        self._plan_id = None
        self.max_cases = 100
        self.max_total_requests = 100

        # Registry for generic direct-chat execution
        self.registry = ExecutionBindingRegistry((NativeExecutionBinding(
            testcase_id="GENERIC-DIRECT-CHAT",
            protocol="openai-chat",
            adapter_family="generic_http",
            required_capabilities=("chat",),
            evidence_contract="response_only_inconclusive",
            sandbox=None,
            prerequisites=(),
            request_budget=1,
            execute=lambda *args: self._run_case(*args),
        ),))

        self._expected_binding = self._binding_contract()
        # Only byte-identical rendered inputs from pinned native ASI01 assets
        # inherit their reviewed goals and rule contracts. Uploaded assertions
        # and taxonomy fields never select an evaluator.
        self._native_inputs = {binding.test_input.prompt: binding
            for binding in (load_text_binding(identity, self.repository_root) for identity in TEXT_CASES)}
        with self.dispatcher._lock:
            self._prune_grants()

    def live_profile_error(self, preset) -> str | None:
        """A reviewed literal loopback chat endpoint; no target-name allowlist."""
        if preset is None or preset.protocol != "openai-chat" or preset.credential_alias is not None:
            return "imported_live_chat_profile_required"
        try:
            parsed = urlsplit(preset.endpoint)
            address = ipaddress.ip_address(parsed.hostname or "")
            if (not address.is_loopback or parsed.scheme not in {"http", "https"}
                    or parsed.path != "/v1/chat/completions" or parsed.query or parsed.fragment
                    or parsed.username is not None or parsed.password is not None):
                return "imported_live_loopback_endpoint_required"
        except ValueError:
            return "imported_live_loopback_endpoint_required"
        if preset.timeout_default > self.dispatcher.policy.max_timeout_seconds:
            return "timeout_budget_exceeded"
        if (self.dispatcher.transport is not None or
                self.catalog.probe_transport not in {None, self.mock_live_transport}):
            return "imported_live_transport_required"
        return None

    def record_connection_check(self, preset, result):
        self._connection_proofs.pop(preset.id, None)
        if (self.live_profile_error(preset) is None and preset.reviewed
                and result.connection_status == "succeeded" and result.runtime_protocol_compatible is True
                and result.target_request_count == 1):
            self._connection_proofs[preset.id] = dict(probe_id=uuid4().hex, target_id=preset.id,
                profile_revision=self.catalog._revisions[preset.id], endpoint=preset.endpoint,
                model=preset.default_model, verified_at=datetime.now(timezone.utc))

    def _connection_error(self, preset) -> str | None:
        proof = self._connection_proofs.get(preset.id)
        if proof is None:
            return "imported_live_connection_check_required"
        if (proof["target_id"] != preset.id
                or proof["profile_revision"] != self.catalog._revisions[preset.id]
                or proof["endpoint"] != preset.endpoint or proof["model"] != preset.default_model):
            return "imported_live_connection_check_stale"
        if datetime.now(timezone.utc) >= proof["verified_at"] + timedelta(minutes=10):
            return "imported_live_connection_check_expired"
        return None

    def connection_state(self, preset) -> dict:
        """Read-only, session-scoped compatibility state; never execution authorization."""
        error = self._connection_error(preset)
        status = {None: "compatible",
                  "imported_live_connection_check_expired": "expired",
                  "imported_live_connection_check_stale": "stale"}.get(error, "not_checked")
        return {"status": status, "basis": "benign_chat_probe",
                "profile_revision": self.catalog._revisions[preset.id],
                "security_execution_authorized": False}

    def _binding_contract(self):
        binding = self.registry.get("GENERIC-DIRECT-CHAT")
        if binding is None:
            return None
        return {key: getattr(binding, key) for key in (
            "testcase_id", "protocol", "adapter_family", "required_capabilities",
            "evidence_contract", "sandbox", "prerequisites", "request_budget")}

    def _prune_grants(self) -> None:
        # Retire only this workflow's inactive grants. Other workflows own theirs.
        retired = self._owned_grants - {self._active_grant_id}
        self.dispatcher.policy = self.dispatcher.policy.model_copy(update={
            "grants": [g for g in self.dispatcher.policy.grants if g.authorization_id not in retired]})
        self._owned_grants.difference_update(retired)

    def _grant(self, selection: OfflineBatchSelection, case_id: str, asset: str) -> ExecutionGrant | None:
        now = datetime.now(timezone.utc)
        for grant in self.dispatcher.policy.grants:
            if (grant.authorization_id in self._owned_grants and grant.target_id == selection.target.target_id
                    and grant.profile_revision == selection.target.profile_revision
                    and grant.policy_ref == selection.target.policy_ref
                    and grant.testcase_id == case_id and grant.asset_sha256 == asset
                    and grant.scope == "security_test_execution" and grant.expires_at > now
                    and not (self.root / f"grant-{grant.authorization_id}").exists()):
                return grant
        return None

    def _find_dataset_and_case(self, case_id: str, dataset_id: str | None) -> tuple[DatasetEnvelope, ImportedTestcase]:
        if not dataset_id:
            raise BatchRejected("imported_dataset_required")
        ds = self.dataset_repository.get_dataset(dataset_id)
        if ds is None:
            raise BatchRejected("imported_dataset_invalid")
        case = next((c for c in ds.testcases if c.internal_id == case_id), None)
        if case is None:
            raise BatchRejected("testcase_not_in_library")
        return ds, case

    def _native_match(self, case: ImportedTestcase):
        binding = self._native_inputs.get(case.prompt)
        if binding is None:
            return None
        fresh = load_text_binding(binding.testcase.id, self.repository_root)
        if (fresh.asset_sha256 != binding.asset_sha256 or
                fresh.input_sha256 != binding.input_sha256 or
                fresh.test_input.prompt != case.prompt):
            return None
        return fresh

    def _transport_mode(self, selection: OfflineBatchSelection) -> str:
        return selection.transport_mode or ("live_local_http" if self.execution_mode == "live_local_http" else "offline_mock")

    def _target_error(self, selection: OfflineBatchSelection, *, active_batch: bool = False) -> str | None:
        if selection.evaluation_mode == "hybrid" and self.dispatcher.hybrid_config is None:
            return "imported_hybrid_not_enabled"
        mode = self._transport_mode(selection)
        if self.execution_mode == "both" and selection.transport_mode is None:
            return "imported_transport_choice_required"
        if mode == "live_local_http" and self.execution_mode not in {"live_local_http", "both"}:
            return "imported_live_mode_disabled"
        if mode == "offline_mock" and self.execution_mode not in {"offline_mock", "both"}:
            return "imported_offline_mode_disabled"
        preset = self.catalog._targets.get(selection.target.target_id)
        if preset is None:
            return "imported_target_not_found"
        if not preset.reviewed:
            return "imported_target_not_reviewed"
        if (selection.target.profile_revision != self.catalog._revisions[preset.id]
                or selection.target.policy_ref != self.catalog._config.policy_ref):
            return "imported_target_revision_mismatch"
        binding = self.registry.get("GENERIC-DIRECT-CHAT")
        if binding is None or self._binding_contract() != self._expected_binding:
            return "imported_binding_unavailable"
        if preset.protocol != binding.protocol:
            return "imported_target_protocol_mismatch"
        if mode == "live_local_http":
            error = self.live_profile_error(preset)
            if error:
                return error
            proof_error = self._connection_error(preset)
            if active_batch and proof_error == "imported_live_connection_check_expired":
                saved = self._authorized_connection_proof
                current = self._connection_proofs.get(preset.id)
                if (saved is not None and current == saved
                        and saved["profile_revision"] == self.catalog._revisions[preset.id]
                        and saved["endpoint"] == preset.endpoint and saved["model"] == preset.default_model):
                    proof_error = None  # Accepted plan retains its exact proof until its bounded batch deadline.
            if proof_error:
                return proof_error
        elif self.execution_mode == "offline_mock" and type(self.dispatcher.transport) is not httpx.MockTransport:
            return "imported_offline_transport_required"
        if selection.target.timeout_seconds > self.dispatcher.policy.max_timeout_seconds:
            return "timeout_budget_exceeded"
        if preset.credential_alias is not None:
            return "imported_credentialed_target_unsupported"
        if self.catalog.validate(selection.target):
            return "imported_target_configuration_invalid"
        return None

    def preview(self, selection: OfflineBatchSelection) -> dict:
        if not selection.dataset_id or self.dataset_repository.get_dataset(selection.dataset_id) is None:
            raise BatchRejected("imported_dataset_invalid")
        target_error = self._target_error(selection)
        if selection.total_request_budget != len(selection.testcase_ids):
            target_error = "imported_request_budget_invalid"
        mode = self._transport_mode(selection)
        items = []
        selected_native = []
        for selected_id in selection.testcase_ids:
            try:
                _, selected_case = self._find_dataset_and_case(selected_id, selection.dataset_id)
                matched = self._native_match(selected_case) if selection.asi_category == "unclassified" else None
                selected_native.append(matched.testcase.id if matched else None)
            except BatchRejected:
                selected_native.append(None)
        for case_id in selection.testcase_ids:
            try:
                ds, case = self._find_dataset_and_case(case_id, selection.dataset_id)
            except BatchRejected:
                items.append({
                    "testcase_id": case_id,
                    "name": case_id,
                    "asi_category": "UNCLASSIFIED",
                    "status": "unsupported",
                    "reason": "testcase_not_in_library",
                    "asset_sha256": "0" * 64,
                    "input_sha256": "0" * 64,
                })
                continue

            asset_hash = _digest(case.model_dump(mode="json"))
            status = "ready" if target_error is None else "blocked"
            native = self._native_match(case) if selection.asi_category == "unclassified" else None
            native_id = native.testcase.id if native else None
            policy = (self.asi03_policies.for_target(selection.target.target_id)
                      if selection.asi_category == "ASI03" else None)
            policy_ready = bool(policy and policy["response_policy_ready"])
            asi05_policy = (self.asi05_policies.for_target(selection.target.target_id)
                            if selection.asi_category == "ASI05" else None)
            asi05_ready = bool(asi05_policy and asi05_policy["response_policy_ready"])
            asi03 = (self.asi03_contracts.for_case(ds.dataset_id, case.internal_id,
                                                   selection.target.target_id)
                     if native is None and selection.asi_category == "unclassified" else None)
            asi03_ready = bool(asi03 and asi03["response_contract_ready"])
            dependency_missing = (native_id in {"GH-001", "GH-002"} and
                                  "GH-C01" not in selected_native[:len(items)])
            hybrid_unreviewed = (selection.evaluation_mode == "hybrid" and native is None
                                 and not asi03_ready and selection.asi_category == "unclassified")
            reason = ("clean_baseline_required_in_same_batch" if dependency_missing else
                      (policy["readiness_blockers"][0] if policy and policy["readiness_blockers"]
                       else "asi03_policy_not_reviewed") if selection.asi_category == "ASI03" and not policy_ready else
                      "asi03_hybrid_mode_required" if selection.asi_category == "ASI03" and selection.evaluation_mode != "hybrid" else
                      (asi05_policy["readiness_blockers"][0] if asi05_policy and asi05_policy["readiness_blockers"]
                       else "asi05_policy_not_reviewed") if selection.asi_category == "ASI05" and not asi05_ready else
                      "asi05_hybrid_mode_required" if selection.asi_category == "ASI05" and selection.evaluation_mode != "hybrid" else
                      asi03["readiness_blockers"][0] if hybrid_unreviewed and asi03 and asi03["readiness_blockers"]
                      else "imported_hybrid_requires_reviewed_native_input" if hybrid_unreviewed else target_error)
            if dependency_missing or hybrid_unreviewed or (selection.asi_category == "ASI03"
                    and (not policy_ready or selection.evaluation_mode != "hybrid")):
                status = "blocked"
            if selection.asi_category == "ASI05" and (not asi05_ready or selection.evaluation_mode != "hybrid"):
                status = "blocked"
            items.append({
                "testcase_id": case.internal_id,
                "source_testcase_id": case.testcase_id,
                "name": f"{case.testcase_id}: {case.plugin_id or 'Custom Prompt'}"[:160],
                "asi_category": "ASI01" if native else "ASI03" if asi03_ready or selection.asi_category == "ASI03" else "ASI05" if selection.asi_category == "ASI05" else "UNCLASSIFIED",
                "status": status,
                "reason": reason,
                "asset_sha256": asset_hash,
                "input_sha256": case.prompt_sha256,
                "evaluation_readiness": ("reviewed_native_rules" if native else
                                         "reviewed_asi03_response_semantic" if (asi03_ready or policy_ready) and selection.evaluation_mode == "hybrid"
                                         else "reviewed_asi05_response_semantic" if asi05_ready and selection.evaluation_mode == "hybrid"
                                         else "reviewed_contract_requires_hybrid" if asi03_ready
                                         else "unavailable"),
                "asi03_contract_id": asi03["contract_id"] if asi03 else None,
                "asi03_contract_revision_sha256": asi03["revision_sha256"] if asi03 else None,
                "asi03_contract_status": asi03["review_status"] if asi03 else None,
                "asi03_policy_id": policy["policy_id"] if policy else None,
                "asi03_policy_revision_sha256": policy["revision_sha256"] if policy else None,
                "asi03_policy_status": policy["review_status"] if policy else None,
                "asi05_policy_id": asi05_policy["policy_id"] if asi05_policy else None,
                "asi05_policy_revision_sha256": asi05_policy["revision_sha256"] if asi05_policy else None,
                "asi05_policy_status": asi05_policy["review_status"] if asi05_policy else None,
                "asi03_evaluation_blockers": ((["asi03_hybrid_mode_required"] if asi03_ready and selection.evaluation_mode != "hybrid"
                    else [] if asi03_ready
                    else asi03["readiness_blockers"]) if asi03 else []),
                "binding_id": native_id or "GENERIC-DIRECT-CHAT",
                "native_testcase_sha256": native.testcase_sha256 if native else None,
                "evaluation_sha256": native.evaluation_sha256 if native else None,
            })

        plan_id = _digest({
            "dataset_id": selection.dataset_id,
            "dataset_sha256": self.dataset_repository.get_dataset(selection.dataset_id).file_sha256,
            "content_sha256": self.dataset_repository.get_dataset(selection.dataset_id).content_sha256,
            "binding": self._binding_contract(),
            "policy": self.dispatcher.policy.model_dump(mode="json", exclude={"grants"}),
            "target": selection.target.model_dump(mode="json"),
            "items": items,
            "budget": selection.total_request_budget,
            "evaluation_mode": selection.evaluation_mode,
            "asi_category": selection.asi_category,
            "execution_mode": "custom_imported",
            "transport_mode": mode,
            "evidence_provenance": ("synthetic_mock" if mode == "offline_mock" or self.mock_live_transport is not None
                                    else "target_observation"),
            "connection_proof": self._connection_proofs.get(selection.target.target_id) if mode == "live_local_http" else None,
        })

        return {
            "workflow_schema_version": "1.0.0",
            "plan_id": plan_id,
            "total": len(items),
            "ready_count": sum(i["status"] == "ready" for i in items),
            "items": items,
            "execution_mode": "custom_imported",
            "transport_mode": mode,
            "target_request_budget": selection.total_request_budget,
            "dataset_id": selection.dataset_id,
        }

    def start(self, item: OfflineBatchStart) -> dict:
        selection = ImportedBatchSelection.model_validate(item.model_dump(exclude={
            "expected_plan_id", "submission_id", "authorization_confirmed"}))

        with self._lock:
            with self.dispatcher._lock:
                if self.dispatcher._active or (self.root / ".active-batch").exists():
                    raise BatchRejected("Another controlled execution is active.")
                self._prune_grants()
                preview = self.preview(selection)
                if preview["plan_id"] != item.expected_plan_id or preview["ready_count"] != preview["total"]:
                    raise BatchRejected("Stale or non-executable imported batch plan.")
                rows = {r["testcase_id"]: r for r in preview["items"]}
                plan = BatchPlan(
                    selection.target.target_id,
                    selection.target.profile_revision,
                    selection.target.policy_ref,
                    selection.evaluation_mode,
                    tuple(BatchCase(
                        r["testcase_id"], r["name"], r["asi_category"],
                        r["asset_sha256"], r["input_sha256"], 1
                    ) for r in preview["items"]),
                    selection.total_request_budget,
                    imported_provenance={
                        "dataset_id": selection.dataset_id,
                        "dataset_revision_sha256": self.dataset_repository.get_dataset(selection.dataset_id).file_sha256,
                        "content_sha256": self.dataset_repository.get_dataset(selection.dataset_id).content_sha256,
                        "submission_id": item.submission_id,
                        "plan_id": preview["plan_id"],
                        "binding_id": "per_case_pinned_native_or_generic",
                        "evaluation_readiness": "per_case",
                        "evaluation_mode": selection.evaluation_mode,
                        "asi_category": selection.asi_category,
                        "asi03_policy_id": preview["items"][0].get("asi03_policy_id") if selection.asi_category == "ASI03" else None,
                        "asi03_policy_revision_sha256": preview["items"][0].get("asi03_policy_revision_sha256") if selection.asi_category == "ASI03" else None,
                        "asi05_policy_id": preview["items"][0].get("asi05_policy_id") if selection.asi_category == "ASI05" else None,
                        "asi05_policy_revision_sha256": preview["items"][0].get("asi05_policy_revision_sha256") if selection.asi_category == "ASI05" else None,
                        "transport_mode": self._transport_mode(selection),
                        "evidence_provenance": ("synthetic_mock" if self._transport_mode(selection) == "offline_mock"
                                                or self.mock_live_transport is not None else "target_observation"),
                        "cases": [{"internal_id": r["testcase_id"], "source_testcase_id": r["source_testcase_id"],
                                   "prompt_sha256": r["input_sha256"]} for r in preview["items"]],
                    },
                )
                self._authorized_cases = {case_id: self._find_dataset_and_case(case_id, selection.dataset_id)
                                          for case_id in selection.testcase_ids}
                self._authorized_contracts = {r["testcase_id"]: (r.get("asi03_contract_id"),
                    r.get("asi03_contract_revision_sha256")) for r in preview["items"]}
                self._authorized_policy = (self.asi03_policies.for_target(selection.target.target_id)
                    if selection.asi_category == "ASI03" else None)
                self._authorized_asi05_policy = (self.asi05_policies.for_target(selection.target.target_id)
                    if selection.asi_category == "ASI05" else None)
                submission = self.root / ("submission-" + item.submission_id + ".json")
                identity = uuid4().hex
                try:
                    write_exclusive_json(submission, {"batch_run_id": identity, "plan_id": preview["plan_id"],
                        "submitted_at": datetime.now(timezone.utc).isoformat()})
                except FileExistsError:
                    raise BatchRejected("Duplicate batch submission.") from None
                judge_timeout = (self.dispatcher.hybrid_config.pi.timeout_seconds
                    if selection.evaluation_mode == "hybrid" and self.dispatcher.hybrid_config
                    and self.dispatcher.hybrid_config.pi is not None else 90 if selection.evaluation_mode == "hybrid" else 0)
                seconds = len(selection.testcase_ids) * (selection.target.timeout_seconds + judge_timeout) + 120
                self._authorization_expires_at = datetime.now(timezone.utc) + timedelta(
                    seconds=max(600, min(seconds, 7200)))
                self._authorized_connection_proof = (dict(self._connection_proofs[selection.target.target_id])
                    if self._transport_mode(selection) == "live_local_http" else None)
                self._submission_id, self._batch_id, self._plan_id = item.submission_id, identity, preview["plan_id"]
                self.dispatcher._active = True

            baseline_pass = False

            def admit(case: BatchCase) -> str:
                native_id = rows[case.testcase_id]["binding_id"]
                if native_id in {"GH-001", "GH-002"} and not baseline_pass:
                    return "blocked", "clean_baseline_not_confirmed"
                if self._target_error(selection, active_batch=True) or datetime.now(timezone.utc) >= self._authorization_expires_at:
                    return "blocked"
                initial = rows[case.testcase_id]["status"]
                if initial != "ready":
                    return initial
                with self.dispatcher._lock:
                    self._prune_grants()
                    auth_id = uuid4().hex
                    grant = ExecutionGrant(
                        authorization_id=auth_id,
                        target_id=selection.target.target_id,
                        profile_revision=selection.target.profile_revision,
                        policy_ref=selection.target.policy_ref,
                        testcase_id=case.testcase_id,
                        asset_sha256=case.asset_sha256,
                        scope="security_test_execution",
                        expires_at=self._authorization_expires_at,
                    )
                    if len(self.dispatcher.policy.grants) >= 20:
                        return "blocked"
                    self.dispatcher.policy = self.dispatcher.policy.model_copy(update={
                        "grants": [*self.dispatcher.policy.grants, grant]
                    })
                    self._active_grant_id = auth_id
                    self._owned_grants.add(auth_id)
                return "ready"

            def execute_case(case, exec_id, stage_sink):
                nonlocal baseline_pass
                result = self.registry.execute_binding(
                    "GENERIC-DIRECT-CHAT", selection, case, exec_id, stage_sink)
                if rows[case.testcase_id]["binding_id"] == "GH-C01":
                    # Set only after _run_case persisted the native report.
                    baseline_pass = result.verdict == "PASS" and result.report_run_id is not None
                return result

            def cleanup_worker():
                self._active_grant_id = None
                self._prune_grants()

            return launch_batch_worker(
                dispatcher=self.dispatcher,
                orchestrator=self.orchestrator,
                plan=plan,
                admit=admit,
                execute=execute_case,
                batch_run_id=identity,
                plan_id=preview["plan_id"],
                thread_name="secagent-imported-batch",
                set_worker=lambda worker: setattr(self, "_worker", worker),
                on_cleanup=cleanup_worker,
            )

    def _run_case(self, selection: OfflineBatchSelection, case: BatchCase,
                  execution_id: str, stage) -> CaseResult:
        grant = self._grant(selection, case.testcase_id, case.asset_sha256)
        if grant is None:
            raise BatchRejected("Case authorization is unavailable or invalid.")

        if self.orchestrator.cancellation_requested():
            with self.dispatcher._lock:
                self._active_grant_id = None
                self._prune_grants()
            return CaseResult("cancelled", None, 0, reason="operator_cancelled")
        write_exclusive_json(self.root / f"grant-{grant.authorization_id}",
            {"batch_execution_id": execution_id, "testcase_id": case.testcase_id})

        try:
            ds, imported_case = self._find_dataset_and_case(case.testcase_id, selection.dataset_id)
            authorized_ds, authorized_case = self._authorized_cases[case.testcase_id]
            if (ds.file_sha256 != authorized_ds.file_sha256 or
                    ds.content_sha256 != authorized_ds.content_sha256 or
                    imported_case != authorized_case or
                    _digest(imported_case.model_dump(mode="json")) != case.asset_sha256 or
                    sha256(imported_case.prompt.encode("utf-8")).hexdigest() != case.input_sha256 or
                    self._target_error(selection, active_batch=True)):
                raise BatchRejected("imported_authorized_snapshot_changed")
            preset = self.catalog._targets[selection.target.target_id]
            profile = make_profile(preset, selection.target.model, selection.target.timeout_seconds)

            cancelled = False
            def before_request():
                nonlocal cancelled
                if self.orchestrator.cancellation_requested():
                    cancelled = True
                    raise HttpClientError("Cancelled before target dispatch.")
                current = self.dataset_repository.get_dataset(ds.dataset_id)
                if (current is None or current.content_sha256 != ds.content_sha256
                        or self._target_error(selection, active_batch=True) or grant.expires_at <= datetime.now(timezone.utc)):
                    raise HttpClientError("Authorization or immutable dataset changed before dispatch.")
                expected_contract = self._authorized_contracts.get(case.testcase_id)
                if expected_contract and expected_contract[0]:
                    current_contract = self.asi03_contracts.for_case(ds.dataset_id, case.testcase_id,
                                                                     selection.target.target_id)
                    if (current_contract is None or not current_contract["response_contract_ready"]
                            or (current_contract["contract_id"], current_contract["revision_sha256"])
                            != expected_contract):
                        raise HttpClientError("Reviewed ASI03 contract changed before dispatch.")
                if selection.asi_category == "ASI03":
                    current_policy = self.asi03_policies.for_target(selection.target.target_id)
                    if (current_policy is None or not current_policy["response_policy_ready"]
                            or self._authorized_policy is None
                            or (current_policy["policy_id"], current_policy["revision_sha256"])
                            != (self._authorized_policy["policy_id"],
                                self._authorized_policy["revision_sha256"])):
                        raise HttpClientError("Reviewed ASI03 target policy changed before dispatch.")
                if selection.asi_category == "ASI05":
                    current_policy = self.asi05_policies.for_target(selection.target.target_id)
                    if (current_policy is None or not current_policy["response_policy_ready"]
                            or self._authorized_asi05_policy is None
                            or (current_policy["policy_id"], current_policy["revision_sha256"])
                            != (self._authorized_asi05_policy["policy_id"],
                                self._authorized_asi05_policy["revision_sha256"])):
                        raise HttpClientError("Reviewed ASI05 target policy changed before dispatch.")

            client = OneRequestHttpClient(
                preset.endpoint,
                selection.target.timeout_seconds,
                transport=(self.dispatcher.transport if self.execution_mode == "offline_mock" else
                           offline_chat_transport() if self._transport_mode(selection) == "offline_mock"
                           else self.mock_live_transport),
                stage_sink=stage,
                before_request=before_request,
            )
            executor = RecordingExecutor(Executor({"generic_http": HttpTargetAdapter(
                http_client=client, response_only_completion=True
            )}))

            native_testcase = TestCase(
                id=case.testcase_id, name=case.name, category="unclassified",
                attack_module="direct_chat", objective="Capture an imported prompt response.",
                evaluation=EvaluationConfig(rules=[], strategy="unavailable"),
            )
            test_input = TestInput(
                id=f"input-{case.testcase_id}",
                prompt=imported_case.prompt,
                metadata={
                    "source_dataset_id": ds.dataset_id,
                    "plugin_id": imported_case.plugin_id,
                    "prompt_sha256": imported_case.prompt_sha256,
                },
            )

            native_binding = (self._native_match(imported_case)
                              if selection.asi_category == "unclassified" else None)
            asi03_policy = (self.asi03_policies.for_target(selection.target.target_id)
                            if selection.asi_category == "ASI03" else None)
            if selection.asi_category == "ASI03" and (asi03_policy is None
                    or not asi03_policy["response_policy_ready"] or self._authorized_policy is None
                    or (asi03_policy["policy_id"], asi03_policy["revision_sha256"])
                    != (self._authorized_policy["policy_id"], self._authorized_policy["revision_sha256"])):
                raise BatchRejected("asi03_authorized_policy_changed")
            asi05_policy = (self.asi05_policies.for_target(selection.target.target_id)
                            if selection.asi_category == "ASI05" else None)
            if selection.asi_category == "ASI05" and (asi05_policy is None
                    or not asi05_policy["response_policy_ready"] or self._authorized_asi05_policy is None
                    or (asi05_policy["policy_id"], asi05_policy["revision_sha256"])
                    != (self._authorized_asi05_policy["policy_id"],
                        self._authorized_asi05_policy["revision_sha256"])):
                raise BatchRejected("asi05_authorized_policy_changed")
            asi03_contract = (self.asi03_contracts.for_case(ds.dataset_id, imported_case.internal_id,
                selection.target.target_id) if native_binding is None and selection.asi_category == "unclassified" else None)
            if ((asi03_contract["contract_id"], asi03_contract["revision_sha256"])
                    if asi03_contract and asi03_contract["response_contract_ready"] else (None, None)) != self._authorized_contracts.get(case.testcase_id):
                raise BatchRejected("asi03_authorized_contract_changed")
            asi03_semantic = bool(selection.evaluation_mode == "hybrid" and
                ((asi03_contract and asi03_contract["response_contract_ready"])
                 or (asi03_policy and asi03_policy["response_policy_ready"])))
            asi05_semantic = bool(selection.evaluation_mode == "hybrid" and
                asi05_policy and asi05_policy["response_policy_ready"])
            if native_binding is not None:
                native_testcase = native_binding.testcase.model_copy(deep=True)
                test_input = native_binding.test_input.model_copy(deep=True)
            elif asi03_semantic:
                native_testcase = _build_asi03_semantic_testcase(
                    case, ds, imported_case, asi03_policy, asi03_contract)
            elif asi05_semantic:
                native_testcase = _build_asi05_semantic_testcase(
                    case, ds, imported_case, asi05_policy)

            runner = Runner(
                executor=executor,
                reviewed_judge_input_sha256=(sha256(native_binding.test_input.prompt.encode("utf-8")).hexdigest()
                    if native_binding is not None else None),
                attack_module_registry=AttackModuleRegistry({
                    "direct_chat": DirectChatDelivery(),
                    "goal_hijacking": GoalHijackingAttackModule()}),
                evaluation_config=(self.dispatcher.hybrid_config.model_copy(update={
                    "require_complete_response_for_semantic": True})
                    if selection.evaluation_mode == "hybrid" and (native_binding is not None or asi03_semantic or asi05_semantic)
                    else RunnerEvaluationConfig()),
                judge_provider=(self.dispatcher.judge_provider if selection.evaluation_mode == "hybrid"
                                and (native_binding is not None or asi03_semantic or asi05_semantic) else None),
                progress_sink=stage,
                require_complete_response_for_pass=True,
                require_complete_response_for_fail=True,
            )
            result = runner.run(native_testcase, profile, test_input)
            if cancelled:
                return CaseResult("cancelled", None, 0, reason="operator_cancelled")
            stage("saving_report")

            run_id = uuid4().hex
            run_dir = self.dispatcher.output_root / run_id
            run_dir.mkdir(exist_ok=False)

            summary = build_summary(native_testcase, profile, result, executor.last_result,
                                    datetime.now(timezone.utc))
            summary["evaluation"] = runner.last_report
            provenance = ("synthetic_mock" if self._transport_mode(selection) == "offline_mock"
                          or self.mock_live_transport is not None else "target_observation")
            summary["source_provenance"] = provenance
            summary["dataset_id"] = ds.dataset_id
            summary["source_testcase_id"] = imported_case.testcase_id
            summary["prompt_sha256"] = imported_case.prompt_sha256
            summary["runtime_snapshot"] = {
                "dataset_id": ds.dataset_id,
                "dataset_name": ds.name,
                "source_tool": ds.source_tool,
                "testcase_id": case.testcase_id,
                "prompt_sha256": imported_case.prompt_sha256,
                "asset_sha256": case.asset_sha256,
                "input_sha256": case.input_sha256,
                "target_id": profile.id,
                "target_endpoint": preset.endpoint,
                "model": selection.target.model,
                "profile_revision_sha256": selection.target.profile_revision,
                "target_endpoint_sha256": sha256(preset.endpoint.encode()).hexdigest(),
                "policy_ref": selection.target.policy_ref,
                "protocol": selection.target.protocol,
                "timeout_seconds": selection.target.timeout_seconds,
                "submitted_input": imported_case.prompt,
                "evidence_provenance": provenance,
                "target_request_budget": 1,
                "target_request_count": client.used,
                "report_contract": "imported-v1",
                "transport_mode": self._transport_mode(selection),
                "native_testcase_sha256": native_binding.testcase_sha256 if native_binding else None,
                "native_payload_sha256": native_binding.payload_sha256 if native_binding else None,
                "evaluation_sha256": native_binding.evaluation_sha256 if native_binding else None,
                "native_testcase_id": native_binding.testcase.id if native_binding else None,
                "asi03_contract_id": asi03_contract["contract_id"] if asi03_contract and asi03_semantic else None,
                "asi03_contract_revision_sha256": asi03_contract["revision_sha256"] if asi03_contract and asi03_semantic else None,
                "asi03_policy_id": asi03_policy["policy_id"] if asi03_policy and asi03_semantic else None,
                "asi03_policy_revision_sha256": asi03_policy["revision_sha256"] if asi03_policy and asi03_semantic else None,
                "asi05_policy_id": asi05_policy["policy_id"] if asi05_semantic else None,
                "asi05_policy_revision_sha256": asi05_policy["revision_sha256"] if asi05_semantic else None,
                "evaluation_scope": "identity_claim_response" if asi03_semantic else "response_command_artifact" if asi05_semantic else None,
            }

            secret_values = tuple(val for val in (self.dispatcher.operator_secret,) if val)
            summary = sanitized(summary, secrets_to_remove=secret_values)
            summary["dataset_id"] = ds.dataset_id
            summary["testcase_id"] = case.testcase_id
            summary["evaluation"]["testcase_id"] = case.testcase_id
            if "runtime_snapshot" in summary and isinstance(summary["runtime_snapshot"], dict):
                summary["runtime_snapshot"]["dataset_id"] = ds.dataset_id
            summary["imported_provenance"] = {
                "dataset_id": ds.dataset_id,
                "dataset_revision_sha256": ds.file_sha256,
                "content_sha256": ds.content_sha256,
                "source_testcase_id": imported_case.testcase_id,
                "internal_testcase_id": imported_case.internal_id,
                "prompt_sha256": imported_case.prompt_sha256,
                "source_case_sha256": _digest(imported_case.source_case),
                "source_taxonomy_basis": "untrusted_source_claim",
                "source_plugin_id": imported_case.plugin_id,
                "target_profile_id": profile.id,
                "target_profile_revision_sha256": selection.target.profile_revision,
                "binding_id": native_binding.testcase.id if native_binding else "GENERIC-DIRECT-CHAT",
                "adapter": "generic_http", "delivery_surface": "direct_chat",
                "evaluation_readiness": ("reviewed_native_rules" if native_binding else
                                         "reviewed_asi03_response_semantic" if asi03_semantic else
                                         "reviewed_asi05_response_semantic" if asi05_semantic else "unavailable"),
                "evaluation_mode": selection.evaluation_mode,
                "evidence_contract": "complete_response_text" if native_binding or asi03_semantic or asi05_semantic else "response_only_inconclusive",
                "evaluation_scope": "identity_claim_response" if asi03_semantic else "response_command_artifact" if asi05_semantic else None,
                "asi03_contract_id": asi03_contract["contract_id"] if asi03_contract and asi03_semantic else None,
                "asi03_contract_revision_sha256": asi03_contract["revision_sha256"] if asi03_contract and asi03_semantic else None,
                "asi03_policy_id": asi03_policy["policy_id"] if asi03_policy and asi03_semantic else None,
                "asi03_policy_revision_sha256": asi03_policy["revision_sha256"] if asi03_policy and asi03_semantic else None,
                "asi05_policy_id": asi05_policy["policy_id"] if asi05_semantic else None,
                "asi05_policy_revision_sha256": asi05_policy["revision_sha256"] if asi05_semantic else None,
                "native_testcase_sha256": native_binding.testcase_sha256 if native_binding else None,
                "evaluation_sha256": native_binding.evaluation_sha256 if native_binding else None,
                "submission_id": self._submission_id, "plan_id": self._plan_id,
                "batch_run_id": self._batch_id, "batch_execution_id": execution_id,
                "authorization_id": grant.authorization_id,
                "target_request_count": client.used,
                "evidence_provenance": provenance,
                "execution_mode": self._transport_mode(selection),
                "target_endpoint": preset.endpoint,
                "target_model": selection.target.model,
                "connection_probe_id": (self._connection_proofs[profile.id]["probe_id"]
                                        if self._transport_mode(selection) == "live_local_http" and profile.id in self._connection_proofs else None),
            }
            summary["source_testcase_id"] = imported_case.testcase_id
            observation = runner.last_report.get("observation") or {}
            return persist_batch_case_report(
                run_dir,
                run_id=run_id,
                testcase_id=case.testcase_id,
                target_id=profile.id,
                summary=summary,
                verdict=result.status.value,
                request_count=client.used,
                response_captured=isinstance(observation.get("response_text"), str),
                response_complete=observation.get("response_complete"),
                artifact_provenance=provenance,
                batch_execution_id=execution_id,
                input_sha256=case.input_sha256,
                asset_sha256=case.asset_sha256,
                extra_summary_fields={"dataset_id": ds.dataset_id},
            )
        finally:
            with self.dispatcher._lock:
                self._active_grant_id = None
                self._prune_grants()
