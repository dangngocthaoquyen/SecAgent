"""Opt-in GH-WEB-001 batch binding for the separately guarded ResearchBot lab."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from threading import Lock
from uuid import uuid4

import httpx

from testing.report_builder import RecordingExecutor, build_summary
from targets.adapters.http_adapter import HttpTargetAdapter
from testing import Executor, Runner, RunnerEvaluationConfig
from testing.web_fixture import now
from workflow.admission import ExecutionGrant
from workflow.batch import BatchOrchestrator, BatchRejected, CaseResult, _write_atomic, persist_batch_case_report, write_exclusive_json
from workflow.catalog import make_profile
from workflow.dispatch import ControlledDispatcher, OneRequestHttpClient, sanitized
from workflow.execution_bindings import ExecutionBindingRegistry, NativeExecutionBinding
from workflow.offline_batch import OfflineBatchWorkflow, OfflineBatchSelection, OfflineBatchStart, _digest
from workflow.plans import ROOT
from workflow.web_lab_runtime import DockerWebLabRuntime, CHAT, TARGET, ORIGIN
from workflow.web_lab_assets import load_web_assets, _input, WEB_ATTACK, WEB_CONTROL
from tools.http import HttpClientError


class WebLabPreviewRejected(BatchRejected):
    """Stable, non-sensitive reason for a rejected Web Lab preview."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class _CancellableClient(OneRequestHttpClient):
    def __init__(self, *args, cancellation_requested, **kwargs):
        super().__init__(*args, **kwargs)
        self._cancellation_requested = cancellation_requested

    def request(self, **kwargs):
        if self._cancellation_requested():
            raise HttpClientError("Batch cancellation accepted before target request.")
        return super().request(**kwargs)


class ResearchBotWebBatchWorkflow(OfflineBatchWorkflow):
    """One native Web case, two requests, existing coordinator and evaluator."""

    def __init__(self, dispatcher: ControlledDispatcher, runtime, *, root: Path = ROOT,
                 test_only_mock: bool = False):
        if not isinstance(dispatcher, ControlledDispatcher) or dispatcher.fixture_runtime is not None:
            raise ValueError("Web batch requires the controlled dispatcher without a fixture fallback.")
        mock = isinstance(dispatcher.transport, httpx.MockTransport)
        if mock:
            if not test_only_mock or getattr(runtime, "provenance", None) != "synthetic_mock":
                raise ValueError("Mock Web runtime is permitted only by explicit test injection.")
        elif (dispatcher.transport is not None or not isinstance(runtime, DockerWebLabRuntime)
              or not runtime.ready()):
            raise ValueError("Live Web batch requires a verified Docker Web Lab startup.")
        self.dispatcher, self.catalog, self.runtime = dispatcher, dispatcher.catalog, runtime
        self.repository_root = Path(root).resolve()
        self.assets = load_web_assets(self.repository_root)
        self.registry = ExecutionBindingRegistry((NativeExecutionBinding(
            testcase_id=WEB_ATTACK, protocol="openai-chat", adapter_family="generic_http",
            required_capabilities=("chat", "verified_web_fetch", "collector_callback"),
            evidence_contract="fresh_correlated_collector_receipt",
            sandbox="restricted_researchbot_web_lab",
            prerequisites=("verified_web_capability_preflight",),
            request_budget=2, execute=self._run_web_case),))
        self.max_cases, self.max_total_requests = 2, 2
        self.root = dispatcher.output_root / "batch-runs"
        self.orchestrator = BatchOrchestrator(self.root)
        self._lock = Lock()
        self._worker = None
        self._active_plan_id = None
        self._active_runtime_identity = None

    def _target_issue(self, selection: OfflineBatchSelection) -> str | None:
        preset = self.catalog._targets.get(selection.target.target_id)
        if preset is None:
            return "web_lab_target_not_found"
        if preset.id != TARGET:
            return "web_lab_target_mismatch"
        if selection.target.profile_revision != self.catalog._revisions[preset.id]:
            return "web_lab_profile_revision_mismatch"
        if not preset.reviewed:
            return "web_lab_target_not_reviewed"
        if preset.endpoint != CHAT or selection.target.endpoint != CHAT:
            return "web_lab_endpoint_mismatch"
        if preset.protocol != "openai-chat" or selection.target.protocol != "openai-chat":
            return "web_lab_protocol_mismatch"
        if preset.credential_alias is not None:
            return "web_lab_credentials_unsupported"
        if selection.target.model != "researchbot" or "researchbot" not in preset.models:
            return "web_lab_model_mismatch"
        if selection.target.timeout_seconds > 30:
            return "web_lab_timeout_exceeded"
        if self.catalog.validate(selection.target):
            return "web_lab_target_configuration_invalid"
        return None

    def _target_ready(self, selection: OfflineBatchSelection) -> bool:
        return self._target_issue(selection) is None

    def _request_budget_for_case(self, case_id: str) -> int:
        contract = self.registry.get(case_id)
        return contract.request_budget if contract else 0

    def preview(self, selection: OfflineBatchSelection) -> dict:
        issue = self._target_issue(selection)
        if issue is not None:
            raise WebLabPreviewRejected(issue)
        if len(selection.testcase_ids) > 2 or selection.total_request_budget != 2:
            raise WebLabPreviewRejected("web_lab_request_budget_invalid")
        try:
            assets = load_web_assets(self.repository_root)
        except (OSError, ValueError):
            raise WebLabPreviewRejected("web_lab_assets_unavailable") from None
        rows = []
        for identity in selection.testcase_ids:
            if identity == WEB_ATTACK:
                reason = None if self.runtime.ready() else "web_lab_runtime_unverified"
                rows.append(dict(testcase_id=identity, name=assets.attack.name,
                    asi_category="ASI01", status="ready" if reason is None else "blocked",
                    reason=reason, asset_sha256=assets.asset_sha256,
                    input_sha256=assets.input_sha256, grant_id=None))
            elif identity == WEB_CONTROL:
                reason = "web_control_security_contract_unverified"
                rows.append(dict(testcase_id=identity, name=assets.control.name,
                    asi_category="ASI01", status="blocked", reason=reason,
                    asset_sha256=_digest([identity, reason]),
                    input_sha256=_digest([identity, "no_input"]), grant_id=None))
            else:
                rows.append(dict(testcase_id=identity, name=identity,
                    asi_category="unknown", status="unsupported",
                    reason="no_verified_web_binding",
                    asset_sha256=_digest([identity, "unsupported"]),
                    input_sha256=_digest([identity, "no_input"]), grant_id=None))
        material = dict(selection=selection.model_dump(mode="json"), rows=rows,
            policy_revision=self.dispatcher.policy.revision,
            lab_identity=self.runtime.identity(), contract="restricted_web_lab_gh_web_001_v1")
        return dict(workflow_schema_version="1.0.0", plan_id=_digest(material),
            items=rows, total=len(rows), ready_count=sum(r["status"] == "ready" for r in rows),
            target_request_budget=2, execution_model="sequential_restricted_web_lab",
            fixture_origin=ORIGIN, target_endpoint=CHAT,
            lab_image_sha256=self.runtime.identity()["images"]["dvaa_image"].removeprefix("sha256:"))

    def _admit_case(self, selection, case, rows):
        initial = rows[case.testcase_id]
        if initial["status"] != "ready":
            return initial["status"], initial.get("reason")
        fresh = load_web_assets(self.repository_root)
        if (case.testcase_id != WEB_ATTACK or not self._target_ready(selection)
                or not self.runtime.ready() or fresh.asset_sha256 != case.asset_sha256
                or fresh.input_sha256 != case.input_sha256
                or super()._grant(selection, WEB_ATTACK, case.asset_sha256) is None):
            return "blocked", "web_binding_or_authorization_changed"
        return "ready"

    def start(self, item: OfflineBatchStart) -> dict:
        selection = OfflineBatchSelection.model_validate(item.model_dump(exclude={
            "expected_plan_id", "submission_id", "authorization_confirmed"}))
        with self.dispatcher._lock:
            if self.dispatcher._active or (self.root / ".active-batch").exists():
                raise BatchRejected("Another controlled execution is active.")
            plan = self.preview(selection)
            if (plan["plan_id"] != item.expected_plan_id or plan["ready_count"] != 1
                    or WEB_ATTACK not in selection.testcase_ids):
                raise BatchRejected("Stale or non-executable Web Lab plan.")
            if (self.root / ("submission-" + item.submission_id + ".json")).exists():
                raise BatchRejected("Duplicate Web Lab submission.")
            if len(self.dispatcher.policy.grants) >= 20:
                raise BatchRejected("Case-scoped grant budget exhausted.")
            grant = ExecutionGrant(authorization_id=uuid4().hex,
                target_id=selection.target.target_id,
                profile_revision=selection.target.profile_revision,
                policy_ref=selection.target.policy_ref, testcase_id=WEB_ATTACK,
                asset_sha256=self.assets.asset_sha256, scope="security_test_execution",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10))
            self.dispatcher.policy = self.dispatcher.policy.model_copy(update={
                "grants": [*self.dispatcher.policy.grants, grant]})
            self._active_plan_id = plan["plan_id"]
            self._active_runtime_identity = self.runtime.identity()
            return super().start(item)

    def _run_case(self, selection, case, execution_id: str, stage) -> CaseResult:
        return self.registry.execute(selection, case, execution_id, stage)

    def _run_web_case(self, selection, case, execution_id: str, stage) -> CaseResult:
        fresh = load_web_assets(self.repository_root)
        grant = super()._grant(selection, WEB_ATTACK, case.asset_sha256)
        if (case.testcase_id != WEB_ATTACK or grant is None or not self.runtime.ready()
                or fresh.asset_sha256 != case.asset_sha256
                or fresh.input_sha256 != case.input_sha256):
            raise BatchRejected("Web Lab asset, runtime or authorization changed.")
        write_exclusive_json(self.root / ("grant-" + grant.authorization_id),
            {"batch_execution_id": execution_id, "testcase_id": WEB_ATTACK})
        preset = self.catalog._targets[selection.target.target_id]
        profile = make_profile(preset, selection.target.model, selection.target.timeout_seconds)
        stage("preparing_web_fixture")
        with self.runtime.open() as assessment:
            if self.runtime.identity() != self._active_runtime_identity:
                raise BatchRejected("Web Lab changed after plan authorization.")
            preflight_id = assessment.identity["assessment_id"]
            approval = dict(schema=1, approval_id=grant.authorization_id,
                scope="restricted_researchbot_web_gh_web_001", plan_id=self._active_plan_id,
                assessment_id=preflight_id, target_id=profile.id,
                profile_revision=selection.target.profile_revision,
                policy_ref=selection.target.policy_ref,
                testcase_id=WEB_ATTACK, asset_sha256=fresh.asset_sha256,
                lab_identity=self.runtime.identity(), endpoint=preset.endpoint,
                guard_image_id=getattr(self.runtime, "last_guard_image_id", None),
                preflight_url=assessment.preflight.page_url,
                attack_url=assessment.attack.page_url,
                collector_path=assessment.attack.callback_path,
                fixture_origin=assessment.preflight.config["origin"],
                request_budget=2, expires_at=grant.expires_at.isoformat(),
                authorization_confirmed=True)
            approval_path = assessment.directory / "approval.json"
            _write_atomic(approval_path, approval)

            def check_approval():
                current = json.loads(approval_path.read_text(encoding="utf-8"))
                if (current != approval or datetime.now(timezone.utc) >= grant.expires_at
                        or self.runtime.identity() != approval["lab_identity"]
                        or not self._target_ready(selection)):
                    raise BatchRejected("Web Lab approval is stale or changed.")

            check_approval()
            if self.orchestrator.cancellation_requested():
                return CaseResult("cancelled", None, 0,
                    evidence_provenance=self.runtime.provenance,
                    reason="cancelled_before_web_preflight", preflight_id=preflight_id)
            control = assessment.preflight.bind(fresh.control.model_copy(deep=True), profile.id)
            control_input = _input(control, fresh.payloads, preflight_id)
            client = _CancellableClient(preset.endpoint, selection.target.timeout_seconds,
                transport=self.dispatcher.transport, stage_sink=stage,
                cancellation_requested=self.orchestrator.cancellation_requested)
            executor = RecordingExecutor(Executor({"generic_http": HttpTargetAdapter(
                http_client=client, response_only_completion=True)}), assessment.preflight)
            started = now()
            execution = executor.execute(profile, control_input)
            ended = now()
            stage("verifying_web_capability")
            if client.used != 1:
                if self.orchestrator.cancellation_requested():
                    return CaseResult("cancelled", None, 0,
                        evidence_provenance=self.runtime.provenance,
                        reason="cancelled_before_web_preflight", preflight_id=preflight_id)
                return CaseResult("error", "ERROR", client.used,
                    evidence_provenance=self.runtime.provenance, preflight_id=preflight_id)
            preflight = assessment.verify_preflight(started, ended,
                target_request_count=client.used, target_execution_success=execution.success)
            if not execution.success:
                return CaseResult("error", "ERROR", client.used,
                    evidence_provenance=self.runtime.provenance, preflight_id=preflight_id)
            if preflight["status"] != "verified":
                return CaseResult("blocked", None, client.used,
                    evidence_provenance=self.runtime.provenance,
                    reason="web_capability_preflight_unverified", preflight_id=preflight_id)
            if self.orchestrator.cancellation_requested():
                return CaseResult("cancelled", None, client.used,
                    evidence_provenance=self.runtime.provenance,
                    reason="cancelled_after_web_preflight", preflight_id=preflight_id)

            check_approval()
            stage("preparing_web_fixture")
            attack = assessment.attack.bind(fresh.attack.model_copy(deep=True), profile.id)
            attack_input = _input(attack, fresh.payloads, execution_id)
            attack_client = _CancellableClient(preset.endpoint, selection.target.timeout_seconds,
                transport=self.dispatcher.transport, stage_sink=stage,
                cancellation_requested=self.orchestrator.cancellation_requested)
            attack_executor = RecordingExecutor(Executor({"generic_http": HttpTargetAdapter(
                http_client=attack_client, response_only_completion=True)}), assessment.attack)
            runner = Runner(executor=attack_executor, evaluation_config=RunnerEvaluationConfig(),
                progress_sink=stage, require_complete_response_for_pass=True)
            attack_started = now()
            result = runner.run(attack, profile, attack_input)
            attack_ended = now()
            if attack_client.used == 0 and self.orchestrator.cancellation_requested():
                return CaseResult("cancelled", None, client.used,
                    evidence_provenance=self.runtime.provenance,
                    reason="cancelled_after_web_preflight", preflight_id=preflight_id)
            observation_record = None
            if attack_client.used == 1:
                observation_record = assessment.record_attack_observation(attack_started, attack_ended,
                    target_request_count=attack_client.used)
            stage("saving_report")
            run_id = uuid4().hex
            run_dir = self.dispatcher.output_root / run_id
            run_dir.mkdir(exist_ok=False)
            summary = build_summary(attack, profile, result, attack_executor.last_result,
                                    datetime.now(timezone.utc))
            summary["evaluation"] = runner.last_report
            summary["source_provenance"] = self.runtime.provenance
            summary["runtime_snapshot"] = dict(testcase_sha256=fresh.hashes[WEB_ATTACK + ".yaml"],
                payload_sha256=fresh.hashes["goal_hijacking.yaml"],
                control_fixture_sha256=fresh.hashes["control.html"],
                attack_fixture_sha256=fresh.hashes["attack.html"],
                asset_sha256=fresh.asset_sha256,
                input_sha256=_digest(attack_input.model_dump(mode="json")),
                evaluation_sha256=_digest(attack.evaluation.model_dump(mode="json")),
                target_id=profile.id, profile_revision_sha256=selection.target.profile_revision,
                policy_ref=selection.target.policy_ref, submitted_input=attack_input.prompt,
                original_goal=attack.evaluation.semantic.trusted_context.get("original_goal"),
                payload_ref=attack_input.payload_ref,
                assessment_id=preflight_id, preflight_run_id=assessment.preflight.config["run_id"],
                attack_run_id=assessment.attack.config["run_id"],
                fixture_url=assessment.attack.page_url,
                fixture_page_sha256=sha256(assessment.attack.page().encode()).hexdigest(),
                preflight_sha256=sha256((assessment.directory / "preflight-result.json").read_bytes()).hexdigest(),
                attack_observation_sha256=(sha256((assessment.directory / "attack-observation.json").read_bytes()).hexdigest()
                    if observation_record is not None else None),
                approval_sha256=sha256(approval_path.read_bytes()).hexdigest(),
                lab_identity_sha256=_digest(self.runtime.identity()),
                target_request_budget=2, target_request_count=client.used + attack_client.used,
                evidence_provenance=self.runtime.provenance)
            summary = sanitized(summary, secrets_to_remove=(self.dispatcher.operator_secret,
                assessment.preflight.config["canary"], assessment.attack.config["canary"]))
            summary["runtime_snapshot"]["assessment_id"] = preflight_id
            summary["runtime_snapshot"]["attack_run_id"] = assessment.attack.config["run_id"]
            observed = runner.last_report.get("observation") or {}
            return persist_batch_case_report(
                run_dir, run_id=run_id, testcase_id=WEB_ATTACK, target_id=profile.id,
                summary=summary, verdict=result.status.value,
                request_count=client.used + attack_client.used,
                response_captured=isinstance(observed.get("response_text"), str),
                response_complete=observed.get("response_complete"),
                artifact_provenance=self.runtime.provenance, batch_execution_id=execution_id,
                input_sha256=summary["runtime_snapshot"]["input_sha256"],
                asset_sha256=fresh.asset_sha256, preflight_id=preflight_id)
