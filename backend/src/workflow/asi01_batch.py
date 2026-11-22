"""Opt-in, reviewed DVAA text batch over the existing coordinator.

GH-C01 must establish the legitimate summary task before an attack case is
dispatched. Web-fetch cases have no independent action/collector observer here.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from threading import Event, Lock
from uuid import uuid4

import httpx
from typing import ClassVar

from testing.report_builder import RecordingExecutor, build_summary
from core.models import TestInput
from integrations.external_evaluator.skills import SkillBundleError, SkillBundleLoader
from payloads import PayloadLoader, PayloadRenderer
from targets.adapters.http_adapter import HttpTargetAdapter
from testing import Executor, Runner, RunnerEvaluationConfig, TestCaseLoader
from workflow.admission import ExecutionGrant
from workflow.batch import BatchRejected, CaseResult, BatchOrchestrator, persist_batch_case_report, write_exclusive_json
from workflow.catalog import make_profile
from workflow.dispatch import ControlledDispatcher, OneRequestHttpClient, sanitized
from workflow.execution_bindings import ExecutionBindingRegistry, NativeExecutionBinding
from workflow.offline_batch import OfflineBatchWorkflow, OfflineBatchSelection, OfflineBatchStart, _digest
from workflow.plans import ROOT, safe_file


TEXT_CASES = ("GH-C01", "GH-001", "GH-002")
REVIEWED_CASE_SHA256 = {
    "GH-C01": "924ede76a3b276c65c360940f7e37523147da28e4dcaf644d79f0e6607d0edb3",
    "GH-001": "1e7a8843442be8956c04f5e757f9f9954faef2b4184101b9b6c4888dcf50b63c",
    "GH-002": "013b3ea9f5b025c919556dbdd8236368ec6b1735515d4020e28d6f3684be6559",
}
REVIEWED_PAYLOAD_SHA256 = "9fe37ad8711d90fee6029564f9db30a18904296fc177400f6cfc9d5d064177cb"
WEB_BLOCKERS = {"GH-WEB-C01": "verified_web_fetch_and_action_scope_missing",
                "GH-WEB-001": "fresh_fixture_and_collector_required"}
@dataclass(frozen=True)
class ReviewedTextTarget:
    target_id: str
    endpoint: str
    model: str


# Trusted runtime policy. Target Management may save other profiles, but it
# cannot expand this list or approve an endpoint merely by naming it DVAA.
REVIEWED_TEXT_TARGETS = (
    ReviewedTextTarget("dvaa-researchbot", "http://127.0.0.1:7015/v1/chat/completions", "researchbot"),
    ReviewedTextTarget("dvaa-securebot", "http://127.0.0.1:7001/v1/chat/completions", "securebot"),
)


class TextTargetRejected(BatchRejected):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class Asi01BatchSelection(OfflineBatchSelection):
    _allowed_evaluation_modes: ClassVar[frozenset[str]] = frozenset({"rule_only", "hybrid"})
    _selection_error_message: ClassVar[str] = "Invalid ASI01 batch selection."


class Asi01BatchStart(OfflineBatchStart):
    _allowed_evaluation_modes: ClassVar[frozenset[str]] = frozenset({"rule_only", "hybrid"})
    _selection_error_message: ClassVar[str] = "Invalid ASI01 batch selection."


@dataclass(frozen=True)
class NativeTextBinding:
    testcase: object
    test_input: TestInput
    testcase_sha256: str
    payload_sha256: str
    asset_sha256: str
    input_sha256: str
    evaluation_sha256: str


def load_text_binding(case_id: str, root: Path = ROOT) -> NativeTextBinding:
    if case_id not in TEXT_CASES:
        raise ValueError("ASI01 batch case is not verified for text execution.")
    case_path = root / "testcases" / "goal_hijacking" / f"{case_id}.yaml"
    payload_path = root / "payload" / "goal_hijacking.yaml"
    safe_file(case_path, root)
    safe_file(payload_path, root)
    case = TestCaseLoader().load(case_path)
    payloads = PayloadLoader().load_repository(payload_path)
    if (case.id != case_id or case.category != "goal_hijacking"
            or case.attack_module != "goal_hijacking" or len(case.payload_refs) != 1
            or case.payload_refs[0] not in payloads
            or any(rule.type not in {"marker", "regex"} for rule in case.evaluation.rules)
            or case.evaluation.semantic is None
            or case.evaluation.semantic.skill != "goal_hijacking"):
        raise ValueError("ASI01 text asset contract changed.")
    payload = payloads[case.payload_refs[0]]
    if payload.category != case.category:
        raise ValueError("ASI01 payload category changed.")
    prompt = PayloadRenderer().render(payload, case.variables)
    if "{{" in prompt or "REQUIRES_" in prompt:
        raise ValueError("ASI01 input has unbound variables.")
    test_input = TestInput(id=f"native-batch-{case_id}", prompt=prompt,
                           payload_ref=payload.id)
    case_hash, payload_hash = (sha256(path.read_bytes()).hexdigest()
                               for path in (case_path, payload_path))
    if case_hash != REVIEWED_CASE_SHA256[case_id] or payload_hash != REVIEWED_PAYLOAD_SHA256:
        raise ValueError("ASI01 native asset changed since runtime review.")
    return NativeTextBinding(case, test_input, case_hash, payload_hash,
        _digest([case_hash, payload_hash, case.evaluation.model_dump(mode="json")]),
        _digest(test_input.model_dump(mode="json")),
        _digest(case.evaluation.model_dump(mode="json")))


class Asi01BatchWorkflow(OfflineBatchWorkflow):
    """Trusted startup opt-in; never substitutes a mock transport in production."""

    selection_model = Asi01BatchSelection

    def __init__(self, dispatcher: ControlledDispatcher, *, root: Path = ROOT):
        if not isinstance(dispatcher, ControlledDispatcher) or dispatcher.fixture_runtime is not None:
            raise ValueError("ASI01 batch requires the controlled HTTP dispatcher.")
        self.dispatcher, self.catalog = dispatcher, dispatcher.catalog
        self.provenance = ("synthetic_mock" if isinstance(dispatcher.transport, httpx.MockTransport)
                           else "target_observation")
        self.repository_root = Path(root).resolve()
        self.bindings = {identity: load_text_binding(identity, self.repository_root)
                         for identity in TEXT_CASES}
        self.registry = ExecutionBindingRegistry(tuple(NativeExecutionBinding(
            testcase_id=identity, protocol="openai-chat", adapter_family="generic_http",
            required_capabilities=("chat",), evidence_contract="complete_response_text",
            sandbox=None, prerequisites=() if identity == "GH-C01" else ("GH-C01:PASS",),
            request_budget=1, execute=self._run_text_case) for identity in TEXT_CASES))
        self.max_cases, self.max_total_requests = 5, 3
        self.root = dispatcher.output_root / "batch-runs"
        self.orchestrator = BatchOrchestrator(self.root)
        self._lock = Lock()
        self._worker = None
        self._baseline_pass = False

    @staticmethod
    def _ordered(ids):
        return ["GH-C01"] * ("GH-C01" in ids) + [identity for identity in ids if identity != "GH-C01"]

    @staticmethod
    def public_target_contracts():
        return [contract.__dict__.copy() for contract in REVIEWED_TEXT_TARGETS]

    def _target_error(self, selection):
        preset = self.catalog._targets.get(selection.target.target_id)
        if preset is None:
            return "asi01_target_not_found"
        if not preset.reviewed:
            return "asi01_target_not_reviewed"
        if (selection.target.profile_revision != self.catalog._revisions[preset.id]
                or selection.target.policy_ref != self.catalog._config.policy_ref):
            return "asi01_target_revision_mismatch"
        contract = next((item for item in REVIEWED_TEXT_TARGETS
                         if item.target_id == preset.id), None)
        if contract is None or preset.platform_id != "dvaa":
            return "asi01_target_not_supported"
        if preset.endpoint != contract.endpoint:
            return "asi01_target_endpoint_mismatch"
        if preset.protocol != "openai-chat":
            return "asi01_target_protocol_mismatch"
        if selection.target.model != contract.model:
            return "asi01_target_model_mismatch"
        if selection.target.timeout_seconds > 30:
            return "asi01_target_timeout_exceeded"
        if preset.credential_alias is not None:
            return "asi01_target_credentials_unsupported"
        if self.catalog.validate(selection.target):
            return "asi01_target_configuration_invalid"
        return None

    def preview(self, selection: OfflineBatchSelection) -> dict:
        if selection.evaluation_mode == "hybrid":
            config = self.dispatcher.hybrid_config
            if config is None or config.mode != "hybrid" or not config.judge_enabled or config.max_judge_calls != 1:
                raise TextTargetRejected("asi01_hybrid_judge_unavailable")
            try:
                skill_sha256 = SkillBundleLoader().load("goal_hijacking").identity.sha256
            except SkillBundleError:
                raise TextTargetRejected("asi01_hybrid_skill_unavailable") from None
        elif selection.evaluation_mode == "rule_only":
            skill_sha256 = None
        else:
            raise TextTargetRejected("asi01_evaluation_mode_unsupported")
        target_error = self._target_error(selection)
        if target_error:
            raise TextTargetRejected(target_error)
        if len(selection.testcase_ids) > self.max_cases or selection.total_request_budget > self.max_total_requests:
            raise BatchRejected("ASI01 case or request budget exceeded.")
        rows = []
        for identity in self._ordered(selection.testcase_ids):
            contract = self.registry.get(identity)
            binding = self.bindings.get(identity)
            if contract is None or binding is None:
                reason = WEB_BLOCKERS.get(identity, "no_verified_asi01_runtime_binding")
                rows.append(dict(testcase_id=identity, status="blocked" if identity in WEB_BLOCKERS else "unsupported",
                    reason=reason, asset_sha256=_digest([identity, reason]),
                    input_sha256=_digest([identity, "no_input"]), grant_id=None,
                    name=identity, asi_category="ASI01" if identity in WEB_BLOCKERS else "unknown"))
                continue
            fresh = load_text_binding(identity, self.repository_root)
            reason = ("native_asset_changed" if fresh.asset_sha256 != binding.asset_sha256
                      or fresh.input_sha256 != binding.input_sha256 else
                      "baseline_control_required" if identity != "GH-C01" and "GH-C01" not in selection.testcase_ids
                      else None)
            rows.append(dict(testcase_id=identity, status="blocked" if reason else "ready",
                reason=reason, asset_sha256=binding.asset_sha256,
                input_sha256=binding.input_sha256, grant_id=None,
                name=binding.testcase.name, asi_category="ASI01"))
        material = dict(selection=selection.model_dump(mode="json") | {"testcase_ids": self._ordered(selection.testcase_ids)},
                        rows=rows, policy_revision=self.dispatcher.policy.revision,
                        max_cases=self.max_cases, max_total_requests=self.max_total_requests)
        if skill_sha256 is not None:
            config = self.dispatcher.hybrid_config.model_copy(update={
                "require_complete_response_for_semantic": True})
            material.update(runner_config_sha256=_digest(config.model_dump(mode="json")),
                            skill_sha256=skill_sha256)
        return dict(workflow_schema_version="1.0.0", plan_id=_digest(material), items=rows,
            total=len(rows), ready_count=sum(row["status"] == "ready" for row in rows),
            target_request_budget=selection.total_request_budget,
            execution_model="sequential_reviewed_asi01")

    def _grant(self, selection, case_id, asset):
        if case_id != "GH-C01" and not self._baseline_pass:
            return None
        return super()._grant(selection, case_id, asset)

    def _request_budget_for_case(self, case_id: str) -> int:
        contract = self.registry.get(case_id)
        return contract.request_budget if contract else 0

    def _admit_case(self, selection, case, rows):
        initial = rows[case.testcase_id]
        if initial["status"] != "ready":
            return initial["status"], initial.get("reason")
        if case.testcase_id != "GH-C01" and not self._baseline_pass:
            return "blocked", "clean_baseline_not_confirmed"
        return super()._admit_case(selection, case, rows)

    def start(self, item: OfflineBatchStart) -> dict:
        ordered = item.model_copy(update={"testcase_ids": self._ordered(item.testcase_ids)})
        selection = Asi01BatchSelection.model_validate(ordered.model_dump(exclude={
            "expected_plan_id", "submission_id", "authorization_confirmed"}))
        with self.dispatcher._lock:
            if self.dispatcher._active or (self.root / ".active-batch").exists():
                raise BatchRejected("Another controlled execution is active.")
            preview = self.preview(selection)
            if preview["plan_id"] != item.expected_plan_id or preview["ready_count"] == 0:
                raise BatchRejected("Stale or non-executable ASI01 batch plan.")
            if (self.root / ("submission-" + item.submission_id + ".json")).exists():
                raise BatchRejected("Duplicate batch submission.")
            grants = []
            for row in preview["items"]:
                if row["status"] != "ready":
                    continue
                grants.append(ExecutionGrant(authorization_id=uuid4().hex,
                    target_id=selection.target.target_id,
                    profile_revision=selection.target.profile_revision,
                    policy_ref=selection.target.policy_ref,
                    testcase_id=row["testcase_id"], asset_sha256=row["asset_sha256"],
                    scope="security_test_execution",
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)))
            if len(self.dispatcher.policy.grants) + len(grants) > 20:
                raise BatchRejected("Case-scoped grant budget exhausted.")
            self.dispatcher.policy = self.dispatcher.policy.model_copy(update={
                "grants": [*self.dispatcher.policy.grants, *grants]})
            self._baseline_pass = False
            return super().start(ordered)

    def _run_case(self, selection, case, execution_id: str, stage) -> CaseResult:
        return self.registry.execute(selection, case, execution_id, stage)

    def _run_text_case(self, selection, case, execution_id: str, stage) -> CaseResult:
        binding = self.bindings[case.testcase_id]
        fresh = load_text_binding(case.testcase_id, self.repository_root)
        grant = super()._grant(selection, case.testcase_id, case.asset_sha256)
        if (fresh.asset_sha256 != case.asset_sha256 or fresh.input_sha256 != case.input_sha256
                or grant is None):
            raise BatchRejected("Case asset, input or authorization changed.")
        write_exclusive_json(self.root / ("grant-" + grant.authorization_id),
            {"batch_execution_id": execution_id, "testcase_id": case.testcase_id})
        preset = self.catalog._targets[selection.target.target_id]
        profile = make_profile(preset, selection.target.model, selection.target.timeout_seconds)
        client = OneRequestHttpClient(preset.endpoint, selection.target.timeout_seconds,
                                      transport=self.dispatcher.transport, stage_sink=stage)
        executor = RecordingExecutor(Executor({"generic_http": HttpTargetAdapter(
            http_client=client, response_only_completion=True)}))
        evaluation_config = (self.dispatcher.hybrid_config.model_copy(update={
            "require_complete_response_for_semantic": True})
            if selection.evaluation_mode == "hybrid" else RunnerEvaluationConfig())
        runner = Runner(executor=executor, evaluation_config=evaluation_config,
                        reviewed_judge_input_sha256=sha256(binding.test_input.prompt.encode("utf-8")).hexdigest(),
                        judge_provider=(self.dispatcher.judge_provider
                            if selection.evaluation_mode == "hybrid" else None),
                        progress_sink=stage, require_complete_response_for_pass=True,
                        require_complete_response_for_fail=True)
        result = runner.run(binding.testcase.model_copy(deep=True), profile,
                            binding.test_input.model_copy(deep=True))
        stage("saving_report")
        run_id = uuid4().hex
        run_dir = self.dispatcher.output_root / run_id
        run_dir.mkdir(exist_ok=False)
        summary = build_summary(binding.testcase, profile, result, executor.last_result,
                                datetime.now(timezone.utc))
        summary["evaluation"] = runner.last_report
        if self.provenance == "synthetic_mock":
            summary["source_provenance"] = self.provenance
        summary["runtime_snapshot"] = dict(testcase_sha256=binding.testcase_sha256,
            payload_sha256=binding.payload_sha256, asset_sha256=binding.asset_sha256,
            input_sha256=binding.input_sha256, evaluation_sha256=binding.evaluation_sha256,
            target_id=profile.id, profile_revision_sha256=selection.target.profile_revision,
            target_endpoint_sha256=sha256(preset.endpoint.encode()).hexdigest(),
            policy_ref=selection.target.policy_ref, model=selection.target.model,
            protocol=selection.target.protocol, timeout_seconds=selection.target.timeout_seconds,
            request_mapping=selection.target.request_mapping,
            response_parser=selection.target.response_parser,
            runner_config_sha256=_digest(evaluation_config.model_dump(mode="json")),
            original_goal=binding.testcase.evaluation.semantic.trusted_context.get("original_goal"),
            submitted_input=binding.test_input.prompt, payload_ref=binding.test_input.payload_ref,
            evidence_provenance=self.provenance, target_request_budget=1)
        secret_values = tuple(value for value in (self.dispatcher.operator_secret,) if value)
        summary = sanitized(summary, secrets_to_remove=secret_values)
        observation = runner.last_report.get("observation") or {}
        case_result = persist_batch_case_report(
            run_dir, run_id=run_id, testcase_id=case.testcase_id, target_id=profile.id,
            summary=summary, verdict=result.status.value, request_count=client.used,
            response_captured=isinstance(observation.get("response_text"), str),
            response_complete=observation.get("response_complete"),
            artifact_provenance=self.provenance, batch_execution_id=execution_id,
            input_sha256=binding.input_sha256, asset_sha256=binding.asset_sha256)
        if case.testcase_id == "GH-C01":
            self._baseline_pass = result.status.value == "PASS"
        return case_result
