"""Explicitly injected offline batch workflow over native Runner and mock HTTP.

Normal Workflow API startup never constructs this service. It cannot send a
real target request or widen the controlled GH-C01 dispatcher allowlist.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
import re
from threading import Lock, Thread
from uuid import uuid4

import httpx
from pydantic import Field, model_validator
from typing import ClassVar, Literal

from testing.report_builder import RecordingExecutor, build_summary
from core.models import Observation, TestCase, TestInput
from evaluators.registry import build_default_registry
from evaluators.rules import RuleConfigurationError
from targets.adapters.http_adapter import HttpTargetAdapter
from testing import Executor, Runner, RunnerEvaluationConfig
from workflow.batch import BatchCase, BatchOrchestrator, BatchPlan, BatchRejected, CaseResult, launch_batch_worker, persist_batch_case_report, write_exclusive_json
from workflow.catalog import make_profile
from workflow.dispatch import ControlledDispatcher, OneRequestHttpClient, sanitized
from workflow.models import ClosedModel, Identifier, TargetDraft


def _digest(value) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        default=str).encode()).hexdigest()


class OfflineBatchSelection(ClosedModel):
    _allowed_evaluation_modes: ClassVar[frozenset[str]] = frozenset({"rule_only"})
    _selection_error_message: ClassVar[str] = "Invalid offline batch selection."

    target: TargetDraft
    testcase_ids: list[Identifier] = Field(min_length=1, max_length=100)
    total_request_budget: int = Field(ge=0, le=100)
    evaluation_mode: str = "rule_only"
    dataset_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    transport_mode: Literal["offline_mock", "live_local_http"] | None = None

    @model_validator(mode="after")
    def unique_and_rule_only(self):
        if (len(set(self.testcase_ids)) != len(self.testcase_ids)
                or self.evaluation_mode not in self._allowed_evaluation_modes):
            raise ValueError(self._selection_error_message)
        return self


class OfflineBatchStart(OfflineBatchSelection):
    expected_plan_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    submission_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    authorization_confirmed: bool

    @model_validator(mode="after")
    def confirmed(self):
        if self.authorization_confirmed is not True:
            raise ValueError("Explicit execution confirmation required.")
        return self


@dataclass(frozen=True)
class OfflineCaseBinding:
    """Trusted in-process synthetic case; never constructed from HTTP JSON."""

    testcase: TestCase
    test_input: TestInput

    def __post_init__(self):
        if (self.testcase.category != "goal_hijacking"
                or self.testcase.attack_module != "goal_hijacking"
                or self.testcase.evaluation.semantic is not None
                or self.testcase.payload_refs or self.testcase.variables
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.testcase.id)
                or self.testcase.id in {"GH-C01", "GH-WEB-001"}
                or not re.fullmatch(r"[A-Za-z0-9 ._-]{1,160}", self.testcase.name)
                or not isinstance(self.test_input.prompt, str)
                or not re.fullmatch(r"Synthetic benign [A-Za-z0-9_.-]{1,64}", self.test_input.prompt)
                or self.test_input.environment or self.test_input.parameters
                or self.test_input.artifact_refs or self.test_input.file_refs):
            raise ValueError("Offline binding must be a benign synthetic response case.")
        registry = build_default_registry()
        for rule in self.testcase.evaluation.rules:
            if rule.type not in {"marker", "regex"}:
                raise ValueError("Offline binding requires response-only rules.")
            try:
                registry.resolve(rule.type).match(rule, Observation(response_text=""))
            except RuleConfigurationError:
                raise ValueError("Invalid response rule configuration.") from None

    @property
    def asset_sha256(self):
        return _digest(self.testcase.model_dump(mode="json"))

    @property
    def input_sha256(self):
        return _digest(self.test_input.model_dump(mode="json"))


class OfflineBatchWorkflow:
    """Mock-transport-only API backend with exact grants and durable reports."""

    selection_model = OfflineBatchSelection

    def __init__(self, dispatcher: ControlledDispatcher, bindings: list[OfflineCaseBinding],
                 *, max_cases: int, max_total_requests: int):
        if (not isinstance(dispatcher.transport, httpx.MockTransport)
                or max_cases < 1 or max_total_requests < 1
                or max_cases > 100 or max_total_requests > 100):
            raise ValueError("Offline batch requires explicit bounded mock transport.")
        self.dispatcher = dispatcher
        self.catalog = dispatcher.catalog
        if any(p.credential_alias is not None for p in self.catalog._targets.values()):
            raise ValueError("Offline batch mock targets cannot use credentials.")
        self.bindings = {item.testcase.id: item for item in bindings}
        if not bindings or len(self.bindings) != len(bindings):
            raise ValueError("Offline batch bindings must have unique IDs.")
        self.max_cases, self.max_total_requests = max_cases, max_total_requests
        self.root = dispatcher.output_root / "batch-runs"
        self.orchestrator = BatchOrchestrator(self.root)
        self._lock = Lock()
        self._worker: Thread | None = None

    def _grant(self, selection: OfflineBatchSelection, case_id: str, asset: str):
        now = datetime.now(timezone.utc)
        for grant in self.dispatcher.policy.grants:
            if (grant.authorization_id and grant.target_id == selection.target.target_id
                    and grant.profile_revision == selection.target.profile_revision
                    and grant.policy_ref == selection.target.policy_ref
                    and grant.testcase_id == case_id and grant.asset_sha256 == asset
                    and grant.scope == "security_test_execution" and grant.expires_at > now
                    and not (self.root / ("grant-" + grant.authorization_id)).exists()):
                return grant
        return None

    def _request_budget_for_case(self, case_id: str) -> int:
        return 1

    def _admit_case(self, selection, case, rows):
        if self.catalog.validate(selection.target):
            return "blocked"
        initial = rows[case.testcase_id]["status"]
        if initial != "ready":
            return initial
        binding = self.bindings.get(case.testcase_id)
        if binding is None or binding.asset_sha256 != case.asset_sha256 or binding.input_sha256 != case.input_sha256:
            return "blocked"
        return "ready" if self._grant(selection, case.testcase_id, case.asset_sha256) else "blocked"

    def preview(self, selection: OfflineBatchSelection) -> dict:
        errors = self.catalog.validate(selection.target)
        if errors:
            raise BatchRejected("Target is unreviewed, stale or invalid.")
        if len(selection.testcase_ids) > self.max_cases or selection.total_request_budget > self.max_total_requests:
            raise BatchRejected("Offline batch policy budget exceeded.")
        rows = []
        for case_id in selection.testcase_ids:
            binding = self.bindings.get(case_id)
            if binding is None:
                rows.append({"testcase_id": case_id, "status": "unsupported",
                             "asset_sha256": _digest([case_id, "unsupported"]),
                             "input_sha256": _digest([case_id, "no_input"]),
                             "grant_id": None, "name": case_id, "asi_category": "unknown"})
                continue
            asset = binding.asset_sha256
            grant = self._grant(selection, case_id, asset)
            rows.append({"testcase_id": case_id, "status": "ready" if grant else "blocked",
                         "asset_sha256": asset, "input_sha256": binding.input_sha256,
                         "grant_id": grant.authorization_id if grant else None,
                         "name": binding.testcase.name, "asi_category": "ASI01"})
        material = {"selection": selection.model_dump(mode="json"), "rows": rows,
                    "policy_revision": self.dispatcher.policy.revision,
                    "max_cases": self.max_cases, "max_total_requests": self.max_total_requests}
        return {"workflow_schema_version": "1.0.0", "plan_id": _digest(material),
                "items": rows, "total": len(rows), "ready_count": sum(r["status"] == "ready" for r in rows),
                "target_request_budget": selection.total_request_budget,
                "execution_model": "sequential_offline_mock"}

    def _run_case(self, selection, case: BatchCase, execution_id: str, stage) -> CaseResult:
        binding = self.bindings[case.testcase_id]
        grant = self._grant(selection, case.testcase_id, case.asset_sha256)
        if grant is None or binding.input_sha256 != case.input_sha256:
            raise BatchRejected("Case authorization or input snapshot changed.")
        write_exclusive_json(self.root / ("grant-" + grant.authorization_id),
            {"batch_execution_id": execution_id, "testcase_id": case.testcase_id})
        preset = self.catalog._targets[selection.target.target_id]
        credential_name = self.catalog._config.credential_aliases.get(preset.credential_alias)
        profile = make_profile(preset, selection.target.model,
            selection.target.timeout_seconds, credential_name)
        client = OneRequestHttpClient(preset.endpoint, selection.target.timeout_seconds,
            transport=self.dispatcher.transport, stage_sink=stage)
        adapter = HttpTargetAdapter(http_client=client, response_only_completion=True)
        executor = RecordingExecutor(Executor({"generic_http": adapter}))
        runner = Runner(executor=executor, evaluation_config=RunnerEvaluationConfig(),
                        progress_sink=stage, require_complete_response_for_pass=True)
        result = runner.run(binding.testcase.model_copy(deep=True), profile,
                            binding.test_input.model_copy(deep=True))
        stage("saving_report")
        run_id = uuid4().hex
        run_dir = self.dispatcher.output_root / run_id
        run_dir.mkdir(exist_ok=False)
        summary = build_summary(binding.testcase, profile, result, executor.last_result,
                                datetime.now(timezone.utc))
        summary["evaluation"] = runner.last_report
        summary["source_provenance"] = "synthetic_mock"
        secret_values = tuple(v for v in (self.dispatcher.operator_secret,
            os.environ.get(credential_name, "") if credential_name else "") if v)
        summary = sanitized(summary, secrets_to_remove=secret_values)
        observation = runner.last_report.get("observation") or {}
        return persist_batch_case_report(
            run_dir, run_id=run_id, testcase_id=case.testcase_id, target_id=profile.id,
            summary=summary, verdict=result.status.value, request_count=client.used,
            response_captured=isinstance(observation.get("response_text"), str),
            response_complete=observation.get("response_complete"),
            artifact_provenance="synthetic_mock", batch_execution_id=execution_id,
            input_sha256=case.input_sha256, asset_sha256=case.asset_sha256)

    def start(self, item: OfflineBatchStart) -> dict:
        selection = self.selection_model.model_validate(item.model_dump(exclude={
            "expected_plan_id", "submission_id", "authorization_confirmed"}))
        with self._lock:
            with self.dispatcher._lock:
                if self.dispatcher._active or (self.root / ".active-batch").exists():
                    raise BatchRejected("Another controlled execution is active.")
                preview = self.preview(selection)
                if preview["plan_id"] != item.expected_plan_id:
                    raise BatchRejected("Stale batch plan identity.")
                submission = self.root / ("submission-" + item.submission_id + ".json")
                identity = uuid4().hex
                try:
                    write_exclusive_json(submission, {"batch_run_id": identity, "plan_id": preview["plan_id"],
                        "submitted_at": datetime.now(timezone.utc).isoformat()})
                except FileExistsError:
                    raise BatchRejected("Duplicate batch submission.") from None
                rows = {r["testcase_id"]: r for r in preview["items"]}
                plan = BatchPlan(selection.target.target_id, selection.target.profile_revision,
                    selection.target.policy_ref, selection.evaluation_mode,
                    tuple(BatchCase(r["testcase_id"], r["name"], r["asi_category"],
                        r["asset_sha256"], r["input_sha256"],
                        self._request_budget_for_case(r["testcase_id"]) if r["status"] == "ready" else 0)
                        for r in preview["items"]), selection.total_request_budget)
                self.dispatcher._active = True
        return launch_batch_worker(
            dispatcher=self.dispatcher,
            orchestrator=self.orchestrator,
            plan=plan,
            admit=lambda case: self._admit_case(selection, case, rows),
            execute=lambda case, execution_id, stage: self._run_case(selection, case, execution_id, stage),
            batch_run_id=identity,
            plan_id=preview["plan_id"],
            thread_name="secagent-offline-batch",
            set_worker=lambda worker: setattr(self, "_worker", worker),
        )
