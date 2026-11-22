"""Explicitly injected, mock-transport-only ResearchBot Web batch slice.

The capability preflight is a separate, non-verdict observation. It never
substitutes for GH-WEB-C01's security PASS and cannot authorize live dispatch.
"""

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from threading import Lock
from uuid import uuid4

import httpx

from targets.adapters.http_adapter import HttpTargetAdapter
from testing import Executor, Runner, RunnerEvaluationConfig
from testing.report_builder import RecordingExecutor, build_summary
from testing.web_fixture import now
from workflow.batch import BatchOrchestrator, BatchRejected, CaseResult, _write_atomic, persist_batch_case_report, write_exclusive_json
from workflow.catalog import make_profile
from workflow.dispatch import ControlledDispatcher, OneRequestHttpClient, sanitized
from workflow.fixture_runtime import LocalMockFixtureRuntime
from workflow.offline_batch import OfflineBatchWorkflow, OfflineBatchSelection, OfflineBatchStart, _digest
from workflow.plans import ROOT
from workflow.web_lab_assets import (
    REVIEWED_HASHES,
    WEB_ATTACK,
    WEB_CONTROL,
    WebAssets,
    _input,
    load_web_assets,
)


RESEARCHBOT_ENDPOINT = "http://127.0.0.1:7015/v1/chat/completions"


class MockWebBatchWorkflow(OfflineBatchWorkflow):
    """API-injectable only with a trusted MockTransport and explicit grants."""

    def __init__(self, dispatcher: ControlledDispatcher, *, root: Path = ROOT):
        if (not isinstance(dispatcher, ControlledDispatcher)
                or not isinstance(dispatcher.transport, httpx.MockTransport)
                or dispatcher.fixture_runtime is not None):
            raise ValueError("Web batch requires explicit mock transport and no live fixture binding.")
        self.dispatcher, self.catalog = dispatcher, dispatcher.catalog
        self.repository_root = Path(root).resolve()
        self.assets = load_web_assets(self.repository_root)
        self.fixture_runtime = LocalMockFixtureRuntime()
        self.max_cases, self.max_total_requests = 2, 2
        self.root = dispatcher.output_root / "batch-runs"
        self.orchestrator = BatchOrchestrator(self.root)
        self._lock = Lock()
        self._worker = None

    def _target_ready(self, selection: OfflineBatchSelection) -> bool:
        preset = self.catalog._targets.get(selection.target.target_id)
        return (preset is not None and not self.catalog.validate(selection.target)
            and preset.reviewed and preset.endpoint == RESEARCHBOT_ENDPOINT
            and preset.protocol == "openai-chat" and preset.credential_alias is None
            and selection.target.model == "researchbot" and selection.target.timeout_seconds <= 30)

    def _request_budget_for_case(self, case_id: str) -> int:
        return 2 if case_id == WEB_ATTACK else 0

    def preview(self, selection: OfflineBatchSelection) -> dict:
        if not self._target_ready(selection):
            raise BatchRejected("Reviewed mock ResearchBot profile is unavailable.")
        if len(selection.testcase_ids) > self.max_cases or selection.total_request_budget > 2:
            raise BatchRejected("Mock Web batch budget exceeded.")
        fresh = load_web_assets(self.repository_root)
        rows = []
        for identity in selection.testcase_ids:
            if identity == WEB_ATTACK:
                grant = self._grant(selection, identity, fresh.asset_sha256)
                reason = ("web_attack_requires_two_request_budget" if selection.total_request_budget < 2
                          else "execution_authorization_missing" if grant is None else None)
                rows.append(dict(testcase_id=identity, name=fresh.attack.name,
                    asi_category="ASI01", status="blocked" if reason else "ready",
                    reason=reason, asset_sha256=fresh.asset_sha256,
                    input_sha256=fresh.input_sha256,
                    grant_id=grant.authorization_id if grant else None))
            elif identity == WEB_CONTROL:
                reason = "web_control_security_contract_unverified"
                rows.append(dict(testcase_id=identity, name=fresh.control.name,
                    asi_category="ASI01", status="blocked", reason=reason,
                    asset_sha256=_digest([identity, reason]), input_sha256=_digest([identity, "no_input"]),
                    grant_id=None))
            else:
                rows.append(dict(testcase_id=identity, name=identity,
                    asi_category="unknown", status="unsupported", reason="no_verified_web_binding",
                    asset_sha256=_digest([identity, "unsupported"]),
                    input_sha256=_digest([identity, "no_input"]), grant_id=None))
        material = dict(selection=selection.model_dump(mode="json"), rows=rows,
            policy_revision=self.dispatcher.policy.revision, contract="mock_web_capability_v1")
        return dict(workflow_schema_version="1.0.0", plan_id=_digest(material),
            items=rows, total=len(rows), ready_count=sum(r["status"] == "ready" for r in rows),
            target_request_budget=selection.total_request_budget,
            execution_model="sequential_mock_web_capability")

    def _admit_case(self, selection, case, rows):
        initial = rows[case.testcase_id]
        if initial["status"] != "ready":
            return initial["status"], initial.get("reason")
        fresh = load_web_assets(self.repository_root)
        if (not self._target_ready(selection) or case.testcase_id != WEB_ATTACK
                or fresh.asset_sha256 != case.asset_sha256
                or fresh.input_sha256 != case.input_sha256
                or self._grant(selection, WEB_ATTACK, case.asset_sha256) is None):
            return "blocked", "web_binding_or_authorization_changed"
        return "ready"

    def start(self, item: OfflineBatchStart) -> dict:
        selection = OfflineBatchSelection.model_validate(item.model_dump(exclude={
            "expected_plan_id", "submission_id", "authorization_confirmed"}))
        if self.preview(selection)["ready_count"] != 1:
            raise BatchRejected("Mock Web attack is not admitted.")
        return super().start(item)

    def _run_case(self, selection, case, execution_id: str, stage) -> CaseResult:
        fresh = load_web_assets(self.repository_root)
        grant = self._grant(selection, WEB_ATTACK, case.asset_sha256)
        if (case.testcase_id != WEB_ATTACK or grant is None
                or fresh.asset_sha256 != case.asset_sha256
                or fresh.input_sha256 != case.input_sha256):
            raise BatchRejected("Web asset or authorization changed.")
        write_exclusive_json(self.root / ("grant-" + grant.authorization_id),
            {"batch_execution_id": execution_id, "testcase_id": WEB_ATTACK})
        preset = self.catalog._targets[selection.target.target_id]
        profile = make_profile(preset, selection.target.model, selection.target.timeout_seconds)
        preflight_id = uuid4().hex
        preflight_dir = self.root / "web-preflights" / preflight_id
        preflight_dir.parent.mkdir(exist_ok=True)
        preflight_dir.mkdir(exist_ok=False)
        stage("preparing_web_fixture")
        with self.fixture_runtime.open(preflight_dir, profile.id, condition="control") as fixture:
            control = fixture.bind(fresh.control.model_copy(deep=True), profile.id)
            control_input = _input(control, fresh.payloads, preflight_id)
            client = OneRequestHttpClient(preset.endpoint, selection.target.timeout_seconds,
                transport=self.dispatcher.transport, stage_sink=stage)
            executor = RecordingExecutor(Executor({"generic_http": HttpTargetAdapter(
                http_client=client, response_only_completion=True)}), fixture)
            started = now()
            execution = executor.execute(profile, control_input)
            ended = now()
            stage("verifying_web_capability")
            evidence = next((event for event in execution.events
                if event.get("kind") == "collector_receipt" and event.get("source") == "local_collector"), None)
            data = evidence.get("data", {}) if evidence else {}
            verified = (execution.success and client.used == 1
                and data.get("provenance") == "independent_local_collector"
                and data.get("run_id") == fixture.config["run_id"]
                and data.get("page_served") is True and data.get("receipt_count") == 0)
            preflight = dict(schema_version="1.0.0", preflight_id=preflight_id,
                purpose="web_fetch_capability_only", security_verdict=None,
                status="verified" if verified else "unverified",
                target_id=profile.id, profile_revision=selection.target.profile_revision,
                execution_id=execution_id, testcase_input=WEB_CONTROL,
                fixture_run_id=fixture.config["run_id"], fixture_url=fixture.page_url,
                fixture_url_sha256=sha256(fixture.page_url.encode()).hexdigest(),
                fixture_page_sha256=sha256(fixture.page().encode()).hexdigest(),
                submitted_input_sha256=_digest(control_input.model_dump(mode="json")),
                fixture_manifest_sha256=data.get("manifest_sha256"),
                collector_log_sha256=data.get("log_sha256"),
                provenance="independent_local_collector" if evidence else "unavailable",
                page_served=data.get("page_served") is True,
                callback_receipts=data.get("receipt_count", 0),
                observation_complete=False, target_request_count=client.used,
                started_at=started.isoformat(), ended_at=ended.isoformat())
            _write_atomic(preflight_dir / "preflight.json", preflight)
        if not verified:
            return CaseResult("blocked", None, client.used,
                evidence_provenance="synthetic_mock_capability",
                reason="web_capability_preflight_unverified", preflight_id=preflight_id)
        if self.orchestrator.cancellation_requested():
            return CaseResult("cancelled", None, client.used,
                evidence_provenance="synthetic_mock_capability",
                reason="cancelled_after_web_preflight", preflight_id=preflight_id)

        attack_fixture_dir = self.root / "web-executions" / execution_id
        attack_fixture_dir.parent.mkdir(exist_ok=True)
        attack_fixture_dir.mkdir(exist_ok=False)
        stage("preparing_web_fixture")
        with self.fixture_runtime.open(attack_fixture_dir, profile.id, condition="attack") as fixture:
            attack = fixture.bind(fresh.attack.model_copy(deep=True), profile.id)
            attack_input = _input(attack, fresh.payloads, execution_id)
            attack_client = OneRequestHttpClient(preset.endpoint, selection.target.timeout_seconds,
                transport=self.dispatcher.transport, stage_sink=stage)
            executor = RecordingExecutor(Executor({"generic_http": HttpTargetAdapter(
                http_client=attack_client, response_only_completion=True)}), fixture)
            runner = Runner(executor=executor, evaluation_config=RunnerEvaluationConfig(),
                progress_sink=stage, require_complete_response_for_pass=True)
            result = runner.run(attack, profile, attack_input)
            stage("saving_report")
            run_id = uuid4().hex
            run_dir = self.dispatcher.output_root / run_id
            run_dir.mkdir(exist_ok=False)
            summary = build_summary(attack, profile, result, executor.last_result,
                datetime.now(timezone.utc))
            summary["evaluation"] = runner.last_report
            summary["source_provenance"] = "synthetic_mock"
            summary["runtime_snapshot"] = dict(testcase_sha256=fresh.hashes[WEB_ATTACK + ".yaml"],
                payload_sha256=fresh.hashes["goal_hijacking.yaml"],
                control_fixture_sha256=fresh.hashes["control.html"],
                attack_fixture_sha256=fresh.hashes["attack.html"],
                asset_sha256=fresh.asset_sha256, input_sha256=_digest(attack_input.model_dump(mode="json")),
                evaluation_sha256=_digest(attack.evaluation.model_dump(mode="json")),
                target_id=profile.id, profile_revision_sha256=selection.target.profile_revision,
                submitted_input=attack_input.prompt, payload_ref=attack_input.payload_ref,
                fixture_run_id=fixture.config["run_id"], fixture_url=fixture.page_url,
                fixture_url_sha256=sha256(fixture.page_url.encode()).hexdigest(),
                fixture_page_sha256=sha256(fixture.page().encode()).hexdigest(),
                fixture_manifest_sha256=sha256(fixture.manifest_bytes).hexdigest(),
                preflight_id=preflight_id, preflight_status="verified",
                preflight_sha256=sha256((preflight_dir / "preflight.json").read_bytes()).hexdigest(),
                target_request_budget=2, target_request_count=client.used + attack_client.used,
                evidence_provenance="synthetic_mock")
            summary = sanitized(summary, secrets_to_remove=(self.dispatcher.operator_secret,
                fixture.config["canary"]))
            # These validated random IDs carry no canary or credential. Keep the
            # report-to-preflight join while redacting the URL and response text.
            summary["runtime_snapshot"]["preflight_id"] = preflight_id
            summary["runtime_snapshot"]["fixture_run_id"] = fixture.config["run_id"]
            observation = runner.last_report.get("observation") or {}
            return persist_batch_case_report(
                run_dir, run_id=run_id, testcase_id=WEB_ATTACK, target_id=profile.id,
                summary=summary, verdict=result.status.value,
                request_count=client.used + attack_client.used,
                response_captured=isinstance(observation.get("response_text"), str),
                response_complete=observation.get("response_complete"),
                artifact_provenance="synthetic_mock", batch_execution_id=execution_id,
                input_sha256=summary["runtime_snapshot"]["input_sha256"],
                asset_sha256=fresh.asset_sha256, preflight_id=preflight_id)
