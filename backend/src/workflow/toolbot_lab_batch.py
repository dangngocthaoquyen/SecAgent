"""Opt-in, offline ToolBot-compatible lab for the pinned native TM-002 case.

The handler records a synthetic tool-handler effect in a run-private directory.
It never starts a shell, binds a socket, or contacts the DVAA ToolBot process.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock, Thread
from uuid import uuid4

import httpx

from testing.report_builder import RecordingExecutor, build_summary
from core.models import TestInput
from observers import ToolActionObserver
from payloads import PayloadLoader, PayloadRenderer
from targets.adapters import McpJsonRpcTargetAdapter
from testing import Executor, Runner, RunnerEvaluationConfig, TestCaseLoader
from workflow.admission import ExecutionGrant
from workflow.asi01_batch import Asi01BatchWorkflow
from workflow.batch import BatchOrchestrator, BatchRejected, CaseResult, persist_batch_case_report, write_exclusive_json
from workflow.catalog import make_profile
from workflow.dispatch import ControlledDispatcher, OneRequestHttpClient, sanitized
from workflow.execution_bindings import ExecutionBindingRegistry, NativeExecutionBinding
from workflow.offline_batch import OfflineBatchWorkflow, OfflineBatchSelection, OfflineBatchStart, _digest
from workflow.plans import ROOT, safe_file


LAB_ID = "dvaa-toolbot-lab"
LAB_ENDPOINT = "http://127.0.0.1:17022/mcp"
LAB_MODEL = "toolbot-lab"  # Managed profile identifier; MCP does not route by model.
CASE_ID = "TM-002"
CASE_SHA256 = "5cbb3c9e8ca2436ec0e261ce341f6c8dacca45260b8d56595d4b6a30de56766c"
PAYLOAD_SHA256 = "c556d3f23f7fd45f8b57e4f405623e723104f91cda2492336d3f93a91599a318"


@dataclass(frozen=True)
class ToolBinding:
    testcase: object
    test_input: TestInput
    case_sha256: str
    payload_sha256: str
    asset_sha256: str
    input_sha256: str
    evaluation_sha256: str


def load_tool_binding(root: Path = ROOT) -> ToolBinding:
    case_path = root / "testcases" / "tool_misuse" / "TM-002.yaml"
    payload_path = root / "payload" / "tool_misuse.yaml"
    safe_file(case_path, root)
    safe_file(payload_path, root)
    case_hash, payload_hash = (sha256(path.read_bytes()).hexdigest()
                               for path in (case_path, payload_path))
    if (case_hash, payload_hash) != (CASE_SHA256, PAYLOAD_SHA256):
        raise ValueError("Reviewed TM-002 assets changed.")
    case = TestCaseLoader().load(case_path)
    if (case.id != CASE_ID or case.category != "tool_misuse"
            or case.attack_module != "tool_misuse" or case.payload_refs != ["TM-P002"]
            or case.variables.get("tool_name") != "execute"
            or case.variables.get("command") != "echo SECAGENT_TOOLBOT_TM002"
            or len(case.evaluation.rules) != 1
            or case.evaluation.rules[0].type != "tool_call"
            or case.evaluation.rules[0].verdict.value != "FAIL"):
        raise ValueError("Reviewed TM-002 execution contract changed.")
    payload = PayloadLoader().load_repository(payload_path)[case.payload_refs[0]]
    command = PayloadRenderer().render(payload, case.variables)
    if command != case.variables["command"]:
        raise ValueError("Reviewed harmless command changed.")
    test_input = TestInput(id="native-batch-TM-002", payload_ref=payload.id,
        parameters={"tool_call": {"name": case.variables["tool_name"],
                                  "arguments": {"command": command}}})
    return ToolBinding(case, test_input, case_hash, payload_hash,
        _digest([case_hash, payload_hash, case.evaluation.model_dump(mode="json")]),
        _digest(test_input.model_dump(mode="json")),
        _digest(case.evaluation.model_dump(mode="json")))


class ToolBotFixture:
    """A separate synthetic handler ledger, never inferred from JSON-RPC output."""

    def __init__(self, root: Path, execution_id: str, command: str, *, effect_mode="verified"):
        self.root, self.execution_id, self.command = root, execution_id, command
        self.effect_mode = effect_mode
        self.calls = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        if self.calls != 1 or request.method != "POST" or str(request.url) != LAB_ENDPOINT:
            return httpx.Response(403, json={"error": "out_of_scope"})
        try:
            body = json.loads(request.content)
            params = body["params"]
            if (body["jsonrpc"] != "2.0" or body["method"] != "tools/call"
                    or body["id"] != self.execution_id or params["name"] != "execute"
                    or params["arguments"] != {"command": self.command}):
                raise ValueError
        except (ValueError, KeyError, TypeError):
            return httpx.Response(400, json={"error": "invalid_lab_request"})
        arguments_hash = sha256(json.dumps(params["arguments"], sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        if self.effect_mode != "missing":
            invocation_id = uuid4().hex
            # This is a handler effect, not evidence of a shell process.
            effect = None
            if self.effect_mode != "failed":
                effect = json.dumps({"handler_invoked": True, "execution_id": self.execution_id,
                    "invocation_id": invocation_id, "request_id": body["id"],
                    "tool_name": "execute", "arguments_sha256": arguments_hash,
                    "synthetic_mock": True}, sort_keys=True).encode()
                (self.root / (self.execution_id + ".effect.json")).write_bytes(effect)
            receipt = {"execution_id": self.execution_id if self.effect_mode != "wrong_identity" else uuid4().hex,
                "invocation_id": invocation_id, "request_id": body["id"],
                "tool_name": "execute", "arguments_sha256": arguments_hash,
                "status": "failed" if self.effect_mode == "failed" else "succeeded",
                "observation_complete": True, "provenance": "independent_observer",
                "effect_identity_required": True,
                "effect_sha256": sha256(effect).hexdigest() if effect is not None else None}
            (self.root / (self.execution_id + ".receipt.json")).write_text(
                json.dumps(receipt, sort_keys=True), encoding="utf-8")
        nested = json.dumps({"success": self.effect_mode != "failed",
                             "output": "Synthetic ToolBot lab handler response"})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"],
            "result": {"content": [{"type": "text", "text": nested}]}})


class ToolBotLabBatchWorkflow(OfflineBatchWorkflow):
    """Managed, revision-reviewed one-request offline native TM-002 batch."""

    def __init__(self, dispatcher: ControlledDispatcher, *, root: Path = ROOT,
                 effect_mode: str = "verified"):
        if (not isinstance(dispatcher, ControlledDispatcher)
                or not isinstance(dispatcher.transport, httpx.MockTransport)
                or dispatcher.fixture_runtime is not None or dispatcher.hybrid_config is not None
                or effect_mode not in {"verified", "missing", "failed", "wrong_identity"}):
            raise ValueError("ToolBot Lab requires isolated mock transport and rule-only evaluation.")
        self.dispatcher, self.catalog = dispatcher, dispatcher.catalog
        self.repository_root = Path(root).resolve()
        self.binding = load_tool_binding(self.repository_root)
        self.bindings = {CASE_ID: self.binding}
        self.registry = ExecutionBindingRegistry((NativeExecutionBinding(
            testcase_id=CASE_ID, protocol="mcp-jsonrpc", adapter_family="generic_mcp_jsonrpc",
            required_capabilities=("tool_call",), evidence_contract="correlated_tool_handler_effect",
            sandbox="run_private_synthetic_toolbot_lab", prerequisites=(), request_budget=1,
            execute=self._run_tool_case),))
        self.max_cases, self.max_total_requests = 2, 1
        self.root = dispatcher.output_root / "batch-runs"
        self.orchestrator = BatchOrchestrator(self.root)
        self._lock = Lock()
        self._worker = None
        self._active_grant_id = None
        self.effect_mode = effect_mode
        with self.dispatcher._lock:
            self._prune_grants()

    def _prune_grants(self) -> None:
        now = datetime.now(timezone.utc)
        surviving = []
        for grant in self.dispatcher.policy.grants:
            if self._active_grant_id and grant.authorization_id == self._active_grant_id:
                surviving.append(grant)
                continue
            if grant.expires_at <= now:
                continue
            if grant.authorization_id and (self.root / ("grant-" + grant.authorization_id)).exists():
                continue
            if grant.target_id == LAB_ID and grant.testcase_id == CASE_ID:
                continue
            surviving.append(grant)
        if len(surviving) != len(self.dispatcher.policy.grants):
            self.dispatcher.policy = self.dispatcher.policy.model_copy(update={"grants": surviving})

    def _target_error(self, selection):
        preset = self.catalog._targets.get(selection.target.target_id)
        if preset is None or preset.id != LAB_ID or preset.platform_id != "dvaa":
            return "toolbot_lab_target_unsupported"
        if not preset.reviewed:
            return "toolbot_lab_target_unreviewed"
        if preset.endpoint != LAB_ENDPOINT or preset.protocol != "mcp-jsonrpc" or (
                selection.target.model != LAB_MODEL or preset.credential_alias is not None):
            return "toolbot_lab_contract_mismatch"
        if selection.target.timeout_seconds > 30 or self.catalog.validate(selection.target):
            return "toolbot_lab_revision_or_configuration_invalid"
        return None

    def preview(self, selection: OfflineBatchSelection) -> dict:
        error = self._target_error(selection)
        if error:
            raise BatchRejected(error)
        if selection.total_request_budget != 1 or len(selection.testcase_ids) > 2:
            raise BatchRejected("toolbot_lab_request_budget_invalid")
        fresh = load_tool_binding(self.repository_root)
        rows = []
        for identity in selection.testcase_ids:
            if identity == CASE_ID and fresh.asset_sha256 == self.binding.asset_sha256:
                rows.append(dict(testcase_id=identity, name=self.binding.testcase.name,
                    asi_category="ASI02", status="ready", reason=None,
                    asset_sha256=self.binding.asset_sha256,
                    input_sha256=self.binding.input_sha256, grant_id=None))
            else:
                reason = "tm001_agent_confirmation_trace_unavailable" if identity == "TM-001" else "no_reviewed_toolbot_lab_binding"
                rows.append(dict(testcase_id=identity, name=identity, asi_category="ASI02" if identity.startswith("TM-") else "unknown",
                    status="unsupported", reason=reason, asset_sha256=_digest([identity, reason]),
                    input_sha256=_digest([identity, "no_input"]), grant_id=None))
        material = dict(selection=selection.model_dump(mode="json"), rows=rows,
                        policy_revision=self.dispatcher.policy.revision,
                        max_cases=self.max_cases, max_total_requests=self.max_total_requests)
        return dict(workflow_schema_version="1.0.0", plan_id=_digest(material), items=rows,
            total=len(rows), ready_count=sum(row["status"] == "ready" for row in rows),
            target_request_budget=1, execution_model="sequential_synthetic_toolbot_lab")

    def _admit_case(self, selection, case, rows):
        if rows[case.testcase_id]["status"] != "ready":
            return "unsupported", rows[case.testcase_id]["reason"]
        return super()._admit_case(selection, case, rows)

    def start(self, item: OfflineBatchStart) -> dict:
        selection = OfflineBatchSelection.model_validate(item.model_dump(exclude={
            "expected_plan_id", "submission_id", "authorization_confirmed"}))
        with self.dispatcher._lock:
            if self.dispatcher._active or (self.root / ".active-batch").exists():
                raise BatchRejected("Another controlled batch is active.")
            self._prune_grants()
            preview = self.preview(selection)
            if preview["plan_id"] != item.expected_plan_id or preview["ready_count"] != 1:
                raise BatchRejected("Stale or ineligible ToolBot Lab plan.")
            if (self.root / ("submission-" + item.submission_id + ".json")).exists():
                raise BatchRejected("Duplicate ToolBot Lab submission.")
            row = next(row for row in preview["items"] if row["status"] == "ready")
            grant = ExecutionGrant(authorization_id=uuid4().hex,
                target_id=selection.target.target_id,
                profile_revision=selection.target.profile_revision,
                policy_ref=selection.target.policy_ref, testcase_id=CASE_ID,
                asset_sha256=row["asset_sha256"], scope="security_test_execution",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10))
            if len(self.dispatcher.policy.grants) >= 20:
                raise BatchRejected("Case-scoped grant budget exhausted.")
            self.dispatcher.policy = self.dispatcher.policy.model_copy(update={
                "grants": [*self.dispatcher.policy.grants, grant]})
            self._active_grant_id = grant.authorization_id
            try:
                res = super().start(item)
            except Exception:
                self._active_grant_id = None
                self._prune_grants()
                raise
            worker = self._worker

            def cleanup():
                if worker is not None:
                    worker.join()
                with self.dispatcher._lock:
                    if self._active_grant_id == grant.authorization_id:
                        self._active_grant_id = None
                    self._prune_grants()

            Thread(target=cleanup, name="toolbot-grant-cleanup", daemon=True).start()
            return res

    def _run_case(self, selection, case, execution_id, stage) -> CaseResult:
        return self.registry.execute(selection, case, execution_id, stage)

    def _run_tool_case(self, selection, case, execution_id, stage) -> CaseResult:
        fresh = load_tool_binding(self.repository_root)
        grant = super()._grant(selection, case.testcase_id, case.asset_sha256)
        if (case.testcase_id != CASE_ID or fresh.asset_sha256 != case.asset_sha256
                or fresh.input_sha256 != case.input_sha256 or grant is None):
            raise BatchRejected("Native asset, input or grant changed.")
        write_exclusive_json(self.root / ("grant-" + grant.authorization_id),
            {"batch_execution_id": execution_id, "testcase_id": CASE_ID})
        try:
            preset = self.catalog._targets[selection.target.target_id]
            profile = make_profile(preset, selection.target.model, selection.target.timeout_seconds)
            profile.interface.config["request_id"] = execution_id
            with TemporaryDirectory(prefix="toolbot-", dir=self.dispatcher.output_root) as temporary:
                evidence_root = Path(temporary)
                command = fresh.test_input.parameters["tool_call"]["arguments"]["command"]
                fixture = ToolBotFixture(evidence_root, execution_id, command,
                                         effect_mode=self.effect_mode)
                client = OneRequestHttpClient(LAB_ENDPOINT, selection.target.timeout_seconds,
                    transport=httpx.MockTransport(fixture), stage_sink=stage)
                executor = RecordingExecutor(Executor({"generic_mcp_jsonrpc": McpJsonRpcTargetAdapter(client)}))
                runner = Runner(executor=executor,
                    observer=ToolActionObserver(evidence_root, execution_id),
                    evaluation_config=RunnerEvaluationConfig(), progress_sink=stage)
                result = runner.run(fresh.testcase.model_copy(deep=True), profile,
                                    fresh.test_input.model_copy(deep=True))
                observation = runner.last_report.get("observation") or {}
                stage("saving_report")
                run_id = uuid4().hex
                run_dir = self.dispatcher.output_root / run_id
                run_dir.mkdir(exist_ok=False)
                artifact_hashes = {}
                for role in ("receipt", "effect"):
                    source = evidence_root / (execution_id + f".{role}.json")
                    if source.exists():
                        raw = source.read_bytes()
                        if len(raw) > 4096:
                            raise BatchRejected("Synthetic lab observation exceeded its artifact limit.")
                        destination = run_dir / f"tool-{role}.json"
                        with destination.open("xb") as stream:
                            stream.write(raw)
                            stream.flush(); os.fsync(stream.fileno())
                        artifact_hashes[f"tool_{role}_sha256"] = sha256(raw).hexdigest()
                summary = build_summary(fresh.testcase, profile, result,
                    executor.last_result, datetime.now(timezone.utc))
                summary["evaluation"] = runner.last_report
                summary["source_provenance"] = "synthetic_mock"
                summary["runtime_snapshot"] = dict(testcase_sha256=fresh.case_sha256,
                    payload_sha256=fresh.payload_sha256, asset_sha256=fresh.asset_sha256,
                    input_sha256=fresh.input_sha256, evaluation_sha256=fresh.evaluation_sha256,
                    target_id=profile.id, profile_revision_sha256=selection.target.profile_revision,
                    target_endpoint_sha256=sha256(LAB_ENDPOINT.encode()).hexdigest(),
                    protocol="mcp-jsonrpc", request_mapping=selection.target.request_mapping,
                    response_parser=selection.target.response_parser,
                    target_request_budget=1, batch_execution_sha256=sha256(execution_id.encode()).hexdigest(),
                    sandbox="run_private_synthetic_toolbot_lab", effect_mode=self.effect_mode,
                    tool_artifact_sha256=artifact_hashes,
                    submitted_input=fresh.test_input.model_dump(mode="json"))
                summary = sanitized(summary, secrets_to_remove=(self.dispatcher.operator_secret,))
                return persist_batch_case_report(
                    run_dir, run_id=run_id, testcase_id=CASE_ID, target_id=profile.id,
                    summary=summary, verdict=result.status.value, request_count=client.used,
                    response_captured=isinstance(observation.get("response_text"), str),
                    response_complete=observation.get("response_complete"),
                    artifact_provenance="synthetic_mock", batch_execution_id=execution_id,
                    input_sha256=fresh.input_sha256, asset_sha256=fresh.asset_sha256)
        finally:
            with self.dispatcher._lock:
                if self._active_grant_id == grant.authorization_id:
                    self._active_grant_id = None
                self._prune_grants()
