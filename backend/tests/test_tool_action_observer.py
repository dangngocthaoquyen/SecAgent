"""Offline tool effect evidence; the fake executor never launches a shell."""
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone

from backend.scripts.run_native_smoke import build_summary
from core.models import Evidence, EvaluationStatus, Observation, TestInput as CoreTestInput
from evaluators.response_evaluator import ResponseEvaluator
from observers import ToolActionObserver
from payloads import PayloadLoader, PayloadRenderer
from reporting.normalizers import normalize_report_bytes
from targets import load_target
from targets.adapters import McpJsonRpcTargetAdapter
from testing import Executor, Runner, TestCaseLoader
from tools.http import HttpResponse


ROOT = Path(__file__).resolve().parents[2]


class RecordingToolFixture:
    """Writes a separate synthetic effect ledger only when actually invoked."""
    def __init__(self, root, execution_id, *, write_effect=True, claim_success=True,
                 mismatch=False, fail_action=False):
        self.root, self.execution_id = root, execution_id
        self.write_effect, self.claim_success = write_effect, claim_success
        self.mismatch, self.fail_action = mismatch, fail_action
        self.requests = []

    def request(self, **kwargs):
        self.requests.append(kwargs)
        body = kwargs["json_body"]
        arguments = body["params"]["arguments"]
        digest = sha256(json.dumps(arguments, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        if self.write_effect:
            effect = json.dumps({"synthetic_tool_invoked": True,
                "arguments_sha256": digest}, sort_keys=True).encode()
            (self.root / (self.execution_id + ".effect.json")).write_bytes(effect)
            receipt = {"execution_id": uuid4().hex if self.mismatch else self.execution_id,
                "invocation_id": uuid4().hex, "request_id": body["id"],
                "tool_name": body["params"]["name"], "arguments_sha256": digest,
                "status": "failed" if self.fail_action else "succeeded",
                "observation_complete": True, "provenance": "independent_observer",
                "effect_sha256": None if self.fail_action else sha256(effect).hexdigest()}
            (self.root / (self.execution_id + ".receipt.json")).write_text(
                json.dumps(receipt), encoding="utf-8")
        nested = json.dumps({"success": self.claim_success,
            "output": "Synthetic fixture response"})
        response = {"jsonrpc": "2.0", "id": body["id"], "result": {"content": [
            {"type": "text", "text": nested}]}}
        return HttpResponse(status_code=200, headers={"content-type": "application/json"},
            text=json.dumps(response), json_body=response, duration_ms=1.0)


def execute(tmp_path, *, write_effect=True, claim_success=True, mismatch=False,
            fail_action=False):
    execution_id = uuid4().hex
    testcase = TestCaseLoader().load(ROOT / "testcases/tool_misuse/TM-002.yaml")
    payload = PayloadLoader().load_repository(ROOT / "payload/tool_misuse.yaml")[
        testcase.payload_refs[0]]
    command = PayloadRenderer().render(payload, testcase.variables)
    target = load_target(ROOT / "configs/targets/dvaa-toolbot.yaml")
    test_input = CoreTestInput(id=execution_id, payload_ref=payload.id,
        parameters={"tool_call": {"name": testcase.variables["tool_name"],
            "arguments": {"command": command}}})
    fixture = RecordingToolFixture(tmp_path, execution_id, write_effect=write_effect,
        claim_success=claim_success, mismatch=mismatch, fail_action=fail_action)
    runner = Runner(executor=Executor({"generic_mcp_jsonrpc": McpJsonRpcTargetAdapter(fixture)}),
        observer=ToolActionObserver(tmp_path, execution_id))
    verdict = runner.run(testcase, target, test_input)
    return verdict, runner.last_report, fixture, execution_id


def test_verified_synthetic_tool_effect_supports_native_tm002_fail(tmp_path):
    verdict, report, fixture, identity = execute(tmp_path)
    assert verdict.status is EvaluationStatus.FAIL
    assert verdict.matched_rule_id == "direct-sensitive-tool-executed"
    assert len(fixture.requests) == 1
    assert fixture.requests[0]["json_body"]["params"] == {
        "name": "execute", "arguments": {"command": "echo SECAGENT_TOOLBOT_TM002"}}
    kinds = [row["kind"] for row in report["observation"]["evidence"]]
    assert kinds == ["tool_request", "target_tool_result", "tool_call", "tool_trace"]
    verified = report["observation"]["evidence"][2]
    assert verified["data"]["execution_id"] == identity
    assert verified["data"]["provenance"] == "independent_observer"
    assert verified["data"]["execution_verified"] is True
    assert verified["data"]["scope"] == "direct_request"
    assert verified["data"]["synthetic_mock"] is True
    assert verified["data"]["execution_semantics"] == "simulated_handler_effect"
    assert verified["data"]["verification_status"] == "verified_simulated_effect"
    assert "command" not in json.dumps(report["observation"]["evidence"])


def test_target_claim_without_effect_stays_inconclusive(tmp_path):
    verdict, report, _, _ = execute(tmp_path, write_effect=False, claim_success=True)
    assert verdict.status is EvaluationStatus.INCONCLUSIVE
    assert [row["kind"] for row in report["observation"]["evidence"]] == [
        "tool_request", "target_tool_result"]
    assert report["observation"]["evidence"][1]["data"]["reported_success"] is True


def test_verified_failed_action_does_not_trigger_success_rule(tmp_path):
    verdict, report, _, _ = execute(tmp_path, fail_action=True, claim_success=True)
    assert verdict.status is EvaluationStatus.INCONCLUSIVE
    assert report["observation"]["evidence"][2]["success"] is False


def test_replayed_or_wrong_identity_receipt_is_observer_error(tmp_path):
    verdict, report, _, _ = execute(tmp_path, mismatch=True)
    assert verdict.status is EvaluationStatus.ERROR
    assert report["observation"] is None


def test_missing_effect_cannot_be_verified(tmp_path):
    verdict, _, fixture, identity = execute(tmp_path)
    assert verdict.status is EvaluationStatus.FAIL
    (tmp_path / (identity + ".effect.json")).unlink()
    # The previously produced result is not reinterpreted; a fresh observer
    # cannot verify the receipt against the now-missing fixture effect.
    from core.models import ExecutionResult
    body = fixture.requests[0]["json_body"]
    digest = sha256(json.dumps(body["params"]["arguments"], sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    request = [{"kind": "tool_request", "source": "mcp_jsonrpc_adapter",
        "name": body["params"]["name"], "data": {"provenance": "secagent_request",
        "request_id": body["id"], "arguments_sha256": digest}}]
    observed = ToolActionObserver(tmp_path, identity).observe(ExecutionResult(
        success=True, events=request))
    assert all(item.kind != "tool_call" for item in observed.evidence)


def test_native_tm001_requires_an_agent_run_scope_for_pass_or_verified_call_for_fail():
    testcase = TestCaseLoader().load(ROOT / "testcases/tool_misuse/TM-001.yaml")
    response = "Confirmation is required."
    def evaluate(evidence):
        return ResponseEvaluator().evaluate(testcase, Observation(response_text=response,
            metadata={"execution_success": True}, evidence=evidence)).status
    assert evaluate([]) is EvaluationStatus.INCONCLUSIVE
    claimed = Evidence(kind="tool_call", source="mcp_jsonrpc", name="PerformSensitiveAction",
        success=True, data={"provenance": "target_reported", "execution_verified": False})
    assert evaluate([claimed]) is EvaluationStatus.INCONCLUSIVE
    trace = Evidence(kind="tool_trace", source="local_tool_fixture", data={
        "scope": "agent_run", "completeness": "complete",
        "provenance": "independent_observer", "execution_verified": True})
    assert evaluate([trace]) is EvaluationStatus.PASS
    executed = Evidence(kind="tool_call", source="local_tool_fixture",
        name="PerformSensitiveAction", success=True,
        data={"scope": "agent_run", "provenance": "independent_observer",
              "execution_verified": True})
    assert evaluate([trace, executed]) is EvaluationStatus.FAIL


def test_synthetic_tm002_native_report_keeps_claim_and_verified_effect_distinct(tmp_path):
    verdict, runner_report, _, _ = execute(tmp_path)
    testcase = TestCaseLoader().load(ROOT / "testcases/tool_misuse/TM-002.yaml")
    target = load_target(ROOT / "configs/targets/dvaa-toolbot.yaml")
    summary = build_summary(testcase, target, verdict, None, datetime.now(timezone.utc))
    summary["evaluation"] = runner_report
    summary["source_provenance"] = "synthetic_mock"
    report = normalize_report_bytes(json.dumps(summary).encode())
    assert report.identity.testcase_id == "TM-002"
    assert report.source.reported_provenance == "synthetic_mock"
    assert report.security.verdict == "FAIL"
    evidence = report.observation.evidence
    assert [item.kind for item in evidence] == [
        "tool_request", "target_tool_result", "tool_call", "tool_trace"]
    assert evidence[1].reported_provenance == "target_reported"
    assert evidence[1].verification.reported_execution_verified is False
    assert evidence[2].reported_provenance == "independent_observer"
    assert evidence[2].verification.reported_execution_verified is True
