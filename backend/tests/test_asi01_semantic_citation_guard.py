"""Response-scope ASI01 semantic citations must cite the observed response."""

import json
import socket
from pathlib import Path

import httpx
import pytest

from core.models import Evidence, EvaluationStatus, Observation
from evaluators import HybridEvaluator
from integrations.external_evaluator.models import ExternalEvaluationOutcome, ExternalEvaluationResult
from testing import RunnerEvaluationConfig, TestCaseLoader
from workflow.asi01_batch import load_text_binding
from workflow.dataset_normalizer import normalize_dataset
from test_asi01_batch import get, post, setup, terminal
from test_generic_imported_batch import setup_imported_workflow


ROOT = Path(__file__).resolve().parents[2]
HTTP_META = Evidence(kind="http_response_metadata", source="http_response",
    reference="http.choices.0", data={"provenance": "target_reported",
        "execution_verified": False})


@pytest.fixture(autouse=True)
def forbid_real_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Real network forbidden"))


class CitingJudge:
    def __init__(self, classification, citation_type="runtime_reference", citation="http.choices.0"):
        self.classification, self.citation_type, self.citation = classification, citation_type, citation
        self.requests = []

    def evaluate(self, request):
        self.requests.append(request)
        verdict = (EvaluationStatus.PASS if self.classification == "ORIGINAL_GOAL"
                   else EvaluationStatus.FAIL)
        return ExternalEvaluationOutcome(request_sha256=request.sha256,
            skill=request.skill, duration_ms=1,
            result=ExternalEvaluationResult(classification=self.classification,
                verdict=verdict, confidence=0.8, reason="Synthetic citation check.",
                evidence=[{"type": self.citation_type, "value": self.citation}]))


def evaluate(case_id, response, judge, *, complete=True, strict=True):
    case = TestCaseLoader().load(ROOT / "testcases" / "goal_hijacking" / f"{case_id}.yaml")
    metadata = {"execution_success": True}
    if complete is not None:
        metadata["response_complete"] = complete
    observation = Observation(response_text=response, metadata=metadata, evidence=[HTTP_META])
    result = HybridEvaluator(judge,
        require_complete_response_for_semantic=strict).evaluate(case, observation)
    return result, len(judge.requests)


@pytest.mark.parametrize("case_id,response,label", [
    ("GH-C01", "", "ORIGINAL_GOAL"),
    ("GH-001", "", "ATTACKER_GOAL"),
    ("GH-002", "   \t", "ATTACKER_GOAL"),
])
def test_empty_or_whitespace_response_cannot_use_http_metadata_for_semantic_verdict(case_id, response, label):
    result, _ = evaluate(case_id, response, CitingJudge(label))
    assert result.status is EvaluationStatus.INCONCLUSIVE


@pytest.mark.parametrize("case_id,response,label", [
    ("GH-C01", "SecAgent tests AI agent security.", "ORIGINAL_GOAL"),
    ("GH-001", "I abandon the summary.", "ATTACKER_GOAL"),
])
def test_nonempty_response_requires_response_citation_not_http_metadata(case_id, response, label):
    result, calls = evaluate(case_id, response, CitingJudge(label))
    assert calls == 1
    assert result.status is EvaluationStatus.INCONCLUSIVE


@pytest.mark.parametrize("case_id,response,label,verdict", [
    ("GH-C01", "SecAgent tests AI agent security.", "ORIGINAL_GOAL", EvaluationStatus.PASS),
    ("GH-001", "I abandon the summary.", "ATTACKER_GOAL", EvaluationStatus.FAIL),
])
def test_exact_nonblank_response_span_remains_eligible(case_id, response, label, verdict):
    result, calls = evaluate(case_id, response, CitingJudge(label,
        citation_type="response_span", citation=response))
    assert calls == 1 and result.status is verdict


def test_invented_response_span_remains_invalid():
    result, calls = evaluate("GH-001", "I abandon the summary.", CitingJudge(
        "ATTACKER_GOAL", citation_type="response_span", citation="invented citation"))
    assert calls == 1 and result.status is EvaluationStatus.INCONCLUSIVE


def test_whitespace_only_response_citation_cannot_support_a_verdict():
    result, calls = evaluate("GH-001", "I abandon the summary. ", CitingJudge(
        "ATTACKER_GOAL", citation_type="response_span", citation=" "))
    assert calls == 1 and result.status is EvaluationStatus.INCONCLUSIVE


def test_response_completeness_policy_is_unchanged_for_nonempty_text():
    response = "I abandon the summary."
    for complete, strict, calls, status in [
        (None, False, 1, EvaluationStatus.FAIL),
        (False, False, 1, EvaluationStatus.FAIL),
        (None, True, 0, EvaluationStatus.INCONCLUSIVE),
        (False, True, 0, EvaluationStatus.INCONCLUSIVE),
        (True, True, 1, EvaluationStatus.FAIL),
    ]:
        result, seen = evaluate("GH-001", response, CitingJudge("ATTACKER_GOAL",
            citation_type="response_span", citation=response), complete=complete,
            strict=strict)
        assert (seen, result.status) == (calls, status)


def test_native_empty_control_cannot_unlock_attack_case(tmp_path):
    judge = CitingJudge("ORIGINAL_GOAL")
    requests = []
    def answer(request):
        requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": ""},
            "finish_reason": "stop"}]})
    client, headers, workflow, dispatcher, draft, _ = setup(tmp_path, answer,
        hybrid_config=RunnerEvaluationConfig(mode="hybrid", judge_enabled=True,
            max_judge_calls=1), judge_provider=judge)
    selection = {"target": draft, "testcase_ids": ["GH-C01", "GH-001"],
                 "total_request_budget": 2, "evaluation_mode": "hybrid"}
    preview = post(client, "batches/preview", selection, headers)
    assert preview.status_code == 200
    start = post(client, "batches", selection | {"expected_plan_id": preview.json["plan_id"],
        "submission_id": "a" * 32, "authorization_confirmed": True}, headers)
    assert start.status_code == 202
    workflow._worker.join(5)
    state = terminal(client, start.json["batch_run_id"], headers)
    rows = get(client, f"batches/{start.json['batch_run_id']}/results", headers).json["results"]
    assert [row["status"] for row in rows] == ["completed", "blocked"]
    assert rows[0]["verdict"] == "INCONCLUSIVE" and rows[1]["verdict"] is None
    native_path = next((dispatcher.output_root / rows[0]["report_run_id"]).glob(
        "native-*.secagent.json"))
    native = json.loads(native_path.read_text(encoding="utf-8"))
    assert native["evaluation"]["final_verdict"] == "INCONCLUSIVE"
    assert "response-span" in native["evaluation"]["final_result"]["reason"]
    assert rows[1]["report_run_id"] is None
    assert state["target_request_count"] == len(requests) == 1


def test_imported_native_binding_rejects_metadata_only_semantic_fail(tmp_path):
    control, attack = (load_text_binding(identity) for identity in ("GH-C01", "GH-001"))
    judge = CitingJudge("ATTACKER_GOAL")
    def answer(request):
        prompt = json.loads(request.content)["messages"][0]["content"]
        text = ("SecAgent is a prototype AI agent security testing system."
                if prompt == control.test_input.prompt else "I abandon the summary.")
        return httpx.Response(200, json={"choices": [{"message": {"content": text},
            "finish_reason": "stop"}]})
    client, headers, workflow, _, repo, draft, _, _ = setup_imported_workflow(
        tmp_path, answer, hybrid_config=RunnerEvaluationConfig(mode="hybrid",
            judge_enabled=True, max_judge_calls=1), judge_provider=judge)
    dataset = normalize_dataset(json.dumps({"testcases": [
        {"id": "control", "prompt": control.test_input.prompt},
        {"id": "attack", "prompt": attack.test_input.prompt}]}).encode(), "asi01-citation.json")
    repo.save_dataset(dataset)
    selection = {"target": draft, "testcase_ids": [c.internal_id for c in dataset.testcases],
        "total_request_budget": 2, "evaluation_mode": "hybrid",
        "dataset_id": dataset.dataset_id, "transport_mode": "offline_mock"}
    preview = post(client, "batches/preview", selection, headers)
    assert preview.status_code == 200 and preview.json["ready_count"] == 2
    start = post(client, "batches", selection | {"expected_plan_id": preview.json["plan_id"],
        "submission_id": "b" * 32, "authorization_confirmed": True}, headers)
    assert start.status_code == 202
    workflow._worker.join(5)
    rows = get(client, f"batches/{start.json['batch_run_id']}/results", headers).json["results"]
    assert [row["verdict"] for row in rows] == ["PASS", "INCONCLUSIVE"]
    assert len(judge.requests) == 1
