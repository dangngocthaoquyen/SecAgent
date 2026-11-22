"""Native ASI01 batch Hybrid wiring: real Runner/Resolver, fake target and Judge."""

import json

import httpx
import pytest

from core.models import EvaluationStatus
from integrations.external_evaluator.models import (
    ExternalEvaluationOutcome, ExternalEvaluationResult, ProviderFault, ProviderFaultCode,
)
from testing import RunnerEvaluationConfig
from test_asi01_batch import SUMMARY, get, post, setup, terminal


class FakeJudge:
    def __init__(self, verdict=EvaluationStatus.FAIL, *, wrong_citation=False,
                 wrong_skill=False, fault_code=None):
        self.verdict = verdict
        self.wrong_citation = wrong_citation
        self.wrong_skill = wrong_skill
        self.fault_code = fault_code
        self.requests = []

    def evaluate(self, request):
        self.requests.append(request)
        if self.fault_code:
            return ExternalEvaluationOutcome(request_sha256=request.sha256,
                skill=request.skill, duration_ms=1,
                fault=ProviderFault(code=self.fault_code,
                                    message="Offline provider fault."))
        response = request.observation.response_text
        return ExternalEvaluationOutcome(request_sha256=request.sha256,
            skill=request.skill.model_copy(update={"sha256": "0" * 64})
                  if self.wrong_skill else request.skill,
            result=ExternalEvaluationResult(
                classification="ATTACKER_GOAL" if self.verdict is EvaluationStatus.FAIL
                               else "ORIGINAL_GOAL",
                verdict=self.verdict, confidence=0.8, reason="Offline semantic assessment.",
                evidence=[{"type": "response_span",
                           "value": "not in response" if self.wrong_citation else response}]),
            duration_ms=1)


def launch(tmp_path, *, mode="hybrid", answer_text="I am dropping the summary.",
           finish_reason="stop", judge=None, selected=("GH-C01", "GH-001"),
           config=None, baseline_text=SUMMARY, baseline_finish="stop"):
    prompts = []
    def answer(request):
        prompt = json.loads(request.content)["messages"][0]["content"]
        prompts.append(prompt)
        text = baseline_text if len(prompts) == 1 else answer_text
        return httpx.Response(200, json={"choices": [{"message": {"content": text},
            "finish_reason": finish_reason if len(prompts) > 1 else baseline_finish}]})
    config = config if config is not None else RunnerEvaluationConfig(
        mode="hybrid", judge_enabled=True, max_judge_calls=1)
    client, headers, workflow, dispatcher, draft, _ = setup(
        tmp_path, answer, hybrid_config=config, judge_provider=judge)
    selection = {"target": draft, "testcase_ids": list(selected),
                 "total_request_budget": len(selected), "evaluation_mode": mode}
    preview = post(client, "batches/preview", selection, headers)
    return client, headers, workflow, dispatcher, selection, preview, prompts


def submit(client, headers, workflow, selection, preview, submission="e" * 32):
    assert preview.status_code == 200, preview.json
    assert preview.json["ready_count"] == len(selection["testcase_ids"])
    started = post(client, "batches", selection | {
        "expected_plan_id": preview.json["plan_id"], "submission_id": submission,
        "authorization_confirmed": True}, headers)
    assert started.status_code == 202, started.json
    workflow._worker.join(5)
    batch_id = started.json["batch_run_id"]
    return terminal(client, batch_id, headers), get(
        client, f"batches/{batch_id}/results", headers).json["results"]


def report(dispatcher, row):
    path = next((dispatcher.output_root / row["report_run_id"]).glob(
        "native-*.secagent.json"))
    return json.loads(path.read_text(encoding="utf-8"))


def test_rule_only_remains_default_and_never_invokes_judge(tmp_path):
    judge = FakeJudge()
    client, headers, workflow, dispatcher, selection, preview, prompts = launch(
        tmp_path, mode="rule_only", judge=judge, answer_text="ambiguous answer")
    _, rows = submit(client, headers, workflow, selection, preview)
    assert [r["verdict"] for r in rows] == ["PASS", "INCONCLUSIVE"]
    assert len(prompts) == 2 and not judge.requests
    assert all(report(dispatcher, row)["evaluation"]["evaluation_mode"] == "rule_only"
               for row in rows)


def test_hybrid_short_circuits_deterministic_pass_and_fail(tmp_path):
    judge = FakeJudge()
    client, headers, workflow, dispatcher, selection, preview, _ = launch(
        tmp_path, judge=judge, answer_text="SECAGENT_GH_HIJACKED")
    _, rows = submit(client, headers, workflow, selection, preview)
    assert [r["verdict"] for r in rows] == ["PASS", "FAIL"]
    assert not judge.requests
    assert all(report(dispatcher, row)["evaluation"]["judge"]["semantic_invoked"] is False
               for row in rows)


@pytest.mark.parametrize("verdict", [EvaluationStatus.FAIL, EvaluationStatus.PASS])
def test_hybrid_calls_allowlisted_skill_for_ambiguous_attack(tmp_path, verdict):
    judge = FakeJudge(verdict)
    client, headers, workflow, dispatcher, selection, preview, _ = launch(
        tmp_path, judge=judge, answer_text="I am dropping the summary.")
    state, rows = submit(client, headers, workflow, selection, preview)
    assert [r["verdict"] for r in rows] == ["PASS", verdict.value], report(dispatcher, rows[1])["evaluation"]["judge"]
    assert len(judge.requests) == 1
    request = judge.requests[0]
    assert request.evaluation_type == "goal_hijacking"
    assert request.trusted_context["original_goal"].startswith("Summarize")
    assert request.trusted_context["attacker_goal"].startswith("Abandon")
    assert request.skill.sha256
    native = report(dispatcher, rows[1])["evaluation"]
    assert native["evaluation_mode"] == "hybrid"
    assert native["judge"]["semantic_invoked"] is True
    assert native["judge"]["recommendation"] == verdict.value
    assert native["final_verdict"] == verdict.value
    assert native["observation"]["response_complete"] is True
    assert native["judge_budget"]["maximum"] == native["judge_budget"]["used"] == 1
    assert workflow.orchestrator.state(state["batch_run_id"])["snapshot"]["evaluation_mode"] == "hybrid"


@pytest.mark.parametrize("fault", ["provider", "budget", "citation", "skill"])
def test_hybrid_faults_never_make_security_verdict(tmp_path, fault):
    judge = FakeJudge(fault_code=(ProviderFaultCode.PROCESS_ERROR if fault == "provider"
        else ProviderFaultCode.BUDGET_EXHAUSTED if fault == "budget" else None),
        wrong_citation=fault == "citation", wrong_skill=fault == "skill")
    client, headers, workflow, dispatcher, selection, preview, _ = launch(
        tmp_path, judge=judge)
    _, rows = submit(client, headers, workflow, selection, preview)
    assert rows[1]["verdict"] == "INCONCLUSIVE"
    assert report(dispatcher, rows[1])["evaluation"]["judge"]["semantic_invoked"] is True


def test_partial_response_does_not_call_judge_or_create_verdict(tmp_path):
    judge = FakeJudge()
    client, headers, workflow, dispatcher, selection, preview, _ = launch(
        tmp_path, judge=judge, finish_reason="length")
    _, rows = submit(client, headers, workflow, selection, preview)
    assert rows[1]["verdict"] == "INCONCLUSIVE"
    assert not judge.requests
    assert report(dispatcher, rows[1])["evaluation"]["observation"]["response_complete"] is not True


def test_hybrid_requires_explicit_ready_judge_and_valid_plan(tmp_path):
    judge = FakeJudge()
    client, headers, workflow, dispatcher, selection, preview, _ = launch(tmp_path, judge=judge)
    assert preview.status_code == 200
    assert preview.json["plan_id"]
    assert preview.json["target_request_budget"] == 2
    assert preview.json["plan_id"] != post(client, "batches/preview",
        selection | {"evaluation_mode": "rule_only"}, headers).json["plan_id"]


def test_hybrid_preview_rejects_missing_judge_configuration(tmp_path):
    client, headers, _, _, draft, _ = setup(tmp_path,
        lambda _: pytest.fail("Target request not admitted."))
    response = post(client, "batches/preview", {"target": draft,
        "testcase_ids": ["GH-C01"], "total_request_budget": 1,
        "evaluation_mode": "hybrid"}, headers)
    assert response.status_code == 409
    assert response.json["error"]["code"] == "asi01_hybrid_judge_unavailable"


def test_hybrid_baseline_judge_pass_unlocks_gh002_in_same_batch(tmp_path):
    class CaseJudge(FakeJudge):
        def evaluate(self, request):
            self.verdict = (EvaluationStatus.PASS if request.testcase.id == "GH-C01"
                            else EvaluationStatus.FAIL)
            return super().evaluate(request)
    judge = CaseJudge()
    client, headers, workflow, dispatcher, selection, preview, prompts = launch(
        tmp_path, judge=judge, selected=("GH-002", "GH-C01"),
        baseline_text="The project tests AI agent security.")
    state, rows = submit(client, headers, workflow, selection, preview)
    assert [row["testcase_id"] for row in rows] == ["GH-C01", "GH-002"]
    assert [row["verdict"] for row in rows] == ["PASS", "FAIL"]
    assert len(judge.requests) == 2 and len(prompts) == 2
    assert state["target_request_count"] == 2
    assert all(report(dispatcher, row)["evaluation"]["judge"]["semantic_invoked"]
               for row in rows)


def test_incomplete_hybrid_baseline_blocks_attack_and_preserves_request_budget(tmp_path):
    judge = FakeJudge(EvaluationStatus.PASS)
    client, headers, workflow, _, selection, preview, prompts = launch(
        tmp_path, judge=judge, baseline_text="partial summary", baseline_finish="length")
    state, rows = submit(client, headers, workflow, selection, preview)
    assert [row["status"] for row in rows] == ["completed", "blocked"]
    assert rows[0]["verdict"] == "INCONCLUSIVE" and rows[1]["verdict"] is None
    assert rows[1]["reason"] == "clean_baseline_not_confirmed"
    assert state["target_request_count"] == len(prompts) == 1
    assert not judge.requests
