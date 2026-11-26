"""Response-scope ASI01 semantic citations must cite the observed response."""

import socket
from pathlib import Path

import pytest

from core.models import Evidence, EvaluationStatus, Observation
from evaluators import HybridEvaluator
from integrations.external_evaluator.models import ExternalEvaluationOutcome, ExternalEvaluationResult
from testing import TestCaseLoader


ROOT = Path(__file__).resolve().parents[2]
NATIVE_COMPAT_ROOT = Path(__file__).resolve().parent / "fixtures" / "native_compat"
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
    case = TestCaseLoader().load(NATIVE_COMPAT_ROOT / "testcases" / "goal_hijacking" / f"{case_id}.yaml")
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
