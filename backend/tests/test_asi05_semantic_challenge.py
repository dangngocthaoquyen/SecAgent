"""Offline data-contract checks for the independent ASI05 challenge corpus."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import socket
import subprocess

import pytest
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from backend.scripts import run_asi05_semantic_pilot as pilot
from core.models import EvaluationStatus, Observation
from evaluators.evaluation_request_builder import EvaluationRequestBuilder
from evaluators.hybrid_evaluator import HybridEvaluator
from integrations.external_evaluator.skills import SkillBundleLoader
from integrations.external_evaluator.validation import LABEL_VERDICTS


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "asi05"
CHALLENGE = FIXTURES / "semantic_challenge" / "cases.json"
CHALLENGE_SHA256 = "fb6cd8204910bc5811dd86ae58ce1fa597bfd20faf93fcd9b3113e0185feac00"
IDS = ("X02", "X03", "X04", "X05", "X06", "X07", "X08", "X09", "X10")
HUMAN_REVIEW = {"X04", "X06", "X08", "X10"}


@pytest.fixture(autouse=True)
def no_process_or_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Challenge corpus tests must not use a process or the network")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


class StrictFixture(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EvidenceRequirement(StrictFixture):
    response_spans: list[str]
    runtime_receipts: str
    citation_policy: str


class ChallengeCase(StrictFixture):
    fixture_id: str = Field(min_length=1)
    attacker_input: str = Field(min_length=1)
    target_response: str = Field(min_length=1)
    response_complete: bool
    evaluation_lane: str
    expected_classification: str | None
    expected_verdict: str
    reference_rationale: str = Field(min_length=1)
    required_evidence: EvidenceRequirement
    policy_basis: list[str] = Field(min_length=1)
    review_status: str


class ChallengeCorpus(StrictFixture):
    schema_version: str
    corpus_id: str
    scope: str
    label_source: str
    policy_id: str
    policy_revision_sha256: str
    policy_binding: dict[str, str]
    judge_skill_sha256: str
    cases: list[ChallengeCase]


def load_corpus() -> ChallengeCorpus:
    return ChallengeCorpus.model_validate_json(CHALLENGE.read_bytes())


def source_rows(cases):
    return [{"id": case.fixture_id, "attacker_input": case.attacker_input,
             "response": case.target_response} for case in cases]


def assert_binding(corpus, snapshot):
    assert corpus.scope == snapshot["draft"]["evaluation_scope"]
    assert corpus.policy_id == snapshot["policy_id"]
    assert corpus.policy_revision_sha256 == snapshot["revision_sha256"] == snapshot["reviewed_revision_sha256"]
    assert corpus.policy_binding == snapshot["binding"]


def test_challenge_schema_labels_and_evidence_contract():
    corpus = load_corpus()
    assert corpus.schema_version == "1.0"
    assert corpus.corpus_id == "asi05-independent-semantic-challenge-v1"
    assert tuple(case.fixture_id for case in corpus.cases) == IDS
    assert len({case.fixture_id for case in corpus.cases}) == len(IDS)
    assert {case.fixture_id for case in corpus.cases if case.review_status == "NEEDS_HUMAN_REVIEW"} == HUMAN_REVIEW
    assert all(case.review_status in {"PROVISIONAL_REFERENCE", "NEEDS_HUMAN_REVIEW"}
               for case in corpus.cases)
    assert all(case.required_evidence.runtime_receipts == "absent" for case in corpus.cases)
    assert all(not hasattr(case, "trusted_context") for case in corpus.cases)

    allowed_basis = {
        "draft.prohibited_command_behavior", "draft.allowed_benign_context",
        "draft.expected_response_boundary", "skill.untrusted_input_no_authority",
        "skill.attribution_and_intent", "skill.response_verdict_mapping",
        "skill.no_runtime_inference", "pipeline.complete_response_gate",
    }
    for case in corpus.cases:
        assert set(case.policy_basis) <= allowed_basis
        assert all(span and span in case.target_response
                   for span in case.required_evidence.response_spans)
        if case.evaluation_lane == "semantic_judge":
            assert case.response_complete is True
            assert case.expected_classification in LABEL_VERDICTS["unexpected_code_execution"]
            assert LABEL_VERDICTS["unexpected_code_execution"][case.expected_classification].value == case.expected_verdict
            assert case.required_evidence.citation_policy == (
                "optional_on_inconclusive" if case.expected_verdict == "INCONCLUSIVE"
                else "required_for_pass_fail")
        else:
            assert case.fixture_id == "X09"
            assert case.evaluation_lane == "pre_judge_gate"
            assert case.response_complete is False
            assert case.expected_classification is None
            assert case.expected_verdict == "INCONCLUSIVE"
            assert case.required_evidence.response_spans == []
            assert case.required_evidence.citation_policy == "no_judge"


def test_schema_rejects_missing_or_extra_reference_fields():
    raw = json.loads(CHALLENGE.read_text(encoding="utf-8"))
    missing = deepcopy(raw)
    del missing["cases"][0]["required_evidence"]
    with pytest.raises(ValidationError):
        ChallengeCorpus.model_validate(missing)
    extra = deepcopy(raw)
    extra["cases"][0]["production_judge_verdict"] = "FAIL"
    with pytest.raises(ValidationError):
        ChallengeCorpus.model_validate(extra)


def test_challenge_and_existing_corpus_hashes_policy_binding_and_skill():
    assert sha256(CHALLENGE.read_bytes()).hexdigest() == CHALLENGE_SHA256
    assert sha256((FIXTURES / "semantic_cases.json").read_bytes()).hexdigest() == pilot.CORPUS_SHA256
    snapshot_bytes = (FIXTURES / "reviewed_policy_snapshot.json").read_bytes()
    assert sha256(snapshot_bytes).hexdigest() == pilot.POLICY_FILE_SHA256
    corpus = load_corpus()
    snapshot = json.loads(snapshot_bytes)
    assert snapshot["review_status"] == "reviewed"
    assert_binding(corpus, snapshot)
    assert corpus.judge_skill_sha256 == pilot.SKILL_SHA256
    assert SkillBundleLoader().load("unexpected_code_execution").identity.sha256 == corpus.judge_skill_sha256

    changed = corpus.model_copy(update={"policy_binding": {**corpus.policy_binding, "target_model": "other"}})
    with pytest.raises(AssertionError):
        assert_binding(changed, snapshot)
    changed_revision = corpus.model_copy(update={"policy_revision_sha256": "0" * 64})
    with pytest.raises(AssertionError):
        assert_binding(changed_revision, snapshot)


def test_reference_fields_are_excluded_from_judge_request():
    corpus = load_corpus()
    snapshot = json.loads((FIXTURES / "reviewed_policy_snapshot.json").read_text(encoding="utf-8"))
    source_hash = pilot.request_material_sha256(source_rows(corpus.cases))
    assert source_hash == pilot.request_material_sha256(source_rows(
        [case.model_copy(update={"expected_classification": "UNCLEAR",
                                 "expected_verdict": "INCONCLUSIVE",
                                 "reference_rationale": "changed reference only",
                                 "review_status": "NEEDS_HUMAN_REVIEW"}) for case in corpus.cases]))

    for case in corpus.cases:
        if not case.response_complete:
            continue
        row = source_rows([case])[0]
        testcase = pilot.make_case(row, snapshot, source_hash)
        observation = Observation(response_text=case.target_response, status_code=None,
                                  evidence=[], metadata={"execution_success": True,
                                                         "response_complete": True})
        request = EvaluationRequestBuilder().build(testcase, observation)
        serialized = request.model_dump_json()
        assert request.testcase.untrusted_input == case.attacker_input
        assert request.observation.response_text == case.target_response
        assert request.observation.evidence == []
        assert case.reference_rationale not in serialized
        assert all(key not in serialized for key in (
            "expected_classification", "expected_verdict", "reference_rationale",
            "required_evidence", "review_status"))


def test_incomplete_case_stops_before_external_judge():
    corpus = load_corpus()
    case = next(case for case in corpus.cases if case.fixture_id == "X09")
    snapshot = json.loads((FIXTURES / "reviewed_policy_snapshot.json").read_text(encoding="utf-8"))
    testcase = pilot.make_case(source_rows([case])[0], snapshot,
                               pilot.request_material_sha256(source_rows(corpus.cases)))
    observation = Observation(response_text=case.target_response, status_code=None,
                              evidence=[], metadata={"execution_success": True,
                                                     "response_complete": False})

    class NeverJudge:
        def evaluate(self, _request):
            pytest.fail("Incomplete ASI05 observation reached external Judge")

    diagnostics = []
    result = HybridEvaluator(NeverJudge(), diagnostic_sink=diagnostics.append,
                             require_complete_response_for_semantic=True).evaluate(testcase, observation)
    assert result.status == EvaluationStatus.INCONCLUSIVE
    assert diagnostics[-1].semantic_invoked is False
    assert pilot.make_observation({"response": case.target_response}).metadata["response_complete"] is True


def test_current_pilot_is_pinned_to_other_corpus_and_case_shape():
    corpus = load_corpus()
    assert sha256(CHALLENGE.read_bytes()).hexdigest() != pilot.CORPUS_SHA256
    assert tuple(case.fixture_id for case in corpus.cases) != pilot.EXPECTED_IDS
    assert "fixture_id" in ChallengeCase.model_fields
    assert "id" not in ChallengeCase.model_fields
