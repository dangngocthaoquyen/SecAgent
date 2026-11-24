"""Evaluate authored ASI05 challenge responses without a Target request.

Validation is the default. Dry-run uses a local fake Judge. Execute requires an
explicit flag and accepts only pilot-ready fixtures plus the zero-call gate case.
"""

from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.scripts import run_asi05_semantic_pilot as base  # noqa: E402
from core.models import Observation  # noqa: E402
from evaluators.evaluation_request_builder import EvaluationRequestBuilder  # noqa: E402
from integrations.external_evaluator.validation import JudgeOutputError, parse_judge_response  # noqa: E402
from testing.evaluation_config import configured_evaluator  # noqa: E402


CORPUS = base.FIXTURES / "semantic_challenge" / "cases.json"
CORPUS_SHA256 = "fb6cd8204910bc5811dd86ae58ce1fa597bfd20faf93fcd9b3113e0185feac00"
EXPECTED_IDS = ("X02", "X03", "X04", "X05", "X06", "X07", "X08", "X09", "X10")
PILOT_READY = ("X02", "X03", "X05", "X07")
HUMAN_REVIEW = frozenset({"X04", "X06", "X08", "X10"})
GATE_ONLY = "X09"
CASE_FIELDS = {
    "fixture_id", "attacker_input", "target_response", "response_complete",
    "evaluation_lane", "expected_classification", "expected_verdict",
    "reference_rationale", "required_evidence", "policy_basis", "review_status",
}
RESULT_FIELDS = (
    "fixture_id", "evaluation_lane", "review_status", "expected_classification",
    "expected_verdict", "attacker_input_sha256", "response_sha256",
    "response_complete", "request_source_sha256", "reviewed_policy_id",
    "reviewed_policy_revision", "judge_skill_sha256", "judge_config_sha256",
    "judge_request_sha256", "external_judge_attempts", "actual_classification",
    "judge_recommendation", "resolved_verdict", "exact_response_citation",
    "judge_explanation", "provider_fault", "provider_diagnostic_code",
    "agreement_with_reference", "comparison_status", "disagreement_reason",
)


class ChallengeValidationError(ValueError):
    pass


def fail(message: str) -> None:
    raise ChallengeValidationError(message)


def digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def source_material_sha256(rows: list[dict]) -> str:
    """Bind only Judge inputs and gate state, never reference labels."""
    material = [{key: row[key] for key in (
        "fixture_id", "attacker_input", "target_response", "response_complete",
        "evaluation_lane") } for row in rows]
    return digest(json.dumps(material, sort_keys=True, ensure_ascii=False,
                             separators=(",", ":")).encode("utf-8"))


def validate_corpus(path: Path) -> tuple[dict, list[dict], str]:
    data = path.read_bytes()
    if digest(data) != CORPUS_SHA256:
        fail("Challenge corpus SHA256 mismatch")
    corpus = json.loads(data)
    if (set(corpus) != {"schema_version", "corpus_id", "scope", "label_source",
                        "policy_id", "policy_revision_sha256", "policy_binding",
                        "judge_skill_sha256", "cases"}
            or corpus["schema_version"] != "1.0"
            or corpus["corpus_id"] != "asi05-independent-semantic-challenge-v1"
            or corpus["scope"] != "response_command_artifact"
            or not isinstance(corpus["label_source"], str)):
        fail("Challenge corpus header or schema mismatch")
    rows = corpus["cases"]
    if not isinstance(rows, list) or tuple(row.get("fixture_id") for row in rows) != EXPECTED_IDS:
        fail("Challenge corpus must contain X02–X10 exactly once in order")
    for row in rows:
        case_id = row["fixture_id"]
        if set(row) != CASE_FIELDS:
            fail(f"{case_id}: challenge fixture fields mismatch")
        if any(not isinstance(row[key], str) or not row[key].strip()
               for key in ("attacker_input", "target_response", "reference_rationale",
                           "expected_verdict", "evaluation_lane", "review_status")):
            fail(f"{case_id}: invalid fixture text")
        if type(row["response_complete"]) is not bool:
            fail(f"{case_id}: response_complete must be boolean")
        if (row["evaluation_lane"] == "pre_judge_gate") != (case_id == GATE_ONLY):
            fail(f"{case_id}: evaluation lane mismatch")
        if case_id == GATE_ONLY:
            if (row["response_complete"] is not False or row["expected_classification"] is not None
                    or row["expected_verdict"] != "INCONCLUSIVE"):
                fail("X09 must remain an incomplete, unclassified pre-Judge gate case")
        elif (row["evaluation_lane"] != "semantic_judge" or row["response_complete"] is not True
              or row["expected_classification"] not in base.LABELS
              or base.LABEL_VERDICTS["unexpected_code_execution"][row["expected_classification"]].value != row["expected_verdict"]):
            fail(f"{case_id}: semantic label/verdict mapping mismatch")
        expected_review = "NEEDS_HUMAN_REVIEW" if case_id in HUMAN_REVIEW else "PROVISIONAL_REFERENCE"
        if row["review_status"] != expected_review:
            fail(f"{case_id}: review status differs from approved pilot cohort")
        evidence = row["required_evidence"]
        if (not isinstance(evidence, dict)
                or set(evidence) != {"response_spans", "runtime_receipts", "citation_policy"}
                or not isinstance(evidence["response_spans"], list)
                or any(not isinstance(span, str) or not span or span not in row["target_response"]
                       for span in evidence["response_spans"])
                or evidence["runtime_receipts"] != "absent"
                or evidence["citation_policy"] != (
                    "no_judge" if case_id == GATE_ONLY else
                    "optional_on_inconclusive" if row["expected_verdict"] == "INCONCLUSIVE"
                    else "required_for_pass_fail")):
            fail(f"{case_id}: required evidence contract mismatch")
        if not isinstance(row["policy_basis"], list) or not row["policy_basis"] or any(
                not isinstance(item, str) or not item for item in row["policy_basis"]):
            fail(f"{case_id}: policy basis missing")
    return corpus, rows, digest(data)


def _select_skill_loader(args):
    skill_root = getattr(args, "skill_root", None)
    return base.SkillBundleLoader(skill_root) if skill_root is not None else base.SkillBundleLoader()


def validate_environment(args, corpus: dict, corpus_sha256: str, rows: list[dict]):
    snapshot_bytes = args.policy_snapshot.read_bytes()
    if digest(snapshot_bytes) != base.POLICY_FILE_SHA256:
        fail("Reviewed ASI05 policy snapshot SHA256 mismatch")
    policy = json.loads(snapshot_bytes)
    material = {key: policy[key] for key in ("policy_version", "draft", "binding")}
    base.ASI05PolicyDraft.model_validate(policy["draft"])
    if (policy["review_status"] != "reviewed"
            or policy["revision_sha256"] != base.POLICY_REVISION
            or policy["reviewed_revision_sha256"] != base.POLICY_REVISION
            or base._hash(material) != base.POLICY_REVISION
            or corpus["policy_id"] != policy["policy_id"]
            or corpus["policy_revision_sha256"] != policy["revision_sha256"]
            or corpus["policy_binding"] != policy["binding"]):
        fail("Challenge corpus reviewed policy revision or binding mismatch")

    target_dir = args.target_data_dir
    state = base.ManagedState.model_validate(base.read_json(target_dir / "target-catalog.json"))
    catalog = base.ManagedTargetCatalog(state.catalog, target_dir)
    store = base.ASI05PolicyStore(catalog)
    live = store.load(policy["policy_id"])
    if live is None or store.status(live)["response_policy_ready"] is not True:
        fail("Live ASI05 reviewed policy or target binding unavailable/stale")
    if any(live[key] != policy[key] for key in (
            "policy_id", "revision_sha256", "draft", "binding", "review_status")):
        fail("Live ASI05 reviewed policy differs from pinned snapshot")

    loader = _select_skill_loader(args)
    skill = loader.load("unexpected_code_execution").identity
    if skill.sha256 != base.SKILL_SHA256 or skill.sha256 != corpus["judge_skill_sha256"]:
        fail("Trusted ASI05 Judge Skill identity mismatch")
    config_bytes = args.judge_config.read_bytes()
    if digest(config_bytes) != base.CONFIG_SHA256:
        fail("Production Judge configuration SHA256 mismatch")
    config = base.RunnerEvaluationConfig.model_validate(json.loads(config_bytes))
    if (config.mode != "hybrid" or not config.judge_enabled or not config.allow_live_judge
            or config.pi is None or config.max_judge_calls != 1
            or not config.require_complete_response_for_semantic):
        fail("Production Judge configuration is not the one-attempt Hybrid contract")
    source_sha256 = source_material_sha256(rows)
    return policy, config, skill, {
        "mode": "validated", "corpus_id": corpus["corpus_id"],
        "corpus_sha256": corpus_sha256, "request_source_sha256": source_sha256,
        "fixture_count": len(rows), "policy_id": policy["policy_id"],
        "policy_revision_sha256": policy["revision_sha256"],
        "policy_snapshot_sha256": digest(snapshot_bytes),
        "policy_binding_verified": True, "live_reviewed_policy_verified": True,
        "judge_skill_sha256": skill.sha256, "judge_config_sha256": digest(config_bytes),
        "reference_labels_are_judge_input": False,
        "runtime_receipts_present": False,
    }


def make_testcase(row: dict, policy: dict, source_sha256: str):
    return base.make_case({"id": row["fixture_id"], "attacker_input": row["attacker_input"],
                           "response": row["target_response"]}, policy, source_sha256)


def make_observation(row: dict) -> Observation:
    return Observation(response_text=row["target_response"], status_code=None, evidence=[],
                       metadata={"execution_success": True,
                                 "response_complete": row["response_complete"]})


class GateSentinel:
    def evaluate(self, _request):
        raise AssertionError("Pre-Judge gate case reached the external Judge")


def evaluate_case(
    row,
    policy,
    config,
    source_sha256,
    *,
    execute,
    provider=None,
    bundle_loader=None,
    expected_skill=None,
):
    testcase = make_testcase(row, policy, source_sha256)
    observation = make_observation(row)
    selected_config = config if execute else config.model_copy(update={"allow_live_judge": False})
    active_loader = bundle_loader if bundle_loader is not None else base.SkillBundleLoader()
    if row["evaluation_lane"] == "pre_judge_gate":
        delegate = GateSentinel()
    else:
        delegate = (
            provider
            if provider is not None
            else base.PiEvaluatorProvider(config.pi, bundle_loader=active_loader)
        ) if execute else base.DryRunJudge()
    recording = base.RecordingProvider(delegate)
    diagnostics = []
    evaluator, budget = configured_evaluator(
        selected_config,
        recording,
        diagnostics.append,
        bundle_loader=active_loader,
    )
    result = evaluator.evaluate(testcase, observation)
    diagnostic = diagnostics[-1] if diagnostics else None
    if row["evaluation_lane"] == "pre_judge_gate":
        if (result.status.value != "INCONCLUSIVE" or budget.used != 0
                or recording.request is not None or diagnostic is None
                or diagnostic.semantic_invoked):
            fail("X09 completeness gate failed or attempted an external Judge call")
    else:
        request = recording.request
        if expected_skill is not None and request is not None:
            if request.skill != expected_skill:
                fail(f"{row['fixture_id']}: EvaluationRequest Skill identity mismatch")
            if (diagnostic is not None and diagnostic.skill_sha256 is not None
                    and diagnostic.skill_sha256 != expected_skill.sha256):
                fail(f"{row['fixture_id']}: Diagnostic Skill identity mismatch")
            if (recording.outcome is not None and recording.outcome.skill is not None
                    and recording.outcome.skill != expected_skill):
                fail(f"{row['fixture_id']}: Provider Skill identity mismatch")
        if not execute:
            if (request is None or diagnostic is None or not diagnostic.semantic_invoked
                    or budget.used != 1 or result.status.value != "INCONCLUSIVE"):
                fail(f"{row['fixture_id']}: dry-run did not traverse the production Judge gate")
            independent = EvaluationRequestBuilder(bundle_loader=active_loader).build(testcase, observation)
            if (independent.observation != request.observation
                    or independent.trusted_context != request.trusted_context
                    or independent.testcase != request.testcase
                    or independent.skill != request.skill):
                fail(f"{row['fixture_id']}: EvaluationRequestBuilder disagreement")
    return result, diagnostic, budget.used, recording


def comparison(row, diagnostic, result, recording):
    if row["fixture_id"] not in PILOT_READY:
        return None, "excluded_from_provisional_agreement", "Fixture is not in the reviewed pilot cohort."
    if diagnostic is None or diagnostic.provider_fault_code is not None:
        code = diagnostic.provider_fault_code.value if diagnostic and diagnostic.provider_fault_code else "unknown"
        if (code == "invalid_output" and recording.request is not None
                and recording.outcome is not None and recording.outcome.result is not None):
            try:
                parse_judge_response(recording.outcome.result.model_dump_json(), recording.request)
            except JudgeOutputError as exc:
                if "citation" in str(exc).lower():
                    return None, "invalid_citation", "Judge citation failed exact response-span validation."
        return None, "provider_fault", f"Judge provider/validation fault: {code}"
    if diagnostic.downgrade_reason or diagnostic.classification is None or diagnostic.recommendation is None:
        return None, "insufficient_evidence", diagnostic.downgrade_reason or "No validated semantic recommendation."
    agrees = (diagnostic.classification == row["expected_classification"]
              and result.status.value == row["expected_verdict"])
    return agrees, "agreement" if agrees else "semantic_disagreement_candidate", (
        None if agrees else "Validated Judge result differs from provisional reference; human adjudication is pending.")


def write_outputs(output_dir: Path, validation: dict, rows: list[dict], summary: dict) -> None:
    output_dir.mkdir(parents=True, exist_ok=False)
    for name, value in (("validation_report.json", validation), ("challenge_results.json", rows),
                        ("challenge_summary.json", summary)):
        (output_dir / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with (output_dir / "challenge_results.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=RESULT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    (output_dir / "README.md").write_text(
        "# ASI05 independent semantic challenge\n\n"
        f"Mode: `{summary['mode']}`. Target requests: 0. External Judge attempts: {summary['judge_attempts']}.\n\n"
        "Only X02, X03, X05, and X07 are provisional pilot references. "
        "X04, X06, X08, and X10 require human review. X09 is a zero-call completeness gate. "
        "Reference labels and rationales are excluded from Judge requests. "
        "No response text is a runtime execution receipt. Agreement is provisional, not confirmed accuracy.\n",
        encoding="utf-8",
    )


def run(args, *, provider_factory=None):
    output = args.output_dir.resolve()
    if args.output_dir.exists() or output.is_relative_to(ROOT) or output.is_relative_to(args.target_data_dir.resolve()):
        fail("Output directory must be new and outside repository and target data")
    if args.execute and not args.allow_external_judge:
        fail("--execute requires --allow-external-judge")
    corpus, rows, corpus_sha256 = validate_corpus(args.corpus)
    selected = (list(PILOT_READY) + [GATE_ONLY] if args.execute and not args.fixtures_select
                else list(EXPECTED_IDS) if not args.fixtures_select
                else args.fixtures_select.split(","))
    if not selected or len(set(selected)) != len(selected) or any(case_id not in EXPECTED_IDS for case_id in selected):
        fail("--fixtures-select must list unique IDs from X02–X10")
    if args.execute and any(case_id in HUMAN_REVIEW for case_id in selected):
        fail("--execute excludes X04, X06, X08, and X10 pending human review")
    policy, config, skill, validation = validate_environment(args, corpus, corpus_sha256, rows)
    bundle_loader = _select_skill_loader(args)
    validation["selected_fixtures"] = selected
    mode = "execute" if args.execute else "dry-run" if args.dry_run else "validate-only"
    results = []
    judge_attempts = 0
    fake_judge_calls = 0
    for row in rows:
        case_id = row["fixture_id"]
        if case_id not in selected:
            continue
        result_row = {key: None for key in RESULT_FIELDS}
        result_row.update(
            fixture_id=case_id, evaluation_lane=row["evaluation_lane"],
            review_status=row["review_status"],
            expected_classification=row["expected_classification"],
            expected_verdict=row["expected_verdict"],
            attacker_input_sha256=digest(row["attacker_input"].encode("utf-8")),
            response_sha256=digest(row["target_response"].encode("utf-8")),
            response_complete=row["response_complete"],
            request_source_sha256=validation["request_source_sha256"],
            reviewed_policy_id=policy["policy_id"],
            reviewed_policy_revision=policy["revision_sha256"],
            judge_skill_sha256=skill.sha256,
            judge_config_sha256=validation["judge_config_sha256"],
            external_judge_attempts=0,
        )
        if mode == "validate-only":
            result_row["comparison_status"] = "validated_no_judge"
        else:
            provider = provider_factory() if args.execute and row["evaluation_lane"] == "semantic_judge" and provider_factory else None
            result, diagnostic, attempts, recording = evaluate_case(
                row, policy, config, validation["request_source_sha256"],
                execute=args.execute, provider=provider,
                bundle_loader=bundle_loader, expected_skill=skill)
            if recording.request is not None:
                result_row["judge_skill_sha256"] = recording.request.skill.sha256
            result_row["judge_request_sha256"] = recording.request.sha256 if recording.request else None
            if row["evaluation_lane"] == "pre_judge_gate":
                result_row.update(resolved_verdict=result.status.value,
                                  comparison_status="pre_judge_gate_no_external_judge")
            elif mode == "dry-run":
                fake_judge_calls += attempts
                result_row["comparison_status"] = "dry_run_request_valid_no_production_judge"
            else:
                judge_attempts += attempts
                agreement, status, reason = comparison(row, diagnostic, result, recording)
                result_row.update(
                    external_judge_attempts=attempts,
                    actual_classification=diagnostic.classification if diagnostic else None,
                    judge_recommendation=(diagnostic.recommendation.value if diagnostic and diagnostic.recommendation else None),
                    resolved_verdict=result.status.value,
                    exact_response_citation=([item["value"] for item in diagnostic.judge_evidence] if diagnostic else []),
                    judge_explanation=diagnostic.judge_reason if diagnostic else None,
                    provider_fault=(diagnostic.provider_fault_code.value if diagnostic and diagnostic.provider_fault_code else None),
                    provider_diagnostic_code=(recording.outcome.fault.diagnostic_code.value
                        if recording.outcome and recording.outcome.fault
                        and recording.outcome.fault.diagnostic_code else None),
                    agreement_with_reference=agreement,
                    comparison_status=status, disagreement_reason=reason,
                )
        results.append(result_row)
    comparable = [row for row in results if row["agreement_with_reference"] is not None]
    summary = {
        "mode": mode, "selected_count": len(results),
        "judge_attempts": judge_attempts, "fake_judge_calls": fake_judge_calls,
        "target_request_count": 0,
        "production_judge_called": bool(args.execute and provider_factory is None and judge_attempts),
        "pilot_ready_selected": [case_id for case_id in selected if case_id in PILOT_READY],
        "human_review_selected": [case_id for case_id in selected if case_id in HUMAN_REVIEW],
        "gate_only_selected": GATE_ONLY in selected,
        "provisional_reference_count": sum(case_id in PILOT_READY for case_id in selected),
        "comparable_count": len(comparable),
        "provisional_agreement_rate": (
            sum(row["agreement_with_reference"] for row in comparable) / len(comparable)
            if comparable else None),
        "confirmed_accuracy": None,
        "reference_labels_are_judge_input": False,
    }
    write_outputs(args.output_dir, validation, results, summary)
    return summary


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_mutually_exclusive_group()
    modes.add_argument("--validate-only", action="store_true")
    modes.add_argument("--dry-run", action="store_true")
    modes.add_argument("--execute", action="store_true")
    p.add_argument("--corpus", type=Path, default=CORPUS)
    p.add_argument("--policy-snapshot", type=Path, default=base.FIXTURES / "reviewed_policy_snapshot.json")
    p.add_argument("--target-data-dir", type=Path, required=True)
    p.add_argument("--judge-config", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--fixtures-select", help="Comma-separated X02–X10; default all for safe modes")
    p.add_argument("--skill-root", type=Path, default=None, help="Optional archived Skill bundle directory for historical v1.0.0 replay")
    p.add_argument("--allow-external-judge", action="store_true")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    if not args.dry_run and not args.execute:
        args.validate_only = True
    try:
        summary = run(args)
    except (ChallengeValidationError, ValueError, KeyError, OSError) as exc:
        print(f"Semantic challenge validation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
