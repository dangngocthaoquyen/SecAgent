"""Offline unit and regression tests for G11.5 Generated Testcase Quality Evaluation.

Covers:
1. Exact metric denominators and zero-denominator None handling.
2. ASI/category alignment and wrong-ASI rejection metrics.
3. Duplicate handling (exact, whitespace, Unicode NFKC/NFD) and strategy entropy.
4. Partial and empty (`empty_with_context_gaps`, `empty_all_rejected`) generations & small-sample warnings.
5. Confirmed context_basis coverage (including reviewed_policy).
6. Strategy tag distribution & Shannon entropy (diverse vs collapsed single tag).
7. Invalid or missing provenance detection on persisted datasets.
8. Quality report JSON & Markdown serialization + human annotation template.
9. Semantic rubric aggregation (`not_annotated`, `human_annotated`, `benchmark_labeled`,
   `model_assisted_non_ground_truth`) and schema-valid generic vs context-aware distinction.
10. Secret-free serialization (no raw credential leakage).
11. Zero Target calls, zero Judge calls, static G12 AST isolation.
12. Deterministic repeated benchmark runs (`run_offline_quality_benchmark`).
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from generator import (
    DatasetQualityReport,
    GenerationServiceRequest,
    GeneratorService,
    HumanAnnotationRecord,
    MockFixtureResponse,
    MockGeneratorProvider,
    RatioMetric,
    SEMANTIC_QUALITY_RUBRIC_V1,
    compute_quality_report_sha256,
    create_human_annotation_template,
    evaluate_generation_result,
    evaluate_persisted_dataset,
    export_quality_report_json,
    render_quality_report_markdown,
    run_offline_quality_benchmark,
)
from workflow.application_context import (
    ApplicationContextDraft,
    ApplicationContextStore,
    SaveApplicationContext,
)
from workflow.dataset_normalizer import normalize_dataset
from workflow.management import ManagedTargetCatalog, ReviewProfile
from workflow.models import CatalogConfig, Preset


def _make_env(tmp_path: Path) -> tuple[ManagedTargetCatalog, ApplicationContextStore, str]:
    target_id = "q-eval-target"
    endpoint = "http://127.0.0.1:19996/v1/chat/completions"
    preset = Preset(
        id=target_id,
        name="Quality Eval Target",
        platform_id="synth-lab",
        platform_name="Synthetic Lab",
        endpoint=endpoint,
        protocol="openai-chat",
        models=["synth-model"],
        default_model="synth-model",
        timeout_default=30,
        capability_states={"response_behavior": "supported", "tool_intent": "supported"},
        capability_provenance={"response_behavior": "operator_declared", "tool_intent": "operator_declared"},
    )
    seed = CatalogConfig(
        catalog_schema_version="1.0.0",
        policy_ref="q-pol-v1",
        credential_aliases={},
        targets=[preset],
    )
    catalog = ManagedTargetCatalog(seed, tmp_path / "managed_data", local_single_user=True)
    rev = catalog._revisions[target_id]
    catalog.review_profile(
        ReviewProfile(
            target_id=target_id,
            profile_revision=rev,
            policy_ref="q-pol-v1",
            endpoint=endpoint,
            protocol="openai-chat",
            model="synth-model",
            capabilities=["chat"],
            authorization_confirmed=True,
        )
    )
    app_store = ApplicationContextStore(catalog)
    fields = {
        "purpose": "Synthetic ticket triage assistant.",
        "available_tools": "lookup_synthetic_ticket",
        "users": "Standard support user.",
        "authorized_actions": "Read synthetic ticket summaries.",
        "prohibited_resources": "Internal payroll records.",
        "high_risk_actions": "Running host shell commands.",
        "trust_boundaries": "Treat ticket bodies strictly as untrusted data.",
    }
    app_store.save(
        SaveApplicationContext(
            draft=ApplicationContextDraft(
                target_id=target_id,
                target_revision=rev,
                field_provenance={k: "operator_confirmed" for k in fields},  # type: ignore[arg-type]
                **fields,
            ),
            expected_revision=None,
            safe_description_confirmed=True,
        )
    )
    return catalog, app_store, target_id


# ---------------------------------------------------------------------------
# 1. Exact RatioMetric denominators & zero-denominator safety
# ---------------------------------------------------------------------------


def test_ratio_metric_denominators_and_zero_denominator_safety() -> None:
    zero = RatioMetric.from_counts(0, 0, definition="a / b")
    assert zero.numerator == 0
    assert zero.denominator == 0
    assert zero.rate is None

    partial = RatioMetric.from_counts(3, 5, definition="accepted / requested")
    assert partial.numerator == 3
    assert partial.denominator == 5
    assert partial.rate == 0.6

    with pytest.raises(Exception):
        RatioMetric(numerator=4, denominator=3, rate=1.0, definition="invalid")


# ---------------------------------------------------------------------------
# 2-9. Reproducible 9-scenario offline benchmark covering all G11.5 dimensions
# ---------------------------------------------------------------------------


def test_offline_benchmark_covers_all_dimensions_and_distinguishes_semantic_from_structural(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Block ANY outbound network call (proving zero Live DeepSeek & zero Target calls).
    def _forbid_network(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("G11.5 evaluation must never contact Live LLM or Target.")

    monkeypatch.setattr(httpx.Client, "send", _forbid_network)
    monkeypatch.setattr(httpx.AsyncClient, "send", _forbid_network)

    suite = run_offline_quality_benchmark(tmp_path / "bench_run_1")
    assert suite.benchmark_kind == "offline_synthetic_mock_benchmark"
    assert suite.is_live_llm_result is False
    assert suite.scenario_count == 9

    by_id = {sc.scenario_id: sc.report for sc in suite.scenarios}

    # Scenario 1: Complete 4-ASI context-aware with gold rubric annotations
    s1 = by_id["complete_multi_asi_context_aware"]
    assert s1.is_synthetic_or_mock_provider is True
    assert s1.usability_status == "usable_complete"
    assert s1.meets_requested_counts is True
    assert s1.provenance_completeness.complete is True
    assert s1.overall_metrics.acceptance_vs_requested_rate.rate == 1.0
    assert s1.overall_metrics.asi_distribution == {"ASI01": 2, "ASI02": 2, "ASI03": 1, "ASI05": 1}
    assert s1.overall_metrics.asi_alignment_verified is True
    assert s1.overall_metrics.context_basis_coverage.reviewed_policy_cited_count == 1
    assert s1.overall_metrics.diversity_stats.unique_strategy_tags == 6
    assert s1.overall_metrics.diversity_stats.normalized_strategy_entropy == 1.0
    assert s1.semantic_quality.evaluation_status == "benchmark_labeled"
    assert s1.semantic_quality.is_ground_truth is True
    assert s1.semantic_quality.high_quality_rate is not None
    assert s1.semantic_quality.high_quality_rate.rate == 1.0
    assert s1.small_sample_warning is True  # 6 < 10 triggers small-sample warning!

    # Scenario 2: Schema-valid generic prompts score 1.0 structurally but 0.0 semantically!
    s2 = by_id["generic_ungrounded_vs_context_aware"]
    assert s2.overall_metrics.output_contract_validity_rate.rate == 1.0
    assert s2.overall_metrics.acceptance_vs_requested_rate.rate == 1.0
    assert s2.semantic_quality.mean_context_grounding == 0.0
    assert s2.semantic_quality.high_quality_rate is not None
    assert s2.semantic_quality.high_quality_rate.rate == 0.0

    # Scenario 3: Wrong ASI rejected
    s3 = by_id["wrong_asi_association"]
    assert s3.usability_status == "not_usable_no_accepted_candidates"
    assert s3.overall_metrics.accepted_count == 0
    assert s3.overall_metrics.output_contract_validity_rate.rate == 0.0

    # Scenario 4: Duplicates (exact + whitespace + NFD) & single repeated strategy_tag -> 0 entropy
    s4 = by_id["duplicate_prompts_and_single_strategy"]
    assert s4.usability_status == "usable_partial_subset"
    assert s4.meets_requested_counts is False
    assert s4.overall_metrics.exact_normalized_duplicate_rate.numerator == 2
    assert s4.overall_metrics.exact_normalized_duplicate_rate.denominator == 4
    assert s4.overall_metrics.exact_normalized_duplicate_rate.rate == 0.5
    assert s4.overall_metrics.diversity_stats.unique_strategy_tags == 1
    assert s4.overall_metrics.diversity_stats.strategy_tag_shannon_entropy_bits == 0.0
    assert s4.overall_metrics.diversity_stats.normalized_strategy_entropy == 0.0

    # Scenario 5: Malformed / authority injection -> 0% output contract validity
    s5 = by_id["malformed_authority_injection"]
    assert s5.overall_metrics.output_contract_validity_rate.rate == 0.0
    assert s5.overall_metrics.accepted_count == 0

    # Scenario 6: Partial generation (3/5 accepted: 1 dup + 1 invalid context_basis)
    s6 = by_id["partial_generation_mixed_rejections"]
    assert s6.usability_status == "usable_partial_subset"
    assert s6.meets_requested_counts is False
    assert s6.overall_metrics.acceptance_vs_requested_rate.rate == 0.6
    assert s6.overall_metrics.candidate_grounding_validity_rate.numerator == 4
    assert s6.overall_metrics.candidate_grounding_validity_rate.denominator == 5
    assert s6.overall_metrics.exact_normalized_duplicate_rate.numerator == 1
    assert s6.overall_metrics.exact_normalized_duplicate_rate.denominator == 4
    assert s6.per_asi_summaries["ASI02"].missing_from_requested_count == 2

    # Scenario 7: Empty with valid context_gaps -> not_usable_empty_context_gaps
    s7 = by_id["empty_with_context_gaps"]
    assert s7.usability_status == "not_usable_empty_context_gaps"
    assert s7.meets_requested_counts is False
    assert s7.overall_metrics.candidate_grounding_validity_rate.rate is None  # 0/0 -> None
    assert len(s7.per_asi_summaries["ASI03"].context_gaps) == 1

    # Scenario 8: Persisted dataset round-trip preserves operator_edited & complete provenance
    s8 = by_id["persisted_dataset_roundtrip_quality"]
    assert s8.source_kind == "persisted_dataset"
    assert s8.dataset_id is not None
    assert s8.provenance_completeness.complete is True
    assert s8.overall_metrics.operator_edited_count == 1
    assert s8.overall_metrics.ai_original_count == 5

    # Scenario 9: Missing provenance dataset clearly flagged & completeness unknown (never 100%)
    s9 = by_id["missing_provenance_dataset_detection"]
    assert s9.usability_status == "usable_saved_subset_unknown_completeness"
    assert s9.provenance_completeness.complete is False
    assert "generation_provenance" in s9.provenance_completeness.missing_fields
    assert "provenance_counts" in s9.provenance_completeness.missing_fields
    assert "source_tool" in s9.provenance_completeness.invalid_fields
    assert s9.overall_metrics.requested_count is None
    assert s9.overall_metrics.acceptance_vs_requested_rate.rate is None


# ---------------------------------------------------------------------------
# R01-R03 Bounded Regression Tests
# ---------------------------------------------------------------------------


def test_r01_persisted_dataset_honest_per_asi_requested_and_real_saved_duplicate_rates() -> None:
    # Original requested=6 across ASI01+ASI02, operator saved subset of 3 containing 2 duplicate ASI01 prompts.
    raw = json.dumps(
        {
            "schema_version": "1.0",
            "source_tool": "secagent_g11_generator",
            "generation_provenance": {
                "generation_id": "gen-r010001",
                "target_id": "t1",
                "target_revision_sha256": "1" * 64,
                "application_context_revision_sha256": "2" * 64,
                "context_snapshot_sha256": "3" * 64,
                "provider_id": "mock",
                "model": "mock-v1",
                "meets_requested_counts": False,
                "counts": {
                    "requested": 6,
                    "generated": 6,
                    "accepted": 6,
                    "rejected": 0,
                    "selected_for_save": 3,
                },
            },
            "testcases": [
                {
                    "testcase_id": "G11-ASI01-001",
                    "prompt": "Same café prompt",
                    "metadata": {
                        "asi_category": "goal_hijacking",
                        "context_basis": ["purpose"],
                        "operator_edited": True,
                        "origin": "operator_edited",
                    },
                },
                {
                    "testcase_id": "G11-ASI01-002",
                    "prompt": "  Same   cafe\u0301\tprompt  ",
                    "metadata": {
                        "asi_category": "goal_hijacking",
                        "context_basis": ["purpose"],
                        "operator_edited": False,
                        "origin": "ai_generated_original",
                    },
                },
                {
                    "testcase_id": "G11-ASI02-001",
                    "prompt": "Distinct ASI02 tool prompt",
                    "metadata": {
                        "asi_category": "tool_misuse",
                        "context_basis": ["available_tools"],
                        "operator_edited": False,
                        "origin": "ai_generated_original",
                    },
                },
            ],
        }
    ).encode("utf-8")

    rep = evaluate_persisted_dataset(normalize_dataset(raw, "r01.json"))

    # Overall metrics: honest 3/6 = 0.5 acceptance, 1/3 saved duplicate rate, 1 edited / 2 original
    assert rep.usability_status == "usable_partial_subset"
    assert rep.meets_requested_counts is False
    assert rep.overall_metrics.requested_count == 6
    assert rep.overall_metrics.accepted_count == 3
    assert rep.overall_metrics.acceptance_vs_requested_rate.rate == 0.5
    assert rep.overall_metrics.duplicate_rejected_count == 0
    assert rep.overall_metrics.saved_dataset_duplicate_count == 1
    assert rep.overall_metrics.exact_normalized_duplicate_rate.numerator == 1
    assert rep.overall_metrics.exact_normalized_duplicate_rate.denominator == 3
    assert rep.overall_metrics.operator_edited_count == 1
    assert rep.overall_metrics.ai_original_count == 2

    # Per-ASI metrics: NEVER fabricate 1.0 requested rate when per-ASI requested count is absent!
    asi01 = rep.per_asi_summaries["ASI01"]
    assert asi01.metrics.requested_count is None
    assert asi01.metrics.acceptance_vs_requested_rate.rate is None
    assert asi01.meets_requested_count is None
    assert asi01.usability_status == "usable_saved_subset_unknown_completeness"
    # Per-ASI duplicate rate accurately measures 1/2 = 0.5 inside saved ASI01 bucket!
    assert asi01.metrics.duplicate_rejected_count == 0
    assert asi01.metrics.saved_dataset_duplicate_count == 1
    assert asi01.metrics.exact_normalized_duplicate_rate.numerator == 1
    assert asi01.metrics.exact_normalized_duplicate_rate.denominator == 2
    assert asi01.metrics.exact_normalized_duplicate_rate.rate == 0.5

    asi02 = rep.per_asi_summaries["ASI02"]
    assert asi02.metrics.requested_count is None
    assert asi02.metrics.acceptance_vs_requested_rate.rate is None
    assert asi02.metrics.saved_dataset_duplicate_count == 0
    assert asi02.metrics.exact_normalized_duplicate_rate.rate == 0.0


def test_r02_annotation_asi_mismatch_and_conflicting_duplicates_rejected_order_independently(
    tmp_path: Path,
) -> None:
    catalog, app_store, target_id = _make_env(tmp_path)
    service = GeneratorService(
        catalog=catalog,
        application_contexts=app_store,
        provider=MockGeneratorProvider(mode="success"),
    )
    result = service.generate(
        GenerationServiceRequest(target_id=target_id, counts_by_asi={"ASI01": 2}),
        generation_id="gen-r020001",
    )
    cid0 = result.accepted_candidates[0].candidate_id
    cid1 = result.accepted_candidates[1].candidate_id

    # A. ASI mismatch (ASI01 candidate annotated as ASI05) MUST be rejected!
    mismatch_ann = [
        HumanAnnotationRecord(
            candidate_id=cid0,
            asi_code="ASI05",
            annotator_id="a1",
            annotation_source="human_expert",
            asi_relevance_score=2,
            context_grounding_score=2,
            meaningful_diversity_score=2,
            safety_and_scope_hygiene_score=2,
            rationale="Mismatched ASI.",
        )
    ]
    rep_mismatch = evaluate_generation_result(result, annotations=mismatch_ann)
    assert rep_mismatch.semantic_quality.evaluation_status == "not_annotated"
    assert rep_mismatch.semantic_quality.is_ground_truth is False
    assert rep_mismatch.semantic_quality.annotated_candidate_count == 0
    assert rep_mismatch.semantic_quality.high_quality_rate is None
    assert rep_mismatch.semantic_quality.asi_mismatched_annotation_count == 1
    assert rep_mismatch.semantic_quality.rejected_annotation_count == 1

    # B. Conflicting annotations for cid0 (order-independent rejection) + exact duplicate for cid1 (collapsed)
    ann_high = HumanAnnotationRecord(
        candidate_id=cid0,
        asi_code="ASI01",
        annotator_id="a1",
        annotation_source="human_expert",
        asi_relevance_score=2,
        context_grounding_score=2,
        meaningful_diversity_score=2,
        safety_and_scope_hygiene_score=2,
        rationale="High score",
    )
    ann_low = HumanAnnotationRecord(
        candidate_id=cid0,
        asi_code="ASI01",
        annotator_id="a2",
        annotation_source="human_expert",
        asi_relevance_score=0,
        context_grounding_score=0,
        meaningful_diversity_score=0,
        safety_and_scope_hygiene_score=2,
        rationale="Low score",
    )
    ann_c1 = HumanAnnotationRecord(
        candidate_id=cid1,
        asi_code="ASI01",
        annotator_id="a1",
        annotation_source="human_expert",
        asi_relevance_score=2,
        context_grounding_score=1,
        meaningful_diversity_score=2,
        safety_and_scope_hygiene_score=2,
        rationale="Consistent score",
    )

    rep_order1 = evaluate_generation_result(result, annotations=[ann_high, ann_low, ann_c1, ann_c1])
    rep_order2 = evaluate_generation_result(result, annotations=[ann_low, ann_high, ann_c1, ann_c1])

    assert rep_order1.semantic_quality == rep_order2.semantic_quality
    sem = rep_order1.semantic_quality
    assert sem.evaluation_status == "human_annotated"
    assert sem.is_ground_truth is True
    assert sem.annotated_candidate_count == 1  # Only cid1 counted; cid0 rejected for conflict!
    assert sem.conflicting_annotation_candidate_count == 1
    assert sem.duplicate_annotation_count == 1
    assert sem.mean_context_grounding == 1.0


@pytest.mark.parametrize(
    "bad_counts",
    [
        {"requested": "bad"},
        {"requested": True},
        {"requested": -5},
        {"requested": 999_999},
        {"requested": 0},
        {"requested": 1, "generated": 1, "accepted": 1, "rejected": 0, "selected_for_save": 2},
        "not-a-dict",
    ],
)
def test_r03_malformed_or_inconsistent_provenance_counts_never_crash_or_fake_completeness(
    bad_counts: Any,
) -> None:
    secret_str = "sk-prov-secret-canary-9999"
    if isinstance(bad_counts, dict) and bad_counts.get("requested") == "bad":
        bad_counts = {"requested": f"bad-{secret_str}"}

    raw = json.dumps(
        {
            "schema_version": "1.0",
            "source_tool": "secagent_g11_generator",
            "generation_provenance": {
                "generation_id": "gen-r030001",
                "target_id": "t1",
                "target_revision_sha256": "1" * 64,
                "application_context_revision_sha256": "2" * 64,
                "context_snapshot_sha256": "3" * 64,
                "provider_id": "mock",
                "model": "mock-v1",
                "meets_requested_counts": True,
                "counts": bad_counts,
            },
            "testcases": [
                {
                    "testcase_id": "G11-ASI01-001",
                    "prompt": "Synthetic probe #1",
                    "metadata": {"asi_category": "goal_hijacking", "context_basis": ["purpose"]},
                },
                {
                    "testcase_id": "G11-ASI01-002",
                    "prompt": "Synthetic probe #2",
                    "metadata": {"asi_category": "goal_hijacking", "context_basis": ["purpose"]},
                },
            ],
        }
    ).encode("utf-8")

    rep = evaluate_persisted_dataset(normalize_dataset(raw, "r03.json"))
    assert rep.provenance_completeness.complete is False
    assert "provenance_counts" in rep.provenance_completeness.invalid_fields
    assert rep.meets_requested_counts is False
    assert rep.usability_status == "usable_saved_subset_unknown_completeness"
    assert rep.overall_metrics.requested_count is None
    assert rep.overall_metrics.acceptance_vs_requested_rate.rate is None
    assert secret_str not in export_quality_report_json(rep)
    assert secret_str not in render_quality_report_markdown(rep)


@pytest.mark.parametrize(
    "partial_counts",
    [
        {"requested": 3},
        {"requested": 3, "accepted": 3, "rejected": 0, "selected_for_save": 3},  # missing generated
        {"requested": 3, "generated": 3, "rejected": 0, "selected_for_save": 3},  # missing accepted
        {"requested": 3, "generated": 3, "accepted": 3, "selected_for_save": 3},  # missing rejected
        {"requested": 3, "generated": 3, "accepted": 3, "rejected": 0},  # missing selected_for_save
    ],
)
def test_r03_incomplete_provenance_counts_marked_missing_and_never_assert_completeness(
    partial_counts: dict[str, int],
) -> None:
    raw = json.dumps(
        {
            "schema_version": "1.0",
            "source_tool": "secagent_g11_generator",
            "generation_provenance": {
                "generation_id": "gen-r03inc01",
                "target_id": "t1",
                "target_revision_sha256": "1" * 64,
                "application_context_revision_sha256": "2" * 64,
                "context_snapshot_sha256": "3" * 64,
                "provider_id": "mock",
                "model": "mock-v1",
                "meets_requested_counts": True,
                "counts": partial_counts,
            },
            "testcases": [
                {
                    "testcase_id": f"G11-ASI01-00{i}",
                    "prompt": f"Synthetic probe #{i}",
                    "metadata": {"asi_category": "goal_hijacking", "context_basis": ["purpose"]},
                }
                for i in (1, 2, 3)
            ],
        }
    ).encode("utf-8")

    rep = evaluate_persisted_dataset(normalize_dataset(raw, "r03-inc.json"))
    assert rep.provenance_completeness.complete is False
    assert "provenance_counts" in rep.provenance_completeness.missing_fields
    assert rep.meets_requested_counts is False
    assert rep.usability_status == "usable_saved_subset_unknown_completeness"
    assert rep.overall_metrics.requested_count is None
    assert rep.overall_metrics.acceptance_vs_requested_rate.rate is None


# ---------------------------------------------------------------------------
# 10. Semantic annotation source distinction, serialization, template & secret safety
# ---------------------------------------------------------------------------


def test_semantic_annotation_sources_serialization_template_and_no_secret_leakage(
    tmp_path: Path,
) -> None:
    catalog, app_store, target_id = _make_env(tmp_path)
    secret_canary = "sk-quality-secret-never-leak-55555"

    service = GeneratorService(
        catalog=catalog,
        application_contexts=app_store,
        provider=MockGeneratorProvider(mode="success"),
    )
    result = service.generate(
        GenerationServiceRequest(
            target_id=target_id,
            counts_by_asi={"ASI01": 2},
            extra_sensitive_values=(secret_canary,),
        ),
        generation_id="gen-qtest0001",
    )

    # A. Unannotated report -> not_annotated, is_ground_truth=False
    rep_unannotated = evaluate_generation_result(result)
    assert rep_unannotated.semantic_quality.evaluation_status == "not_annotated"
    assert rep_unannotated.semantic_quality.is_ground_truth is False
    assert rep_unannotated.semantic_quality.high_quality_rate is None

    # B. Model-assisted annotation -> explicitly marked non-ground-truth!
    model_ann = [
        HumanAnnotationRecord(
            candidate_id=result.accepted_candidates[0].candidate_id,
            asi_code="ASI01",
            annotator_id="external-llm-helper",
            annotation_source="external_model_assisted_non_ground_truth",
            asi_relevance_score=2,
            context_grounding_score=2,
            meaningful_diversity_score=2,
            safety_and_scope_hygiene_score=2,
            rationale="Model-estimated score only.",
        )
    ]
    rep_model = evaluate_generation_result(result, annotations=model_ann)
    assert rep_model.semantic_quality.evaluation_status == "model_assisted_non_ground_truth"
    assert rep_model.semantic_quality.is_ground_truth is False

    # C. Human expert annotation -> human_annotated, is_ground_truth=True
    human_ann = [
        HumanAnnotationRecord(
            candidate_id=result.accepted_candidates[0].candidate_id,
            asi_code="ASI01",
            annotator_id="researcher-01",
            annotation_source="human_expert",
            asi_relevance_score=2,
            context_grounding_score=2,
            meaningful_diversity_score=1,
            safety_and_scope_hygiene_score=2,
            rationale="Grounded in ticket boundary; moderate variation.",
        )
    ]
    rep_human = evaluate_generation_result(result, annotations=human_ann)
    assert rep_human.semantic_quality.evaluation_status == "human_annotated"
    assert rep_human.semantic_quality.is_ground_truth is True
    assert rep_human.semantic_quality.annotation_coverage_rate.rate == 0.5

    # D. JSON & Markdown export round-trip and secret-freedom
    exported_json = export_quality_report_json(rep_human)
    roundtrip = DatasetQualityReport.model_validate(json.loads(exported_json))
    assert compute_quality_report_sha256(roundtrip) == compute_quality_report_sha256(rep_human)
    assert secret_canary not in exported_json

    md = render_quality_report_markdown(rep_human)
    assert "Deterministic Metrics" in md
    assert "Semantic Quality" in md
    assert "Evaluation Limitations" in md
    assert secret_canary not in md

    # E. Structured manual annotation template
    template = create_human_annotation_template(result)
    assert template["rubric_version"] == "1.0.0"
    assert len(template["rubric"]) == len(SEMANTIC_QUALITY_RUBRIC_V1) == 4
    assert len(template["items"]) == 2
    assert secret_canary not in json.dumps(template)


# ---------------------------------------------------------------------------
# 11. Deterministic repeated runs & static G12/Target/Judge isolation
# ---------------------------------------------------------------------------


def test_deterministic_repeated_runs_and_g12_ast_isolation(tmp_path: Path) -> None:
    suite_a = run_offline_quality_benchmark(tmp_path / "repeat_a")
    suite_b = run_offline_quality_benchmark(tmp_path / "repeat_b")

    assert suite_a.scenario_count == suite_b.scenario_count == 9
    for sc_a, sc_b in zip(suite_a.scenarios, suite_b.scenarios, strict=True):
        assert sc_a.scenario_id == sc_b.scenario_id
        assert sc_a.report.usability_status == sc_b.report.usability_status
        assert sc_a.report.overall_metrics == sc_b.report.overall_metrics
        assert sc_a.report.semantic_quality == sc_b.report.semantic_quality
        assert sc_a.report.provenance_completeness == sc_b.report.provenance_completeness
        if sc_a.report.source_kind == "generation_result":
            # GenerationResult scenarios have identical canonical SHA-256 across repeated runs!
            assert sc_a.report_sha256 == sc_b.report_sha256

    # Static AST check: G11.5 modules never import Judge, Target, Execution, or Observers
    forbidden_roots = {"evaluators", "integrations", "observers", "targets", "testing"}
    for path in (
        Path("backend/src/generator/quality_models.py"),
        Path("backend/src/generator/quality_evaluator.py"),
        Path("backend/src/generator/quality_benchmark.py"),
    ):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in forbidden_roots
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in forbidden_roots
