"""Deterministic dataset quality evaluator, rubric aggregator, and report exporters (G11.5).

Reuses G11.3B (`GenerationResult`, `AcceptedCandidate`, `compute_normalized_prompt_sha256`,
`compute_prompt_sha256`) and existing SecAgent dataset contracts (`DatasetEnvelope`,
`infer_testcase_asi_code`) without contacting any LLM, Target, or Judge.
"""

from __future__ import annotations

from hashlib import sha256
import json
import math
from statistics import median
from typing import Any, Mapping, Sequence

from generator.constants import AsiCode, GENERATOR_SOURCE_TOOL, SUPPORTED_ASI_CODES
from generator.deduplication import compute_normalized_prompt_sha256, compute_prompt_sha256
from generator.quality_models import (
    AsiQualitySummary,
    ContextBasisCoverageStats,
    DatasetQualityReport,
    DeterministicDiversityStats,
    DeterministicQualityMetrics,
    HumanAnnotationRecord,
    ProvenanceCompletenessCheck,
    QUALITY_RUBRIC_VERSION,
    RatioMetric,
    SEMANTIC_QUALITY_RUBRIC_V1,
    SMALL_SAMPLE_THRESHOLD,
    SemanticEvaluationStatus,
    SemanticQualitySummary,
    UsabilityStatus,
)
from generator.service import GenerationResult
from workflow.dataset_models import DatasetEnvelope, infer_testcase_asi_code

_BASE_EVALUATION_LIMITATIONS: tuple[str, ...] = (
    "Structural/schema validity does NOT imply security relevance, semantic quality, or realistic attack effectiveness.",
    "Testcase quality is distinct from Target attack success rate (ASR); G11.5 never executes prompts against a Target or computes Target PASS/FAIL verdicts.",
    "Exact/normalized text deduplication and strategy_tag entropy measure surface lexical/tag distribution only, not semantic diversity.",
    "Deterministic metrics cannot substitute for rubric-guided human annotation on ASI relevance and context grounding.",
)

_SHA256_LEN = 64
_MAX_SAFE_PROVENANCE_COUNT = 10_000


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == _SHA256_LEN and all(c in "0123456789abcdef" for c in value)


def _parse_safe_provenance_count(raw: Any) -> tuple[int | None, bool]:
    """Validate a provenance count field strictly without crashing or coercing bools/strings.

    Returns `(value, is_invalid)`:
    - `None` -> `(None, False)` (missing, not malformed)
    - bool / non-int / negative / oversized -> `(None, True)` (malformed)
    - valid int in `[0, _MAX_SAFE_PROVENANCE_COUNT]` -> `(raw, False)`
    """
    if raw is None:
        return None, False
    if isinstance(raw, bool) or not isinstance(raw, int):
        return None, True
    if raw < 0 or raw > _MAX_SAFE_PROVENANCE_COUNT:
        return None, True
    return raw, False


def _compute_shannon_entropy(counts: dict[str, int]) -> tuple[float | None, float | None]:
    total = sum(counts.values())
    if total == 0:
        return None, None
    non_zero = [c for c in counts.values() if c > 0]
    k = len(non_zero)
    if k == 0:
        return None, None
    entropy = 0.0
    for c in non_zero:
        p = c / total
        entropy -= p * math.log2(p)
    entropy = round(max(0.0, entropy), 6)
    if k == 1:
        return entropy, 0.0
    max_entropy = math.log2(k)
    return entropy, round(min(1.0, entropy / max_entropy), 6)


def _compute_diversity_stats(
    prompts: Sequence[str],
    strategy_tags: Sequence[str],
) -> DeterministicDiversityStats:
    accepted_count = len(prompts)
    unique_norm = len({compute_normalized_prompt_sha256(p) for p in prompts})
    tag_counts: dict[str, int] = {}
    for tag in strategy_tags:
        tag_counts[tag] = tag_counts.get(tag, 0) + 1
    unique_tags = len(tag_counts)
    entropy, norm_entropy = _compute_shannon_entropy(tag_counts)

    if accepted_count > 0:
        byte_lengths = [len(p.encode("utf-8")) for p in prompts]
        min_b = min(byte_lengths)
        med_b = round(float(median(byte_lengths)), 2)
        max_b = max(byte_lengths)
    else:
        min_b = None
        med_b = None
        max_b = None

    return DeterministicDiversityStats(
        unique_normalized_prompts=unique_norm,
        unique_strategy_tags=unique_tags,
        strategy_tag_diversity_ratio=RatioMetric.from_counts(
            unique_tags,
            accepted_count,
            definition="unique_strategy_tags / accepted_count",
        ),
        strategy_tag_shannon_entropy_bits=entropy,
        normalized_strategy_entropy=norm_entropy,
        prompt_utf8_bytes_min=min_b,
        prompt_utf8_bytes_median=med_b,
        prompt_utf8_bytes_max=max_b,
    )


def _compute_context_basis_coverage(
    basis_lists: Sequence[Sequence[str]],
    confirmed_snapshot_fields: Sequence[str],
) -> ContextBasisCoverageStats:
    citation_counts: dict[str, int] = {}
    reviewed_policy_cited = 0
    total_basis_entries = 0

    for basis in basis_lists:
        total_basis_entries += len(basis)
        for token in basis:
            citation_counts[token] = citation_counts.get(token, 0) + 1
            if token == "reviewed_policy":
                reviewed_policy_cited += 1

    confirmed_sorted = tuple(sorted(set(confirmed_snapshot_fields)))
    confirmed_set = set(confirmed_sorted)
    distinct_cited = tuple(sorted(citation_counts.keys()))
    cited_confirmed = [f for f in distinct_cited if f in confirmed_set]

    mean_basis = (
        round(total_basis_entries / len(basis_lists), 4)
        if len(basis_lists) > 0
        else None
    )

    return ContextBasisCoverageStats(
        field_citation_counts=dict(sorted(citation_counts.items())),
        distinct_cited_fields=distinct_cited,
        confirmed_snapshot_fields=confirmed_sorted,
        confirmed_field_coverage_rate=RatioMetric.from_counts(
            len(cited_confirmed),
            len(confirmed_sorted),
            definition="distinct_cited_confirmed_fields / total_confirmed_snapshot_fields",
        ),
        mean_basis_fields_per_candidate=mean_basis,
        reviewed_policy_cited_count=reviewed_policy_cited,
    )


def _aggregate_semantic_annotations(
    annotations: Sequence[HumanAnnotationRecord],
    *,
    expected_asi_by_candidate_id: Mapping[str, AsiCode],
    alias_to_canonical_id: Mapping[str, str] | None = None,
) -> SemanticQualitySummary:
    """Aggregate rubric annotations with strict (candidate_id, expected_asi) matching
    and order-independent conflict rejection (R02)."""
    canonical_targets = set(expected_asi_by_candidate_id.keys())
    accepted_count = len(canonical_targets)

    unmatched_count = 0
    asi_mismatched_count = 0
    grouped_valid: dict[str, list[HumanAnnotationRecord]] = {}

    for ann in annotations:
        canonical_id = (
            alias_to_canonical_id.get(ann.candidate_id, ann.candidate_id)
            if alias_to_canonical_id is not None
            else ann.candidate_id
        )
        expected_asi = expected_asi_by_candidate_id.get(canonical_id)
        if expected_asi is None:
            unmatched_count += 1
            continue
        if ann.asi_code != expected_asi:
            asi_mismatched_count += 1
            continue
        grouped_valid.setdefault(canonical_id, []).append(ann)

    matched: list[HumanAnnotationRecord] = []
    conflicting_candidates = 0
    conflicting_records = 0
    duplicate_records = 0

    for canonical_id in sorted(grouped_valid.keys()):
        group = grouped_valid[canonical_id]
        if len(group) == 1:
            matched.append(group[0])
            continue
        signatures = {
            (
                a.annotation_source,
                a.asi_relevance_score,
                a.context_grounding_score,
                a.meaningful_diversity_score,
                a.safety_and_scope_hygiene_score,
            )
            for a in group
        }
        if len(signatures) > 1:
            # Order-independent fail-closed: conflicting annotations for the same candidate are rejected.
            conflicting_candidates += 1
            conflicting_records += len(group)
            continue
        # Exact identical duplicate annotations collapse cleanly independent of input order.
        duplicate_records += len(group) - 1
        matched.append(group[0])

    rejected_total = unmatched_count + asi_mismatched_count + conflicting_records

    extra_notes: list[str] = []
    if asi_mismatched_count > 0:
        extra_notes.append(
            f"Rejected {asi_mismatched_count} annotation(s) whose asi_code did not match the candidate's expected ASI."
        )
    if conflicting_candidates > 0:
        extra_notes.append(
            f"Rejected conflicting annotations for {conflicting_candidates} candidate(s) (order-independent fail-closed)."
        )
    if unmatched_count > 0:
        extra_notes.append(
            f"Ignored {unmatched_count} annotation(s) referencing unknown candidate IDs."
        )

    if not matched:
        base_lim = (
            "No valid matching human rubric annotations supplied; ASI relevance, context grounding, "
            "meaningful diversity, and safety hygiene remain unmeasured semantically."
        )
        return SemanticQualitySummary(
            evaluation_status="not_annotated",
            is_ground_truth=False,
            annotated_candidate_count=0,
            annotation_coverage_rate=RatioMetric.from_counts(
                0,
                accepted_count,
                definition="annotated_candidate_count / accepted_count",
            ),
            rejected_annotation_count=rejected_total,
            asi_mismatched_annotation_count=asi_mismatched_count,
            unmatched_annotation_count=unmatched_count,
            conflicting_annotation_candidate_count=conflicting_candidates,
            duplicate_annotation_count=duplicate_records,
            limitations=(base_lim, *extra_notes),
        )

    sources = {a.annotation_source for a in matched}
    if "external_model_assisted_non_ground_truth" in sources:
        status: SemanticEvaluationStatus = "model_assisted_non_ground_truth"
        is_gt = False
        base_lims: tuple[str, ...] = (
            "Includes model-assisted annotations; scores represent model estimates and MUST NOT "
            "be reported as ground truth.",
        )
    elif sources == {"benchmark_gold_rubric"}:
        status = "benchmark_labeled"
        is_gt = True
        base_lims = (
            "Labels come from the controlled synthetic benchmark gold rubric for offline harness "
            "verification, NOT from Live DeepSeek outputs.",
        )
    else:
        status = "human_annotated"
        is_gt = True
        base_lims = (
            "Semantic scores reflect human rubric annotations over the annotated subset; "
            "inter-annotator agreement should be reported for multi-rater TLCN studies.",
        )

    n = len(matched)
    mean_asi = round(sum(a.asi_relevance_score for a in matched) / n, 4)
    mean_ctx = round(sum(a.context_grounding_score for a in matched) / n, 4)
    mean_div = round(sum(a.meaningful_diversity_score for a in matched) / n, 4)
    mean_safe = round(sum(a.safety_and_scope_hygiene_score for a in matched) / n, 4)
    high_q = sum(
        1
        for a in matched
        if (
            a.asi_relevance_score == 2
            and a.context_grounding_score == 2
            and a.safety_and_scope_hygiene_score == 2
        )
    )

    return SemanticQualitySummary(
        evaluation_status=status,
        is_ground_truth=is_gt,
        annotated_candidate_count=n,
        annotation_coverage_rate=RatioMetric.from_counts(
            n,
            accepted_count,
            definition="annotated_candidate_count / accepted_count",
        ),
        rejected_annotation_count=rejected_total,
        asi_mismatched_annotation_count=asi_mismatched_count,
        unmatched_annotation_count=unmatched_count,
        conflicting_annotation_candidate_count=conflicting_candidates,
        duplicate_annotation_count=duplicate_records,
        mean_asi_relevance=mean_asi,
        mean_context_grounding=mean_ctx,
        mean_meaningful_diversity=mean_div,
        mean_safety_and_scope_hygiene=mean_safe,
        high_quality_rate=RatioMetric.from_counts(
            high_q,
            n,
            definition="candidates_scoring_2_on_asi_context_and_safety / annotated_candidate_count",
        ),
        limitations=(*base_lims, *extra_notes),
    )


def _classify_usability(
    *,
    accepted_count: int,
    meets_requested: bool,
    status_label: str,
) -> UsabilityStatus:
    if accepted_count == 0:
        if status_label == "empty_with_context_gaps":
            return "not_usable_empty_context_gaps"
        return "not_usable_no_accepted_candidates"
    if meets_requested:
        return "usable_complete"
    return "usable_partial_subset"


def _check_generation_provenance(result: GenerationResult) -> ProvenanceCompletenessCheck:
    checked = (
        "generation_id",
        "target_id",
        "target_revision_sha256",
        "application_context_revision_sha256",
        "context_snapshot_sha256",
        "provider_id",
        "model",
        "per_asi_skill_sha256",
        "per_asi_sanitized_request_sha256",
        "accepted_candidate_prompt_hashes",
    )
    missing: list[str] = []
    invalid: list[str] = []

    if not result.generation_id:
        missing.append("generation_id")
    if not result.target_id:
        missing.append("target_id")
    if not _is_hex64(result.target_revision_sha256):
        missing.append("target_revision_sha256")
    if not _is_hex64(result.application_context_revision_sha256):
        missing.append("application_context_revision_sha256")
    if not _is_hex64(result.context_snapshot_sha256):
        missing.append("context_snapshot_sha256")
    if not result.provider_id:
        missing.append("provider_id")
    if not result.model:
        missing.append("model")

    called_asis = [r for r in result.asi_results.values() if r.call_count > 0]
    if any(not _is_hex64(r.skill_sha256) for r in called_asis):
        missing.append("per_asi_skill_sha256")
    if any(not _is_hex64(r.sanitized_request_sha256) for r in called_asis):
        missing.append("per_asi_sanitized_request_sha256")

    for cand in result.accepted_candidates:
        if compute_prompt_sha256(cand.prompt) != cand.prompt_sha256:
            invalid.append("accepted_candidate_prompt_hashes")
            break

    return ProvenanceCompletenessCheck(
        complete=(len(missing) == 0 and len(invalid) == 0),
        checked_fields=checked,
        missing_fields=tuple(missing),
        invalid_fields=tuple(invalid),
    )


def evaluate_generation_result(
    result: GenerationResult,
    *,
    annotations: Sequence[HumanAnnotationRecord] = (),
    confirmed_context_fields: Sequence[str] | None = None,
) -> DatasetQualityReport:
    """Compute a versioned deterministic + optional rubric quality report from a GenerationResult."""
    # Derive confirmed projected context fields from G11.3A provenance inputs if not provided.
    derived_confirmed: set[str] = set(confirmed_context_fields or ())
    if confirmed_context_fields is None:
        for asi_res in result.asi_results.values():
            if asi_res.provenance_inputs is not None:
                derived_confirmed.update(asi_res.provenance_inputs.projected_context_fields)
            if asi_res.reviewed_policy_id is not None:
                derived_confirmed.add("reviewed_policy")
    confirmed_tuple = tuple(sorted(derived_confirmed))

    per_asi_summaries: dict[AsiCode, AsiQualitySummary] = {}
    overall_asi_dist: dict[AsiCode, int] = {}
    overall_strategy_dist: dict[str, int] = {}
    overall_prompts: list[str] = []
    overall_tags: list[str] = []
    overall_basis: list[tuple[str, ...]] = []

    total_provider_called_asis = 0
    total_contract_valid_asis = 0
    total_pre_dedup_valid = 0
    total_post_dedup_valid = 0
    total_dup_rejected = 0
    total_val_rejected = 0
    total_excess_rejected = 0

    for code in result.asi_order:
        r = result.asi_results[code]
        asi_called = 1 if r.call_count > 0 else 0
        asi_contract_valid = (
            1
            if (
                r.call_count > 0
                and r.status in {"completed", "partial", "empty_with_context_gaps", "empty_all_rejected"}
            )
            else 0
        )
        total_provider_called_asis += asi_called
        total_contract_valid_asis += asi_contract_valid

        dup_rej = r.duplicate_rejected_count
        excess_rej = r.rejection_reason_counts.get("exceeds_requested_count", 0)
        val_rej = max(0, r.rejected_count - dup_rej - excess_rej)

        total_pre_dedup_valid += r.pre_dedup_valid_count
        total_post_dedup_valid += r.post_dedup_valid_count
        total_dup_rejected += dup_rej
        total_val_rejected += val_rej
        total_excess_rejected += excess_rej

        asi_prompts = [c.prompt for c in r.accepted_candidates]
        asi_tags = [c.strategy_tag for c in r.accepted_candidates]
        asi_basis = [c.context_basis for c in r.accepted_candidates]
        asi_tag_dist: dict[str, int] = {}
        for tag in asi_tags:
            asi_tag_dist[tag] = asi_tag_dist.get(tag, 0) + 1
            overall_strategy_dist[tag] = overall_strategy_dist.get(tag, 0) + 1

        overall_prompts.extend(asi_prompts)
        overall_tags.extend(asi_tags)
        overall_basis.extend(asi_basis)
        overall_asi_dist[code] = r.accepted_count

        asi_confirmed = (
            tuple(sorted(set(r.provenance_inputs.projected_context_fields) | ({"reviewed_policy"} if r.reviewed_policy_id else set())))
            if (confirmed_context_fields is None and r.provenance_inputs is not None)
            else confirmed_tuple
        )

        asi_metrics = DeterministicQualityMetrics(
            requested_count=r.requested_count,
            generated_count=r.generated_count,
            pre_dedup_valid_count=r.pre_dedup_valid_count,
            post_dedup_valid_count=r.post_dedup_valid_count,
            accepted_count=r.accepted_count,
            rejected_count=r.rejected_count,
            duplicate_rejected_count=dup_rej,
            validation_rejected_count=val_rej,
            excess_rejected_count=excess_rej,
            operator_edited_count=0,
            ai_original_count=r.accepted_count,
            output_contract_validity_rate=RatioMetric.from_counts(
                asi_contract_valid,
                asi_called,
                definition="schema_and_asi_valid_provider_calls / total_provider_called_asis",
            ),
            candidate_grounding_validity_rate=RatioMetric.from_counts(
                r.pre_dedup_valid_count,
                r.generated_count,
                definition="pre_dedup_context_valid_candidates / generated_count",
            ),
            acceptance_vs_requested_rate=RatioMetric.from_counts(
                r.accepted_count,
                r.requested_count,
                definition="accepted_count / requested_count",
            ),
            exact_normalized_duplicate_rate=RatioMetric.from_counts(
                dup_rej,
                r.pre_dedup_valid_count,
                definition="duplicate_rejected_count / pre_dedup_valid_count",
            ),
            asi_distribution={code: r.accepted_count},
            asi_alignment_verified=all(c.asi_code == code for c in r.accepted_candidates),
            strategy_tag_distribution=dict(sorted(asi_tag_dist.items())),
            rejection_reason_counts=dict(sorted(r.rejection_reason_counts.items())),
            diversity_stats=_compute_diversity_stats(asi_prompts, asi_tags),
            context_basis_coverage=_compute_context_basis_coverage(asi_basis, asi_confirmed),
        )

        meets_asi = r.status == "completed" and r.accepted_count == r.requested_count
        per_asi_summaries[code] = AsiQualitySummary(
            asi_code=code,
            generation_status=r.status,
            effective_scope=r.effective_scope,
            usability_status=_classify_usability(
                accepted_count=r.accepted_count,
                meets_requested=meets_asi,
                status_label=r.status,
            ),
            meets_requested_count=meets_asi,
            missing_from_requested_count=max(0, r.requested_count - r.accepted_count),
            context_gaps=r.context_gaps,
            metrics=asi_metrics,
            call_count=r.call_count,
            duration_ms=r.duration_ms,
        )

    overall_metrics = DeterministicQualityMetrics(
        requested_count=result.total_requested,
        generated_count=result.total_generated,
        pre_dedup_valid_count=total_pre_dedup_valid,
        post_dedup_valid_count=total_post_dedup_valid,
        accepted_count=result.total_accepted,
        rejected_count=result.total_rejected,
        duplicate_rejected_count=total_dup_rejected,
        validation_rejected_count=total_val_rejected,
        excess_rejected_count=total_excess_rejected,
        operator_edited_count=0,
        ai_original_count=result.total_accepted,
        output_contract_validity_rate=RatioMetric.from_counts(
            total_contract_valid_asis,
            total_provider_called_asis,
            definition="schema_and_asi_valid_provider_calls / total_provider_called_asis",
        ),
        candidate_grounding_validity_rate=RatioMetric.from_counts(
            total_pre_dedup_valid,
            result.total_generated,
            definition="pre_dedup_context_valid_candidates / generated_count",
        ),
        acceptance_vs_requested_rate=RatioMetric.from_counts(
            result.total_accepted,
            result.total_requested,
            definition="accepted_count / requested_count",
        ),
        exact_normalized_duplicate_rate=RatioMetric.from_counts(
            total_dup_rejected,
            total_pre_dedup_valid,
            definition="duplicate_rejected_count / pre_dedup_valid_count",
        ),
        asi_distribution=overall_asi_dist,
        asi_alignment_verified=all(
            summary.metrics.asi_alignment_verified for summary in per_asi_summaries.values()
        ),
        strategy_tag_distribution=dict(sorted(overall_strategy_dist.items())),
        rejection_reason_counts=dict(sorted(result.rejection_reason_counts.items())),
        diversity_stats=_compute_diversity_stats(overall_prompts, overall_tags),
        context_basis_coverage=_compute_context_basis_coverage(overall_basis, confirmed_tuple),
    )

    expected_asi_map: dict[str, AsiCode] = {
        c.candidate_id: c.asi_code for c in result.accepted_candidates
    }
    semantic = _aggregate_semantic_annotations(
        annotations,
        expected_asi_by_candidate_id=expected_asi_map,
    )
    is_mock = result.provider_id.lower().startswith("mock")
    small_sample = (
        result.total_accepted < SMALL_SAMPLE_THRESHOLD or result.total_requested < SMALL_SAMPLE_THRESHOLD
    )

    limitations = list(_BASE_EVALUATION_LIMITATIONS)
    if is_mock:
        limitations.append(
            "Provider is a synthetic/mock provider; these metrics validate pipeline behavior only "
            "and MUST NOT be reported as Live DeepSeek experimental quality results."
        )
    if not result.meets_requested_counts:
        limitations.append(
            f"Generation did not meet requested count ({result.total_accepted}/{result.total_requested}); "
            "partial or empty datasets require explicit caution before analysis."
        )
    if small_sample:
        limitations.append(
            f"Small sample size (accepted={result.total_accepted}, requested={result.total_requested}, "
            f"threshold={SMALL_SAMPLE_THRESHOLD}); percentages and entropy have high variance."
        )

    return DatasetQualityReport(
        source_kind="generation_result",
        generation_id=result.generation_id,
        target_id=result.target_id,
        provider_id=result.provider_id,
        model=result.model,
        is_synthetic_or_mock_provider=is_mock,
        overall_status=result.overall_status,
        meets_requested_counts=result.meets_requested_counts,
        usability_status=_classify_usability(
            accepted_count=result.total_accepted,
            meets_requested=result.meets_requested_counts,
            status_label=result.overall_status,
        ),
        small_sample_warning=small_sample,
        provenance_completeness=_check_generation_provenance(result),
        overall_metrics=overall_metrics,
        per_asi_summaries=per_asi_summaries,
        semantic_quality=semantic,
        evaluation_limitations=tuple(limitations),
    )


def evaluate_persisted_dataset(
    envelope: DatasetEnvelope,
    *,
    annotations: Sequence[HumanAnnotationRecord] = (),
    expected_confirmed_fields: Sequence[str] | None = None,
) -> DatasetQualityReport:
    """Evaluate a persisted DatasetEnvelope reloaded from DatasetRepository."""
    raw_prov = (
        envelope.source_metadata.get("generation_provenance")
        if isinstance(envelope.source_metadata, dict)
        else None
    )
    prov = raw_prov if isinstance(raw_prov, dict) else {}

    checked_prov_fields = (
        "source_tool",
        "generation_provenance",
        "generation_id",
        "target_id",
        "target_revision_sha256",
        "application_context_revision_sha256",
        "context_snapshot_sha256",
        "provider_id",
        "model",
        "provenance_counts",
        "testcase_prompt_hashes",
    )
    missing_prov: list[str] = []
    invalid_prov: list[str] = []

    if envelope.source_tool != GENERATOR_SOURCE_TOOL:
        invalid_prov.append("source_tool")
    if not prov:
        missing_prov.append("generation_provenance")
    for key in ("generation_id", "target_id", "provider_id", "model"):
        val = prov.get(key)
        if not isinstance(val, str) or not val.strip():
            missing_prov.append(key)
    for sha_key in ("target_revision_sha256", "application_context_revision_sha256", "context_snapshot_sha256"):
        if not _is_hex64(prov.get(sha_key)):
            missing_prov.append(sha_key)

    # Check testcase hashes, duplicate normalized prompts, ASI alignment, and edit status.
    prompts: list[str] = []
    tags: list[str] = []
    basis_lists: list[tuple[str, ...]] = []
    asi_dist: dict[AsiCode, int] = {}
    asi_buckets: dict[AsiCode, list[Any]] = {}
    seen_norm_hashes: set[str] = set()
    dup_in_saved = 0
    edited_count = 0
    ai_orig_count = 0
    asi_aligned = True
    expected_asi_by_tc_id: dict[str, AsiCode] = {}
    alias_to_tc_id: dict[str, str] = {}

    for tc in envelope.testcases:
        if compute_prompt_sha256(tc.prompt) != tc.prompt_sha256:
            invalid_prov.append("testcase_prompt_hashes")
        prompts.append(tc.prompt)
        norm_h = compute_normalized_prompt_sha256(tc.prompt)
        if norm_h in seen_norm_hashes:
            dup_in_saved += 1
        else:
            seen_norm_hashes.add(norm_h)

        tag = tc.strategy_id or "unspecified"
        tags.append(tag)
        meta = tc.metadata if isinstance(tc.metadata, dict) else {}
        raw_basis = meta.get("context_basis")
        basis = tuple(str(x) for x in raw_basis if isinstance(x, str)) if isinstance(raw_basis, list) else ()
        basis_lists.append(basis)

        if meta.get("operator_edited") is True or meta.get("origin") == "operator_edited":
            edited_count += 1
        else:
            ai_orig_count += 1

        inferred = infer_testcase_asi_code(tc, fallback_run_id=envelope.run_id)
        if inferred in SUPPORTED_ASI_CODES:
            asi_code: AsiCode = inferred  # type: ignore[assignment]
            asi_dist[asi_code] = asi_dist.get(asi_code, 0) + 1
            asi_buckets.setdefault(asi_code, []).append(tc)
            expected_asi_by_tc_id[tc.testcase_id] = asi_code
            src_cid = meta.get("source_candidate_id")
            if isinstance(src_cid, str) and src_cid.strip():
                alias_to_tc_id[src_cid.strip()] = tc.testcase_id
        else:
            asi_aligned = False

    saved_count = envelope.total_testcases

    # R03: Strictly validate provenance counts without crashing or fabricating completeness.
    req_count: int | None = None
    gen_count: int | None = None
    rej_count: int | None = None
    counts_valid = False

    if "counts" not in prov:
        missing_prov.append("provenance_counts")
    elif not isinstance(prov.get("counts"), dict):
        invalid_prov.append("provenance_counts")
    else:
        counts_block = prov["counts"]
        p_req, bad_req = _parse_safe_provenance_count(counts_block.get("requested"))
        p_gen, bad_gen = _parse_safe_provenance_count(counts_block.get("generated"))
        p_acc, bad_acc = _parse_safe_provenance_count(counts_block.get("accepted"))
        p_rej, bad_rej = _parse_safe_provenance_count(counts_block.get("rejected"))
        p_sel, bad_sel = _parse_safe_provenance_count(counts_block.get("selected_for_save"))

        any_bad = bad_req or bad_gen or bad_acc or bad_rej or bad_sel
        any_missing = any(v is None for v in (p_req, p_gen, p_acc, p_rej, p_sel))
        inconsistent = False
        if p_req is not None and (p_req < 1 or saved_count > p_req):
            inconsistent = True
        if p_acc is not None and saved_count > p_acc:
            inconsistent = True
        if p_gen is not None and p_acc is not None and p_acc > p_gen:
            inconsistent = True
        if p_sel is not None and p_sel != saved_count:
            inconsistent = True

        if any_bad or inconsistent:
            invalid_prov.append("provenance_counts")
        elif any_missing:
            missing_prov.append("provenance_counts")
        else:
            counts_valid = True
            req_count = p_req
            gen_count = p_gen
            rej_count = p_rej

    meets_req = (
        counts_valid
        and req_count is not None
        and prov.get("meets_requested_counts") is True
        and saved_count == req_count
    )

    if counts_valid and req_count is not None:
        overall_acc_ratio = RatioMetric.from_counts(
            saved_count,
            req_count,
            definition="saved_testcase_count / original_requested_count",
        )
        overall_usability: UsabilityStatus = (
            "usable_complete" if meets_req else "usable_partial_subset"
        )
    else:
        overall_acc_ratio = RatioMetric.from_counts(
            0,
            0,
            definition="unavailable: original requested_count missing or invalid in dataset provenance",
        )
        overall_usability = "usable_saved_subset_unknown_completeness"

    confirmed_fields = tuple(sorted(set(expected_confirmed_fields or ())))
    if not confirmed_fields:
        confirmed_fields = tuple(sorted({tok for b in basis_lists for tok in b}))

    tag_dist: dict[str, int] = {}
    for t in tags:
        tag_dist[t] = tag_dist.get(t, 0) + 1

    overall_metrics = DeterministicQualityMetrics(
        requested_count=req_count,
        generated_count=gen_count,
        pre_dedup_valid_count=saved_count,
        post_dedup_valid_count=saved_count - dup_in_saved,
        accepted_count=saved_count,
        rejected_count=rej_count,
        duplicate_rejected_count=0,
        saved_dataset_duplicate_count=dup_in_saved,
        validation_rejected_count=0,
        excess_rejected_count=0,
        operator_edited_count=edited_count,
        ai_original_count=ai_orig_count,
        output_contract_validity_rate=RatioMetric.from_counts(
            1 if envelope.total_testcases > 0 else 0,
            1,
            definition="valid_persisted_dataset_envelopes / evaluated_dataset_envelopes",
        ),
        candidate_grounding_validity_rate=RatioMetric.from_counts(
            sum(1 for b in basis_lists if len(b) > 0),
            saved_count,
            definition="testcases_with_recorded_context_basis / saved_testcase_count",
        ),
        acceptance_vs_requested_rate=overall_acc_ratio,
        exact_normalized_duplicate_rate=RatioMetric.from_counts(
            dup_in_saved,
            saved_count,
            definition="exact_normalized_duplicates_detected_in_saved_dataset / saved_testcase_count",
        ),
        asi_distribution=asi_dist,
        asi_alignment_verified=asi_aligned,
        strategy_tag_distribution=dict(sorted(tag_dist.items())),
        rejection_reason_counts={},
        diversity_stats=_compute_diversity_stats(prompts, tags),
        context_basis_coverage=_compute_context_basis_coverage(basis_lists, confirmed_fields),
    )

    # R01: Per-ASI persisted metrics never fabricate original requested_count from saved bucket size
    # and always measure real exact/normalized duplicates within each saved ASI bucket.
    per_asi: dict[AsiCode, AsiQualitySummary] = {}
    for code in SUPPORTED_ASI_CODES:
        bucket = asi_buckets.get(code)
        if not bucket:
            continue
        b_prompts = [tc.prompt for tc in bucket]
        b_tags = [tc.strategy_id or "unspecified" for tc in bucket]
        b_basis = [
            tuple(str(x) for x in tc.metadata.get("context_basis", []) if isinstance(x, str))
            if isinstance(tc.metadata, dict) and isinstance(tc.metadata.get("context_basis"), list)
            else ()
            for tc in bucket
        ]
        b_seen_norm: set[str] = set()
        b_dup_in_saved = 0
        for p in b_prompts:
            nh = compute_normalized_prompt_sha256(p)
            if nh in b_seen_norm:
                b_dup_in_saved += 1
            else:
                b_seen_norm.add(nh)

        b_tag_dist: dict[str, int] = {}
        for t in b_tags:
            b_tag_dist[t] = b_tag_dist.get(t, 0) + 1
        b_edited = sum(
            1
            for tc in bucket
            if isinstance(tc.metadata, dict)
            and (tc.metadata.get("operator_edited") is True or tc.metadata.get("origin") == "operator_edited")
        )
        b_scope = (
            bucket[0].metadata.get("effective_scope_metadata")
            if isinstance(bucket[0].metadata, dict)
            and isinstance(bucket[0].metadata.get("effective_scope_metadata"), str)
            else None
        )

        # Only know per-ASI requested count on a persisted dataset if single-ASI AND overall counts are valid.
        is_single_asi_with_valid_req = (
            counts_valid and req_count is not None and len(asi_buckets) == 1 and asi_aligned
        )
        if is_single_asi_with_valid_req and req_count is not None:
            b_req: int | None = req_count
            b_acc_ratio = RatioMetric.from_counts(
                len(bucket),
                req_count,
                definition="asi_saved_count / original_requested_count",
            )
            b_meets: bool | None = meets_req
            b_missing: int | None = max(0, req_count - len(bucket))
            b_usability: UsabilityStatus = (
                "usable_complete" if meets_req else "usable_partial_subset"
            )
        else:
            b_req = None
            b_acc_ratio = RatioMetric.from_counts(
                0,
                0,
                definition="unavailable: per-ASI original requested_count is not persisted in saved dataset",
            )
            b_meets = True if meets_req else None
            b_missing = 0 if meets_req else None
            b_usability = (
                "usable_complete" if meets_req else "usable_saved_subset_unknown_completeness"
            )

        b_metrics = DeterministicQualityMetrics(
            requested_count=b_req,
            generated_count=None,
            pre_dedup_valid_count=len(bucket),
            post_dedup_valid_count=len(bucket) - b_dup_in_saved,
            accepted_count=len(bucket),
            rejected_count=None,
            duplicate_rejected_count=0,
            saved_dataset_duplicate_count=b_dup_in_saved,
            validation_rejected_count=0,
            excess_rejected_count=0,
            operator_edited_count=b_edited,
            ai_original_count=len(bucket) - b_edited,
            output_contract_validity_rate=RatioMetric.from_counts(
                1, 1, definition="valid_persisted_asi_bucket / evaluated_asi_buckets"
            ),
            candidate_grounding_validity_rate=RatioMetric.from_counts(
                sum(1 for b in b_basis if len(b) > 0),
                len(bucket),
                definition="testcases_with_recorded_context_basis / asi_saved_count",
            ),
            acceptance_vs_requested_rate=b_acc_ratio,
            exact_normalized_duplicate_rate=RatioMetric.from_counts(
                b_dup_in_saved,
                len(bucket),
                definition="exact_normalized_duplicates_detected_in_saved_dataset / asi_saved_count",
            ),
            asi_distribution={code: len(bucket)},
            asi_alignment_verified=True,
            strategy_tag_distribution=dict(sorted(b_tag_dist.items())),
            rejection_reason_counts={},
            diversity_stats=_compute_diversity_stats(b_prompts, b_tags),
            context_basis_coverage=_compute_context_basis_coverage(b_basis, confirmed_fields),
        )
        per_asi[code] = AsiQualitySummary(
            asi_code=code,
            generation_status="saved",
            effective_scope=b_scope,
            usability_status=b_usability,
            meets_requested_count=b_meets,
            missing_from_requested_count=b_missing,
            metrics=b_metrics,
        )

    semantic = _aggregate_semantic_annotations(
        annotations,
        expected_asi_by_candidate_id=expected_asi_by_tc_id,
        alias_to_canonical_id=alias_to_tc_id,
    )

    provider_id = prov.get("provider_id") if isinstance(prov.get("provider_id"), str) else None
    model_name = prov.get("model") if isinstance(prov.get("model"), str) else None
    is_mock = bool(provider_id and provider_id.lower().startswith("mock"))
    small_sample = saved_count < SMALL_SAMPLE_THRESHOLD

    limitations = list(_BASE_EVALUATION_LIMITATIONS)
    if is_mock:
        limitations.append(
            "Dataset provenance indicates a synthetic/mock provider; do not cite as Live DeepSeek data."
        )
    if len(asi_buckets) > 1:
        limitations.append(
            "Persisted multi-ASI dataset provenance records overall counts only; per-ASI original "
            "requested counts are unavailable and reported as N/A rather than inferred from saved counts."
        )
    if missing_prov or invalid_prov:
        limitations.append(
            "Dataset provenance is incomplete or invalid; generation lineage and completeness cannot be fully verified."
        )
    if small_sample:
        limitations.append(
            f"Small sample size (saved={saved_count}, threshold={SMALL_SAMPLE_THRESHOLD}); "
            "interpret proportions and entropy cautiously."
        )

    return DatasetQualityReport(
        source_kind="persisted_dataset",
        generation_id=prov.get("generation_id") if isinstance(prov.get("generation_id"), str) else None,
        dataset_id=envelope.dataset_id,
        dataset_name=envelope.name,
        target_id=prov.get("target_id") if isinstance(prov.get("target_id"), str) else envelope.bot,
        provider_id=provider_id,
        model=model_name,
        is_synthetic_or_mock_provider=is_mock,
        overall_status=str(prov.get("overall_status") or "persisted"),
        meets_requested_counts=meets_req,
        usability_status=overall_usability,
        small_sample_warning=small_sample,
        provenance_completeness=ProvenanceCompletenessCheck(
            complete=(len(missing_prov) == 0 and len(invalid_prov) == 0),
            checked_fields=checked_prov_fields,
            missing_fields=tuple(missing_prov),
            invalid_fields=tuple(sorted(set(invalid_prov))),
        ),
        overall_metrics=overall_metrics,
        per_asi_summaries=per_asi,
        semantic_quality=semantic,
        evaluation_limitations=tuple(limitations),
    )


def create_human_annotation_template(result: GenerationResult) -> dict[str, Any]:
    """Generate a structured offline manual-annotation template for TLCN semantic review."""
    return {
        "rubric_version": QUALITY_RUBRIC_VERSION,
        "generation_id": result.generation_id,
        "target_id": result.target_id,
        "instructions": (
            "Score each accepted candidate on 0/1/2 per criterion using SEMANTIC_QUALITY_RUBRIC_V1 "
            "and record a concise rationale. Optional offline research workflow only; NOT required "
            "in Generate & Run."
        ),
        "rubric": [c.model_dump(mode="json") for c in SEMANTIC_QUALITY_RUBRIC_V1],
        "items": [
            {
                "candidate_id": cand.candidate_id,
                "asi_code": cand.asi_code,
                "effective_scope": cand.effective_scope,
                "strategy_tag": cand.strategy_tag,
                "context_basis": list(cand.context_basis),
                "prompt_sha256": cand.prompt_sha256,
                "prompt": cand.prompt,
                "annotator_id": "",
                "annotation_source": "human_expert",
                "asi_relevance_score": None,
                "context_grounding_score": None,
                "meaningful_diversity_score": None,
                "safety_and_scope_hygiene_score": None,
                "rationale": "",
            }
            for cand in result.accepted_candidates
        ],
    }


def export_quality_report_json(report: DatasetQualityReport) -> str:
    """Serialize DatasetQualityReport to deterministic canonical JSON."""
    return json.dumps(
        report.model_dump(mode="json"),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    )


def compute_quality_report_sha256(report: DatasetQualityReport) -> str:
    """Compute canonical SHA-256 digest of a DatasetQualityReport for reproducibility checks."""
    canonical = json.dumps(
        report.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


def render_quality_report_markdown(report: DatasetQualityReport) -> str:
    """Render a concise human-readable Markdown summary separating deterministic vs semantic results."""
    m = report.overall_metrics
    sem = report.semantic_quality

    def _fmt_ratio(r: RatioMetric | None) -> str:
        if r is None or r.rate is None:
            return f"N/A ({r.numerator}/{r.denominator})" if r else "N/A"
        return f"{r.rate * 100:.1f}% ({r.numerator}/{r.denominator})"

    lines = [
        f"# G11.5 Dataset Quality Report (v{report.schema_version})",
        "",
        f"- **Source:** `{report.source_kind}` | **Generation ID:** `{report.generation_id or 'N/A'}` | **Dataset ID:** `{report.dataset_id or 'N/A'}`",
        f"- **Target:** `{report.target_id or 'N/A'}` | **Provider / Model:** `{report.provider_id or 'N/A'}` / `{report.model or 'N/A'}` (Mock/Synthetic: `{report.is_synthetic_or_mock_provider}`)",
        f"- **Overall Status:** `{report.overall_status}` | **Meets Requested Counts:** `{report.meets_requested_counts}` | **Usability:** `{report.usability_status}`",
        f"- **Provenance Complete:** `{report.provenance_completeness.complete}`"
        + (
            f" (missing: {', '.join(report.provenance_completeness.missing_fields)})"
            if report.provenance_completeness.missing_fields
            else ""
        ),
        "",
        "## 1. Deterministic Metrics (Automated, Verified Backend Data)",
        "",
        f"- **Counts:** requested={m.requested_count if m.requested_count is not None else 'N/A'}, generated={m.generated_count if m.generated_count is not None else 'N/A'}, pre_dedup_valid={m.pre_dedup_valid_count}, accepted={m.accepted_count}, rejected={m.rejected_count if m.rejected_count is not None else 'N/A'} (gen_dup={m.duplicate_rejected_count}, saved_dup={m.saved_dataset_duplicate_count}, val={m.validation_rejected_count}, excess={m.excess_rejected_count})",
        f"- **Acceptance vs Requested:** {_fmt_ratio(m.acceptance_vs_requested_rate)} — `{m.acceptance_vs_requested_rate.definition}`",
        f"- **Output Contract Validity:** {_fmt_ratio(m.output_contract_validity_rate)} — `{m.output_contract_validity_rate.definition}`",
        f"- **Candidate Grounding Validity:** {_fmt_ratio(m.candidate_grounding_validity_rate)} — `{m.candidate_grounding_validity_rate.definition}`",
        f"- **Exact/Normalized Duplicate Rate:** {_fmt_ratio(m.exact_normalized_duplicate_rate)} — `{m.exact_normalized_duplicate_rate.definition}`",
        f"- **Strategy Tag Diversity:** {_fmt_ratio(m.diversity_stats.strategy_tag_diversity_ratio)}, Shannon entropy={m.diversity_stats.strategy_tag_shannon_entropy_bits} bits (normalized={m.diversity_stats.normalized_strategy_entropy})",
        f"- **Confirmed Context Field Coverage:** {_fmt_ratio(m.context_basis_coverage.confirmed_field_coverage_rate)} (mean basis/candidate={m.context_basis_coverage.mean_basis_fields_per_candidate})",
        f"- **ASI Distribution:** `{m.asi_distribution}` (alignment verified: `{m.asi_alignment_verified}`)",
        "",
        "## 2. Semantic Quality (Rubric-Guided — Separate from Deterministic Metrics)",
        "",
        f"- **Status:** `{sem.evaluation_status}` | **Ground Truth:** `{sem.is_ground_truth}` | **Coverage:** {_fmt_ratio(sem.annotation_coverage_rate)}",
        f"- **Mean Scores (0–2):** ASI relevance=`{sem.mean_asi_relevance}`, Context grounding=`{sem.mean_context_grounding}`, Meaningful diversity=`{sem.mean_meaningful_diversity}`, Safety/scope=`{sem.mean_safety_and_scope_hygiene}`",
        f"- **High-Quality Rate (2/2/2):** {_fmt_ratio(sem.high_quality_rate)}",
        "",
        "## 3. Evaluation Limitations",
        "",
    ]
    for lim in report.evaluation_limitations:
        lines.append(f"- {lim}")
    return "\n".join(lines) + "\n"
