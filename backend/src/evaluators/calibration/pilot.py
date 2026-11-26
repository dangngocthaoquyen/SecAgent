"""Opt-in, bounded DeepSeek Live Judge Pilot Verification (G12 Phase 5 — Section 7).

Fail-closed by default:
- Never performs live API calls unless `allow_live_deepseek=True` is explicitly supplied by the operator.
- Never reads, logs, or returns API keys or credentials.
- Verifies provider configuration, Evaluation Skills loading, reviewed policy/context grounding,
  Evidence Contract v2 delivery, Judge JSON schema validation, Verdict Resolver boundary protection,
  and bounded request budget enforcement.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from evaluators.calibration.benchmark import build_judge_calibration_benchmark
from evaluators.calibration.harness import (
    _VerifiedLivePilotToken,
    evaluate_benchmark,
    is_trusted_offline_provider,
)
from evaluators.calibration.models import BenchmarkCase, BenchmarkSplit, CalibrationRunReport
from evaluators.evaluation_request_builder import EvaluationRequestBuilder
from integrations.external_evaluator.base import ExternalEvaluatorProvider
from integrations.external_evaluator.pi import PiEvaluatorConfig, PiEvaluatorProvider
from integrations.external_evaluator.skills import SkillBundleLoader
from testing.evaluation_config import (
    BudgetedJudgeProvider,
    LiveJudgeConfigurationError,
    RunnerEvaluationConfig,
    validate_live_pi_config,
)

REQUIRED_PILOT_SKILL_ROUTES: tuple[tuple[str, str | None], ...] = (
    ("goal_hijacking", None),
    ("tool_misuse", None),
    ("tool_misuse", "tool_intent_response"),
    ("identity_privilege_abuse", None),
    ("unexpected_code_execution", None),
)


class DeepSeekPilotConfig(BaseModel):
    """Explicit opt-in configuration for a bounded DeepSeek Live Judge pilot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allow_live_deepseek: bool = Field(default=False, strict=True)
    max_requests: int = Field(default=8, ge=1, le=20, strict=True)
    split: BenchmarkSplit = "holdout"
    case_ids: tuple[str, ...] | None = None
    pi: PiEvaluatorConfig


class DeepSeekPilotPreflightResult(BaseModel):
    """Credential-free preflight verification report before any Live DeepSeek call."""

    model_config = ConfigDict(extra="forbid")

    ready: bool
    live_opt_in_confirmed: bool
    provider: str
    model: str
    max_requests: int
    selected_case_ids: list[str]
    loaded_skills: dict[str, dict[str, str]]
    evidence_v2_verified_count: int
    reviewed_policy_verified_count: int
    blockers: list[str] = Field(default_factory=list)


def _select_pilot_cases(
    config: DeepSeekPilotConfig,
    cases: Sequence[BenchmarkCase] | None = None,
) -> list[BenchmarkCase]:
    corpus = list(cases) if cases is not None else list(build_judge_calibration_benchmark())
    if config.case_ids:
        wanted = set(config.case_ids)
        selected = [c for c in corpus if c.case_id in wanted]
    else:
        selected = [c for c in corpus if c.split == config.split]
    return selected[: config.max_requests]


def preflight_deepseek_pilot(
    config: DeepSeekPilotConfig,
    *,
    cases: Sequence[BenchmarkCase] | None = None,
    environ: Mapping[str, str] | None = None,
    skip_live_credential_check: bool = False,
) -> DeepSeekPilotPreflightResult:
    """Verify all DeepSeek pilot prerequisites without making any network/subprocess call or leaking secrets."""
    blockers: list[str] = []
    if not config.allow_live_deepseek:
        blockers.append("live_deepseek_opt_in_required")

    if not skip_live_credential_check:
        try:
            probe_runner_cfg = RunnerEvaluationConfig(
                mode="hybrid",
                judge_enabled=True,
                allow_live_judge=True,
                max_judge_calls=1,
                pi=config.pi,
            )
            validate_live_pi_config(probe_runner_cfg, environ=environ)
        except (LiveJudgeConfigurationError, ValueError) as exc:
            blockers.append(f"provider_config_error:{exc}")

    loader = SkillBundleLoader()
    loaded_skills: dict[str, dict[str, str]] = {}
    for eval_type, eval_scope in REQUIRED_PILOT_SKILL_ROUTES:
        route_key = f"{eval_type}:{eval_scope}" if eval_scope else eval_type
        try:
            bundle = (
                loader.load(eval_type, evaluation_scope=eval_scope)  # type: ignore[arg-type]
                if eval_scope is not None
                else loader.load(eval_type)  # type: ignore[arg-type]
            )
            loaded_skills[route_key] = {
                "id": bundle.identity.id,
                "version": bundle.identity.version,
                "sha256": bundle.identity.sha256,
            }
        except Exception:
            blockers.append(f"skill_unavailable:{route_key}")

    selected = _select_pilot_cases(config, cases)
    if not selected:
        blockers.append("no_pilot_cases_selected")

    builder = EvaluationRequestBuilder(bundle_loader=loader)
    ev2_ok = 0
    policy_ok = 0
    for case in selected:
        if case.evidence_v2.contract_version == "2.0" and case.evidence_v2.envelope_sha256:
            ev2_ok += 1
        if case.reviewed_policy:
            policy_ok += 1
        try:
            req = builder.build(case.testcase, case.observation, evidence_v2=case.evidence_v2)
            if "evidence_v2_summary" not in req.observation.metadata:
                blockers.append(f"evidence_v2_missing_in_request:{case.case_id}")
        except Exception:
            blockers.append(f"request_build_failed:{case.case_id}")

    return DeepSeekPilotPreflightResult(
        ready=(len(blockers) == 0),
        live_opt_in_confirmed=config.allow_live_deepseek,
        provider=config.pi.provider,
        model=config.pi.model,
        max_requests=config.max_requests,
        selected_case_ids=[c.case_id for c in selected],
        loaded_skills=loaded_skills,
        evidence_v2_verified_count=ev2_ok,
        reviewed_policy_verified_count=policy_ok,
        blockers=blockers,
    )


def run_deepseek_pilot(
    config: DeepSeekPilotConfig,
    *,
    cases: Sequence[BenchmarkCase] | None = None,
    provider_override: ExternalEvaluatorProvider | None = None,
    offline_dry_run: bool = False,
    environ: Mapping[str, str] | None = None,
) -> tuple[DeepSeekPilotPreflightResult, CalibrationRunReport]:
    """Run a strictly budgeted DeepSeek Judge pilot or an explicitly opted-in offline dry-run.

    Security boundaries:
    - Live mode (`offline_dry_run=False`, default) ALWAYS requires `config.allow_live_deepseek=True`
      and a passing `preflight_deepseek_pilot(...)`, even if `provider_override` is supplied.
      Passing an arbitrary or non-`PiEvaluatorProvider` override in live mode is rejected.
    - Offline dry-run mode (`offline_dry_run=True`) ONLY accepts a trusted
      `OfflineSimulatedJudgeProvider` (never `PiEvaluatorProvider` and never an arbitrary
      `ExternalEvaluatorProvider`), still verifies skills/cases/Evidence v2 packaging and enforces
      `max_requests` via `BudgetedJudgeProvider`, and ALWAYS produces `is_live_experiment=False`.
    """
    if offline_dry_run:
        if provider_override is None or not is_trusted_offline_provider(provider_override):
            raise LiveJudgeConfigurationError(
                "Offline pilot dry-run requires an explicit trusted OfflineSimulatedJudgeProvider."
            )
        preflight = preflight_deepseek_pilot(
            config,
            cases=cases,
            environ=environ,
            skip_live_credential_check=True,
        )
        non_live_blockers = [b for b in preflight.blockers if b != "live_deepseek_opt_in_required"]
        if non_live_blockers:
            raise LiveJudgeConfigurationError(
                "Offline pilot dry-run preflight failed: " + ", ".join(non_live_blockers)
            )
        selected = _select_pilot_cases(config, cases)
        runner_budget_cfg = RunnerEvaluationConfig(
            mode="hybrid",
            judge_enabled=True,
            allow_live_judge=False,
            max_judge_calls=config.max_requests,
            pi=None,
        )
        budgeted = BudgetedJudgeProvider(runner_budget_cfg, provider_override)
        report = evaluate_benchmark(
            selected,
            pipeline_mode="llm_judge_skills_v2",
            provider=budgeted,
            execution_origin="offline_simulated_judge",
            provider_label=f"offline_pilot_dry_run:{type(provider_override).__name__}",
            prefer_deterministic_v2=False,
        )
        return preflight, report

    # Live / remote mode: never bypass live opt-in or preflight regardless of provider_override!
    preflight = preflight_deepseek_pilot(
        config,
        cases=cases,
        environ=environ,
        skip_live_credential_check=False,
    )
    if not preflight.ready:
        raise LiveJudgeConfigurationError(
            "DeepSeek live pilot preflight failed: " + ", ".join(preflight.blockers)
        )
    if provider_override is not None and not isinstance(provider_override, PiEvaluatorProvider):
        raise LiveJudgeConfigurationError(
            "Live DeepSeek pilot rejects non-Pi provider overrides; use offline_dry_run=True "
            "with a trusted OfflineSimulatedJudgeProvider for offline simulation."
        )

    selected = _select_pilot_cases(config, cases)
    runner_budget_cfg = RunnerEvaluationConfig(
        mode="hybrid",
        judge_enabled=True,
        allow_live_judge=True,
        max_judge_calls=config.max_requests,
        pi=config.pi,
    )
    delegate: ExternalEvaluatorProvider = (
        provider_override if provider_override is not None else PiEvaluatorProvider(config.pi)
    )
    budgeted = BudgetedJudgeProvider(runner_budget_cfg, delegate)
    live_token = _VerifiedLivePilotToken(
        provider_name=config.pi.provider,
        model_name=config.pi.model,
        max_requests=config.max_requests,
    )
    report = evaluate_benchmark(
        selected,
        pipeline_mode="llm_judge_skills_v2",
        provider=budgeted,
        execution_origin="live_deepseek_pilot",
        provider_label=f"live_deepseek:{config.pi.provider}/{config.pi.model}",
        prefer_deterministic_v2=False,
        _live_pilot_token=live_token,
    )
    return preflight, report
