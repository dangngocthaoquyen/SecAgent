"""Run one testcase through preparation, execution, observation, and evaluation."""

from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from threading import Event
from typing import Any, Sequence
from uuid import uuid4

from attack_modules import (
    AttackModuleRegistry,
    build_default_attack_module_registry,
)
from core.cancellation import RunCancelledError
from core.models import (
    EvaluationResult,
    EvaluationStatus,
    TargetProfile,
    TestCase,
    TestInput,
)
from evaluators import BaseEvaluator
from evaluators.contract import assess_target_scope_compatibility
from evaluators.evidence_v2_evaluator import build_evaluation_explanation
from evaluators.verdict_outcome import (
    VERDICT_POLICY_VERSION,
    VERDICT_SCHEMA_VERSION,
    classify_binary_case_outcome,
)
from evaluators.hybrid_evaluator import apply_heuristic_sufficiency
from core.evidence_v2 import build_evidence_contract_v2
from core.models.evidence import (
    PROVENANCE_RANK,
    canonical_provenance,
    classify_observation_evidence,
    is_execution_verified,
    public_evidence_data,
)
from core.models.provenance import build_case_research_provenance
from observers import (
    BaseObserver,
    CollectorContext,
    CollectorDiagnostic,
    ResponseObserver,
    build_collector_from_spec,
    collect_target_evidence,
)
from testing.executor import Executor
from testing.evaluation_config import RunnerEvaluationConfig, configured_evaluator


class Runner:
    def __init__(
        self,
        executor: Executor | None = None,
        observer: BaseObserver | None = None,
        evaluator: BaseEvaluator | None = None,
        attack_module_registry: AttackModuleRegistry | None = None,
        *,
        evaluation_config: RunnerEvaluationConfig | None = None,
        judge_provider=None,
        report_sink=None,
        progress_sink=None,
        require_complete_response_for_pass: bool = False,
        require_complete_response_for_fail: bool = False,
        reviewed_judge_input_sha256: str | None = None,
        collectors: Sequence[Any] | None = None,
        allowed_collector_roots: tuple[Path, ...] = (),
        allowed_collector_endpoints: tuple[str, ...] = (),
        include_submitted_prompt_preview: bool = False,
        extra_sensitive_values: Sequence[str] = (),
        cancel_event: Event | None = None,
    ) -> None:
        self._executor = executor if executor is not None else Executor()
        self._observer = observer if observer is not None else ResponseObserver()
        if evaluator is not None and (evaluation_config is not None or judge_provider is not None):
            raise ValueError("Choose existing evaluator injection or Runner evaluation configuration, not both.")
        self._diagnostics = []
        self._evaluation_config = evaluation_config or RunnerEvaluationConfig()
        self._judge_provider_name: str | None = None
        self._judge_model_name: str | None = None
        if self._evaluation_config.pi is not None:
            self._judge_provider_name = self._evaluation_config.pi.provider
            self._judge_model_name = self._evaluation_config.pi.model
        elif judge_provider is not None:
            raw_prov = getattr(judge_provider, "provider_name", None) or getattr(judge_provider, "provider", None)
            raw_mod = getattr(judge_provider, "model_name", None) or getattr(judge_provider, "model", None)
            if isinstance(raw_prov, str) and raw_prov.strip():
                self._judge_provider_name = raw_prov.strip()
            if isinstance(raw_mod, str) and raw_mod.strip():
                self._judge_model_name = raw_mod.strip()
        self._budget = None
        self._evaluator = evaluator
        if self._evaluator is None:
            self._evaluator, self._budget = configured_evaluator(self._evaluation_config, judge_provider, self._diagnostics.append)
        self._custom_evaluator = evaluator is not None
        self._report_sink = report_sink
        self._progress_sink = progress_sink
        self._require_complete_response_for_pass = require_complete_response_for_pass
        self._require_complete_response_for_fail = require_complete_response_for_fail
        # Trusted caller permission to disclose one exact public text input.
        # Never taken from TestInput metadata, an observation or imported labels.
        self._reviewed_judge_input_sha256 = reviewed_judge_input_sha256
        self._collectors = list(collectors or ())
        self._allowed_collector_roots = tuple(allowed_collector_roots)
        self._allowed_collector_endpoints = tuple(allowed_collector_endpoints)
        self._include_submitted_prompt_preview = include_submitted_prompt_preview
        self._extra_sensitive_values = tuple(
            v for v in (extra_sensitive_values or ()) if isinstance(v, str) and v
        )
        self._cancel_event = cancel_event
        self._collector_diagnostics: list[CollectorDiagnostic] = []
        self._current_run_id: str | None = None
        self._started_at: str | None = None
        self._ended_at: str | None = None
        self._submitted_prompt: str | None = None
        self._raw_deterministic_result: EvaluationResult | None = None
        self._effective_deterministic_result: EvaluationResult | None = None
        self._evidence_v2_payload: dict[str, Any] | None = None
        self.last_report = None
        self._attack_module_registry = (
            attack_module_registry
            if attack_module_registry is not None
            else build_default_attack_module_registry()
        )

    def run(
        self,
        testcase: TestCase,
        target: TargetProfile,
        test_input: TestInput,
    ) -> EvaluationResult:
        # Preserve the established return API; reporting is an additive snapshot.
        self._diagnostics.clear()
        self._collector_diagnostics.clear()
        self._execution_result = self._observation = None
        self._raw_deterministic_result = self._effective_deterministic_result = None
        self._evidence_v2_payload = None
        self._current_run_id = uuid4().hex
        self._started_at = datetime.now(timezone.utc).isoformat()
        self._ended_at = None
        self._submitted_prompt = None
        result = self._run(testcase, target, test_input)
        self._ended_at = datetime.now(timezone.utc).isoformat()
        try:
            self.last_report = self._build_report(testcase, target, test_input, result)
        except Exception:
            self.last_report = {"final_verdict": result.status.value,
                                "report_fault": "Report construction failed; evaluation unchanged."}
        if self._report_sink is not None:
            try:
                self._report_sink(deepcopy(self.last_report))
            except Exception:
                self.last_report["report_sink_fault"] = "Report sink failed; evaluation unchanged."
        return result

    def _check_cancelled(self, stage: str) -> None:
        if self._cancel_event is not None and self._cancel_event.is_set():
            raise RunCancelledError(f"run_cancelled_{stage}")

    def _run(self, testcase, target, test_input) -> EvaluationResult:
        self._check_cancelled("before_execution")
        req_capability = test_input.parameters.get("required_capability")
        if (
            isinstance(req_capability, str)
            and req_capability.strip()
            and getattr(target, "capability_states", {}).get(req_capability.strip()) == "unsupported"
        ):
            return EvaluationResult(
                status=EvaluationStatus.INCONCLUSIVE,
                reason=f"Target reports required capability '{req_capability.strip()}' as unsupported.",
            )

        declared_scope: str | None = None
        if testcase.evaluation.semantic and isinstance(testcase.evaluation.semantic.trusted_context, dict):
            raw_scope = testcase.evaluation.semantic.trusted_context.get("evaluation_scope")
            if isinstance(raw_scope, str) and raw_scope.strip():
                declared_scope = raw_scope.strip()
        if declared_scope is None and isinstance(test_input.metadata, dict):
            rp_meta = test_input.metadata.get("evaluation_rule_provenance")
            if isinstance(rp_meta, dict) and isinstance(rp_meta.get("evaluation_scope"), str):
                declared_scope = rp_meta["evaluation_scope"].strip() or None
        if declared_scope is not None:
            scope_compat = assess_target_scope_compatibility(
                declared_scope,
                getattr(target, "capability_states", {}),
                capabilities=getattr(target, "capabilities", ()),
                evidence_sources=getattr(target, "evidence_sources", ()),
                has_inline_evidence=bool(
                    isinstance(target.interface.config.get("response"), dict)
                    and isinstance(target.interface.config["response"].get("evidence_mapping"), dict)
                ),
            )
            if not scope_compat.admitted and scope_compat.capability_state == "unsupported":
                return EvaluationResult(
                    status=EvaluationStatus.INCONCLUSIVE,
                    reason=(
                        f"Target capability for evaluation scope '{declared_scope}' is explicitly "
                        f"unsupported ({scope_compat.reason}); execution skipped without downgrading scope."
                    ),
                )

        try:
            attack_module = self._attack_module_registry.resolve(
                testcase.attack_module
            )
        except Exception:
            return EvaluationResult(
                status=EvaluationStatus.ERROR,
                reason="Attack module resolution failed.",
            )

        try:
            prepared_input = attack_module.prepare(testcase, test_input)
        except Exception:
            return EvaluationResult(
                status=EvaluationStatus.ERROR,
                reason="Attack module preparation failed.",
            )

        try:
            self._check_cancelled("before_target_dispatch")
            prepared_prompt = prepared_input.prompt
            self._submitted_prompt = prepared_prompt
            execution_result = self._executor.execute(target, prepared_input)
            self._execution_result = execution_result
        except RunCancelledError:
            raise
        except Exception:
            return EvaluationResult(
                status=EvaluationStatus.ERROR,
                reason="Execution stage failed.",
            )

        self._check_cancelled("after_target_response")
        try:
            if self._progress_sink is not None:
                self._progress_sink("collecting_evidence")
            observation = self._observer.observe(execution_result)
            # These identities come from the trusted Runner call, not from
            # target-reported metadata or an observer's existing values.
            observation.metadata["secagent_testcase_id"] = testcase.id
            observation.metadata["secagent_target_id"] = getattr(target, "id", None)
            observation.metadata["secagent_execution_id"] = test_input.id
            observation.metadata["secagent_run_id"] = self._current_run_id

            active_collectors = list(self._collectors)
            for spec in getattr(target, "evidence_sources", []) or []:
                if isinstance(spec, dict):
                    try:
                        active_collectors.append(build_collector_from_spec(spec))
                    except Exception as exc:
                        self._collector_diagnostics.append(
                            CollectorDiagnostic(
                                collector_id=str(spec.get("id") or "declared_collector"),
                                collector_kind=str(spec.get("kind") or "unknown"),
                                status="error",
                                reason=f"Collector specification invalid: {type(exc).__name__}",
                            )
                        )
            if active_collectors:
                target_corr = observation.metadata.get("target_correlation_id")
                ctx = CollectorContext(
                    run_id=self._current_run_id or uuid4().hex,
                    case_id=testcase.id,
                    execution_id=test_input.id,
                    target_id=str(getattr(target, "id", "") or ""),
                    request_id=str(test_input.parameters.get("request_id") or test_input.id),
                    session_id=str(test_input.parameters.get("session_id") or "") or None,
                    target_correlation_id=str(target_corr) if isinstance(target_corr, str) and target_corr else None,
                    started_at=self._started_at,
                    ended_at=datetime.now(timezone.utc).isoformat(),
                    allowed_roots=self._allowed_collector_roots,
                    allowed_endpoints=self._allowed_collector_endpoints,
                )
                collected = collect_target_evidence(active_collectors, ctx)
                existing_fp_ranks: dict[str, tuple[bool, int]] = {}
                for ev in observation.evidence:
                    if isinstance(ev.data, dict) and isinstance(ev.data.get("event_fingerprint"), str):
                        fp_key = ev.data["event_fingerprint"]
                        rank = (is_execution_verified(ev), PROVENANCE_RANK[canonical_provenance(ev)])
                        prev = existing_fp_ranks.get(fp_key)
                        if prev is None or rank > prev:
                            existing_fp_ranks[fp_key] = rank
                dedup_skipped = 0
                for item in collected.evidence:
                    fp = item.data.get("event_fingerprint") if isinstance(item.data, dict) else None
                    if isinstance(fp, str) and fp in existing_fp_ranks:
                        incoming_rank = (is_execution_verified(item), PROVENANCE_RANK[canonical_provenance(item)])
                        # Never discard stronger or independently verified evidence in favor of weaker target-reported evidence.
                        if incoming_rank <= existing_fp_ranks[fp]:
                            dedup_skipped += 1
                            continue
                        existing_fp_ranks[fp] = incoming_rank
                    elif isinstance(fp, str):
                        existing_fp_ranks[fp] = (is_execution_verified(item), PROVENANCE_RANK[canonical_provenance(item)])
                    observation.evidence.append(item)
                if dedup_skipped:
                    observation.metadata["deduplicated_collector_events"] = dedup_skipped
                self._collector_diagnostics.extend(collected.diagnostics)
                observation.metadata["collector_diagnostics"] = [
                    asdict(item) for item in self._collector_diagnostics
                ]
            self._observation = observation
        except RunCancelledError:
            raise
        except Exception:
            return EvaluationResult(
                status=EvaluationStatus.ERROR,
                reason="Observation stage failed.",
            )

        # Build Evidence Contract v2 after observation and before evaluation so
        # Judge-centric evaluators can use verified v2 facts while preserving
        # fail-safe v1 fallback on any construction error.
        try:
            self._evidence_v2_payload = build_evidence_contract_v2(
                observation=observation,
                execution_result=execution_result,
                effective_scope=declared_scope,
                run_id=self._current_run_id,
                execution_id=test_input.id,
                testcase_id=testcase.id,
                target_id=getattr(target, "id", None),
                request_id=(
                    str(test_input.parameters.get("request_id"))
                    if isinstance(test_input.parameters, dict) and test_input.parameters.get("request_id")
                    else None
                ),
                session_id=(
                    str(test_input.parameters.get("session_id"))
                    if isinstance(test_input.parameters, dict) and test_input.parameters.get("session_id")
                    else None
                ),
                collector_diagnostics=self._collector_diagnostics,
                sensitive_values=self._judge_sensitive_values(target),
                include_response_preview=False,
            ).model_dump(mode="json")
        except Exception:
            self._evidence_v2_payload = {
                "contract_version": "2.0",
                "availability": "unavailable",
                "verified_execution_present": False,
                "reason_codes": ["evidence_v2_construction_failed"],
                "limitations": [
                    "Evidence Contract v2 could not be constructed; existing report fields and verdict were preserved."
                ],
            }

        self._check_cancelled("before_evaluation")
        try:
            rule_prov = (
                test_input.metadata.get("evaluation_rule_provenance")
                if isinstance(test_input.metadata, dict)
                and isinstance(test_input.metadata.get("evaluation_rule_provenance"), dict)
                else {}
            )
            is_reviewed_policy_rules = rule_prov.get("rule_origin") == "reviewed_policy"
            if self._progress_sink is not None and not self._custom_evaluator and self._evaluation_config.mode == "rule_only":
                self._progress_sink("running_rule_evaluator")
            if not self._custom_evaluator and self._evaluation_config.mode == "hybrid":
                evaluated = self._evaluator.evaluate(testcase, observation,
                    prepared_prompt=(prepared_prompt if self._reviewed_judge_input_sha256 else None),
                    reviewed_input_sha256=self._reviewed_judge_input_sha256,
                    sensitive_values=self._judge_sensitive_values(target),
                    evidence_v2=self._evidence_v2_payload)
                if is_reviewed_policy_rules and not (testcase.evaluation.semantic and testcase.evaluation.semantic.enabled):
                    evaluated = apply_heuristic_sufficiency(testcase, evaluated)
            else:
                raw_evaluated = self._evaluator.evaluate(testcase, observation)
                if not self._custom_evaluator and self._evaluation_config.mode == "rule_only":
                    self._raw_deterministic_result = raw_evaluated
                evaluated = (
                    apply_heuristic_sufficiency(testcase, raw_evaluated)
                    if (
                        not self._custom_evaluator
                        and self._evaluation_config.mode == "rule_only"
                        and is_reviewed_policy_rules
                    )
                    else raw_evaluated
                )
            final_evaluated = evaluated
            if (self._require_complete_response_for_pass
                    and final_evaluated.status is EvaluationStatus.PASS
                    and observation.metadata.get("response_complete") is not True):
                verified_exec_pass = (
                    final_evaluated.matched_rule_type in {"asi05_execution", "evidence_v2_verified_absence"}
                    or (
                        final_evaluated.matched_rule_type == "tool_call"
                        and observation.metadata.get("response_complete") is not False
                        and classify_observation_evidence(
                            observation.evidence, observation.response_text
                        ).get("verified_execution_present") is True
                    )
                )
                if not verified_exec_pass:
                    final_evaluated = EvaluationResult(status=EvaluationStatus.INCONCLUSIVE,
                        reason="Response-only PASS requires a complete observed response.")
            if (self._require_complete_response_for_fail
                    and final_evaluated.status is EvaluationStatus.FAIL
                    and observation.metadata.get("response_complete") is not True):
                verified_exec_fail = (
                    final_evaluated.matched_rule_type in {
                        "collector_receipt",
                        "asi05_execution",
                        "evidence_v2_execution",
                        "evidence_v2_simulated_execution",
                    }
                    or (
                        final_evaluated.matched_rule_type == "tool_call"
                        and classify_observation_evidence(
                            observation.evidence, observation.response_text
                        ).get("verified_execution_present") is True
                    )
                )
                if not verified_exec_fail:
                    final_evaluated = EvaluationResult(status=EvaluationStatus.INCONCLUSIVE,
                        reason="Response-only FAIL requires a complete observed response.")
            if not self._custom_evaluator and self._evaluation_config.mode == "rule_only":
                self._effective_deterministic_result = final_evaluated
            self._check_cancelled("after_evaluation")
            return final_evaluated
        except RunCancelledError:
            raise
        except Exception:
            return EvaluationResult(
                status=EvaluationStatus.ERROR,
                reason="Evaluation stage failed.",
            )

    def _judge_sensitive_values(self, target) -> tuple[str, ...]:
        from targets.validator import parse_header_credential_reference

        names = [
            ref for ref in target.credential_refs
            if isinstance(ref, str) and not ref.startswith("sess_")
        ]
        if self._evaluation_config.pi:
            names.extend(self._evaluation_config.pi.credential_env)
        for spec in getattr(target, "evidence_sources", []) or []:
            if isinstance(spec, dict) and isinstance(spec.get("headers"), dict):
                for raw_val in spec["headers"].values():
                    if isinstance(raw_val, str):
                        try:
                            parsed = parse_header_credential_reference(raw_val)
                        except ValueError:
                            parsed = None
                        if parsed is not None and parsed[0] == "env":
                            names.append(parsed[2])
        values = set()
        for name in names:
            raw_secret = os.environ.get(name)
            if raw_secret:
                values.add(raw_secret)
                if raw_secret.strip():
                    values.add(raw_secret.strip())
        for extra in self._extra_sensitive_values:
            values.add(extra)
            if extra.strip():
                values.add(extra.strip())
                if extra.strip().lower().startswith("bearer "):
                    stripped = extra.strip()[7:].strip()
                    if stripped:
                        values.add(stripped)
        if self._evaluation_config.pi and self._evaluation_config.pi.use_pi_auth_file:
            auth_path = Path.home() / ".pi" / "agent" / "auth.json"
            if auth_path.is_file():
                try:
                    auth_obj = json.loads(auth_path.read_text(encoding="utf-8-sig"))
                    entry = auth_obj.get(self._evaluation_config.pi.provider) if isinstance(auth_obj, dict) else None
                    if isinstance(entry, dict):
                        for field_key in ("key", "access", "token", "apiKey", "refresh"):
                            secret_val = entry.get(field_key)
                            if isinstance(secret_val, str) and len(secret_val) >= 4:
                                values.add(secret_val)
                except (OSError, UnicodeError, ValueError):
                    pass
        # Literal private headers are not necessarily environment-backed. Only
        # use them for local rejection; never attach them to Judge/report input.
        headers = target.interface.config.get("headers", {})
        if isinstance(headers, dict):
            for name, value in headers.items():
                if (isinstance(value, str) and value
                        and name.lower() not in {"content-type", "accept", "user-agent"}):
                    values.add(value)
                    if value.lower().startswith(("bearer ", "basic ")):
                        values.add(value.split(" ", 1)[1])
        return tuple(values)

    def _build_report(self, testcase, target, test_input, result):
        executed, observed = self._execution_result, self._observation
        diagnostic = asdict(self._diagnostics[-1]) if self._diagnostics else None
        if diagnostic is not None and isinstance(diagnostic.get("judge_evidence"), tuple):
            diagnostic["judge_evidence"] = list(diagnostic["judge_evidence"])
        final = result.model_dump(mode="json")
        if executed is not None and not executed.success:
            # Adapter error strings can contain URLs/transport details.
            final["reason"] = "Target execution failed; sensitive transport diagnostics omitted."
            final["evidence"] = None
            if diagnostic is not None:
                for key in ("deterministic_result", "effective_deterministic_result"):
                    if diagnostic.get(key):
                        diagnostic[key]["reason"] = final["reason"]
                        diagnostic[key]["evidence"] = None
        semantic = testcase.evaluation.semantic
        context = semantic.trusted_context if semantic else {}
        if diagnostic is not None:
            deterministic_snapshot = diagnostic["deterministic_result"]
            effective_deterministic_snapshot = diagnostic.get("effective_deterministic_result")
            if (
                not diagnostic.get("semantic_invoked")
                and isinstance(effective_deterministic_snapshot, dict)
                and effective_deterministic_snapshot.get("status") in {"PASS", "FAIL"}
                and final.get("status") == "INCONCLUSIVE"
            ):
                effective_deterministic_snapshot = final
        elif (
            not self._custom_evaluator
            and observed is not None
            and self._evaluation_config.mode == "rule_only"
        ):
            raw_det = self._raw_deterministic_result
            eff_det = self._effective_deterministic_result
            deterministic_snapshot = raw_det.model_dump(mode="json") if raw_det is not None else dict(final)
            effective_deterministic_snapshot = eff_det.model_dump(mode="json") if eff_det is not None else dict(final)
            if executed is not None and not executed.success:
                for snap in (deterministic_snapshot, effective_deterministic_snapshot):
                    snap["reason"] = final["reason"]
                    snap["evidence"] = None
        else:
            deterministic_snapshot = None
            effective_deterministic_snapshot = None
        research_prov = build_case_research_provenance(
            testcase=testcase,
            target=target,
            test_input=test_input,
            evaluation_mode="custom" if self._custom_evaluator else self._evaluation_config.mode,
            evaluation_strategy=testcase.evaluation.strategy,
            semantic_enabled=bool(semantic and semantic.enabled),
            trusted_context=context,
            diagnostic=diagnostic,
            evidence=observed.evidence if observed is not None else None,
            judge_provider_name=self._judge_provider_name,
            judge_model_name=self._judge_model_name,
            deterministic_result=deterministic_snapshot,
            effective_deterministic_result=effective_deterministic_snapshot,
            final_result=result,
            execution_success=(executed.success if executed is not None else None),
        )
        top_downgrade_reason = (
            diagnostic["downgrade_reason"]
            if diagnostic and diagnostic.get("downgrade_reason")
            else research_prov["evaluation"]["downgrade_reason"]
        )
        effective_scope_v2 = context.get("evaluation_scope")
        if not isinstance(effective_scope_v2, str) or not effective_scope_v2.strip():
            rp_meta = (
                test_input.metadata.get("evaluation_rule_provenance")
                if isinstance(test_input.metadata, dict)
                else None
            )
            if isinstance(rp_meta, dict) and isinstance(rp_meta.get("evaluation_scope"), str):
                effective_scope_v2 = rp_meta["evaluation_scope"].strip() or None
            else:
                effective_scope_v2 = None
        else:
            effective_scope_v2 = effective_scope_v2.strip()
        evidence_v2_payload = self._evidence_v2_payload
        if evidence_v2_payload is None and observed is not None:
            try:
                evidence_v2_payload = build_evidence_contract_v2(
                    observation=observed,
                    execution_result=executed,
                    effective_scope=effective_scope_v2,
                    run_id=self._current_run_id,
                    execution_id=test_input.id,
                    testcase_id=testcase.id,
                    target_id=getattr(target, "id", None),
                    request_id=(
                        str(test_input.parameters.get("request_id"))
                        if isinstance(test_input.parameters, dict) and test_input.parameters.get("request_id")
                        else None
                    ),
                    session_id=(
                        str(test_input.parameters.get("session_id"))
                        if isinstance(test_input.parameters, dict) and test_input.parameters.get("session_id")
                        else None
                    ),
                    collector_diagnostics=self._collector_diagnostics,
                    sensitive_values=self._judge_sensitive_values(target),
                    include_response_preview=False,
                ).model_dump(mode="json")
            except Exception:
                evidence_v2_payload = {
                    "contract_version": "2.0",
                    "availability": "unavailable",
                    "verified_execution_present": False,
                    "reason_codes": ["evidence_v2_construction_failed"],
                    "limitations": [
                        "Evidence Contract v2 could not be constructed; existing report fields and verdict were preserved."
                    ],
                }
        evaluation_explanation = (
            diagnostic.get("evaluation_explanation")
            if diagnostic and isinstance(diagnostic.get("evaluation_explanation"), dict)
            else build_evaluation_explanation(
                testcase=testcase,
                result=result,
                observation=observed,
                evidence_v2=evidence_v2_payload,
                effective_scope=effective_scope_v2,
                semantic_judge_used=bool(diagnostic and diagnostic.get("semantic_invoked")),
                asi05_execution_used=bool(diagnostic and diagnostic.get("execution_evaluation") is not None),
            ).model_dump(mode="json")
        )
        if executed is not None and not executed.success and isinstance(evaluation_explanation, dict):
            evaluation_explanation = {
                **evaluation_explanation,
                "summary": final["reason"],
            }
        raw_diag_fault = diagnostic.get("provider_fault_code") if isinstance(diagnostic, dict) else None
        obs_complete = (
            observed.metadata.get("response_complete")
            if observed is not None and observed.metadata.get("response_complete") is not None
            else (executed.response_complete if executed is not None else None)
        )
        binary_outcome = classify_binary_case_outcome(
            internal_status=result.status.value,
            response_text=(observed.response_text if observed is not None else None),
            response_complete=obs_complete,
            execution_status=("succeeded" if executed is not None and executed.success else "failed" if executed is not None else None),
            provider_fault_code=getattr(raw_diag_fault, "value", raw_diag_fault),
            json_validation_status=(diagnostic.get("json_validation_status") if isinstance(diagnostic, dict) else None),
            reason=result.reason,
            downgrade_reason=top_downgrade_reason,
            evidence=(observed.evidence if observed is not None else ()),
            evidence_level=result.evidence_level,
            execution_verified=(
                evidence_v2_payload.get("verified_execution_present")
                if isinstance(evidence_v2_payload, dict)
                else None
            ),
            evidence_v2=evidence_v2_payload,
            observation_metadata=(observed.metadata if observed is not None else None),
        )
        if isinstance(research_prov, dict) and isinstance(research_prov.get("evaluation"), dict):
            research_prov["evaluation"]["internal_verdict"] = research_prov["evaluation"].get("effective_verdict")
            research_prov["evaluation"]["effective_verdict"] = binary_outcome["verdict"]
        report = {
            "verdict_schema_version": VERDICT_SCHEMA_VERSION,
            "verdict_policy_version": VERDICT_POLICY_VERSION,
            "security_verdict": binary_outcome["verdict"],
            "evaluation_status": binary_outcome["evaluation_status"],
            "evaluation_reason_code": binary_outcome["evaluation_reason_code"],
            "evidence_limitation_codes": binary_outcome["evidence_limitations"],
            "run_id": self._current_run_id or uuid4().hex, "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_id": getattr(target, "id", None), "target_name": getattr(target, "name", None), "testcase_id": testcase.id,
            "input_id": test_input.id,
            **(
                {"submitted_prompt_preview": self._submitted_prompt[:2048]}
                if self._include_submitted_prompt_preview and isinstance(self._submitted_prompt, str)
                else {}
            ),
            "capability_states": dict(getattr(target, "capability_states", {})),
            "evaluation_mode": "custom" if self._custom_evaluator else self._evaluation_config.mode,
            "evaluation_strategy": testcase.evaluation.strategy,
            "evaluation_scope": context.get("evaluation_scope"),
            "execution_evaluation": diagnostic.get("execution_evaluation") if diagnostic else None,
            "semantic_enabled": bool(semantic and semantic.enabled),
            "execution": None if executed is None else {
                "success": executed.success, "status_code": executed.status_code,
                "duration_ms": executed.duration_ms, "response_complete": executed.response_complete,
                **({"target_correlation_id": executed.target_correlation_id} if executed.target_correlation_id else {}),
                **({"target_run_status": executed.target_run_status} if executed.target_run_status else {}),
            },
            "correlation": {
                "secagent_run_id": self._current_run_id,
                "secagent_execution_id": test_input.id,
                "secagent_testcase_id": testcase.id,
                "target_correlation_id": (
                    observed.metadata.get("target_correlation_id")
                    if observed is not None
                    else (executed.target_correlation_id if executed is not None else None)
                ),
                "target_id_isolated": True,
            },
            "observation": None if observed is None else {
                "response_text": observed.response_text if executed is not None and executed.success else None,
                "response_complete": observed.metadata.get("response_complete"),
                **({"target_correlation_id": observed.metadata.get("target_correlation_id")}
                   if observed.metadata.get("target_correlation_id") else {}),
                **({"target_run_status": observed.metadata.get("target_run_status")}
                   if observed.metadata.get("target_run_status") else {}),
                **({"deduplicated_collector_events": observed.metadata.get("deduplicated_collector_events")}
                   if observed.metadata.get("deduplicated_collector_events") else {}),
                "evidence": [{"kind": item.kind, "source": item.source, "name": item.name,
                    "success": item.success, "reference": item.reference,
                    "data": public_evidence_data(item)} for item in observed.evidence]},
            "collector_diagnostics": [asdict(item) for item in self._collector_diagnostics],
            "deterministic_result": deterministic_snapshot,
            "judge": diagnostic,
            "final_result": final, "final_verdict": result.status.value,
            "evidence_classification": None if observed is None else classify_observation_evidence(
                observed.evidence, observed.response_text
            ),
            "evidence_v2": evidence_v2_payload,
            "evaluation_explanation": evaluation_explanation,
            "research_provenance": research_prov,
            "downgrade_reason": top_downgrade_reason,
            "judge_budget": None if self._budget is None else {
                "enabled": self._evaluation_config.judge_enabled,
                "allow_live": self._evaluation_config.allow_live_judge,
                "maximum": self._evaluation_config.max_judge_calls, "used": self._budget.used,
                "remaining": max(0, self._evaluation_config.max_judge_calls - self._budget.used)},
            "sanitization": "Headers, raw transport bodies and tool arguments omitted; configured credential values redacted in the report only.",
            "evidence_limitations": {
                "scope": context.get("evidence_scope", "Adapter-visible observations only; no inferred internal actions."),
                "original_goal": context.get("original_goal"),
                "attacker_goal": context.get("attacker_objective", context.get("attacker_goal")),
                "attack_surface": context.get("attack_surface"),
                "trust_boundary": context.get("trust_boundary"),
                "actual_lower_trust_boundary": context.get("actual_lower_trust_boundary"),
                "completeness": "Only explicit trusted observer metadata authorizes semantic PASS; HTTP success/finish_reason alone does not.",
                **(
                    {
                        "inline_evidence_disclosure": (
                            "Inline target-reported events omit raw argument and observation values from public/Judge evidence; "
                            "integrity digests and structural keys do not establish authorization or verified execution."
                        )
                    }
                    if observed is not None and any(ev.kind == "target_inline_event" for ev in observed.evidence)
                    else {}
                ),
            }}
        # Redact configured credential values in untrusted runtime-derived fields
        # while preserving trusted framework structural keys, enums, IDs, and SHA-256 digests.
        sanitized = self.redact_report_value(target, report)
        self._verify_report_integrity(sanitized)
        return sanitized

    _PRESERVED_VALUE_KEYS = frozenset({
        # Trusted framework-generated identifiers, schema metadata, enums, and hashes
        "run_id",
        "generic_run_id",
        "batch_id",
        "case_id",
        "testcase_id",
        "target_id",
        "input_id",
        "secagent_run_id",
        "secagent_execution_id",
        "secagent_testcase_id",
        "engine",
        "timestamp",
        "started_at",
        "completed_at",
        "category",
        "attack_module",
        "adapter",
        "adapter_name",
        "protocol",
        "execution_mode",
        "evaluation_mode",
        "evaluation_strategy",
        "evaluation_scope",
        "final_verdict",
        "internal_verdict",
        "effective_verdict",
        "security_verdict",
        "verdict",
        "status",
        "evaluation_status",
        "deterministic_verdict",
        "effective_deterministic_verdict",
        "decision_source",
        "matched_rule_id",
        "matched_rule_type",
        "deterministic_matched_rule_id",
        "deterministic_matched_rule_type",
        "downgrade_reason",
        "recommendation",
        "classification",
        "provider_fault_code",
        "json_validation_status",
        "skill",
        "provider",
        "model",
        "source_provenance",
        "provenance",
        "evidence_level",
        "provenance_tiers",
        "correlation_status",
        "correlation_strength",
        "collector_id",
        "collector_kind",
        "kind",
        "source",
        "policy_id",
        "policy_review_status",
        "reviewed_policy_id",
        "reviewed_policy_status",
        "application_context_id",
        "context_source",
        "rule_origin",
        "payload_ref",
        "source_tool",
        "report_path",
        "sanitization",
        "completeness",
        "inline_evidence_disclosure",
        "observes",
        "limitation",
        "scope",
        "attack_surface",
        "auth_source",
        "session_auth_type",
        "session_auth_header",
        "session_credential_generation",
        "contract_version",
        "projection_origin",
        "effective_evaluation_scope",
        "verified_execution_status",
        "highest_trust_classification",
        "trust_classification",
        "action_trace_completeness",
        "request_trace_completeness",
        "response_completeness",
        "action_presence",
        "refusal_state",
        "scope_family",
        "alignment_status",
        "execution_kind",
        "intent_origin",
        "explicit_refusal",
        "evidence_sufficiency",
        "outcome_reasoning_code",
    })
    _PRESERVED_VALUE_SUFFIXES = ("_sha256", "_fingerprint", "_digest")
    _DYNAMIC_KEY_CONTAINERS = frozenset({"data", "stored_provenance", "extra", "response_sample"})
    _DYNAMIC_TRUSTED_DIGEST_KEYS = frozenset({
        "event_fingerprint",
        "arguments_sha256",
        "observation_sha256",
    })
    _HEX64_PATTERN = None

    @staticmethod
    def _verify_report_integrity(report: Any) -> None:
        if not isinstance(report, dict):
            raise RuntimeError("report_redaction_integrity_failed")
        required_keys = ("run_id", "testcase_id", "final_verdict", "final_result", "research_provenance")
        if any(k not in report for k in required_keys):
            raise RuntimeError("report_redaction_integrity_failed")
        if report.get("final_verdict") not in {s.value for s in EvaluationStatus}:
            raise RuntimeError("report_redaction_integrity_failed")
        if not isinstance(report.get("final_result"), dict) or report["final_result"].get("status") not in {
            s.value for s in EvaluationStatus
        }:
            raise RuntimeError("report_redaction_integrity_failed")
        prov = report.get("research_provenance")
        if not isinstance(prov, dict):
            raise RuntimeError("report_redaction_integrity_failed")
        Runner._verify_sha256_digests(prov)

    @staticmethod
    def _verify_sha256_digests(node: Any) -> None:
        import re as _re

        hex64 = _re.compile(r"^[a-f0-9]{64}$")

        def walk(item: Any) -> None:
            if isinstance(item, dict):
                for k, v in item.items():
                    if isinstance(k, str) and k.endswith("_sha256") and v is not None:
                        if not isinstance(v, str) or not hex64.fullmatch(v):
                            raise RuntimeError("report_redaction_integrity_failed")
                    else:
                        walk(v)
            elif isinstance(item, list):
                for elem in item:
                    walk(elem)

        walk(node)

    def redact_report_value(self, target, value):
        """Redact configured credential values in untrusted fields while preserving trusted report schema."""
        import re as _re
        from reporting.redaction import Redactor

        secrets = sorted(self._judge_sensitive_values(target), key=len, reverse=True)
        if not secrets:
            return value
        cleaner = Redactor(secrets)
        hex64 = _re.compile(r"^[a-f0-9]{64}$")
        fingerprint_re = _re.compile(r"^(?:sha256:)?[a-f0-9]{64}$")
        dynamic_trusted_enums = frozenset({"provenance", "correlation_status", "correlation_strength"})

        def sanitize(item, *, key_name: str | None = None, scrub_keys: bool = False):
            if isinstance(item, str):
                if key_name is not None:
                    if scrub_keys:
                        if key_name in dynamic_trusted_enums:
                            return item
                        if key_name == "event_fingerprint" and fingerprint_re.fullmatch(item):
                            return item
                        if key_name in {"arguments_sha256", "observation_sha256"} and hex64.fullmatch(item):
                            return item
                    else:
                        if key_name in self._PRESERVED_VALUE_KEYS:
                            return item
                        if any(key_name.endswith(sfx) for sfx in self._PRESERVED_VALUE_SUFFIXES) and hex64.fullmatch(item):
                            return item
                return cleaner.redact_secrets_only(item)
            if isinstance(item, dict):
                out = {}
                for k, v in item.items():
                    next_scrub = scrub_keys or (isinstance(k, str) and k in self._DYNAMIC_KEY_CONTAINERS)
                    if scrub_keys and isinstance(k, str) and k not in dynamic_trusted_enums and k not in self._DYNAMIC_TRUSTED_DIGEST_KEYS:
                        clean_k = cleaner.redact_secrets_only(k)
                        if clean_k in out:
                            idx = 2
                            while f"{clean_k}#{idx}" in out:
                                idx += 1
                            clean_k = f"{clean_k}#{idx}"
                    else:
                        clean_k = k
                    field_key = k if isinstance(k, str) else None
                    out[clean_k] = sanitize(v, key_name=field_key, scrub_keys=next_scrub)
                return out
            if isinstance(item, (list, tuple)):
                if not scrub_keys and key_name in self._PRESERVED_VALUE_KEYS:
                    return [val for val in item]
                return [sanitize(val, key_name=None, scrub_keys=scrub_keys) for val in item]
            return item

        return sanitize(value)
