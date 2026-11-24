"""Run one testcase through preparation, execution, observation, and evaluation."""

from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Sequence
from uuid import uuid4

from attack_modules import (
    AttackModuleRegistry,
    build_default_attack_module_registry,
)
from core.models import (
    EvaluationResult,
    EvaluationStatus,
    TargetProfile,
    TestCase,
    TestInput,
)
from evaluators import BaseEvaluator
from core.models.evidence import classify_observation_evidence, public_evidence_data
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
        self._collector_diagnostics: list[CollectorDiagnostic] = []
        self._current_run_id: str | None = None
        self._started_at: str | None = None
        self._ended_at: str | None = None
        self._submitted_prompt: str | None = None
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

    def _run(self, testcase, target, test_input) -> EvaluationResult:
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
            prepared_prompt = prepared_input.prompt
            self._submitted_prompt = prepared_prompt
            execution_result = self._executor.execute(target, prepared_input)
            self._execution_result = execution_result
        except Exception:
            return EvaluationResult(
                status=EvaluationStatus.ERROR,
                reason="Execution stage failed.",
            )

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
                ctx = CollectorContext(
                    run_id=self._current_run_id or uuid4().hex,
                    case_id=testcase.id,
                    execution_id=test_input.id,
                    target_id=str(getattr(target, "id", "") or ""),
                    request_id=str(test_input.parameters.get("request_id") or test_input.id),
                    session_id=str(test_input.parameters.get("session_id") or "") or None,
                    started_at=self._started_at,
                    ended_at=datetime.now(timezone.utc).isoformat(),
                    allowed_roots=self._allowed_collector_roots,
                    allowed_endpoints=self._allowed_collector_endpoints,
                )
                collected = collect_target_evidence(active_collectors, ctx)
                observation.evidence.extend(collected.evidence)
                self._collector_diagnostics.extend(collected.diagnostics)
                observation.metadata["collector_diagnostics"] = [
                    asdict(item) for item in self._collector_diagnostics
                ]
            self._observation = observation
        except Exception:
            return EvaluationResult(
                status=EvaluationStatus.ERROR,
                reason="Observation stage failed.",
            )

        try:
            if self._progress_sink is not None and not self._custom_evaluator and self._evaluation_config.mode == "rule_only":
                self._progress_sink("running_rule_evaluator")
            if not self._custom_evaluator and self._evaluation_config.mode == "hybrid":
                evaluated = self._evaluator.evaluate(testcase, observation,
                    prepared_prompt=(prepared_prompt if self._reviewed_judge_input_sha256 else None),
                    reviewed_input_sha256=self._reviewed_judge_input_sha256,
                    sensitive_values=self._judge_sensitive_values(target))
            else:
                evaluated = self._evaluator.evaluate(testcase, observation)
            if (self._require_complete_response_for_pass
                    and evaluated.status is EvaluationStatus.PASS
                    and observation.metadata.get("response_complete") is not True):
                return EvaluationResult(status=EvaluationStatus.INCONCLUSIVE,
                    reason="Response-only PASS requires a complete observed response.")
            if (self._require_complete_response_for_fail
                    and evaluated.status is EvaluationStatus.FAIL
                    and observation.metadata.get("response_complete") is not True):
                verified_exec_fail = (
                    evaluated.matched_rule_type in {"collector_receipt", "asi05_execution"}
                    or (
                        evaluated.matched_rule_type == "tool_call"
                        and classify_observation_evidence(
                            observation.evidence, observation.response_text
                        ).get("verified_execution_present") is True
                    )
                )
                if not verified_exec_fail:
                    return EvaluationResult(status=EvaluationStatus.INCONCLUSIVE,
                        reason="Response-only FAIL requires a complete observed response.")
            return evaluated
        except Exception:
            return EvaluationResult(
                status=EvaluationStatus.ERROR,
                reason="Evaluation stage failed.",
            )

    def _judge_sensitive_values(self, target) -> tuple[str, ...]:
        from targets.validator import parse_header_credential_placeholder

        names = list(target.credential_refs)
        if self._evaluation_config.pi:
            names.extend(self._evaluation_config.pi.credential_env)
        for spec in getattr(target, "evidence_sources", []) or []:
            if isinstance(spec, dict) and isinstance(spec.get("headers"), dict):
                for raw_val in spec["headers"].values():
                    if isinstance(raw_val, str):
                        try:
                            parsed = parse_header_credential_placeholder(raw_val)
                        except ValueError:
                            parsed = None
                        if parsed is not None:
                            names.append(parsed[1])
        values = set()
        for name in names:
            raw_secret = os.environ.get(name)
            if raw_secret:
                values.add(raw_secret)
                if raw_secret.strip():
                    values.add(raw_secret.strip())
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
        deterministic_snapshot = diagnostic["deterministic_result"] if diagnostic else (
            final if not self._custom_evaluator and observed is not None
            and self._evaluation_config.mode == "rule_only" else None)
        report = {
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
                "duration_ms": executed.duration_ms, "response_complete": executed.response_complete},
            "observation": None if observed is None else {
                "response_text": observed.response_text if executed is not None and executed.success else None,
                "response_complete": observed.metadata.get("response_complete"),
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
            "research_provenance": build_case_research_provenance(
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
                final_result=result,
            ),
            "downgrade_reason": diagnostic["downgrade_reason"] if diagnostic else None,
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
                "completeness": "Only explicit trusted observer metadata authorizes semantic PASS; HTTP success/finish_reason alone does not."}}
        # Redact configured credential values even if a response/reason echoes
        # them. Arbitrary private target data still requires caller data policy.
        return self.redact_report_value(target, report)

    def redact_report_value(self, target, value):
        """Redact configured credential values recursively using Runner's sensitivity list."""
        secrets = sorted(self._judge_sensitive_values(target), key=len, reverse=True)

        def sanitize(item):
            if isinstance(item, str):
                for secret in secrets:
                    item = item.replace(secret, "[REDACTED]")
                return item
            if isinstance(item, dict):
                return {sanitize(key): sanitize(val) for key, val in item.items()}
            if isinstance(item, (list, tuple)):
                return [sanitize(val) for val in item]
            return item

        return sanitize(value)
