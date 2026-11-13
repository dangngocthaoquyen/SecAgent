"""Run one testcase through preparation, execution, observation, and evaluation."""

from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import os
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
from core.models.evidence import public_evidence_data
from observers import BaseObserver, ResponseObserver
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
    ) -> None:
        self._executor = executor if executor is not None else Executor()
        self._observer = observer if observer is not None else ResponseObserver()
        if evaluator is not None and (evaluation_config is not None or judge_provider is not None):
            raise ValueError("Choose existing evaluator injection or Runner evaluation configuration, not both.")
        self._diagnostics = []
        self._evaluation_config = evaluation_config or RunnerEvaluationConfig()
        self._budget = None
        self._evaluator = evaluator
        if self._evaluator is None:
            self._evaluator, self._budget = configured_evaluator(self._evaluation_config, judge_provider, self._diagnostics.append)
        self._custom_evaluator = evaluator is not None
        self._report_sink = report_sink
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
        self._execution_result = self._observation = None
        result = self._run(testcase, target, test_input)
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
            execution_result = self._executor.execute(target, prepared_input)
            self._execution_result = execution_result
        except Exception:
            return EvaluationResult(
                status=EvaluationStatus.ERROR,
                reason="Execution stage failed.",
            )

        try:
            observation = self._observer.observe(execution_result)
            self._observation = observation
        except Exception:
            return EvaluationResult(
                status=EvaluationStatus.ERROR,
                reason="Observation stage failed.",
            )

        try:
            return self._evaluator.evaluate(testcase, observation)
        except Exception:
            return EvaluationResult(
                status=EvaluationStatus.ERROR,
                reason="Evaluation stage failed.",
            )

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
        report = {
            "run_id": uuid4().hex, "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_id": getattr(target, "id", None), "target_name": getattr(target, "name", None), "testcase_id": testcase.id,
            "input_id": test_input.id,
            "evaluation_mode": "custom" if self._custom_evaluator else self._evaluation_config.mode,
            "evaluation_strategy": testcase.evaluation.strategy,
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
            "deterministic_result": diagnostic["deterministic_result"] if diagnostic else (
                final if not self._custom_evaluator and observed is not None
                and self._evaluation_config.mode == "rule_only" else None),
            "judge": diagnostic,
            "final_result": final, "final_verdict": result.status.value,
            "downgrade_reason": diagnostic["downgrade_reason"] if diagnostic else None,
            "judge_budget": None if self._budget is None else {
                "enabled": self._evaluation_config.judge_enabled,
                "allow_live": self._evaluation_config.allow_live_judge,
                "maximum": self._evaluation_config.max_judge_calls, "used": self._budget.used,
                "remaining": max(0, self._evaluation_config.max_judge_calls - self._budget.used)},
            "sanitization": "Headers, raw transport bodies and tool arguments omitted; configured credential values redacted in the report only.",
            "evidence_limitations": {
                "scope": context.get("evidence_scope", "Adapter-visible observations only; no inferred internal actions."),
                "attack_surface": context.get("attack_surface"),
                "trust_boundary": context.get("trust_boundary"),
                "actual_lower_trust_boundary": context.get("actual_lower_trust_boundary"),
                "completeness": "Only explicit trusted observer metadata authorizes semantic PASS; HTTP success/finish_reason alone does not."}}
        # Redact configured credential values even if a response/reason echoes
        # them. Arbitrary private target data still requires caller data policy.
        names = list(getattr(target, "credential_refs", []))
        if self._evaluation_config.pi:
            names.extend(self._evaluation_config.pi.credential_env)
        secrets = sorted({os.environ[name] for name in names if os.environ.get(name)}, key=len, reverse=True)

        def sanitize(value):
            if isinstance(value, str):
                for secret in secrets:
                    value = value.replace(secret, "[REDACTED]")
                return value
            if isinstance(value, dict):
                return {sanitize(key): sanitize(item) for key, item in value.items()}
            if isinstance(value, (list, tuple)):
                return [sanitize(item) for item in value]
            return value
        return sanitize(report)
