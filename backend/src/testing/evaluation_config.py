"""Opt-in Runner composition and a shared, fail-closed provider call budget."""
from threading import Lock
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evaluators import HybridEvaluator, ResponseEvaluator
from integrations.external_evaluator.base import ExternalEvaluatorProvider
from integrations.external_evaluator.models import ExternalEvaluationOutcome, ProviderFault, ProviderFaultCode
from integrations.external_evaluator.pi import PiEvaluatorConfig, PiEvaluatorProvider


class RunnerEvaluationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    mode: Literal["rule_only", "hybrid"] = "rule_only"
    judge_enabled: bool = Field(default=False, strict=True)
    allow_live_judge: bool = Field(default=False, strict=True)
    max_judge_calls: int = Field(default=0, ge=0, strict=True)
    pi: PiEvaluatorConfig | None = None

    @model_validator(mode="after")
    def explicit_activation(self):
        if self.mode == "rule_only" and (self.judge_enabled or self.allow_live_judge or self.max_judge_calls):
            raise ValueError("Judge settings require explicit hybrid mode.")
        if self.allow_live_judge and (not self.judge_enabled or self.pi is None):
            raise ValueError("Live Judge opt-in requires judge_enabled and Pi configuration.")
        return self


class BudgetedJudgeProvider(ExternalEvaluatorProvider):
    """One Runner lifetime budget. Reserve before delegating; never retry/reset."""
    def __init__(self, config: RunnerEvaluationConfig, delegate=None):
        self.config, self.delegate = config, delegate
        self._used = 0
        self._lock = Lock()

    @property
    def used(self):
        with self._lock:
            return self._used

    def evaluate(self, request):
        with self._lock:
            code = None
            if not self.config.judge_enabled:
                code = ProviderFaultCode.JUDGE_DISABLED
            elif self._used >= self.config.max_judge_calls:
                code = ProviderFaultCode.BUDGET_EXHAUSTED
            if code is None:
                self._used += 1  # Exceptions/timeouts still consume the reservation.
        if code is not None:
            return ExternalEvaluationOutcome(request_sha256=request.sha256, skill=request.skill,
                duration_ms=0, fault=ProviderFault(code=code, message="Runner Judge invocation policy prevented a provider call."))
        return self.delegate.evaluate(request)


def configured_evaluator(config, provider, diagnostic_sink):
    if config.mode == "rule_only":
        if provider is not None:
            raise ValueError("A provider requires hybrid mode.")
        return ResponseEvaluator(), None
    if isinstance(provider, PiEvaluatorProvider) and not config.allow_live_judge:
        raise ValueError("Pi requires explicit live Judge opt-in.")
    if config.judge_enabled and provider is None:
        if not config.allow_live_judge:
            raise ValueError("Supply a trusted offline provider or explicitly opt into live Pi.")
        provider = PiEvaluatorProvider(config.pi)
    budget = BudgetedJudgeProvider(config, provider)
    return HybridEvaluator(budget, diagnostic_sink=diagnostic_sink), budget
