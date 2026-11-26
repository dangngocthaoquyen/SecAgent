"""Opt-in Runner composition and a shared, fail-closed provider call budget."""
import json
import os
from pathlib import Path
import re
import shutil
from threading import Lock
from typing import Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evaluators import EvaluationRequestBuilder, HybridEvaluator, ResponseEvaluator
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
    require_complete_response_for_semantic: bool = Field(default=False, strict=True)
    prefer_deterministic_v2: bool = Field(default=False, strict=True)
    max_technical_retries: int = Field(default=0, ge=0, le=3, strict=True)

    @model_validator(mode="after")
    def explicit_activation(self):
        if self.mode == "rule_only" and (self.judge_enabled or self.allow_live_judge or self.max_judge_calls):
            raise ValueError("Judge settings require explicit hybrid mode.")
        if self.allow_live_judge and (not self.judge_enabled or self.pi is None):
            raise ValueError("Live Judge opt-in requires judge_enabled and Pi configuration.")
        return self


class LiveJudgeConfigurationError(ValueError):
    """Fixed, credential-free preflight diagnostic for a live Pi configuration."""


def _has_pi_auth_provider(provider: str) -> bool:
    auth_path = Path.home() / ".pi" / "agent" / "auth.json"
    if not auth_path.is_file():
        return False
    try:
        data = json.loads(auth_path.read_text(encoding="utf-8-sig"))
        return isinstance(data, dict) and bool(data.get(provider))
    except (OSError, UnicodeError, ValueError):
        return False


def validate_live_pi_config(config: RunnerEvaluationConfig, *,
                            environ: Mapping[str, str] | None = None) -> None:
    """Preflight one shared live Pi config without reading or reporting secrets."""
    if (config.mode != "hybrid" or not config.judge_enabled
            or not config.allow_live_judge or config.pi is None
            or config.max_judge_calls != 1):
        raise LiveJudgeConfigurationError("Live Judge requires one bounded Hybrid Pi attempt per testcase.")
    names = config.pi.credential_env
    if config.pi.use_pi_auth_file and not names:
        if not _has_pi_auth_provider(config.pi.provider):
            raise LiveJudgeConfigurationError("Configured Pi auth.json provider credential is unavailable.")
    else:
        if (not names or len(names) > 4 or any(
                not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", name) for name in names)):
            raise LiveJudgeConfigurationError("Live Judge credential environment names are invalid.")
        source = os.environ if environ is None else environ
        if any(not source.get(name) for name in names):
            raise LiveJudgeConfigurationError("Configured Judge credential is unavailable in this process.")
    executable = config.pi.executable
    if not (Path(executable).is_file() or shutil.which(executable)):
        raise LiveJudgeConfigurationError("Configured Pi executable is unavailable.")


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


def configured_evaluator(config, provider, diagnostic_sink, *, bundle_loader=None):
    if config.mode == "rule_only":
        if provider is not None:
            raise ValueError("A provider requires hybrid mode.")
        return ResponseEvaluator(), None
    if isinstance(provider, PiEvaluatorProvider) and not config.allow_live_judge:
        raise ValueError("Pi requires explicit live Judge opt-in.")
    if config.judge_enabled and provider is None:
        if not config.allow_live_judge:
            raise ValueError("Supply a trusted offline provider or explicitly opt into live Pi.")
        provider = PiEvaluatorProvider(config.pi, bundle_loader=bundle_loader)
    budget = BudgetedJudgeProvider(config, provider)
    request_builder = EvaluationRequestBuilder(bundle_loader=bundle_loader) if bundle_loader is not None else None
    return HybridEvaluator(
        budget,
        request_builder=request_builder,
        diagnostic_sink=diagnostic_sink,
        require_complete_response_for_semantic=config.require_complete_response_for_semantic,
        prefer_deterministic_v2=config.prefer_deterministic_v2,
        max_technical_retries=config.max_technical_retries,
    ), budget
