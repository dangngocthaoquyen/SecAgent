"""Provider protocol, strict request/response models, and token budget calculation for G11."""

from __future__ import annotations

from enum import Enum
from typing import Literal, Protocol

from pydantic import Field, model_validator

from generator.constants import AsiCode, HARD_MAX_PER_ASI
from generator.models import StrictGeneratorModel

DEFAULT_TOKEN_BUDGET_BASE: int = 768
DEFAULT_TOKEN_BUDGET_PER_CASE: int = 420
MIN_GENERATION_MAX_TOKENS: int = 512
DEFAULT_MAX_OUTPUT_TOKENS_CEILING: int = 8192


class ProviderErrorCategory(str, Enum):
    """Normalized, secret-free error categories for Generation LLM Providers."""

    CREDENTIAL_MISSING = "credential_missing"
    AUTH_REJECTED = "auth_rejected"
    MODEL_REJECTED = "model_rejected"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    NETWORK_ERROR = "network_error"
    HTTP_ERROR = "http_error"
    RESPONSE_TOO_LARGE = "response_too_large"
    EMPTY_OUTPUT = "empty_output"
    TRUNCATED_RESPONSE = "truncated_response"
    INVALID_RESPONSE_PAYLOAD = "invalid_response_payload"
    CONFIGURATION_ERROR = "configuration_error"


class TokenUsage(StrictGeneratorModel):
    """Token counts reported directly by the provider (never fabricated)."""

    prompt_tokens: int | None = Field(default=None, ge=0, strict=True)
    completion_tokens: int | None = Field(default=None, ge=0, strict=True)
    total_tokens: int | None = Field(default=None, ge=0, strict=True)


class ProviderStatus(StrictGeneratorModel):
    """Local-only provider readiness snapshot (never triggers network calls or leaks secrets)."""

    provider_id: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=128)
    configured: bool
    credential_available: bool
    ready: bool
    reason: str = Field(min_length=1, max_length=128)
    supports_json_mode: bool = False
    max_output_tokens_ceiling: int = Field(ge=MIN_GENERATION_MAX_TOKENS, strict=True)
    # Providers execute at most 1 attempt per generate() call; bounded retries belong to G11.3B service.
    retry_policy: Literal["caller_managed_single_attempt"] = "caller_managed_single_attempt"


class ProviderGenerationRequest(StrictGeneratorModel):
    """Sanitized, bounded LLM generation request handed to a GeneratorLLMProvider."""

    request_id: str = Field(min_length=1, max_length=128)
    asi_code: AsiCode
    requested_count: int = Field(ge=1, le=HARD_MAX_PER_ASI, strict=True)
    system_prompt: str = Field(min_length=1)
    user_payload_json: str = Field(min_length=2)
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    skill_version: str = Field(min_length=1, max_length=32)
    skill_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    max_tokens: int = Field(ge=MIN_GENERATION_MAX_TOKENS, le=16384, strict=True)
    timeout_seconds: float | None = Field(default=None, gt=0, le=120.0, allow_inf_nan=False)


class ProviderGenerationResponse(StrictGeneratorModel):
    """Structured outcome from a single provider invocation (never contains raw credentials)."""

    provider_id: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=128)
    ok: bool
    raw_text: str | None = None
    finish_reason: str | None = None
    token_usage: TokenUsage | None = None
    duration_ms: float = Field(ge=0.0, allow_inf_nan=False)
    call_count: int = Field(ge=0, le=1, strict=True)
    error_category: ProviderErrorCategory | None = None
    error_message: str | None = Field(default=None, max_length=512)
    http_status: int | None = Field(default=None, ge=100, le=599, strict=True)

    @model_validator(mode="after")
    def check_outcome_consistency(self) -> "ProviderGenerationResponse":
        if self.ok:
            if not isinstance(self.raw_text, str) or not self.raw_text.strip():
                raise ValueError("Successful provider response must include non-empty raw_text.")
            if self.error_category is not None:
                raise ValueError("Successful provider response must not carry an error_category.")
        else:
            if self.error_category is None:
                raise ValueError("Failed provider response must specify an error_category.")
            if not isinstance(self.error_message, str) or not self.error_message.strip():
                raise ValueError("Failed provider response must specify a non-empty error_message.")
        return self


def compute_token_budget(
    requested_count: int,
    *,
    ceiling: int = DEFAULT_MAX_OUTPUT_TOKENS_CEILING,
    base_tokens: int = DEFAULT_TOKEN_BUDGET_BASE,
    tokens_per_case: int = DEFAULT_TOKEN_BUDGET_PER_CASE,
) -> int:
    """Scale output token budget with requested testcase count under a strict hard ceiling."""
    if isinstance(requested_count, bool) or not isinstance(requested_count, int) or requested_count < 1:
        raise ValueError("requested_count must be a positive integer.")
    if requested_count > HARD_MAX_PER_ASI:
        raise ValueError(f"requested_count ({requested_count}) exceeds hard ceiling {HARD_MAX_PER_ASI}.")
    if isinstance(ceiling, bool) or not isinstance(ceiling, int) or ceiling < MIN_GENERATION_MAX_TOKENS:
        raise ValueError(f"ceiling must be an integer >= {MIN_GENERATION_MAX_TOKENS}.")
    raw_budget = base_tokens + (requested_count * tokens_per_case)
    return max(MIN_GENERATION_MAX_TOKENS, min(raw_budget, ceiling))


class GeneratorLLMProvider(Protocol):
    """Minimal provider interface decoupling LLM transport from generation/validation/persistence."""

    provider_id: str
    model_name: str

    def status(self) -> ProviderStatus:
        """Return local provider configuration and credential availability without calling the API."""
        ...

    def generate(self, request: ProviderGenerationRequest) -> ProviderGenerationResponse:
        """Execute a single bounded LLM generation call without internal retries or fallback."""
        ...
