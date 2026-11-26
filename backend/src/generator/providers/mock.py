"""Deterministic offline MockGeneratorProvider for G11 unit and contract testing."""

from __future__ import annotations

import json
from typing import Callable, Literal, Sequence

from generator.models import StrictGeneratorModel
from generator.providers.base import (
    DEFAULT_MAX_OUTPUT_TOKENS_CEILING,
    ProviderErrorCategory,
    ProviderGenerationRequest,
    ProviderGenerationResponse,
    ProviderStatus,
    TokenUsage,
)

MockMode = Literal[
    "success",
    "empty_output",
    "invalid_json",
    "unexpected_schema",
    "credential_unavailable",
    "timeout",
    "provider_error",
    "truncated_response",
]


class MockFixtureResponse(StrictGeneratorModel):
    """One deterministic scripted outcome for MockGeneratorProvider."""

    mode: MockMode = "success"
    raw_text: str | None = None
    finish_reason: str | None = None
    token_usage: TokenUsage | None = None
    duration_ms: float = 5.0
    error_category: ProviderErrorCategory | None = None
    error_message: str | None = None
    http_status: int | None = None


def build_synthetic_success_json(request: ProviderGenerationRequest) -> str:
    """Build a harmless synthetic JSON payload matching RawGenerationOutputContract."""
    candidates = [
        {
            "prompt": f"[synthetic {request.asi_code} boundary probe #{idx + 1}]",
            "description": f"Synthetic {request.asi_code} security boundary test #{idx + 1}.",
            "strategy_tag": f"synthetic_boundary_{idx + 1}",
            "context_basis": ["purpose", "trust_boundaries"],
            "scope_note": (
                f"Descriptive metadata only: synthetic fixture #{idx + 1} for {request.asi_code}; "
                "does not alter backend scope or execution authorization."
            ),
        }
        for idx in range(request.requested_count)
    ]
    return json.dumps(
        {
            "schema_version": "1.0",
            "asi_category": request.asi_code,
            "context_gaps": [],
            "candidates": candidates,
        },
        ensure_ascii=False,
    )


class MockGeneratorProvider:
    """Offline mock provider supporting scripted fixtures with zero network access."""

    def __init__(
        self,
        *,
        provider_id: str = "mock",
        model_name: str = "mock-generator-v1",
        mode: MockMode = "success",
        fixtures: Sequence[MockFixtureResponse] | None = None,
        handler: Callable[[ProviderGenerationRequest], ProviderGenerationResponse] | None = None,
        credential_available: bool = True,
        supports_json_mode: bool = True,
        max_output_tokens_ceiling: int = DEFAULT_MAX_OUTPUT_TOKENS_CEILING,
    ) -> None:
        self.provider_id = provider_id
        self.model_name = model_name
        self._default_mode = mode
        self._fixtures = list(fixtures) if fixtures is not None else []
        self._handler = handler
        self._credential_available = credential_available and mode != "credential_unavailable"
        self._supports_json_mode = supports_json_mode
        self._max_output_tokens_ceiling = max_output_tokens_ceiling
        self._cursor = 0
        self.received_requests: list[ProviderGenerationRequest] = []
        self.total_calls: int = 0

    def status(self) -> ProviderStatus:
        ready = self._credential_available
        return ProviderStatus(
            provider_id=self.provider_id,
            model=self.model_name,
            configured=True,
            credential_available=self._credential_available,
            ready=ready,
            reason="ready" if ready else "credential_missing",
            supports_json_mode=self._supports_json_mode,
            max_output_tokens_ceiling=self._max_output_tokens_ceiling,
        )

    def generate(self, request: ProviderGenerationRequest) -> ProviderGenerationResponse:
        self.received_requests.append(request)

        if self._handler is not None:
            resp = self._handler(request)
            self.total_calls += resp.call_count
            return resp

        if self._cursor < len(self._fixtures):
            spec = self._fixtures[self._cursor]
            self._cursor += 1
        else:
            spec = MockFixtureResponse(mode=self._default_mode)

        if not self._credential_available or spec.mode == "credential_unavailable":
            return ProviderGenerationResponse(
                provider_id=self.provider_id,
                model=self.model_name,
                ok=False,
                duration_ms=spec.duration_ms,
                call_count=0,
                error_category=ProviderErrorCategory.CREDENTIAL_MISSING,
                error_message="Mock provider credential is unavailable.",
            )

        self.total_calls += 1

        if spec.mode == "success":
            raw = spec.raw_text if spec.raw_text is not None else build_synthetic_success_json(request)
            usage = spec.token_usage or TokenUsage(
                prompt_tokens=120,
                completion_tokens=60 * request.requested_count,
                total_tokens=120 + (60 * request.requested_count),
            )
            return ProviderGenerationResponse(
                provider_id=self.provider_id,
                model=self.model_name,
                ok=True,
                raw_text=raw,
                finish_reason=spec.finish_reason or "stop",
                token_usage=usage,
                duration_ms=spec.duration_ms,
                call_count=1,
                http_status=spec.http_status or 200,
            )

        if spec.mode == "invalid_json":
            return ProviderGenerationResponse(
                provider_id=self.provider_id,
                model=self.model_name,
                ok=True,
                raw_text=spec.raw_text if spec.raw_text is not None else "{not valid json",
                finish_reason=spec.finish_reason or "stop",
                token_usage=spec.token_usage,
                duration_ms=spec.duration_ms,
                call_count=1,
                http_status=spec.http_status or 200,
            )

        if spec.mode == "unexpected_schema":
            bad_schema = (
                spec.raw_text
                if spec.raw_text is not None
                else json.dumps(
                    {
                        "schema_version": "1.0",
                        "asi_category": request.asi_code,
                        "expected_verdict": "FAIL",
                        "candidates": [],
                    }
                )
            )
            return ProviderGenerationResponse(
                provider_id=self.provider_id,
                model=self.model_name,
                ok=True,
                raw_text=bad_schema,
                finish_reason=spec.finish_reason or "stop",
                token_usage=spec.token_usage,
                duration_ms=spec.duration_ms,
                call_count=1,
                http_status=spec.http_status or 200,
            )

        if spec.mode == "empty_output":
            return ProviderGenerationResponse(
                provider_id=self.provider_id,
                model=self.model_name,
                ok=False,
                finish_reason=spec.finish_reason or "stop",
                token_usage=spec.token_usage,
                duration_ms=spec.duration_ms,
                call_count=1,
                error_category=ProviderErrorCategory.EMPTY_OUTPUT,
                error_message="Provider returned empty completion content.",
                http_status=spec.http_status or 200,
            )

        if spec.mode == "truncated_response":
            return ProviderGenerationResponse(
                provider_id=self.provider_id,
                model=self.model_name,
                ok=False,
                raw_text=spec.raw_text,
                finish_reason="length",
                token_usage=spec.token_usage,
                duration_ms=spec.duration_ms,
                call_count=1,
                error_category=ProviderErrorCategory.TRUNCATED_RESPONSE,
                error_message="Provider completion was truncated at max_tokens limit.",
                http_status=spec.http_status or 200,
            )

        if spec.mode == "timeout":
            return ProviderGenerationResponse(
                provider_id=self.provider_id,
                model=self.model_name,
                ok=False,
                duration_ms=spec.duration_ms,
                call_count=1,
                error_category=ProviderErrorCategory.TIMEOUT,
                error_message="Provider request timed out.",
            )

        return ProviderGenerationResponse(
            provider_id=self.provider_id,
            model=self.model_name,
            ok=False,
            duration_ms=spec.duration_ms,
            call_count=1,
            error_category=spec.error_category or ProviderErrorCategory.HTTP_ERROR,
            error_message=spec.error_message or "Simulated provider HTTP error.",
            http_status=spec.http_status or 502,
        )
