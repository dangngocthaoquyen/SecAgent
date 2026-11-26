"""Server-controlled DeepSeek HTTP provider using httpx (single-attempt, no fallback).

Contract notes (aligned with official DeepSeek Chat Completions API as of 2026-11-26):
- Legacy `deepseek-chat` and `deepseek-reasoner` were retired on 2026-07-24.
  Current official models are `deepseek-flash` (default) and `deepseek-v4-pro`.
- DeepSeek V4 models enable thinking mode by default unless `"thinking": {"type": "disabled"}`
  is sent; in thinking mode `temperature` is ignored and reasoning tokens count toward
  `max_tokens`. For structured JSON generation, this provider defaults to non-thinking mode
  (`thinking: {"type": "disabled"}`) when the model supports thinking control, and sends
  `temperature` only when the configured model/mode actually honors it.
- Unknown models fall back conservatively (`supports_json_mode=False`,
  `supports_thinking_control=False`) and fail closed if unsupported features are requested.
- Endpoint is restricted to an explicit server-owned HTTPS allowlist (never accepts
  arbitrary provider URLs from UI/request).
- Credentials are read strictly from a server-configured environment variable name
  (default: DEEPSEEK_API_KEY); never logs, persists, or returns raw API keys.
- Single attempt per `generate()` call (`call_count` in {0, 1}); bounded retries are
  owned exclusively by the G11.3B Generator Service to avoid nested retry amplification.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Literal, Mapping
from urllib.parse import urlsplit

import httpx
from pydantic import Field, field_validator, model_validator

from generator.models import StrictGeneratorModel
from generator.providers.base import (
    MIN_GENERATION_MAX_TOKENS,
    ProviderErrorCategory,
    ProviderGenerationRequest,
    ProviderGenerationResponse,
    ProviderStatus,
    TokenUsage,
)

ThinkingMode = Literal["disabled", "enabled"]

DEFAULT_DEEPSEEK_ENDPOINT: str = "https://api.deepseek.com/chat/completions"
ALLOWED_DEEPSEEK_ENDPOINTS: frozenset[str] = frozenset({
    "https://api.deepseek.com/chat/completions",
    "https://api.deepseek.com/v1/chat/completions",
})
DEFAULT_DEEPSEEK_CREDENTIAL_ENV: str = "DEEPSEEK_API_KEY"
DEFAULT_DEEPSEEK_MODEL: str = "deepseek-flash"
DEFAULT_DEEPSEEK_TIMEOUT_SECONDS: float = 60.0
DEFAULT_DEEPSEEK_MAX_RESPONSE_BYTES: int = 256 * 1024  # 256 KiB hard response cap

_ENV_VAR_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_MODEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class DeepSeekModelCapabilities(StrictGeneratorModel):
    """Explicit capability profile per DeepSeek model identifier."""

    supports_json_mode: bool
    supports_temperature_non_thinking: bool
    supports_thinking_control: bool
    # SecAgent-owned output token ceilings (intentionally lower than API 384K max for cost bounds).
    max_output_tokens_ceiling: int = Field(ge=MIN_GENERATION_MAX_TOKENS, le=16384, strict=True)


KNOWN_DEEPSEEK_MODEL_CAPABILITIES: dict[str, DeepSeekModelCapabilities] = {
    "deepseek-flash": DeepSeekModelCapabilities(
        supports_json_mode=True,
        supports_temperature_non_thinking=True,
        supports_thinking_control=True,
        max_output_tokens_ceiling=8192,
    ),
    "deepseek-v4-pro": DeepSeekModelCapabilities(
        supports_json_mode=True,
        supports_temperature_non_thinking=True,
        supports_thinking_control=True,
        max_output_tokens_ceiling=16384,
    ),
}

CONSERVATIVE_UNKNOWN_MODEL_CAPABILITIES = DeepSeekModelCapabilities(
    supports_json_mode=False,
    supports_temperature_non_thinking=True,
    supports_thinking_control=False,
    max_output_tokens_ceiling=8192,
)


def resolve_deepseek_model_capabilities(model: str) -> DeepSeekModelCapabilities:
    """Return explicit capability metadata without assuming unknown models support JSON/thinking."""
    return KNOWN_DEEPSEEK_MODEL_CAPABILITIES.get(model, CONSERVATIVE_UNKNOWN_MODEL_CAPABILITIES)


class DeepSeekHttpConfig(StrictGeneratorModel):
    """Server-owned non-secret configuration for DeepSeekHttpProvider."""

    model: str = Field(default=DEFAULT_DEEPSEEK_MODEL, min_length=1, max_length=128)
    endpoint: str = Field(default=DEFAULT_DEEPSEEK_ENDPOINT, min_length=1, max_length=256)
    credential_env: str = Field(default=DEFAULT_DEEPSEEK_CREDENTIAL_ENV, min_length=1, max_length=64)
    timeout_seconds: float = Field(
        default=DEFAULT_DEEPSEEK_TIMEOUT_SECONDS, gt=0.0, le=120.0, allow_inf_nan=False
    )
    max_response_bytes: int = Field(
        default=DEFAULT_DEEPSEEK_MAX_RESPONSE_BYTES, ge=4096, le=1024 * 1024, strict=True
    )
    temperature: float | None = Field(default=0.3, ge=0.0, le=1.5, allow_inf_nan=False)
    use_json_mode: bool | None = None
    thinking_mode: ThinkingMode | None = None
    max_output_tokens_ceiling: int | None = Field(
        default=None, ge=MIN_GENERATION_MAX_TOKENS, le=16384, strict=True
    )

    @field_validator("model")
    @classmethod
    def check_model_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not _MODEL_NAME_RE.fullmatch(cleaned):
            raise ValueError("Invalid DeepSeek model identifier.")
        return cleaned

    @field_validator("endpoint")
    @classmethod
    def check_server_controlled_endpoint(cls, value: str) -> str:
        cleaned = value.strip()
        parsed = urlsplit(cleaned)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or cleaned not in ALLOWED_DEEPSEEK_ENDPOINTS
        ):
            raise ValueError(
                "DeepSeek endpoint must match an explicit server-controlled HTTPS allowlist entry."
            )
        return cleaned

    @field_validator("credential_env")
    @classmethod
    def check_credential_env_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not _ENV_VAR_RE.fullmatch(cleaned):
            raise ValueError("credential_env must be a valid uppercase environment variable name.")
        return cleaned

    @model_validator(mode="after")
    def check_model_capabilities(self) -> "DeepSeekHttpConfig":
        caps = resolve_deepseek_model_capabilities(self.model)
        if self.use_json_mode is True and not caps.supports_json_mode:
            raise ValueError(
                f"Configured model {self.model!r} is not confirmed to support response_format json_object."
            )
        if self.thinking_mode is not None and not caps.supports_thinking_control:
            raise ValueError(
                f"Configured model {self.model!r} is not confirmed to support explicit thinking configuration."
            )
        if (
            self.max_output_tokens_ceiling is not None
            and self.max_output_tokens_ceiling > caps.max_output_tokens_ceiling
        ):
            raise ValueError(
                f"max_output_tokens_ceiling ({self.max_output_tokens_ceiling}) exceeds "
                f"model ceiling ({caps.max_output_tokens_ceiling}) for {self.model!r}."
            )
        return self

    @property
    def effective_json_mode(self) -> bool:
        if self.use_json_mode is not None:
            return self.use_json_mode
        return resolve_deepseek_model_capabilities(self.model).supports_json_mode

    @property
    def effective_thinking_mode(self) -> ThinkingMode | None:
        caps = resolve_deepseek_model_capabilities(self.model)
        if not caps.supports_thinking_control:
            return None
        if self.thinking_mode is not None:
            return self.thinking_mode
        # Default to non-thinking mode for deterministic, bounded structured JSON generation.
        return "disabled"

    @property
    def effective_supports_temperature(self) -> bool:
        caps = resolve_deepseek_model_capabilities(self.model)
        if not caps.supports_temperature_non_thinking:
            return False
        # DeepSeek thinking mode ignores temperature; only send when non-thinking is active.
        return self.effective_thinking_mode != "enabled"

    @property
    def effective_max_output_tokens_ceiling(self) -> int:
        caps = resolve_deepseek_model_capabilities(self.model)
        if self.max_output_tokens_ceiling is not None:
            return min(self.max_output_tokens_ceiling, caps.max_output_tokens_ceiling)
        return caps.max_output_tokens_ceiling


def _parse_token_usage(raw_usage: Any) -> TokenUsage | None:
    if not isinstance(raw_usage, dict):
        return None
    prompt_t = raw_usage.get("prompt_tokens")
    comp_t = raw_usage.get("completion_tokens")
    total_t = raw_usage.get("total_tokens")

    def _safe_nonneg_int(val: Any) -> int | None:
        if isinstance(val, bool) or not isinstance(val, int) or val < 0:
            return None
        return val

    p_val = _safe_nonneg_int(prompt_t)
    c_val = _safe_nonneg_int(comp_t)
    t_val = _safe_nonneg_int(total_t)
    if p_val is None and c_val is None and t_val is None:
        return None
    return TokenUsage(prompt_tokens=p_val, completion_tokens=c_val, total_tokens=t_val)


def _classify_http_error(status_code: int) -> tuple[ProviderErrorCategory, str]:
    if status_code in {401, 403}:
        return (
            ProviderErrorCategory.AUTH_REJECTED,
            f"DeepSeek API rejected authentication (HTTP {status_code}).",
        )
    if status_code == 404:
        return (
            ProviderErrorCategory.MODEL_REJECTED,
            "DeepSeek API reported model or endpoint not found (HTTP 404).",
        )
    if status_code == 429:
        return (
            ProviderErrorCategory.RATE_LIMITED,
            "DeepSeek API rate limit or quota exceeded (HTTP 429).",
        )
    if 300 <= status_code < 400:
        return (
            ProviderErrorCategory.NETWORK_ERROR,
            f"DeepSeek API returned an unexpected redirect (HTTP {status_code}); redirects are disabled.",
        )
    return (
        ProviderErrorCategory.HTTP_ERROR,
        f"DeepSeek API request failed with HTTP {status_code}.",
    )


class DeepSeekHttpProvider:
    """Bounded, single-attempt DeepSeek Chat Completions HTTP client over httpx."""

    provider_id: str = "deepseek_http"

    def __init__(
        self,
        config: DeepSeekHttpConfig | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._config = config or DeepSeekHttpConfig()
        self.model_name = self._config.model
        self._transport = transport
        self._environ = environ

    def __repr__(self) -> str:
        return (
            f"DeepSeekHttpProvider(model={self._config.model!r}, "
            f"endpoint={self._config.endpoint!r}, credential_env={self._config.credential_env!r})"
        )

    def _read_api_key(self) -> str | None:
        source = os.environ if self._environ is None else self._environ
        value = source.get(self._config.credential_env)
        if not isinstance(value, str):
            return None
        cleaned = value.strip()
        return cleaned or None

    def status(self) -> ProviderStatus:
        """Check local configuration and credential presence without making any network call."""
        has_cred = self._read_api_key() is not None
        return ProviderStatus(
            provider_id=self.provider_id,
            model=self._config.model,
            configured=True,
            credential_available=has_cred,
            ready=has_cred,
            reason="ready" if has_cred else "credential_missing",
            supports_json_mode=self._config.effective_json_mode,
            max_output_tokens_ceiling=self._config.effective_max_output_tokens_ceiling,
        )

    def _build_request_body(self, request: ProviderGenerationRequest) -> dict[str, Any]:
        effective_max_tokens = min(
            request.max_tokens, self._config.effective_max_output_tokens_ceiling
        )
        body: dict[str, Any] = {
            "model": self._config.model,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.user_payload_json},
            ],
            "max_tokens": effective_max_tokens,
            "stream": False,
        }
        if self._config.effective_thinking_mode is not None:
            body["thinking"] = {"type": self._config.effective_thinking_mode}
        if self._config.effective_json_mode:
            body["response_format"] = {"type": "json_object"}
        if self._config.effective_supports_temperature and self._config.temperature is not None:
            body["temperature"] = self._config.temperature
        return body

    def generate(self, request: ProviderGenerationRequest) -> ProviderGenerationResponse:
        """Execute exactly one bounded DeepSeek HTTP call without retries or provider fallback."""
        started = time.monotonic()
        api_key = self._read_api_key()
        if api_key is None:
            return ProviderGenerationResponse(
                provider_id=self.provider_id,
                model=self._config.model,
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000.0,
                call_count=0,
                error_category=ProviderErrorCategory.CREDENTIAL_MISSING,
                error_message=(
                    f"Configured DeepSeek credential environment variable "
                    f"'{self._config.credential_env}' is unavailable."
                ),
            )

        effective_timeout = (
            min(request.timeout_seconds, self._config.timeout_seconds)
            if request.timeout_seconds is not None
            else self._config.timeout_seconds
        )
        body = self._build_request_body(request)
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        max_bytes = self._config.max_response_bytes

        status_code: int | None = None
        raw_bytes = bytearray()
        exceeded = False

        try:
            with httpx.Client(
                verify=True,
                follow_redirects=False,
                trust_env=False,
                timeout=httpx.Timeout(effective_timeout),
                transport=self._transport,
            ) as client:
                with client.stream(
                    "POST",
                    self._config.endpoint,
                    headers=headers,
                    json=body,
                ) as response:
                    status_code = response.status_code
                    if status_code >= 300:
                        category, msg = _classify_http_error(status_code)
                        return ProviderGenerationResponse(
                            provider_id=self.provider_id,
                            model=self._config.model,
                            ok=False,
                            duration_ms=(time.monotonic() - started) * 1000.0,
                            call_count=1,
                            error_category=category,
                            error_message=msg,
                            http_status=status_code,
                        )
                    for chunk in response.iter_bytes(chunk_size=8192):
                        if not chunk:
                            continue
                        remaining = max_bytes + 1 - len(raw_bytes)
                        if remaining > 0:
                            raw_bytes.extend(chunk[:remaining])
                        if len(raw_bytes) > max_bytes:
                            exceeded = True
                            break
        except httpx.TimeoutException:
            return ProviderGenerationResponse(
                provider_id=self.provider_id,
                model=self._config.model,
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000.0,
                call_count=1,
                error_category=ProviderErrorCategory.TIMEOUT,
                error_message="DeepSeek API request timed out.",
            )
        except httpx.HTTPError:
            return ProviderGenerationResponse(
                provider_id=self.provider_id,
                model=self._config.model,
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000.0,
                call_count=1,
                error_category=ProviderErrorCategory.NETWORK_ERROR,
                error_message="DeepSeek API transport error occurred.",
            )

        duration_ms = (time.monotonic() - started) * 1000.0
        if exceeded:
            return ProviderGenerationResponse(
                provider_id=self.provider_id,
                model=self._config.model,
                ok=False,
                duration_ms=duration_ms,
                call_count=1,
                error_category=ProviderErrorCategory.RESPONSE_TOO_LARGE,
                error_message=f"DeepSeek API response exceeded the {max_bytes} byte limit.",
                http_status=status_code,
            )

        try:
            payload = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return ProviderGenerationResponse(
                provider_id=self.provider_id,
                model=self._config.model,
                ok=False,
                duration_ms=duration_ms,
                call_count=1,
                error_category=ProviderErrorCategory.INVALID_RESPONSE_PAYLOAD,
                error_message="DeepSeek API returned malformed JSON envelope.",
                http_status=status_code,
            )

        if not isinstance(payload, dict):
            return ProviderGenerationResponse(
                provider_id=self.provider_id,
                model=self._config.model,
                ok=False,
                duration_ms=duration_ms,
                call_count=1,
                error_category=ProviderErrorCategory.INVALID_RESPONSE_PAYLOAD,
                error_message="DeepSeek API response root must be a JSON object.",
                http_status=status_code,
            )

        usage = _parse_token_usage(payload.get("usage"))
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            return ProviderGenerationResponse(
                provider_id=self.provider_id,
                model=self._config.model,
                ok=False,
                token_usage=usage,
                duration_ms=duration_ms,
                call_count=1,
                error_category=ProviderErrorCategory.INVALID_RESPONSE_PAYLOAD,
                error_message="DeepSeek API response is missing choices[0].",
                http_status=status_code,
            )

        first_choice = choices[0]
        raw_finish = first_choice.get("finish_reason")
        finish_reason = raw_finish.strip() if isinstance(raw_finish, str) and raw_finish.strip() else None
        message = first_choice.get("message")
        content = message.get("content") if isinstance(message, dict) else None

        if finish_reason == "length":
            return ProviderGenerationResponse(
                provider_id=self.provider_id,
                model=self._config.model,
                ok=False,
                raw_text=content if isinstance(content, str) else None,
                finish_reason=finish_reason,
                token_usage=usage,
                duration_ms=duration_ms,
                call_count=1,
                error_category=ProviderErrorCategory.TRUNCATED_RESPONSE,
                error_message="DeepSeek API completion was truncated before finishing (finish_reason=length).",
                http_status=status_code,
            )

        if not isinstance(content, str) or not content.strip():
            return ProviderGenerationResponse(
                provider_id=self.provider_id,
                model=self._config.model,
                ok=False,
                finish_reason=finish_reason,
                token_usage=usage,
                duration_ms=duration_ms,
                call_count=1,
                error_category=ProviderErrorCategory.EMPTY_OUTPUT,
                error_message="DeepSeek API returned empty completion content.",
                http_status=status_code,
            )

        return ProviderGenerationResponse(
            provider_id=self.provider_id,
            model=self._config.model,
            ok=True,
            raw_text=content,
            finish_reason=finish_reason,
            token_usage=usage,
            duration_ms=duration_ms,
            call_count=1,
            http_status=status_code,
        )
