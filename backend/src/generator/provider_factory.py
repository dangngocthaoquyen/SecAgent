"""Server-owned provider configuration and credential isolation policy (G11.3C / R02).

Enforces strict backend ownership of DeepSeek credentials and provider endpoints:
- DeepSeek API keys are read exclusively from a server-allowlisted environment variable
  (default and allowlist: `DEEPSEEK_API_KEY`).
- Clients can NEVER supply raw API keys, credential environment variable names, or
  arbitrary provider URLs via JSON bodies, headers, or query parameters.
- No silent fallback from DeepSeek to Mock or any other provider when credentials are
  missing or an API error occurs.
- MockGeneratorProvider continues to operate offline with zero API key for testing.
"""

from __future__ import annotations

import re
from typing import Any, Literal, Mapping

import httpx
from pydantic import Field, field_validator

from generator.models import StrictGeneratorModel
from generator.providers.base import GeneratorLLMProvider
from generator.providers.deepseek_http import (
    ALLOWED_DEEPSEEK_ENDPOINTS,
    DEFAULT_DEEPSEEK_CREDENTIAL_ENV,
    DEFAULT_DEEPSEEK_ENDPOINT,
    DEFAULT_DEEPSEEK_MODEL,
    DEFAULT_DEEPSEEK_TIMEOUT_SECONDS,
    DeepSeekHttpConfig,
    DeepSeekHttpProvider,
    ThinkingMode,
)
from generator.providers.mock import MockGeneratorProvider

ALLOWED_DEEPSEEK_CREDENTIAL_ENVS: frozenset[str] = frozenset({
    DEFAULT_DEEPSEEK_CREDENTIAL_ENV,
})

# Keys that clients must NEVER pass in generator API requests.
FORBIDDEN_CLIENT_REQUEST_KEYS: frozenset[str] = frozenset({
    "api_key",
    "apikey",
    "deepseek_api_key",
    "openai_api_key",
    "credential",
    "credentials",
    "credential_env",
    "token",
    "access_token",
    "session_token",
    "secret",
    "api_secret",
    "authorization",
    "provider_url",
    "provider_endpoint",
    "endpoint",
    "base_url",
    "headers",
})

_RAW_SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"-----BEGIN [A-Z0-9 ]+-----"),
)


class ProviderConfigurationError(ValueError):
    """Raised when server-side provider configuration violates R02 allowlist policy."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ServerGeneratorProviderConfig(StrictGeneratorModel):
    """Server-owned non-secret configuration for instantiating a GeneratorLLMProvider."""

    provider_type: Literal["deepseek_http", "mock"] = "deepseek_http"
    model: str = Field(default=DEFAULT_DEEPSEEK_MODEL, min_length=1, max_length=128)
    endpoint: str = Field(default=DEFAULT_DEEPSEEK_ENDPOINT, min_length=1, max_length=256)
    credential_env: str = Field(default=DEFAULT_DEEPSEEK_CREDENTIAL_ENV, min_length=1, max_length=64)
    timeout_seconds: float = Field(
        default=DEFAULT_DEEPSEEK_TIMEOUT_SECONDS, gt=0.0, le=120.0, allow_inf_nan=False
    )
    thinking_mode: ThinkingMode | None = None

    @field_validator("endpoint")
    @classmethod
    def check_endpoint_allowlist(cls, value: str) -> str:
        cleaned = value.strip()
        if cleaned not in ALLOWED_DEEPSEEK_ENDPOINTS:
            raise ValueError("Provider endpoint is not in ALLOWED_DEEPSEEK_ENDPOINTS.")
        return cleaned

    @field_validator("credential_env")
    @classmethod
    def check_credential_env_allowlist(cls, value: str) -> str:
        cleaned = value.strip()
        if cleaned not in ALLOWED_DEEPSEEK_CREDENTIAL_ENVS:
            raise ValueError(
                "credential_env must be in server-owned ALLOWED_DEEPSEEK_CREDENTIAL_ENVS "
                f"({', '.join(sorted(ALLOWED_DEEPSEEK_CREDENTIAL_ENVS))})."
            )
        return cleaned


def create_server_generator_provider(
    config: ServerGeneratorProviderConfig | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    transport: httpx.BaseTransport | None = None,
    mock_provider: MockGeneratorProvider | None = None,
    allowed_credential_envs: frozenset[str] = ALLOWED_DEEPSEEK_CREDENTIAL_ENVS,
) -> GeneratorLLMProvider:
    """Create a server-controlled GeneratorLLMProvider with zero silent fallback."""
    cfg = config or ServerGeneratorProviderConfig()
    if cfg.provider_type == "mock":
        return mock_provider if mock_provider is not None else MockGeneratorProvider(mode="success")

    if cfg.credential_env not in allowed_credential_envs:
        raise ProviderConfigurationError(
            "disallowed_credential_env",
            "Configured credential environment variable is not in the server allowlist.",
        )

    try:
        http_cfg = DeepSeekHttpConfig(
            model=cfg.model,
            endpoint=cfg.endpoint,
            credential_env=cfg.credential_env,
            timeout_seconds=cfg.timeout_seconds,
            thinking_mode=cfg.thinking_mode,
        )
    except ValueError as exc:
        raise ProviderConfigurationError("invalid_provider_configuration", str(exc)) from exc

    return DeepSeekHttpProvider(config=http_cfg, transport=transport, environ=environ)


def detect_client_credential_or_endpoint_injection(payload: Any) -> str | None:
    """Iteratively detect forbidden client credential/endpoint keys or raw key values.

    Returns a static error code (never echoing the raw key or value) or None if clean.
    """
    stack: list[Any] = [payload]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, val in current.items():
                if isinstance(key, str) and key.strip().lower() in FORBIDDEN_CLIENT_REQUEST_KEYS:
                    return "client_credential_or_endpoint_forbidden"
                stack.append(val)
        elif isinstance(current, list):
            stack.extend(current)
        elif isinstance(current, str):
            for pattern in _RAW_SECRET_VALUE_PATTERNS:
                if pattern.search(current):
                    return "raw_credential_in_request_forbidden"
    return None
