"""Generic adapter for configuration-driven HTTP targets."""

import os
import re
from collections.abc import Callable, Mapping
from typing import Any

from core.models import ExecutionResult, TargetProfile, TestInput
from core.models.execution import resolve_response_completeness
from core.models.tool_intent import (
    build_tool_intent_event,
    extract_structured_tool_fingerprints,
    extract_tool_intent_signals,
)
from targets.adapters.base import BaseTargetAdapter, TargetAdapterError
from targets.adapters.http_evidence import (
    extract_configured_http_response_context,
    reported_http_evidence,
    structured_http_tool_calls,
)
from targets.validator import parse_header_credential_reference
from tools.http import HttpClient, HttpClientError, HttpResponse


INPUT_PLACEHOLDER = "{{input}}"
ENV_CREDENTIAL_PATTERN = re.compile(
    r"\{\{credential:([A-Za-z_][A-Za-z0-9_]*)\}\}"
)


class _ResponsePathError(Exception):
    """Internal error raised when configured response extraction fails."""


def format_bearer_header_value(raw_secret: str) -> str:
    """Format an Authorization Bearer header value without duplicating the Bearer prefix."""
    cleaned = raw_secret.strip()
    if not cleaned:
        raise ValueError("Credential value is empty.")
    if "\r" in cleaned or "\n" in cleaned:
        raise ValueError("Credential value contains invalid control characters.")
    if re.match(r"(?i)^Bearer\s+", cleaned):
        token = re.sub(r"(?i)^Bearer\s+", "", cleaned).strip()
        if not token:
            raise ValueError("Credential value is empty.")
        return f"Bearer {token}"
    return f"Bearer {cleaned}"


class HttpTargetAdapter(BaseTargetAdapter):
    """Render configured HTTP requests and normalize their responses."""

    def __init__(self, http_client: HttpClient | None = None, *,
                 response_only_completion: bool = False,
                 credential_resolver: Callable[[str], str | None] | None = None) -> None:
        self._http_client = http_client
        self._response_only_completion = response_only_completion
        self._credential_resolver = credential_resolver

    @classmethod
    def prepare_request(
        cls,
        target: TargetProfile,
        test_input: TestInput,
        *,
        credential_resolver: Callable[[str], str | None] | None = None,
    ) -> tuple[str, str, dict[str, str] | None, Any, float | None]:
        """Resolve method, URL, headers (including credentials), rendered body, and timeout."""
        config = target.interface.config
        method = cls._required_string(config, "method")
        url = cls._required_string(config, "url")
        headers = cls._headers(
            config.get("headers"),
            target.credential_refs,
            credential_resolver=credential_resolver,
        )
        request_body = cls._render_template(config.get("body"), test_input.prompt)
        timeout = cls._timeout(config.get("timeout"))
        return method, url, headers, request_body, timeout

    def execute(
        self,
        target: TargetProfile,
        test_input: TestInput,
    ) -> ExecutionResult:
        """Execute one test input using the target's HTTP configuration."""

        config = target.interface.config
        method, url, headers, request_body, timeout = self.prepare_request(
            target,
            test_input,
            credential_resolver=self._credential_resolver,
        )

        try:
            response = (self._http_client or HttpClient(trust_env=config.get("trust_env", True))).request(
                method=method,
                url=url,
                headers=headers,
                json_body=request_body,
                timeout=timeout,
            )
        except HttpClientError as exc:
            return ExecutionResult(
                success=False,
                status_code=None,
                duration_ms=exc.duration_ms,
                error=str(exc),
            )

        return self._to_execution_result(response, config.get("response"),
                                         response_only_completion=self._response_only_completion)

    @staticmethod
    def _required_string(config: Mapping[str, Any], key: str) -> str:
        value = config.get(key)
        if not isinstance(value, str) or not value.strip():
            raise TargetAdapterError(
                f"HTTP target configuration requires a non-empty string {key!r}."
            )
        return value

    @staticmethod
    def _headers(
        value: Any,
        credential_refs: list[str],
        *,
        credential_resolver: Callable[[str], str | None] | None = None,
    ) -> dict[str, str] | None:
        if value is None:
            return None
        if not isinstance(value, Mapping):
            raise TargetAdapterError("HTTP target 'headers' must be a mapping.")
        if not all(isinstance(key, str) and isinstance(item, str) for key, item in value.items()):
            raise TargetAdapterError("HTTP target headers must contain string keys and values.")

        headers: dict[str, str] = {}
        seen_lower: set[str] = set()
        for key, item in value.items():
            low = key.lower()
            if low in seen_lower:
                raise TargetAdapterError(f"Duplicate HTTP header {key!r} (case-insensitive).")
            seen_lower.add(low)
            try:
                parsed = parse_header_credential_reference(item)
            except ValueError as exc:
                raise TargetAdapterError(str(exc)) from exc
            if parsed is None:
                headers[key] = item
                continue

            source, prefix, credential_ref = parsed
            if credential_ref not in credential_refs:
                raise TargetAdapterError(
                    f"HTTP header references undeclared credential {credential_ref!r}."
                )

            if source == "env":
                resolved_value = os.environ.get(credential_ref)
                if resolved_value is None or not resolved_value.strip():
                    raise TargetAdapterError(
                        f"Required credential environment variable {credential_ref!r} "
                        "is missing or empty."
                    )
            else:
                # Session-backed credentials resolve strictly from the explicit
                # in-memory resolver and NEVER fall back to os.environ.
                if credential_resolver is None:
                    raise TargetAdapterError(
                        f"Required session credential {credential_ref!r} is unavailable."
                    )
                try:
                    resolved_value = credential_resolver(credential_ref)
                except Exception as exc:
                    raise TargetAdapterError(
                        f"Required session credential {credential_ref!r} failed resolution: {exc}"
                    ) from exc
                if not isinstance(resolved_value, str) or not resolved_value.strip():
                    raise TargetAdapterError(
                        f"Required session credential {credential_ref!r} is missing or unavailable."
                    )

            if prefix == "Bearer ":
                try:
                    headers[key] = format_bearer_header_value(resolved_value)
                except ValueError as exc:
                    raise TargetAdapterError(
                        f"Required credential {credential_ref!r} is invalid: {exc}"
                    ) from exc
                continue
            clean_secret = resolved_value.strip() if (prefix or source == "session") else resolved_value
            if any(ord(c) < 32 or ord(c) == 127 for c in clean_secret):
                raise TargetAdapterError(
                    f"Required credential {credential_ref!r} contains invalid control characters."
                )
            headers[key] = f"{prefix}{clean_secret}"

        return headers

    @staticmethod
    def _timeout(value: Any) -> float | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise TargetAdapterError("HTTP target timeout must be a positive number.")
        return float(value)

    @classmethod
    def _render_template(cls, value: Any, input_value: str | None) -> Any:
        if isinstance(value, dict):
            return {
                key: cls._render_template(item, input_value)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._render_template(item, input_value) for item in value]
        if isinstance(value, str) and INPUT_PLACEHOLDER in value:
            if input_value is None:
                raise TargetAdapterError(
                    "TestInput.prompt is required because the request template "
                    f"contains {INPUT_PLACEHOLDER!r}."
                )
            return value.replace(INPUT_PLACEHOLDER, input_value)
        return value

    @classmethod
    def _to_execution_result(
        cls,
        response: HttpResponse,
        response_config: Any,
        *, response_only_completion: bool = False,
    ) -> ExecutionResult:
        raw_output = (
            response.json_body if response.json_body is not None else response.text
        )
        is_success = 200 <= response.status_code < 300

        if not is_success:
            return ExecutionResult(
                success=False,
                status_code=response.status_code,
                output_text=response.text or None,
                raw_output=raw_output,
                headers=response.headers,
                duration_ms=response.duration_ms,
                error=f"HTTP request returned status code {response.status_code}.",
                events=reported_http_evidence(response.json_body),
            )

        try:
            output_text = cls._extract_response_text(
                response,
                response_config,
            )
        except _ResponsePathError as exc:
            return ExecutionResult(
                success=False,
                status_code=response.status_code,
                raw_output=raw_output,
                headers=response.headers,
                duration_ms=response.duration_ms,
                error=str(exc),
                events=reported_http_evidence(response.json_body),
            )

        events = reported_http_evidence(response.json_body)
        (
            inline_events,
            target_corr_id,
            target_run_status,
            configured_status_complete,
            status_mapping_configured,
        ) = extract_configured_http_response_context(response.json_body, response_config)
        events.extend(inline_events)
        if output_text:
            structured_fps = extract_structured_tool_fingerprints(
                structured_http_tool_calls(response.json_body)
            )
            intent_signal = extract_tool_intent_signals(
                output_text,
                structured_events=events,
                structured_fingerprints=structured_fps,
            )
            if intent_signal.detected:
                response_id = (
                    response.json_body.get("id")
                    if isinstance(response.json_body, dict) and isinstance(response.json_body.get("id"), str)
                    else target_corr_id
                )
                events.append(build_tool_intent_event(intent_signal, reference=response_id))
        is_json_dict = isinstance(response.json_body, dict)
        has_choices = is_json_dict and "choices" in response.json_body
        finish_reason: str | None = None
        truncated_flag: bool | None = None
        if is_json_dict:
            if has_choices:
                choices = response.json_body.get("choices")
                if isinstance(choices, list) and bool(choices) and isinstance(choices[0], dict):
                    raw_fr = choices[0].get("finish_reason")
                    if isinstance(raw_fr, str):
                        finish_reason = raw_fr
            else:
                raw_fr = response.json_body.get("finish_reason")
                if isinstance(raw_fr, str):
                    finish_reason = raw_fr
                raw_trunc = response.json_body.get("truncated")
                if type(raw_trunc) is bool:
                    truncated_flag = raw_trunc
        resp_complete = resolve_response_completeness(
            finish_reason=finish_reason,
            body_complete=response.body_complete,
            has_output_text=output_text is not None,
            response_only_completion=response_only_completion,
            has_choices_envelope=has_choices,
            is_json_dict=is_json_dict,
            is_offline=False,
            truncated_flag=truncated_flag,
            configured_status_complete=configured_status_complete,
            status_mapping_configured=status_mapping_configured,
        )
        return ExecutionResult(
            success=True,
            status_code=response.status_code,
            output_text=output_text,
            response_complete=resp_complete,
            target_correlation_id=target_corr_id,
            target_run_status=target_run_status,
            raw_output=raw_output,
            headers=response.headers,
            duration_ms=response.duration_ms,
            error=None,
            events=events,
        )

    @classmethod
    def _extract_response_text(
        cls,
        response: HttpResponse,
        response_config: Any,
    ) -> str | None:
        if response_config is None:
            return response.text
        if not isinstance(response_config, Mapping):
            raise _ResponsePathError("HTTP response configuration must be a mapping.")

        text_path = response_config.get("text_path")
        if not isinstance(text_path, str) or not text_path.strip():
            raise _ResponsePathError(
                "HTTP response configuration requires a non-empty string 'text_path'."
            )
        if response.json_body is None:
            raise _ResponsePathError(
                f"Response text path {text_path!r} requires a JSON response body."
            )

        extracted = cls._extract_dotted_path(response.json_body, text_path)
        if extracted is not None and not isinstance(extracted, str):
            raise _ResponsePathError(
                f"Response text path {text_path!r} did not resolve to a string or null."
            )
        return extracted

    @staticmethod
    def _extract_dotted_path(data: Any, path: str) -> Any:
        current = data
        for segment in path.split("."):
            if isinstance(current, Mapping):
                if segment not in current:
                    raise _ResponsePathError(
                        f"Response text path not found: {path!r} (missing key {segment!r})."
                    )
                current = current[segment]
                continue

            if isinstance(current, list):
                try:
                    index = int(segment)
                except ValueError as exc:
                    raise _ResponsePathError(
                        f"Response text path not found: {path!r} "
                        f"({segment!r} is not a list index)."
                    ) from exc
                if index < 0 or index >= len(current):
                    raise _ResponsePathError(
                        f"Response text path not found: {path!r} "
                        f"(list index {index} is out of range)."
                    )
                current = current[index]
                continue

            raise _ResponsePathError(
                f"Response text path not found: {path!r} "
                f"(cannot traverse segment {segment!r})."
            )

        return current
