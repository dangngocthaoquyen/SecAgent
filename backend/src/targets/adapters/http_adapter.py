"""Generic adapter for configuration-driven HTTP targets."""

from collections.abc import Mapping
from typing import Any

from core.models import ExecutionResult, TargetProfile, TestInput
from targets.adapters.base import BaseTargetAdapter
from tools.http import HttpClient, HttpClientError, HttpResponse


INPUT_PLACEHOLDER = "{{input}}"


class TargetAdapterError(Exception):
    """Raised when target configuration cannot produce a valid request."""


class _ResponsePathError(Exception):
    """Internal error raised when configured response extraction fails."""


class HttpTargetAdapter(BaseTargetAdapter):
    """Render configured HTTP requests and normalize their responses."""

    def __init__(self, http_client: HttpClient | None = None) -> None:
        self._http_client = http_client or HttpClient()

    def execute(
        self,
        target: TargetProfile,
        test_input: TestInput,
    ) -> ExecutionResult:
        """Execute one test input using the target's HTTP configuration."""

        config = target.interface.config
        method = self._required_string(config, "method")
        url = self._required_string(config, "url")
        headers = self._headers(config.get("headers"))
        request_body = self._render_template(config.get("body"), test_input.prompt)
        timeout = self._timeout(config.get("timeout"))

        try:
            response = self._http_client.request(
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

        return self._to_execution_result(response, config.get("response"))

    @staticmethod
    def _required_string(config: Mapping[str, Any], key: str) -> str:
        value = config.get(key)
        if not isinstance(value, str) or not value.strip():
            raise TargetAdapterError(
                f"HTTP target configuration requires a non-empty string {key!r}."
            )
        return value

    @staticmethod
    def _headers(value: Any) -> dict[str, str] | None:
        if value is None:
            return None
        if not isinstance(value, Mapping):
            raise TargetAdapterError("HTTP target 'headers' must be a mapping.")
        if not all(isinstance(key, str) and isinstance(item, str) for key, item in value.items()):
            raise TargetAdapterError("HTTP target headers must contain string keys and values.")
        return dict(value)

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
            )

        return ExecutionResult(
            success=True,
            status_code=response.status_code,
            output_text=output_text,
            raw_output=raw_output,
            headers=response.headers,
            duration_ms=response.duration_ms,
            error=None,
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
