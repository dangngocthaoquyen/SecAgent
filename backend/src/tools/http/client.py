"""Domain-independent synchronous HTTP client."""

from dataclasses import dataclass
from time import perf_counter
from typing import Any

import httpx


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """HTTP response data safe to pass without exposing httpx.Response."""

    status_code: int
    headers: dict[str, str]
    text: str
    json_body: Any | None
    duration_ms: float


class HttpClientError(Exception):
    """Raised when an HTTP request fails before a response is received."""

    def __init__(self, message: str, *, duration_ms: float | None = None) -> None:
        super().__init__(message)
        self.duration_ms = duration_ms


class HttpClient:
    """Perform HTTP requests without target-specific behavior."""

    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        json_body: object | None = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        """Send one request and preserve responses for every HTTP status."""

        request_kwargs: dict[str, Any] = {
            "method": method,
            "url": url,
            "headers": headers,
            "json": json_body,
        }
        if timeout is not None:
            request_kwargs["timeout"] = timeout

        started_at = perf_counter()
        try:
            if self._client is not None:
                response = self._client.request(**request_kwargs)
            else:
                with httpx.Client() as client:
                    response = client.request(**request_kwargs)
        except httpx.RequestError as exc:
            duration_ms = (perf_counter() - started_at) * 1000
            raise HttpClientError(
                f"HTTP request failed for {method.upper()} {url}: {exc}",
                duration_ms=duration_ms,
            ) from exc

        duration_ms = (perf_counter() - started_at) * 1000
        try:
            json_body_value: Any | None = response.json()
        except ValueError:
            json_body_value = None

        return HttpResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            text=response.text,
            json_body=json_body_value,
            duration_ms=duration_ms,
        )
