"""Unit tests for the domain-independent HTTP client."""

import json

import httpx
import pytest

from tools.http import HttpClient, HttpClientError


def test_post_json_request_uses_expected_method_url_and_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == "https://example.invalid/execute"
        assert json.loads(request.content) == {"message": "Hello"}
        return httpx.Response(200, json={"answer": "Accepted"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as raw_client:
        response = HttpClient(raw_client).request(
            method="POST",
            url="https://example.invalid/execute",
            json_body={"message": "Hello"},
        )

    assert response.status_code == 200


def test_request_sends_headers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-Test-Token"] == "test-value"
        return httpx.Response(204)

    with httpx.Client(transport=httpx.MockTransport(handler)) as raw_client:
        HttpClient(raw_client).request(
            method="GET",
            url="https://example.invalid/status",
            headers={"X-Test-Token": "test-value"},
        )


def test_json_response_is_parsed() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"data": {"answer": "Hello"}})
    )

    with httpx.Client(transport=transport) as raw_client:
        response = HttpClient(raw_client).request(
            method="GET",
            url="https://example.invalid/result",
        )

    assert response.json_body == {"data": {"answer": "Hello"}}
    assert response.text == '{"data":{"answer":"Hello"}}'
    assert response.duration_ms >= 0


def test_non_2xx_response_preserves_status_and_body() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(503, json={"error": "unavailable"})
    )

    with httpx.Client(transport=transport) as raw_client:
        response = HttpClient(raw_client).request(
            method="POST",
            url="https://example.invalid/execute",
        )

    assert response.status_code == 503
    assert response.json_body == {"error": "unavailable"}


def test_transport_error_is_wrapped() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as raw_client:
        with pytest.raises(HttpClientError, match="HTTP request failed") as error_info:
            HttpClient(raw_client).request(
                method="POST",
                url="https://example.invalid/execute",
            )

    assert isinstance(error_info.value.__cause__, httpx.ConnectError)
    assert error_info.value.duration_ms is not None


def test_timeout_is_wrapped() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("request timed out", request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as raw_client:
        with pytest.raises(HttpClientError, match="request timed out") as error_info:
            HttpClient(raw_client).request(
                method="GET",
                url="https://example.invalid/slow",
                timeout=0.1,
            )

    assert isinstance(error_info.value.__cause__, httpx.ReadTimeout)
