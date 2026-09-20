"""Smoke tests for checked-in target configuration files."""

from copy import deepcopy
from pathlib import Path
from typing import Any

from core.models import TestInput as CoreTestInput
from targets import load_target, validate_target
from targets.adapters import HttpTargetAdapter
from testing import Executor
from tools.http import HttpResponse


def test_dvaa_target_config_loads_and_validates_without_network() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    target = load_target(repository_root / "configs" / "targets" / "dvaa.yaml")

    validate_target(target)

    assert target.interface.adapter == "generic_http"
    assert target.credential_refs == []


class StubHttpClient:
    def __init__(self, json_body: Any) -> None:
        self.json_body = json_body
        self.requests: list[dict[str, Any]] = []

    def request(self, **kwargs: Any) -> HttpResponse:
        self.requests.append(kwargs)
        return HttpResponse(
            status_code=200,
            headers={"content-type": "application/json"},
            text="",
            json_body=self.json_body,
            duration_ms=1.0,
        )


def test_dvaa_target_config_execution_remains_credential_free() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    target = load_target(repository_root / "configs" / "targets" / "dvaa.yaml")
    client = StubHttpClient(
        {"choices": [{"message": {"content": "DVAA response"}}]}
    )

    result = HttpTargetAdapter(client).execute(
        target,
        CoreTestInput(id="input-1", prompt="SecAgent test input"),
    )

    assert client.requests[0]["headers"] == {"Content-Type": "application/json"}
    assert client.requests[0]["json_body"] == {
        "messages": [{"role": "user", "content": "SecAgent test input"}]
    }
    assert result.success is True
    assert result.output_text == "DVAA response"


def test_langflow_target_config_loads_validates_and_executes_without_network(
    monkeypatch,
) -> None:
    repository_root = Path(__file__).resolve().parents[2]
    config_path = repository_root / "configs" / "targets" / "langflow.yaml"
    config_text = config_path.read_text(encoding="utf-8")
    target = load_target(config_path)
    original_config = deepcopy(target.interface.config)
    client = StubHttpClient(
        {
            "outputs": [
                {
                    "outputs": [
                        {"results": {"message": {"text": "LANGFLOW_API_OK"}}}
                    ]
                }
            ]
        }
    )
    test_secret = "unit-test-secret"
    monkeypatch.setenv("LANGFLOW_API_KEY", test_secret)

    validate_target(target)
    result = HttpTargetAdapter(client).execute(
        target,
        CoreTestInput(id="input-1", prompt="SecAgent test input"),
    )

    assert target.interface.adapter == "generic_http"
    assert target.credential_refs == ["LANGFLOW_API_KEY"]
    assert test_secret not in config_text
    assert target.interface.config["headers"]["x-api-key"] == (
        "{{credential:LANGFLOW_API_KEY}}"
    )
    assert "session_id" not in target.interface.config["body"]
    assert client.requests[0]["headers"]["x-api-key"] == test_secret
    assert client.requests[0]["json_body"] == {
        "output_type": "chat",
        "input_type": "chat",
        "input_value": "SecAgent test input",
    }
    assert result.success is True
    assert result.output_text == "LANGFLOW_API_OK"
    assert target.interface.config == original_config


def test_langflow_target_missing_credential_returns_safe_failure(
    monkeypatch,
) -> None:
    repository_root = Path(__file__).resolve().parents[2]
    target = load_target(
        repository_root / "configs" / "targets" / "langflow.yaml"
    )
    client = StubHttpClient({})
    monkeypatch.delenv("LANGFLOW_API_KEY", raising=False)

    result = Executor(
        adapters={"generic_http": HttpTargetAdapter(client)}
    ).execute(
        target,
        CoreTestInput(id="input-1", prompt="SecAgent test input"),
    )

    assert result.success is False
    assert result.status_code is None
    assert result.error == (
        "Target adapter failed: Required credential environment variable "
        "'LANGFLOW_API_KEY' is missing or empty."
    )
    assert client.requests == []
