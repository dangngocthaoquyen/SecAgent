"""Unit tests for the Garak CLI security tool provider."""

import subprocess
from pathlib import Path
from typing import Any

import pytest

from integrations.security_tools import GarakProvider, GarakRunConfig


def make_config(**overrides: Any) -> GarakRunConfig:
    values = {
        "target_type": "test.Blank",
        "spec": "probes.test.Test",
        "generations": 2,
        "timeout_seconds": 15.0,
    }
    values.update(overrides)
    return GarakRunConfig.model_validate(values)


def test_successful_process_is_normalized_and_uses_argument_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            command,
            returncode=0,
            stdout="scan completed",
            stderr="diagnostic output",
        )

    monkeypatch.setattr(
        "integrations.security_tools.garak.subprocess.run",
        fake_run,
    )
    provider = GarakProvider(
        executable="garak-custom",
        config=make_config(),
    )

    result = provider.run()

    assert captured["command"] == [
        "garak-custom",
        "--target_type",
        "test.Blank",
        "--spec",
        "probes.test.Test",
        "--generations",
        "2",
    ]
    assert isinstance(captured["command"], list)
    assert captured["kwargs"] == {
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": 15.0,
        "check": False,
        "shell": False,
    }
    assert result.tool_name == "garak"
    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout == "scan completed"
    assert result.stderr == "diagnostic output"
    assert result.error is None
    assert result.metadata == {
        "target_type": "test.Blank",
        "spec": "probes.test.Test",
        "generations": 2,
        "report_prefix": None,
    }
    assert "command" not in result.metadata
    assert "executable" not in result.metadata


def test_nonzero_exit_is_normalized_as_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            returncode=2,
            stdout="partial output",
            stderr="invalid configuration",
        )

    monkeypatch.setattr(
        "integrations.security_tools.garak.subprocess.run",
        fake_run,
    )

    result = GarakProvider(executable="garak", config=make_config()).run()

    assert result.success is False
    assert result.exit_code == 2
    assert result.stdout == "partial output"
    assert result.stderr == "invalid configuration"
    assert result.error == "Garak exited with code 2."


def test_missing_executable_is_normalized_as_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError

    monkeypatch.setattr(
        "integrations.security_tools.garak.subprocess.run",
        fake_run,
    )

    result = GarakProvider(
        executable="missing-garak",
        config=make_config(),
    ).run()

    assert result.success is False
    assert result.exit_code is None
    assert result.stdout is None
    assert result.stderr is None
    assert result.error == "Garak executable not found: missing-garak"


def test_timeout_is_normalized_with_partial_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(
            command,
            timeout=15.0,
            output=b"partial output",
            stderr=b"partial error",
        )

    monkeypatch.setattr(
        "integrations.security_tools.garak.subprocess.run",
        fake_run,
    )

    result = GarakProvider(executable="garak", config=make_config()).run()

    assert result.success is False
    assert result.exit_code is None
    assert result.stdout == "partial output"
    assert result.stderr == "partial error"
    assert result.error == "Garak execution timed out after 15.0 seconds."


def test_report_artifacts_are_discovered_only_for_configured_prefix(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_prefix = tmp_path / "garak-poc"
    expected_artifact = tmp_path / "garak-poc.report.jsonl"
    unrelated_artifact = tmp_path / "other.report.jsonl"
    unrelated_artifact.write_text("unrelated", encoding="utf-8")

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        expected_artifact.write_text("report", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="done", stderr="")

    monkeypatch.setattr(
        "integrations.security_tools.garak.subprocess.run",
        fake_run,
    )
    provider = GarakProvider(
        executable="garak",
        config=make_config(report_prefix=str(report_prefix)),
    )

    result = provider.run()

    assert result.success is True
    assert result.artifacts == [str(expected_artifact.resolve())]
    assert str(unrelated_artifact.resolve()) not in result.artifacts
