"""Tests for normalized evidence written by the Garak smoke script."""

import json
from pathlib import Path

from integrations.security_tools import ExternalToolResult
from integrations.security_tools.smoke_summary import (
    build_smoke_summary,
    write_smoke_summary,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def make_result() -> ExternalToolResult:
    report_prefix = (
        REPOSITORY_ROOT / "results" / "smoke" / "week4" / "example"
    )
    return ExternalToolResult(
        tool_name="garak",
        success=True,
        exit_code=0,
        stdout="large noisy output with token-secret",
        stderr="large noisy progress output",
        artifacts=[str(report_prefix.with_suffix(".report.jsonl"))],
        metadata={
            "target_type": "test.Blank",
            "spec": "probes.test.Test",
            "generations": 1,
            "report_prefix": str(report_prefix),
            "command": ["garak", "--token", "token-secret"],
            "authorization": "Bearer token-secret",
            "environment": {"API_KEY": "token-secret"},
        },
    )


def test_smoke_summary_is_small_allowlisted_process_evidence() -> None:
    summary = build_smoke_summary(make_result(), REPOSITORY_ROOT)

    assert summary == {
        "tool_name": "garak",
        "success": True,
        "exit_code": 0,
        "error": None,
        "artifacts": ["results/smoke/week4/example.report.jsonl"],
        "metadata": {
            "target_type": "test.Blank",
            "spec": "probes.test.Test",
            "generations": 1,
            "report_prefix": "results/smoke/week4/example",
        },
        "success_semantics": {
            "means": "The external Garak process execution succeeded.",
            "does_not_mean": [
                "The target is secure.",
                "A vulnerability test passed.",
                "The SecAgent security verdict is PASS.",
            ],
        },
    }
    serialized = json.dumps(summary)
    assert "stdout" not in summary
    assert "stderr" not in summary
    assert "command" not in serialized
    assert "authorization" not in serialized
    assert "environment" not in serialized
    assert "token-secret" not in serialized
    assert str(REPOSITORY_ROOT) not in serialized


def test_smoke_summary_is_written_next_to_report_prefix(tmp_path: Path) -> None:
    report_prefix = tmp_path / "garak-built-in-test"

    summary_path = write_smoke_summary(
        make_result(),
        report_prefix,
        REPOSITORY_ROOT,
    )

    assert summary_path == tmp_path / "garak-built-in-test.secagent.json"
    assert json.loads(summary_path.read_text(encoding="utf-8")) == (
        build_smoke_summary(make_result(), REPOSITORY_ROOT)
    )
    assert summary_path.stat().st_size < 4096
