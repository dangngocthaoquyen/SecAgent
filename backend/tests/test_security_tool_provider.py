"""Unit tests for generic external security tool contracts."""

from integrations.security_tools import ExternalToolResult, SecurityToolProvider


class StubSecurityToolProvider(SecurityToolProvider):
    def __init__(self, result: ExternalToolResult) -> None:
        self.result = result
        self.run_count = 0

    def run(self) -> ExternalToolResult:
        self.run_count += 1
        return self.result


def test_external_tool_result_has_normalized_defaults() -> None:
    result = ExternalToolResult(tool_name="example", success=True)

    assert result.model_dump() == {
        "tool_name": "example",
        "success": True,
        "exit_code": None,
        "stdout": None,
        "stderr": None,
        "error": None,
        "artifacts": [],
        "metadata": {},
    }


def test_external_tool_result_mutable_defaults_are_isolated() -> None:
    first = ExternalToolResult(tool_name="first", success=True)
    second = ExternalToolResult(tool_name="second", success=False)

    first.artifacts.append("artifact://result.json")
    first.metadata["source"] = "stub"

    assert second.artifacts == []
    assert second.metadata == {}


def test_security_tool_provider_returns_normalized_result() -> None:
    expected = ExternalToolResult(
        tool_name="example",
        success=True,
        exit_code=0,
        stdout="completed",
        artifacts=["artifact://result.json"],
        metadata={"scan_id": "scan-001"},
    )
    provider = StubSecurityToolProvider(expected)

    result = provider.run()

    assert result is expected
    assert provider.run_count == 1
