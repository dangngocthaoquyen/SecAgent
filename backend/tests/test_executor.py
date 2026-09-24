"""Unit tests for minimal execution orchestration."""

from core.models import ExecutionResult, TargetInterface, TargetProfile
from core.models import TestInput as CoreTestInput
from targets.adapters import BaseTargetAdapter, TargetAdapterError
from testing import Executor


class StubAdapter(BaseTargetAdapter):
    def __init__(
        self,
        *,
        result: ExecutionResult | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.calls: list[tuple[TargetProfile, CoreTestInput]] = []

    def execute(
        self,
        target: TargetProfile,
        test_input: CoreTestInput,
    ) -> ExecutionResult:
        self.calls.append((target, test_input))
        if self.error is not None:
            raise self.error
        if self.result is None:
            raise AssertionError("Stub result was not configured")
        return self.result


def make_target(
    *,
    interface_type: str = "http",
    adapter: str = "generic_http",
) -> TargetProfile:
    return TargetProfile(
        id="target-001",
        name="Example target",
        target_type="service",
        interface=TargetInterface(
            type=interface_type,
            adapter=adapter,
            config={
                "url": "https://example.invalid/execute",
                "method": "POST",
            },
        ),
    )


def test_valid_target_selects_adapter_and_returns_exact_result() -> None:
    expected = ExecutionResult(
        success=True,
        status_code=200,
        output_text="Hello",
    )
    adapter = StubAdapter(result=expected)
    target = make_target()
    test_input = CoreTestInput(id="input-001", prompt="Hello")

    result = Executor(adapters={"generic_http": adapter}).execute(
        target=target,
        test_input=test_input,
    )

    assert result is expected
    assert adapter.calls == [(target, test_input)]
    assert adapter.calls[0][0] is target
    assert adapter.calls[0][1] is test_input


def test_validation_failure_returns_failed_result_without_calling_adapter() -> None:
    adapter = StubAdapter(result=ExecutionResult(success=True))

    result = Executor(adapters={"generic_http": adapter}).execute(
        target=make_target(interface_type="cli"),
        test_input=CoreTestInput(id="input-001"),
    )

    assert result.success is False
    assert result.status_code is None
    assert result.error is not None
    assert "Target validation failed" in result.error
    assert "Unsupported interface type" in result.error
    assert adapter.calls == []


def test_missing_adapter_returns_failed_result_instead_of_key_error() -> None:
    result = Executor(adapters={}).execute(
        target=make_target(),
        test_input=CoreTestInput(id="input-001"),
    )

    assert result.success is False
    assert result.status_code is None
    assert result.error == "No adapter available for 'generic_http'."


def test_target_adapter_error_is_normalized() -> None:
    adapter = StubAdapter(
        error=TargetAdapterError("request template requires a prompt")
    )

    result = Executor(adapters={"generic_http": adapter}).execute(
        target=make_target(),
        test_input=CoreTestInput(id="input-001"),
    )

    assert result.success is False
    assert result.status_code is None
    assert result.error == (
        "Target adapter failed: request template requires a prompt"
    )


def test_existing_http_failure_result_is_returned_unchanged() -> None:
    expected = ExecutionResult(
        success=False,
        status_code=503,
        raw_output={"error": "unavailable"},
        error="HTTP request returned status code 503.",
    )
    adapter = StubAdapter(result=expected)

    result = Executor(adapters={"generic_http": adapter}).execute(
        target=make_target(),
        test_input=CoreTestInput(id="input-001"),
    )

    assert result is expected
    assert result.status_code == 503
    assert result.error == "HTTP request returned status code 503."


def test_successful_adapter_result_is_returned_unchanged() -> None:
    expected = ExecutionResult(
        success=True,
        status_code=200,
        output_text="Hello",
    )

    result = Executor(
        adapters={"generic_http": StubAdapter(result=expected)}
    ).execute(
        target=make_target(),
        test_input=CoreTestInput(id="input-001"),
    )

    assert result is expected
    assert result.success is True


def test_unexpected_adapter_exception_propagates() -> None:
    adapter = StubAdapter(error=RuntimeError("programming bug"))

    try:
        Executor(adapters={"generic_http": adapter}).execute(
            target=make_target(),
            test_input=CoreTestInput(id="input-001"),
        )
    except RuntimeError as exc:
        assert str(exc) == "programming bug"
    else:
        raise AssertionError("Executor unexpectedly swallowed RuntimeError")


def test_adapter_mapping_selects_only_requested_adapter() -> None:
    selected = StubAdapter(result=ExecutionResult(success=True, status_code=200))
    unused = StubAdapter(result=ExecutionResult(success=True, status_code=201))

    result = Executor(
        adapters={
            "generic_http": selected,
            "unused_adapter": unused,
        }
    ).execute(
        target=make_target(),
        test_input=CoreTestInput(id="input-001"),
    )

    assert result.status_code == 200
    assert len(selected.calls) == 1
    assert unused.calls == []


def test_mcp_adapter_mapping_resolves_generic_mcp_jsonrpc() -> None:
    expected = ExecutionResult(success=True, status_code=200)
    adapter = StubAdapter(result=expected)

    result = Executor(
        adapters={"generic_mcp_jsonrpc": adapter}
    ).execute(
        target=make_target(
            interface_type="mcp",
            adapter="generic_mcp_jsonrpc",
        ),
        test_input=CoreTestInput(id="input-001"),
    )

    assert result is expected
    assert len(adapter.calls) == 1


def test_default_executor_registers_generic_mcp_jsonrpc_adapter() -> None:
    result = Executor().execute(
        target=make_target(
            interface_type="mcp",
            adapter="generic_mcp_jsonrpc",
        ),
        test_input=CoreTestInput(id="input-001"),
    )

    assert result.success is False
    assert result.error == (
        "Target adapter failed: MCP execution requires a "
        "'parameters.tool_call' mapping."
    )
