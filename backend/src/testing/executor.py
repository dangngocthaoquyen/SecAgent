"""Validate targets, select adapters, and orchestrate execution."""

from collections.abc import Mapping

from core.models import ExecutionResult, TargetProfile, TestInput
from targets.adapters import (
    BaseTargetAdapter,
    HttpTargetAdapter,
    McpJsonRpcTargetAdapter,
    TargetAdapterError,
)
from targets.validator import TargetValidationError, validate_target


class Executor:
    """Orchestrate one target execution through an injected adapter mapping."""

    def __init__(
        self,
        adapters: Mapping[str, BaseTargetAdapter] | None = None,
    ) -> None:
        if adapters is None:
            adapters = {
                "generic_http": HttpTargetAdapter(),
                "generic_mcp_jsonrpc": McpJsonRpcTargetAdapter(),
            }
        self._adapters = dict(adapters)

    def execute(
        self,
        target: TargetProfile,
        test_input: TestInput,
    ) -> ExecutionResult:
        """Validate, select an adapter, and return its normalized result."""

        try:
            validate_target(target)
        except TargetValidationError as exc:
            return ExecutionResult(
                success=False,
                status_code=None,
                error=f"Target validation failed: {exc}",
            )

        adapter_name = target.interface.adapter
        adapter = self._adapters.get(adapter_name)
        if adapter is None:
            return ExecutionResult(
                success=False,
                status_code=None,
                error=f"No adapter available for {adapter_name!r}.",
            )

        try:
            return adapter.execute(target, test_input)
        except TargetAdapterError as exc:
            return ExecutionResult(
                success=False,
                status_code=None,
                error=f"Target adapter failed: {exc}",
            )
