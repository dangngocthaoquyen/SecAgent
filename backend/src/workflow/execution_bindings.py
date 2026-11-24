"""Trusted, in-process native execution bindings; YAML never supplies code.

The registry describes only reviewed runtime contracts. Native catalogue
entries without a registered executor remain selectable but ineligible.
"""

from dataclasses import dataclass
from typing import Callable

from workflow.batch import BatchCase, CaseResult


ExecutorFunction = Callable[[object, BatchCase, str, Callable[[str], None]], CaseResult]


@dataclass(frozen=True)
class NativeExecutionBinding:
    testcase_id: str
    protocol: str
    adapter_family: str
    required_capabilities: tuple[str, ...]
    evidence_contract: str
    sandbox: str | None
    prerequisites: tuple[str, ...]
    request_budget: int
    execute: ExecutorFunction
    allow_variable_request_budget: bool = False

    def __post_init__(self):
        if (not self.testcase_id or not self.protocol or not self.adapter_family
                or not self.evidence_contract or self.request_budget < 1
                or not callable(self.execute)):
            raise ValueError("Invalid trusted native execution binding.")


class ExecutionBindingRegistry:
    def __init__(self, bindings: tuple[NativeExecutionBinding, ...]):
        self._bindings = {binding.testcase_id: binding for binding in bindings}
        if not bindings or len(self._bindings) != len(bindings):
            raise ValueError("Duplicate or empty native execution registry.")

    def get(self, testcase_id: str) -> NativeExecutionBinding | None:
        return self._bindings.get(testcase_id)

    @staticmethod
    def _budget_valid(binding: NativeExecutionBinding, case: BatchCase) -> bool:
        if binding.allow_variable_request_budget:
            return 1 <= case.request_budget <= binding.request_budget
        return case.request_budget == binding.request_budget

    def execute(self, selection, case: BatchCase, execution_id: str, stage) -> CaseResult:
        binding = self.get(case.testcase_id)
        if binding is None or not self._budget_valid(binding, case):
            raise ValueError("Native execution binding is unavailable or changed.")
        return binding.execute(selection, case, execution_id, stage)

    def execute_binding(self, binding_id: str, selection, case: BatchCase, execution_id: str, stage) -> CaseResult:
        """Resolve a server-selected delivery contract independently of source IDs."""
        binding = self.get(binding_id)
        if binding is None or not self._budget_valid(binding, case):
            raise ValueError("Native delivery binding is unavailable or changed.")
        return binding.execute(selection, case, execution_id, stage)
