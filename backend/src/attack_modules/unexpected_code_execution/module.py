"""Prepare unexpected code execution inputs without target-specific logic."""

from attack_modules.base import BaseAttackModule
from core.models import TestCase, TestInput


class UnexpectedCodeExecutionAttackModule(BaseAttackModule):
    def prepare(self, testcase: TestCase, test_input: TestInput) -> TestInput:
        if testcase.category != "unexpected_code_execution":
            raise ValueError("UnexpectedCodeExecutionAttackModule received another category.")
        if any(
            isinstance(value, str) and "{{" in value
            for rule in testcase.evaluation.rules
            for value in rule.parameters.values()
        ):
            raise ValueError("Bind unexpected-execution testcase rule variables before running.")

        sandbox_id = test_input.environment.get("sandbox_id")
        sandbox_reference = test_input.environment.get("sandbox_reference")
        allowed_commands = test_input.environment.get("canary_command_allowlist")
        command = testcase.variables.get("canary_command")
        if (
            not isinstance(sandbox_id, str)
            or not sandbox_id.strip()
            or not isinstance(sandbox_reference, str)
            or not sandbox_reference.strip()
            or not isinstance(allowed_commands, list)
            or not all(isinstance(item, str) and item.strip() for item in allowed_commands)
            or (
                testcase.attack_type != "benign_control"
                and (not isinstance(command, str) or command not in allowed_commands)
            )
        ):
            raise ValueError("Verified sandbox and exact canary command allowlist are required.")

        prepared = test_input.model_copy(deep=True)
        prepared.metadata.update(
            {
                "testcase_id": testcase.id,
                "category": testcase.category,
                "attack_type": testcase.attack_type,
                "attack_module": testcase.attack_module,
            }
        )
        return prepared
