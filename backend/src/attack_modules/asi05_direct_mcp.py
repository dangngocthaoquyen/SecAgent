"""Prepare a policy-bound, direct MCP ASI05 tool-service request."""

from hashlib import sha256
import json
from collections.abc import Mapping

from attack_modules.base import BaseAttackModule
from core.models.asi05_execution import Asi05ExecutionPolicy


class Asi05DirectMcpDelivery(BaseAttackModule):
    def prepare(self, testcase, test_input):
        semantic = testcase.evaluation.semantic
        if (testcase.category != "unexpected_code_execution"
                or testcase.evaluation.strategy != "action"
                or semantic is None or not semantic.enabled
                or semantic.trusted_context.get("evaluation_scope") != "execution_action"
                or test_input.id != testcase.variables.get("asi05_execution_id")):
            raise ValueError("ASI05 direct MCP execution contract is unavailable.")
        policy = Asi05ExecutionPolicy.model_validate(
            semantic.trusted_context.get("asi05_execution_policy"))
        call = test_input.parameters.get("tool_call")
        if (policy.subject != "tool_service" or not isinstance(call, Mapping)
                or set(test_input.parameters) != {"tool_call"}
                or not isinstance(call.get("name"), str)
                or not isinstance(call.get("arguments"), Mapping)):
            raise ValueError("ASI05 direct MCP input requires one bound tool call.")
        digest = sha256(json.dumps(call["arguments"], sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        signature = (call["name"], digest)
        reviewed = {(a.tool_name, a.arguments_sha256) for a in
            [*policy.authorized_actions, *policy.prohibited_actions]}
        if policy.testcase_id != testcase.id or signature not in reviewed:
            raise ValueError("ASI05 direct MCP call is not bound to the reviewed policy.")
        return test_input.model_copy(deep=True)
