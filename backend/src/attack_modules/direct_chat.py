"""Trusted delivery only; imported metadata never chooses executable behavior."""
from attack_modules.base import BaseAttackModule


class DirectChatDelivery(BaseAttackModule):
    def prepare(self, testcase, test_input):
        imported_capture = (testcase.category == "unclassified"
                            and testcase.evaluation.strategy == "unavailable")
        reviewed_response_claim = (testcase.category == "identity_privilege_abuse"
            and testcase.evaluation.strategy == "semantic"
            and testcase.evaluation.semantic is not None
            and testcase.evaluation.semantic.enabled
            and testcase.evaluation.semantic.skill == "identity_privilege_abuse"
            and testcase.evaluation.semantic.trusted_context.get("evaluation_scope") == "identity_claim_response"
            and (testcase.evaluation.semantic.trusted_context.get("asi03_contract_revision_sha256")
                 or testcase.evaluation.semantic.trusted_context.get("asi03_policy_revision_sha256")))
        reviewed_command_response = (testcase.category == "unexpected_code_execution"
            and testcase.evaluation.strategy == "semantic"
            and testcase.evaluation.semantic is not None
            and testcase.evaluation.semantic.enabled
            and testcase.evaluation.semantic.skill == "unexpected_code_execution"
            and testcase.evaluation.semantic.trusted_context.get("evaluation_scope") == "response_command_artifact"
            and testcase.evaluation.semantic.trusted_context.get("asi05_policy_revision_sha256"))
        reviewed_execution_action = (testcase.category == "unexpected_code_execution"
            and testcase.evaluation.strategy == "action"
            and testcase.evaluation.semantic is not None
            and testcase.evaluation.semantic.enabled
            and testcase.evaluation.semantic.skill == "unexpected_code_execution"
            and testcase.evaluation.semantic.trusted_context.get("evaluation_scope") == "execution_action"
            and isinstance(testcase.evaluation.semantic.trusted_context.get("asi05_execution_policy"), dict))
        if (not (imported_capture or reviewed_response_claim or reviewed_command_response
                 or reviewed_execution_action)
                or test_input.parameters or test_input.environment or test_input.file_refs or test_input.artifact_refs):
            raise ValueError("Direct chat requires an imported capture or reviewed response contract without action inputs.")
        return test_input.model_copy(deep=True)
