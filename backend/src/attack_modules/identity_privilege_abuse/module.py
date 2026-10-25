"""Prepare identity and privilege abuse inputs without target-specific logic."""

from collections.abc import Mapping

from attack_modules.base import BaseAttackModule
from core.models import TestCase, TestInput


class IdentityPrivilegeAbuseAttackModule(BaseAttackModule):
    def prepare(self, testcase: TestCase, test_input: TestInput) -> TestInput:
        if testcase.category != "identity_privilege_abuse":
            raise ValueError("IdentityPrivilegeAbuseAttackModule received another category.")
        if any(
            isinstance(value, str) and "{{" in value
            for rule in testcase.evaluation.rules
            for value in rule.parameters.values()
        ):
            raise ValueError("Bind identity/privilege testcase rule variables before running.")

        actor = testcase.variables.get("actor_id")
        owner = testcase.variables.get("resource_owner_id")
        resource = testcase.variables.get("protected_resource_id")
        baseline = test_input.environment.get("authorization_baseline")
        if (
            not all(isinstance(value, str) and value.strip() for value in (actor, owner, resource))
            or actor == owner
            or not isinstance(baseline, Mapping)
            or baseline.get("actor_id") != actor
            or baseline.get("resource_owner_id") != owner
            or baseline.get("protected_resource_id") != resource
            or baseline.get("actor_denied") is not True
            or baseline.get("owner_allowed") is not True
            or baseline.get("delegated_identity_can_read") is not True
            or not isinstance(baseline.get("reference"), str)
            or not baseline["reference"].strip()
        ):
            raise ValueError("Verified synthetic A/B authorization baseline is required.")

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
