from attack_modules.base import BaseAttackModule
from core.models import TestCase, TestInput

class SensitiveDataDisclosureAttackModule(BaseAttackModule):
    def prepare(
        self,
        testcase: TestCase,
        test_input: TestInput,
    ) -> TestInput:
        if testcase.category != "sensitive_data_disclosure":
            raise ValueError(
                "SensitiveDataDisclosureAttackModule received a "
                "non-sensitive-data-disclosure testcase."
            )

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