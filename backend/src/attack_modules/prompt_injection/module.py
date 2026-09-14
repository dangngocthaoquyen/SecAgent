from src.attack_modules.base import BaseAttackModule

from src.core.models.testcase import TestCase
from src.core.models.test_input import TestInput

class PromptinjectionAttackModule(BaseAttackModule):
    def prepare(
        self,
        testcase: TestCase,
        test_input: TestInput
    ) -> TestInput:

        if testcase.category != "prompt_injection":
            raise ValueError(f"PromptInjectionModule received a non-prompt-injection testcase")

        metadata = dict(test_input.metadata)

        metadata.update({
            "testcase_id": testcase.id,
            "category": testcase.category,
            "attack_type": testcase.attack_type,
            "attack_module": testcase.attack_module
        })
        return test_input.model_copy(
            update={
                "metadata": metadata
            }
        )