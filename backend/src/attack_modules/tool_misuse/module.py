from attack_modules.base import BaseAttackModule
from core.models import TestCase, TestInput

class ToolMisuseAttackModule(BaseAttackModule):
    def prepare(
        self,
        testcase: TestCase,
        test_input: TestInput,
    ) -> TestInput:
        if testcase.category != "tool_misuse":
            raise ValueError(
                "ToolMisuseAttackModule received a "
                "non-tool-misuse testcase"
            )

        metadata = dict(test_input.metadata)

        metadata.update({
            "testcase_id": testcase.id,
            "category": testcase.category,
            "attack_type": testcase.attack_type,
            "attack_module": testcase.attack_module
        })
        return test_input.model_copy(
            deep=True,
            update={
                "metadata": metadata
            }
        )