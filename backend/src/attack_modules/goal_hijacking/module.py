from attack_modules.base import BaseAttackModule
from core.models import TestCase, TestInput

class GoalHijackingAttackModule(BaseAttackModule):
    def prepare(
            self,
            testcase: TestCase,
            test_input: TestInput,
    ) -> TestInput:
        if testcase.category != "goal_hijacking":
            raise ValueError("GoalHijackingAttackModule received a "
                "non-goal-hijacking testcase.")

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