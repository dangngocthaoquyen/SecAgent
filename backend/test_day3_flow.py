from __future__ import annotations

import re
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
project_root = backend_dir.parent

if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from src.attack_modules.prompt_injection.module import (
    PromptinjectionAttackModule
)
from src.core.models.test_input import TestInput
from src.payloads.loader import PayloadLoader
from src.testing.testcase_loader import TestCaseLoader

class PayloadRenderer:
    VARIABLE_PATTERN = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")

    def render(self, template: str, variables: dict[str, object]) -> str:
        def replace_variable(match: re.Match[str]) -> str:
            variable_name = match.group(1)
            if variable_name not in variables:
                raise ValueError(f"Missing payload variable: {variable_name}")
            return str(variables[variable_name])

        return self.VARIABLE_PATTERN.sub(replace_variable, template)


def main() -> None:
    testcase_loader = TestCaseLoader()
    testcase = testcase_loader.load(
        project_root / "testcases" / "prompt_injection" / "PI-001.yaml"
    )

    payload_loader = PayloadLoader()
    payload_repository = payload_loader.load_repository(
        project_root / "payload" / "prompt_injection.yaml"
    )

    payload_id = testcase.payload_refs[0]
    payload = payload_repository.get(payload_id)
    if payload is None:
        raise KeyError(f"Payload '{payload_id}' not found in repository")

    renderer = PayloadRenderer()
    rendered_prompt = renderer.render(
        template=payload.template,
        variables=testcase.variables,
    )

    test_input = TestInput(
        id=f"{testcase.id}:{payload.id}",
        prompt=rendered_prompt,
        metadata={
            "testcase_id": testcase.id,
            "payload_id": payload.id,
            "category": testcase.category,
        },
    )

    module = PromptinjectionAttackModule()
    prepared_input = module.prepare(
        testcase=testcase,
        test_input=test_input,
    )

    print("=== TESTCASE ===")
    print(testcase.id)

    print("\n=== PAYLOAD ===")
    print(payload.id)

    print("\n=== RENDERED PROMPT ===")
    print(rendered_prompt)

    print("\n=== TEST INPUT ===")
    print(test_input.model_dump_json(indent=2))

    print("\n=== TEST INPUT AFTER MODULE ===")
    print(prepared_input.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
