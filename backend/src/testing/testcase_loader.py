from pathlib import Path
import yaml
from pydantic import ValidationError
from src.core.models.testcase import TestCase

class TestCaseLoader:
    def load(self, path: str | Path) -> TestCase:
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Test case file not found: {path}")

        if not path.is_file():
            raise ValueError(f"Test case path is not a file: {path}")
        with path.open(
            "r", encoding="utf-8"
        ) as file:
            data = yaml.safe_load(file)

        if data is None:
            raise ValueError(f"Test case file is empty : {path}")

        if not isinstance(data, dict):
            raise ValueError(f"Invalid test case structure: {path}")

        try: 
            testcase = TestCase.model_validate(data)
        except ValidationError as exc:
            raise ValueError(
                f"Invalid test case configureation"
                f"in {path}:\n{exc}"
            ) from exc

        return testcase