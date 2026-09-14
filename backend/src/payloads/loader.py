from pathlib import Path

import yaml

from core.models import PayloadTemplate


class PayloadLoader:
    def load_repository(self, path: str | Path) -> dict[str, PayloadTemplate]:
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Payload file not found: {path}")

        if not path.is_file():
            raise ValueError(f"Payload path is not a file: {path}")

        with path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file)

        if data is None:
            raise ValueError(f"Payload file is empty: {path}")

        if not isinstance(data, dict):
            raise ValueError(f"Invalid payload repository: {path}")

        raw_payloads = data.get("payloads", {})

        if not isinstance(raw_payloads, dict):
            raise ValueError(f"'payloads' must be a mapping: {path}")

        repository: dict[str, PayloadTemplate] = {}

        for payload_id, payload_data in raw_payloads.items():
            if not isinstance(payload_data, dict):
                raise ValueError(f"Invalid payload data for '{payload_id}': {path}")

            repository[payload_id] = PayloadTemplate.model_validate(
                {"id": payload_id, **payload_data}
            )

        return repository
