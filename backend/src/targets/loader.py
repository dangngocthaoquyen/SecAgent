"""Load external target configuration into core domain models."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from core.models import TargetProfile


class TargetLoadError(Exception):
    """Raised when a target configuration cannot be loaded."""


def load_target(path: str | Path) -> TargetProfile:
    """Read a UTF-8 YAML file and convert it to a TargetProfile."""

    target_path = Path(path)
    if not target_path.is_file():
        raise TargetLoadError(f"Target configuration file not found: {target_path}")

    try:
        yaml_content = target_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise TargetLoadError(
            f"Unable to read target configuration as UTF-8: {target_path}"
        ) from exc

    try:
        raw_config: Any = yaml.safe_load(yaml_content)
    except yaml.YAMLError as exc:
        raise TargetLoadError(
            f"Invalid YAML in target configuration: {target_path}"
        ) from exc

    if not isinstance(raw_config, dict):
        raise TargetLoadError(
            "Invalid target configuration schema: "
            f"YAML root must be a mapping/object: {target_path}"
        )

    try:
        return TargetProfile.model_validate(raw_config)
    except ValidationError as exc:
        raise TargetLoadError(
            f"Invalid target configuration schema: {target_path}"
        ) from exc
