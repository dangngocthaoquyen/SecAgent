"""Unit tests for loading target YAML configuration."""

from pathlib import Path

import pytest

from targets.loader import TargetLoadError, load_target


VALID_TARGET_YAML = """
id: target-001
name: Example target
target_type: ai_agent
interface:
  type: http
  adapter: generic_http
  config:
    url: https://example.invalid/execute
    method: POST
capabilities:
  - chat
observability:
  - response
credential_refs: []
metadata:
  environment: test
"""


def write_config(tmp_path: Path, content: str) -> Path:
    config_path = tmp_path / "target.yaml"
    config_path.write_text(content, encoding="utf-8")
    return config_path


def test_load_valid_yaml_returns_target_profile(tmp_path: Path) -> None:
    target = load_target(write_config(tmp_path, VALID_TARGET_YAML))

    assert target.id == "target-001"
    assert target.interface.type == "http"
    assert target.interface.adapter == "generic_http"


def test_load_missing_file_raises_target_load_error(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.yaml"

    with pytest.raises(TargetLoadError, match="Target configuration file not found"):
        load_target(missing_path)


def test_load_invalid_yaml_syntax_raises_target_load_error(tmp_path: Path) -> None:
    config_path = write_config(tmp_path, "interface: [unterminated")

    with pytest.raises(TargetLoadError, match="Invalid YAML in target configuration"):
        load_target(config_path)


def test_load_invalid_schema_raises_target_load_error(tmp_path: Path) -> None:
    config_path = write_config(
        tmp_path,
        """
name: Missing identifier
target_type: ai_agent
interface:
  type: http
  adapter: generic_http
  config: {}
""",
    )

    with pytest.raises(TargetLoadError, match="Invalid target configuration schema"):
        load_target(config_path)


def test_load_non_mapping_yaml_root_raises_target_load_error(tmp_path: Path) -> None:
    config_path = write_config(tmp_path, "- item-one\n- item-two\n")

    with pytest.raises(TargetLoadError, match="YAML root must be a mapping/object"):
        load_target(config_path)


def test_load_unknown_target_field_raises_target_load_error(tmp_path: Path) -> None:
    config_path = write_config(
        tmp_path,
        VALID_TARGET_YAML + "\nobservabilty:\n  - traces\n",
    )

    with pytest.raises(TargetLoadError, match="Invalid target configuration schema"):
        load_target(config_path)
