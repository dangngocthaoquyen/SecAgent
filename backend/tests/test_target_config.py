"""Smoke tests for checked-in target configuration files."""

from pathlib import Path

from targets import load_target, validate_target


def test_dvaa_target_config_loads_and_validates_without_network() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    target = load_target(repository_root / "configs" / "targets" / "dvaa.yaml")

    validate_target(target)

    assert target.interface.adapter == "generic_http"
