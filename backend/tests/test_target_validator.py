"""Unit tests for target business-rule validation."""

from typing import Any

import pytest

from core.models import TargetInterface, TargetProfile
from targets.validator import TargetValidationError, validate_target


def make_target(
    *,
    interface_type: str = "http",
    adapter: str = "generic_http",
    config: dict[str, Any] | None = None,
) -> TargetProfile:
    if config is None:
        config = {
            "url": "https://example.invalid/execute",
            "method": "POST",
        }

    return TargetProfile(
        id="target-001",
        name="Example target",
        target_type="ai_agent",
        interface=TargetInterface(
            type=interface_type,
            adapter=adapter,
            config=config,
        ),
    )


def test_valid_http_target_does_not_raise() -> None:
    target = make_target(
        config={
            "url": "https://example.invalid/execute",
            "method": "Post",
            "headers": {"Content-Type": "application/json"},
        }
    )

    validate_target(target)

    assert target.interface.config["method"] == "Post"


def test_valid_mcp_jsonrpc_target_does_not_require_configured_method() -> None:
    target = make_target(
        interface_type="mcp",
        adapter="generic_mcp_jsonrpc",
        config={"url": "https://example.invalid/mcp"},
    )

    validate_target(target)


def test_mcp_interface_rejects_http_adapter() -> None:
    target = make_target(
        interface_type="mcp",
        adapter="generic_http",
        config={"url": "https://example.invalid/mcp"},
    )

    with pytest.raises(TargetValidationError, match="Unsupported target adapter"):
        validate_target(target)


def test_missing_url_raises_target_validation_error() -> None:
    target = make_target(config={"method": "POST"})

    with pytest.raises(TargetValidationError, match="non-empty string 'url'"):
        validate_target(target)


def test_empty_url_raises_target_validation_error() -> None:
    target = make_target(config={"url": "   ", "method": "POST"})

    with pytest.raises(TargetValidationError, match="non-empty string 'url'"):
        validate_target(target)


def test_missing_method_raises_target_validation_error() -> None:
    target = make_target(config={"url": "https://example.invalid/execute"})

    with pytest.raises(TargetValidationError, match="non-empty string 'method'"):
        validate_target(target)


def test_unsupported_http_method_raises_target_validation_error() -> None:
    target = make_target(
        config={"url": "https://example.invalid/execute", "method": "TRACE"}
    )

    with pytest.raises(TargetValidationError, match="Unsupported HTTP method"):
        validate_target(target)


def test_unsupported_interface_type_raises_target_validation_error() -> None:
    target = make_target(interface_type="cli")

    with pytest.raises(TargetValidationError, match="Unsupported interface type"):
        validate_target(target)


def test_unsupported_adapter_raises_target_validation_error() -> None:
    target = make_target(adapter="dvaa_http")

    with pytest.raises(TargetValidationError, match="Unsupported target adapter"):
        validate_target(target)


def test_non_mapping_headers_raise_target_validation_error() -> None:
    target = make_target(
        config={
            "url": "https://example.invalid/execute",
            "method": "POST",
            "headers": ["not", "a", "mapping"],
        }
    )

    with pytest.raises(TargetValidationError, match="headers.*mapping"):
        validate_target(target)


def test_declared_header_credential_reference_is_valid() -> None:
    target = make_target(
        config={
            "url": "https://example.invalid/execute",
            "method": "POST",
            "headers": {"Authorization": "{{credential:GENERIC_API_KEY}}"},
        }
    )
    target.credential_refs = ["GENERIC_API_KEY"]

    validate_target(target)


def test_undeclared_header_credential_reference_is_rejected() -> None:
    target = make_target(
        config={
            "url": "https://example.invalid/execute",
            "method": "POST",
            "headers": {"Authorization": "{{credential:GENERIC_API_KEY}}"},
        }
    )

    with pytest.raises(TargetValidationError, match="undeclared credential"):
        validate_target(target)
