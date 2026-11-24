"""Business-rule validation for target profiles."""

import re
from collections.abc import Mapping

from core.models import TargetProfile


SUPPORTED_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
SUPPORTED_INTERFACE_ADAPTERS = {
    "http": "generic_http",
    "mcp": "generic_mcp_jsonrpc",
    "agent": "mcp_agent_runtime",
    "offline": "offline_stored",
}
ENV_CREDENTIAL_PATTERN = re.compile(
    r"\{\{credential:([A-Za-z_][A-Za-z0-9_]*)\}\}"
)
HEADER_CREDENTIAL_PATTERN = re.compile(
    r"^(?:(Bearer )?\{\{credential:([A-Za-z_][A-Za-z0-9_]*)\}\})$"
)


def parse_header_credential_placeholder(value: str) -> tuple[str, str] | None:
    """Parse strictly allowed header credential templates:

    - ``{{credential:ENV_NAME}}`` -> ``("", "ENV_NAME")``
    - ``Bearer {{credential:ENV_NAME}}`` -> ``("Bearer ", "ENV_NAME")``

    Any other string containing ``{{`` or ``}}`` is rejected fail-closed so
    arbitrary template interpolation in headers is never permitted.
    """
    match = HEADER_CREDENTIAL_PATTERN.fullmatch(value)
    if match is not None:
        return (match.group(1) or "", match.group(2))
    if "{{" in value or "}}" in value:
        raise ValueError(
            "HTTP header contains an unsupported credential placeholder format. "
            "Only '{{credential:ENV_NAME}}' or 'Bearer {{credential:ENV_NAME}}' is allowed."
        )
    return None


class TargetValidationError(Exception):
    """Raised when a target is unsupported or operationally incomplete."""


def validate_target(target: TargetProfile) -> None:
    """Validate the target against the framework capabilities available today."""

    interface = target.interface

    expected_adapter = SUPPORTED_INTERFACE_ADAPTERS.get(interface.type)
    if expected_adapter is None:
        supported_types = ", ".join(sorted(SUPPORTED_INTERFACE_ADAPTERS))
        raise TargetValidationError(
            f"Unsupported interface type: {interface.type!r}. "
            f"Supported interface types: {supported_types}."
        )

    if interface.adapter != expected_adapter:
        raise TargetValidationError(
            f"Unsupported target adapter: {interface.adapter!r}. "
            f"Supported adapter for {interface.type!r}: {expected_adapter!r}."
        )

    url = interface.config.get("url")
    if interface.type != "offline" and (not isinstance(url, str) or not url.strip()):
        raise TargetValidationError(
            "HTTP target configuration requires a non-empty string 'url'."
        )

    if interface.type == "http":
        method = interface.config.get("method")
        if not isinstance(method, str) or not method.strip():
            raise TargetValidationError(
                "HTTP target configuration requires a non-empty string 'method'."
            )

        normalized_method = method.strip().upper()
        if normalized_method not in SUPPORTED_HTTP_METHODS:
            supported_methods = ", ".join(sorted(SUPPORTED_HTTP_METHODS))
            raise TargetValidationError(
                f"Unsupported HTTP method: {method!r}. "
                f"Supported methods: {supported_methods}."
            )

    if "headers" in interface.config:
        headers = interface.config["headers"]
        if not isinstance(headers, Mapping):
            raise TargetValidationError("HTTP target 'headers' must be a mapping.")
        if not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in headers.items()
        ):
            raise TargetValidationError(
                "HTTP target headers must contain string keys and values."
            )

        for value in headers.values():
            try:
                parsed = parse_header_credential_placeholder(value)
            except ValueError as exc:
                raise TargetValidationError(str(exc)) from exc
            if parsed is None:
                continue
            _, credential_ref = parsed
            if credential_ref not in target.credential_refs:
                raise TargetValidationError(
                    f"HTTP header references undeclared credential {credential_ref!r}."
                )
