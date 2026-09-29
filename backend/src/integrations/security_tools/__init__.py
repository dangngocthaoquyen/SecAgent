"""Contracts for external security testing tools."""

from integrations.security_tools.base import SecurityToolProvider
from integrations.security_tools.models import ExternalToolResult

__all__ = ["ExternalToolResult", "SecurityToolProvider"]
