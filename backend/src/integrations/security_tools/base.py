"""Base contract for external security tool providers."""

from abc import ABC, abstractmethod

from integrations.security_tools.models import ExternalToolResult


class SecurityToolProvider(ABC):
    """Invoke an external security tool."""

    @abstractmethod
    def run(self) -> ExternalToolResult:
        """Run the configured security tool and return its normalized result."""
