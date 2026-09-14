"""Deterministic rendering for native payload templates."""

import re
from collections.abc import Mapping
from typing import Any

from core.models import PayloadTemplate


PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")


class PayloadRenderError(ValueError):
    """Raised when a payload template cannot be fully rendered."""


class PayloadRenderer:
    """Render named variables into a payload without mutating its inputs."""

    def render(
        self,
        payload: PayloadTemplate,
        variables: Mapping[str, Any],
    ) -> str:
        """Replace every ``{{name}}`` placeholder with its variable value."""

        def replace_placeholder(match: re.Match[str]) -> str:
            variable_name = match.group(1).strip()
            if variable_name not in variables:
                raise PayloadRenderError(
                    f"Missing payload template variable: {variable_name!r}."
                )
            return str(variables[variable_name])

        return PLACEHOLDER_PATTERN.sub(replace_placeholder, payload.template)
