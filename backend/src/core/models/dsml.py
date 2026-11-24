"""Non-authoritative DSML tool-intent signal detection shared across adapters and importers."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

_DSML_FULLWIDTH_RE = re.compile(r"</?[｜|]{1,2}\s*DSML\s*[｜|]{1,2}\s*([a-zA-Z_][\w-]*)([^>]*)>")
_DSML_GENERIC_RE = re.compile(r"<[^>]*DSML[^>]*>", re.IGNORECASE)
_DSML_INVOKE_NAME_RE = re.compile(
    r"<(?:[｜|]{1,2}\s*DSML\s*[｜|]{1,2}\s*)?invoke\b[^>]*\bname\s*=\s*\"([^\"]+)\"",
    re.IGNORECASE,
)


class DsmlIntentSignal(BaseModel):
    """Non-authoritative DSML tool-intent signal parsed from response text."""

    model_config = ConfigDict(extra="forbid")

    detected: bool
    format: Literal["deepseek_dsml_fullwidth", "dsml_tag"] | None = None
    tag_count: int = 0
    invoke_count: int = 0
    invoked_tool_names: list[str] = Field(default_factory=list)
    provenance: Literal["model_reported"] = "model_reported"
    execution_verified: Literal[False] = False


def detect_dsml_intent(output_text: str) -> DsmlIntentSignal:
    """Detect DSML syntax strictly as unverified model_reported tool intent."""
    fullwidth_matches = _DSML_FULLWIDTH_RE.findall(output_text)
    generic_matches = _DSML_GENERIC_RE.findall(output_text)
    if not fullwidth_matches and not generic_matches:
        return DsmlIntentSignal(detected=False)

    invoked_tools = _DSML_INVOKE_NAME_RE.findall(output_text)
    fmt: Literal["deepseek_dsml_fullwidth", "dsml_tag"] = (
        "deepseek_dsml_fullwidth" if fullwidth_matches else "dsml_tag"
    )
    tag_count = len(fullwidth_matches) if fullwidth_matches else len(generic_matches)
    return DsmlIntentSignal(
        detected=True,
        format=fmt,
        tag_count=tag_count,
        invoke_count=len(invoked_tools),
        invoked_tool_names=invoked_tools,
        provenance="model_reported",
        execution_verified=False,
    )
