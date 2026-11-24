"""Declarative models for imported custom testcase datasets."""

from typing import Any
from hashlib import sha256
import json
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator


class ImportedTestcase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    testcase_id: str = Field(min_length=1, max_length=4096)
    internal_id: str = Field(pattern=r"^import-[a-f0-9]{24}$")
    source_case: dict[str, Any]
    description: str | None = None
    plugin_id: str | None = None
    strategy_id: str | None = None
    prompt: str = Field(min_length=1, max_length=65536)
    prompt_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    @model_validator(mode="after")
    def check_prompt_hash(self):
        if sha256(self.prompt.encode("utf-8")).hexdigest() != self.prompt_sha256:
            raise ValueError("Imported prompt digest mismatch.")
        return self

    assertions: list[dict[str, Any]] = Field(default_factory=list, max_length=50)
    metadata: dict[str, Any] = Field(default_factory=dict)
    options: dict[str, Any] = Field(default_factory=dict)
    extra: dict[str, Any] = Field(default_factory=dict)
    index: int = Field(ge=0, le=1000)



class DatasetEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    name: str = Field(min_length=1, max_length=160)
    schema_version: str = "1.0"
    source_tool: str = Field(min_length=1, max_length=64)
    platform: str | None = Field(default=None, max_length=64)
    bot: str | None = Field(default=None, max_length=64)
    run_id: str | None = Field(default=None, max_length=64)
    imported_at: str
    file_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    total_testcases: int = Field(ge=1, le=100)
    testcases: list[ImportedTestcase] = Field(min_length=1, max_length=100)
    source_metadata: dict[str, Any] = Field(default_factory=dict)

    _source_bytes: bytes = PrivateAttr(default=b"")
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    def computed_content_sha256(self) -> str:
        value = self.model_dump(mode="json", exclude={"content_sha256", "imported_at", "name"})
        return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()).hexdigest()

    def to_summary(self) -> "DatasetSummary":
        has_stored = any(
            isinstance(tc.extra, dict)
            and isinstance(tc.extra.get("stored_response") or tc.extra.get("response_text"), str)
            for tc in self.testcases
        )
        modes = ["live", "offline"] if has_stored else ["live"]
        asi_counts: dict[str, int] = {}
        for tc in self.testcases:
            cat = infer_testcase_asi_code(tc, fallback_run_id=self.run_id)
            asi_counts[cat] = asi_counts.get(cat, 0) + 1
        return DatasetSummary(
            dataset_id=self.dataset_id,
            name=self.name,
            schema_version=self.schema_version,
            source_tool=self.source_tool,
            platform=self.platform,
            bot=self.bot,
            run_id=self.run_id,
            imported_at=self.imported_at,
            file_sha256=self.file_sha256,
            total_testcases=self.total_testcases,
            has_stored_responses=has_stored,
            supported_modes=modes,
            asi_breakdown=asi_counts,
        )


_PLUGIN_TO_ASI_CODE: dict[str, str] = {
    "prompt-injection": "ASI01",
    "indirect-prompt-injection": "ASI01",
    "hijacking": "ASI01",
    "goal-hijacking": "ASI01",
    "goal_hijacking": "ASI01",
    "asi01": "ASI01",
    "excessive-agency": "ASI02",
    "tool-misuse": "ASI02",
    "tool_misuse": "ASI02",
    "mcp": "ASI02",
    "asi02": "ASI02",
    "rbac": "ASI03",
    "bola": "ASI03",
    "bfla": "ASI03",
    "imitation": "ASI03",
    "identity-privilege-abuse": "ASI03",
    "identity_privilege_abuse": "ASI03",
    "asi03": "ASI03",
    "code-execution": "ASI05",
    "shell-injection": "ASI05",
    "sql-injection": "ASI05",
    "ssrf": "ASI05",
    "unexpected-code-execution": "ASI05",
    "unexpected_code_execution": "ASI05",
    "asi05": "ASI05",
}


def infer_testcase_asi_code(tc: ImportedTestcase, *, fallback_run_id: str | None = None) -> str:
    """Deterministically resolve ASI category code (ASI01/ASI02/ASI03/ASI05) or 'unmapped'."""
    meta = tc.metadata if isinstance(tc.metadata, dict) else {}
    for candidate in (
        meta.get("asi_category"),
        meta.get("category"),
        meta.get("owasp_asi"),
        tc.plugin_id,
        meta.get("pluginId"),
        fallback_run_id,
    ):
        if isinstance(candidate, str) and candidate.strip():
            key = candidate.strip().lower()
            if key.startswith("promptfoo:redteam:"):
                key = key.split(":")[-1]
            if key in _PLUGIN_TO_ASI_CODE:
                return _PLUGIN_TO_ASI_CODE[key]
            upper = candidate.strip().upper()
            if upper in {"ASI01", "ASI02", "ASI03", "ASI05"}:
                return upper
    for assertion in tc.assertions or []:
        if isinstance(assertion, dict):
            atype = assertion.get("type")
            if isinstance(atype, str) and ":" in atype:
                tail = atype.split(":")[-1].strip().lower()
                if tail in _PLUGIN_TO_ASI_CODE:
                    return _PLUGIN_TO_ASI_CODE[tail]
    return "unmapped"


class DatasetSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    name: str = Field(min_length=1, max_length=160)
    schema_version: str = "1.0"
    source_tool: str = Field(min_length=1, max_length=64)
    platform: str | None = None
    bot: str | None = None
    run_id: str | None = None
    imported_at: str
    file_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    total_testcases: int
    has_stored_responses: bool = False
    supported_modes: list[str] = Field(default_factory=lambda: ["live"])
    asi_breakdown: dict[str, int] = Field(default_factory=dict)
