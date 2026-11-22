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
        )


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
