from typing import Any

from pydantic import BaseModel, ConfigDict, Field

class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str = Field(min_length=1)
    source: str = Field(min_length=1)

    name: str | None = None
    success: bool | None = None

    data: dict[str, Any] = Field(default_factory=dict)
    reference: str | None = None