from typing import Any

from pydantic import BaseModel, Field


class TestInput(BaseModel):
    id: str
    prompt: str

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )