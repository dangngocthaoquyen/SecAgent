from typing import Any

from pydantic import BaseModel, Field

class Observation(BaseModel):
    response_text: str
    status: int | None = None

    metadata: dict[str,Any] = Field(default_factory=dict)