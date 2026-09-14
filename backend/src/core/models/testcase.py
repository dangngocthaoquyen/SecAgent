from typing import Any
from pydantic import BaseModel, Field

class TaxonomyReference(BaseModel):
    id: str
    name: str


class TestCaseTaxonomy(BaseModel):
    owasp: list[TaxonomyReference] = Field(default_factory=list)
    mitre_atlas: list[TaxonomyReference] = Field(default_factory=list)

class ExternalReference(BaseModel):
    title: str
    url: str

class EvaluationConfig(BaseModel):
    type: str
    marker: str | None = None


class TestCase(BaseModel):
    id: str
    name: str

    category: str
    attack_type: str | None = None

    description: str | None = None
    objective: str

    taxonomy: TestCaseTaxonomy = Field(default_factory=TestCaseTaxonomy)

    references: list[ExternalReference] = Field(default_factory=list)

    attack_module: str

    payload_refs: list[str] = Field(default_factory=list)

    variables: dict[str, Any] = Field(default_factory=dict)

    evaluation: EvaluationConfig