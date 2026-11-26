"""Execution authorization policy and grant models (deny-by-default)."""

from hashlib import sha256
import json
from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from workflow.models import ClosedModel, Identifier


class ExecutionGrant(ClosedModel):
    authorization_id: Identifier | None = None
    target_id: Identifier
    profile_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_ref: Identifier
    testcase_id: Identifier
    asset_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    scope: Literal["security_test_execution"]
    expires_at: AwareDatetime = Field(strict=False)


class AdmissionPolicy(ClosedModel):
    revision: Identifier = "deny-by-default"
    grants: list[ExecutionGrant] = Field(default_factory=list, max_length=20)
    max_testcases: int = Field(default=1, ge=1, le=1)
    max_target_requests: int = Field(default=1, ge=1, le=1)
    max_timeout_seconds: int = Field(default=30, ge=1, le=60)

    @model_validator(mode="after")
    def unique_authorizations(self):
        ids = [g.authorization_id for g in self.grants if g.authorization_id is not None]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate execution authorization identity.")
        return self


def digest(value) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
