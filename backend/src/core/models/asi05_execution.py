"""Strict, synthetic Phase 1 ASI05 action-evidence contract.

This contract is separate from the reviewed response-command-artifact policy.
Arguments are represented only by a digest; raw arguments never enter reports.
"""

from hashlib import sha256
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.models.evaluation import EvaluationStatus


Hex32 = str
Hex64 = str
ExecutionLevel = Literal["tool_invocation", "simulated_execution", "sandbox_effect"]
Attribution = Literal["agent_selected", "direct_request"]
HandlerStatus = Literal["not_invoked", "unverified", "rejected", "failed", "succeeded"]


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ActionSignature(ClosedModel):
    tool_name: str = Field(min_length=1, max_length=128)
    arguments_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class ProhibitedAction(ActionSignature):
    minimum_level: ExecutionLevel


class Asi05ExecutionPolicy(ClosedModel):
    schema_version: Literal["1.0"] = "1.0"
    policy_id: str = Field(min_length=1, max_length=128)
    policy_version: str = Field(min_length=1, max_length=32)
    review_status: Literal["draft", "reviewed"]
    revision_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    testcase_id: str = Field(min_length=1, max_length=128)
    target_id: str = Field(min_length=1, max_length=128)
    subject: Literal["agent_run", "tool_service"]
    authorized_actions: list[ActionSignature] = Field(default_factory=list)
    prohibited_actions: list[ProhibitedAction] = Field(default_factory=list)

    @model_validator(mode="after")
    def verify_binding_and_revision(self):
        allowed = {(a.tool_name, a.arguments_sha256) for a in self.authorized_actions}
        prohibited = {(a.tool_name, a.arguments_sha256) for a in self.prohibited_actions}
        if allowed & prohibited or len(allowed) != len(self.authorized_actions) or len(prohibited) != len(self.prohibited_actions):
            raise ValueError("Execution policy action signatures conflict.")
        material = self.model_dump(exclude={"revision_sha256"})
        digest = sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if digest != self.revision_sha256:
            raise ValueError("Execution policy revision does not match its content.")
        return self


class ObservedAction(ClosedModel):
    testcase_id: str = Field(min_length=1, max_length=128)
    target_id: str = Field(min_length=1, max_length=128)
    execution_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    invocation_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    attribution: Attribution
    evidence_type: Literal["tool_invocation", "simulated_execution", "sandbox_effect"]
    execution_level: ExecutionLevel
    tool_name: str = Field(min_length=1, max_length=128)
    arguments_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    handler_status: HandlerStatus
    effect_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    evidence_reference: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def level_consistent_with_handler(self):
        if self.evidence_type != self.execution_level:
            raise ValueError("Execution evidence type and level disagree.")
        if self.execution_level == "sandbox_effect":
            if self.handler_status != "succeeded" or self.effect_sha256 is None:
                raise ValueError("Sandbox effect requires a successful handler and effect hash.")
        elif self.effect_sha256 is not None:
            raise ValueError("Non-effect evidence cannot claim an effect hash.")
        if self.execution_level == "simulated_execution" and self.handler_status not in {"succeeded", "failed"}:
            raise ValueError("Simulated execution requires an invoked handler.")
        if self.execution_level == "tool_invocation" and self.handler_status not in {"not_invoked", "unverified", "rejected"}:
            raise ValueError("Handler outcome requires simulated or effect evidence.")
        return self


class Asi05ExecutionTrace(ClosedModel):
    schema_version: Literal["1.0"] = "1.0"
    testcase_id: str = Field(min_length=1, max_length=128)
    target_id: str = Field(min_length=1, max_length=128)
    execution_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    attribution: Attribution
    source_provenance: Literal["synthetic_mock"]
    trace_complete: bool
    actions: list[ObservedAction] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def check_actions(self):
        ids = [a.invocation_id for a in self.actions]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate invocation identity.")
        for action in self.actions:
            if (action.testcase_id != self.testcase_id or action.target_id != self.target_id
                    or action.execution_id != self.execution_id or action.attribution != self.attribution):
                raise ValueError("Action identity differs from trace.")
        return self


class Asi05ExecutionRequest(ClosedModel):
    evaluation_scope: Literal["execution_action"] = "execution_action"
    testcase_id: str
    target_id: str
    execution_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    policy: Asi05ExecutionPolicy
    provenance: Literal["independent_observer", "secagent_observed_request", "instrumented_target_handler"]
    source_provenance: Literal["synthetic_mock", "live_mcp_request", "instrumented_target_lab"]
    correlation_status: Literal["verified"]
    trace_completeness: Literal["complete", "partial"]
    attribution: Attribution
    actions: list[ObservedAction]
    evidence_references: list[str]


class Asi05ExecutionDecision(ClosedModel):
    evaluation_scope: Literal["execution_action"] = "execution_action"
    testcase_id: str
    target_id: str
    execution_id: str | None = None
    policy_id: str | None = None
    policy_revision_sha256: str | None = None
    verdict: EvaluationStatus
    rationale: str
    evidence_level: Literal["response_artifact", "tool_invocation", "simulated_execution", "sandbox_effect", "missing_evidence", "uncorrelated_evidence"]
    provenance: str | None = None
    correlation_status: str
    trace_completeness: str
    attribution: str | None = None
    policy_violation: bool | None = None
    evidence_references: list[str] = Field(default_factory=list)
    unsupported_execution_claims: list[str] = Field(default_factory=list)
