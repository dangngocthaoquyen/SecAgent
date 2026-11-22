"""Build a validated, deterministic ASI05 execution request from trusted evidence."""

import re

from core.models import Observation, TestCase
from core.models.asi05_execution import (
    Asi05ExecutionPolicy, Asi05ExecutionRequest, ObservedAction,
)


class ExecutionEvidenceRejected(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def build_execution_request(testcase: TestCase, observation: Observation) -> Asi05ExecutionRequest:
    semantic = testcase.evaluation.semantic
    if (testcase.category != "unexpected_code_execution"
            or testcase.evaluation.strategy != "action"
            or testcase.evaluation.rules
            or semantic is None or not semantic.enabled
            or semantic.skill != testcase.category
            or semantic.trusted_context.get("evaluation_scope") != "execution_action"):
        raise ExecutionEvidenceRejected("execution_contract_unavailable")
    try:
        policy = Asi05ExecutionPolicy.model_validate(
            semantic.trusted_context["asi05_execution_policy"])
    except (KeyError, ValueError, TypeError):
        raise ExecutionEvidenceRejected("execution_policy_invalid") from None
    if policy.testcase_id != testcase.id:
        raise ExecutionEvidenceRejected("execution_policy_binding_mismatch")
    execution_id = testcase.variables.get("asi05_execution_id")
    if not isinstance(execution_id, str) or not re.fullmatch(r"[a-f0-9]{32}", execution_id):
        raise ExecutionEvidenceRejected("execution_identity_missing")
    if (observation.metadata.get("secagent_testcase_id") != testcase.id
            or observation.metadata.get("secagent_target_id") != policy.target_id
            or observation.metadata.get("secagent_execution_id") != execution_id):
        raise ExecutionEvidenceRejected("runner_identity_mismatch")
    if observation.metadata.get("asi05_execution_evidence_fault"):
        raise ExecutionEvidenceRejected(str(observation.metadata["asi05_execution_evidence_fault"]))
    if observation.metadata.get("asi05_execution_observer_verified") is not True:
        raise ExecutionEvidenceRejected("trusted_observer_missing")
    if observation.metadata.get("execution_success") is not True:
        raise ExecutionEvidenceRejected("target_transport_unavailable")
    traces = [e for e in observation.evidence if e.kind == "asi05_execution_trace"]
    action_events = [e for e in observation.evidence if e.kind == "asi05_execution_action"]
    if len(traces) != 1:
        raise ExecutionEvidenceRejected("missing_trace" if not traces else "duplicate_trace")
    trace = traces[0]
    data = trace.data
    if trace.source == "asi05_execution_fixture":
        provenance, source_provenance = "independent_observer", "synthetic_mock"
    elif trace.source == "asi05_mcp_request_observer":
        provenance, source_provenance = "secagent_observed_request", "live_mcp_request"
    elif trace.source == "instrumented_handler_receipt":
        provenance, source_provenance = "instrumented_target_handler", "instrumented_target_lab"
    else:
        raise ExecutionEvidenceRejected("untrusted_trace_source")
    common = {
        "testcase_id": testcase.id, "target_id": policy.target_id,
        "execution_id": execution_id, "provenance": provenance,
        "source_provenance": source_provenance,
        "correlation_status": "verified",
    }
    if (any(data.get(key) != value for key, value in common.items())
            or (trace.source == "asi05_execution_fixture") != (data.get("synthetic_mock") is True)
            or trace.reference != "asi05-trace/" + execution_id
            or data.get("trace_completeness") not in {"complete", "partial"}
            or (trace.source in {"asi05_mcp_request_observer", "instrumented_handler_receipt"}
                and data.get("trace_completeness") != "partial")
            or (trace.source == "instrumented_handler_receipt"
                and data.get("attribution") != "direct_request")
            or data.get("attribution") not in {"agent_selected", "direct_request"}
            or type(data.get("observed_action_count")) is not int
            or data["observed_action_count"] != len(action_events)):
        raise ExecutionEvidenceRejected("uncorrelated_trace")
    attribution = data["attribution"]
    if (policy.subject == "agent_run" and attribution != "agent_selected"
            or policy.subject == "tool_service" and attribution != "direct_request"):
        raise ExecutionEvidenceRejected("attribution_mismatch")
    actions = []
    for event in action_events:
        row = event.data
        if (event.source != trace.source
                or any(row.get(key) != value for key, value in common.items())
                or (trace.source == "asi05_execution_fixture") != (row.get("synthetic_mock") is True)
                or row.get("attribution") != attribution
                or event.reference is None
                or event.name != row.get("tool_name") and "tool_name" in row):
            raise ExecutionEvidenceRejected("uncorrelated_action")
        try:
            action = ObservedAction.model_validate({
                "testcase_id": row.get("testcase_id"),
                "target_id": row.get("target_id"),
                "execution_id": row.get("execution_id"),
                "invocation_id": row.get("invocation_id"),
                "attribution": row.get("attribution"),
                "evidence_type": row.get("evidence_type"),
                "execution_level": row.get("execution_level"),
                "tool_name": event.name,
                "arguments_sha256": row.get("arguments_sha256"),
                "handler_status": row.get("handler_status"),
                "effect_sha256": row.get("effect_sha256"),
                "evidence_reference": event.reference,
            })
        except (ValueError, TypeError):
            raise ExecutionEvidenceRejected("invalid_action_evidence") from None
        if (action.evidence_reference != "asi05-action/" + action.invocation_id
                or event.success is not (action.handler_status == "succeeded")):
            raise ExecutionEvidenceRejected("action_status_mismatch")
        if (trace.source == "asi05_mcp_request_observer" and
                (attribution != "direct_request" or action.execution_level != "tool_invocation"
                 or action.handler_status != "unverified" or action.effect_sha256 is not None)):
            raise ExecutionEvidenceRejected("unsupported_live_execution_claim")
        if trace.source == "instrumented_handler_receipt":
            receipts = [e for e in observation.evidence if e.kind == "handler_receipt"
                and e.source == "instrumented_handler_receipt"]
            matching = [e for e in receipts if e.name == action.tool_name
                and e.data.get("testcase_id") == testcase.id
                and e.data.get("target_id") == policy.target_id
                and e.data.get("execution_id") == execution_id
                and e.data.get("request_id") == execution_id
                and e.data.get("invocation_id") == action.invocation_id
                and e.data.get("arguments_sha256") == action.arguments_sha256
                and e.data.get("handler_status") == action.handler_status
                and e.data.get("provenance") == "instrumented_target_handler"
                and e.data.get("source_provenance") == "instrumented_target_lab"
                and e.data.get("trace_completeness") == "partial"
                and e.data.get("attribution") == "direct_request"
                and e.data.get("execution_verified") is False
                and e.data.get("receipt_sha256") == row.get("receipt_sha256")
                and e.reference == "handler-receipt/" + action.invocation_id]
            if (len(receipts) != 1 or len(matching) != 1
                    or action.effect_sha256 is not None
                    or action.execution_level != ("tool_invocation" if action.handler_status == "rejected"
                        else "simulated_execution")):
                raise ExecutionEvidenceRejected("handler_receipt_mismatch")
        actions.append(action)
    if len({a.invocation_id for a in actions}) != len(actions):
        raise ExecutionEvidenceRejected("duplicate_invocation")
    if attribution == "direct_request":
        outbound = [e for e in observation.evidence
                    if e.kind == "tool_request" and e.source == "mcp_jsonrpc_adapter"
                    and e.data.get("provenance") == "secagent_request"]
        if len(outbound) != len(actions) or any(
                not any(request.name == action.tool_name
                        and request.data.get("request_id") == execution_id
                        and request.data.get("arguments_sha256") == action.arguments_sha256
                        for request in outbound)
                for action in actions):
            raise ExecutionEvidenceRejected("direct_request_mismatch")
    try:
        return Asi05ExecutionRequest(
            testcase_id=testcase.id, target_id=policy.target_id, execution_id=execution_id,
            policy=policy, provenance=provenance,
            source_provenance=source_provenance, correlation_status="verified",
            trace_completeness=data["trace_completeness"], attribution=attribution,
            actions=actions,
            evidence_references=[trace.reference] + [a.evidence_reference for a in actions]
                + (["handler-receipt/" + actions[0].invocation_id]
                   if trace.source == "instrumented_handler_receipt" and len(actions) == 1 else []),
        )
    except (ValueError, TypeError):
        raise ExecutionEvidenceRejected("invalid_evaluation_request") from None
