"""Generic direct MCP request and optional correlated handler observation.

This observer records only request identity, target-reported result, and an
optional collector receipt. It never promotes a receipt to an independent
effect or an agent-selected invocation.
"""

from datetime import datetime
from hashlib import sha256
import re

from core.models import Evidence, ExecutionResult, Observation
from observers.action_evidence_collector import ActionEvidenceCollector
from observers.response_observer import ResponseObserver


class McpDirectRequestObserver(ResponseObserver):
    @classmethod
    def for_target(cls, testcase, target, test_input):
        semantic = testcase.evaluation.semantic
        if (not semantic or semantic.trusted_context.get("evaluation_scope") != "execution_action"
                or target.interface.type != "mcp"
                or target.interface.adapter != "generic_mcp_jsonrpc"
                or target.interface.config.get("asi05_live_evidence") is not True):
            return None
        return cls(testcase_id=testcase.id, target_id=target.id,
                   execution_id=test_input.id, receipt_collector=None,
                   execution_scope=True)

    def __init__(self, *, testcase_id: str, target_id: str, execution_id: str,
                 receipt_collector: ActionEvidenceCollector | None = None,
                 execution_scope: bool = True):
        self.testcase_id, self.target_id, self.execution_id = testcase_id, target_id, execution_id
        self.receipt_collector, self.execution_scope = receipt_collector, execution_scope

    def observe(self, result: ExecutionResult) -> Observation:
        observation = super().observe(result)
        requests = [e for e in observation.evidence
                    if e.kind == "tool_request" and e.source == "mcp_jsonrpc_adapter"]
        if len(requests) != 1:
            observation.metadata["asi05_execution_evidence_fault"] = (
                "missing_request" if not requests else "duplicate_request")
            return observation
        request = requests[0]
        data = request.data
        stamp = data.get("observed_at")
        try:
            if not isinstance(stamp, str) or datetime.fromisoformat(stamp).tzinfo is None:
                raise ValueError
            if (not re.fullmatch(r"[a-f0-9]{32}", self.execution_id)
                    or data.get("request_id") != self.execution_id
                    or data.get("provenance") != "secagent_request"
                    or data.get("verification_status") != "request_recorded"
                    or not isinstance(request.name, str) or not request.name
                    or not re.fullmatch(r"[a-f0-9]{64}", data.get("arguments_sha256", ""))):
                raise ValueError
        except (ValueError, TypeError):
            observation.metadata["asi05_execution_evidence_fault"] = "request_identity_mismatch"
            return observation
        results = [e for e in observation.evidence
                   if e.kind == "target_tool_result" and e.source == "mcp_jsonrpc"]
        if result.success and (len(results) != 1 or results[0].name != request.name
                or results[0].data.get("request_id") != self.execution_id
                or results[0].data.get("arguments_sha256") != data["arguments_sha256"]
                or results[0].data.get("provenance") != "target_reported"):
            observation.metadata["asi05_execution_evidence_fault"] = "target_result_mismatch"
            return observation
        receipt = None
        if self.receipt_collector is not None:
            try:
                if not result.success or not isinstance(result.output_text, str):
                    raise ValueError("No validated MCP result for receipt correlation.")
                receipt = self.receipt_collector.collect(request_id=self.execution_id,
                    tool_name=request.name, arguments_sha256=data["arguments_sha256"],
                    result_sha256=sha256(result.output_text.encode()).hexdigest())
            except (ValueError, OSError):
                observation.metadata["asi05_execution_evidence_fault"] = "handler_receipt_invalid"
                return observation
            if receipt is None:
                observation.metadata["asi05_execution_evidence_fault"] = "handler_receipt_missing"
            else:
                observation.evidence.append(Evidence(kind="handler_receipt",
                    source="instrumented_handler_receipt", name=request.name,
                    success=receipt.handler_status == "succeeded",
                    reference="handler-receipt/" + receipt.invocation_id,
                    data={"testcase_id": self.testcase_id, "target_id": self.target_id,
                        "execution_id": self.execution_id, "request_id": receipt.request_id,
                        "invocation_id": receipt.invocation_id,
                        "arguments_sha256": receipt.arguments_sha256,
                        "result_sha256": receipt.result_sha256,
                        "receipt_sha256": receipt.receipt_sha256,
                        "handler_status": receipt.handler_status,
                        "provenance": receipt.provenance,
                        "source_provenance": "instrumented_target_lab",
                        "trace_completeness": receipt.trace_completeness,
                        "attribution": "direct_request", "execution_verified": False,
                        "execution_level": "simulated_execution" if receipt.handler_status != "rejected"
                            else "tool_invocation"}))
        if not self.execution_scope:
            return observation
        # Without a receipt, this ID identifies only a local request observation.
        invocation_id = sha256((self.execution_id + ":" + request.name + ":"
            + data["arguments_sha256"]).encode()).hexdigest()[:32]
        handler = receipt is not None
        if handler:
            invocation_id = receipt.invocation_id
        common = {
            "testcase_id": self.testcase_id, "target_id": self.target_id,
            "execution_id": self.execution_id, "attribution": "direct_request",
            "provenance": "instrumented_target_handler" if handler else "secagent_observed_request",
            "source_provenance": "instrumented_target_lab" if handler else "live_mcp_request",
            "correlation_status": "verified",
        }
        observation.evidence.append(Evidence(
            kind="asi05_execution_trace", source=("instrumented_handler_receipt" if handler
                else "asi05_mcp_request_observer"),
            reference="asi05-trace/" + self.execution_id,
            data={**common, "trace_completeness": "partial", "observed_action_count": 1,
                  "observed_at": stamp}))
        observation.evidence.append(Evidence(
            kind="asi05_execution_action", source=("instrumented_handler_receipt" if handler
                else "asi05_mcp_request_observer"),
            name=request.name, success=receipt.handler_status == "succeeded" if handler else False,
            reference="asi05-action/" + invocation_id,
            data={**common, "invocation_id": invocation_id,
                  "arguments_sha256": data["arguments_sha256"],
                  "evidence_type": ("simulated_execution" if handler and receipt.handler_status != "rejected"
                      else "tool_invocation"),
                  "execution_level": ("simulated_execution" if handler and receipt.handler_status != "rejected"
                      else "tool_invocation"),
                  "handler_status": receipt.handler_status if handler else "unverified",
                  "receipt_sha256": receipt.receipt_sha256 if handler else None,
                  "observed_at": stamp}))
        observation.metadata["asi05_execution_observer_verified"] = True
        return observation
