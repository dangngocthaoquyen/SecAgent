"""Trusted SecAgent-side observer for bounded McpAgentRuntime traces.

Distinguishes model intent (`agent_tool_intent`), SecAgent MCP dispatch
(`secagent_mcp_request`), target response (`target_mcp_response`), and
optional correlated handler receipts (`ActionEvidenceCollector`).

Never infers tool execution from assistant text, never trusts forged
target events, and never auto-promotes `tool_invocation` to `simulated_execution`
or `sandbox_effect`.
"""

from __future__ import annotations

from collections.abc import Collection
from datetime import datetime
from hashlib import sha256
import json
import re
from typing import Any

from core.models import Evidence, ExecutionResult, Observation
from observers.action_evidence_collector import ActionEvidenceCollector, HandlerReceipt
from observers.response_observer import ResponseObserver

HEX32 = re.compile(r"^[a-f0-9]{32}$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
AGENT_EVENT_KINDS = frozenset({
    "agent_tool_intent",
    "secagent_mcp_request",
    "target_mcp_response",
    "rejected_tool_call",
})
EXPECTED_PROVENANCE = {
    "agent_tool_intent": "model_reported",
    "secagent_mcp_request": "secagent_request",
    "target_mcp_response": "target_reported",
    "rejected_tool_call": "secagent_policy",
}


class McpAgentExecutionObserver(ResponseObserver):
    """Correlate SecAgent-observed agent_run runtime traces and optional receipts."""

    def __init__(
        self,
        *,
        testcase_id: str,
        target_id: str,
        execution_id: str,
        expected_tool_names: Collection[str],
        receipt_collector: ActionEvidenceCollector | None = None,
        execution_scope: bool = True,
    ) -> None:
        if not HEX32.fullmatch(execution_id):
            raise ValueError("Invalid agent execution identity.")
        if not expected_tool_names:
            raise ValueError("McpAgentExecutionObserver requires reviewed tool names.")
        self.testcase_id = testcase_id
        self.target_id = target_id
        self.execution_id = execution_id
        self.expected_tool_names = frozenset(expected_tool_names)
        self.receipt_collector = receipt_collector
        self.execution_scope = execution_scope

    @staticmethod
    def _fault(observation: Observation, code: str) -> Observation:
        observation.metadata["asi05_execution_evidence_fault"] = code
        return observation

    @staticmethod
    def _valid_timestamp(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return None
        return value

    def _validate_receipt(
        self,
        receipt: HandlerReceipt,
        *,
        invocation_id: str,
        tool_name: str,
        arguments_sha256: str,
        result_sha256: str,
    ) -> bool:
        return (
            isinstance(receipt, HandlerReceipt)
            and receipt.request_id == invocation_id
            and receipt.execution_id == self.execution_id
            and receipt.invocation_id == invocation_id
            and receipt.target_id == self.target_id
            and receipt.tool_name == tool_name
            and receipt.arguments_sha256 == arguments_sha256
            and receipt.result_sha256 == result_sha256
            and receipt.handler_status in {"succeeded", "failed", "rejected"}
            and receipt.provenance == "instrumented_target_handler"
            and receipt.trace_completeness in {"partial", "complete"}
            and bool(HEX64.fullmatch(receipt.receipt_sha256))
        )

    def observe(self, result: ExecutionResult) -> Observation:
        observation = super().observe(result)

        # Reject any pre-injected observer or handler evidence in raw events.
        if any(
            item.kind in {"asi05_execution_trace", "asi05_execution_action", "handler_receipt"}
            or item.source in {"asi05_agent_mcp_observer", "asi05_mcp_request_observer",
                               "asi05_execution_fixture", "instrumented_handler_receipt"}
            for item in observation.evidence
        ):
            return self._fault(observation, "forged_observer_evidence")

        raw_record = (
            result.raw_output.get("agent_runtime_result")
            if isinstance(result.raw_output, dict)
            else None
        )
        if raw_record is not None:
            if (
                not isinstance(raw_record, dict)
                or raw_record.get("llm_target_id") != self.target_id
                or raw_record.get("subject") != "agent_run"
                or raw_record.get("attribution") != "agent_selected"
                or not isinstance(raw_record.get("run_id"), str)
            ):
                return self._fault(observation, "agent_identity_mismatch")

        agent_events = [
            item for item in observation.evidence
            if item.kind in AGENT_EVENT_KINDS or item.source == "mcp_agent_runtime"
        ]
        # Any non-empty unknown evidence alongside agent events must not silently slip through.
        if any(item.kind not in AGENT_EVENT_KINDS or item.source != "mcp_agent_runtime" for item in agent_events):
            return self._fault(observation, "invalid_agent_event")

        intents: dict[tuple[str, int], Evidence] = {}
        dispatched_requests: list[Evidence] = []
        dispatched_by_invocation: dict[str, Evidence] = {}
        responses_by_invocation: dict[str, Evidence] = {}
        seen_seq: set[int] = set()
        latest_stamp: str | None = None

        for ev in agent_events:
            data = ev.data
            if (
                data.get("execution_id") != self.execution_id
                or data.get("execution_verified") is not False
                or data.get("subject") != "agent_run"
                or data.get("attribution") != "agent_selected"
                or data.get("provenance") != EXPECTED_PROVENANCE.get(ev.kind)
            ):
                return self._fault(observation, "invalid_provenance")
            seq = data.get("sequence_index")
            model_idx = data.get("model_call_index")
            if type(seq) is not int or seq < 0 or seq in seen_seq or type(model_idx) is not int or model_idx < 1:
                return self._fault(observation, "invalid_trace_sequence")
            seen_seq.add(seq)
            stamp = self._valid_timestamp(data.get("timestamp"))
            if stamp is None:
                return self._fault(observation, "invalid_timestamp")
            latest_stamp = stamp

            if ev.kind == "agent_tool_intent":
                call_id = data.get("tool_call_id")
                if isinstance(call_id, str) and call_id:
                    intents[(call_id, model_idx)] = ev
            elif ev.kind == "secagent_mcp_request":
                inv_id = data.get("invocation_id")
                call_id = data.get("tool_call_id")
                arg_hash = data.get("arguments_sha256")
                if (
                    not isinstance(inv_id, str) or not HEX32.fullmatch(inv_id)
                    or not isinstance(call_id, str) or not call_id
                    or not isinstance(ev.name, str) or ev.name not in self.expected_tool_names
                    or not isinstance(arg_hash, str) or not HEX64.fullmatch(arg_hash)
                    or data.get("request_status") != "dispatched"
                ):
                    return self._fault(observation, "request_identity_mismatch")
                if inv_id in dispatched_by_invocation:
                    return self._fault(observation, "duplicate_invocation")
                intent = intents.get((call_id, model_idx))
                if (
                    intent is None
                    or intent.name != ev.name
                    or intent.data.get("sequence_index", seq) >= seq
                ):
                    return self._fault(observation, "missing_tool_intent")
                dispatched_by_invocation[inv_id] = ev
                dispatched_requests.append(ev)
            elif ev.kind == "target_mcp_response":
                inv_id = data.get("invocation_id")
                call_id = data.get("tool_call_id")
                arg_hash = data.get("arguments_sha256")
                if not isinstance(inv_id, str) or inv_id not in dispatched_by_invocation:
                    return self._fault(observation, "missing_request")
                if inv_id in responses_by_invocation:
                    return self._fault(observation, "duplicate_invocation")
                req = dispatched_by_invocation[inv_id]
                if (
                    ev.name != req.name
                    or call_id != req.data.get("tool_call_id")
                    or arg_hash != req.data.get("arguments_sha256")
                    or req.data.get("sequence_index", seq) >= seq
                ):
                    return self._fault(observation, "target_result_mismatch")
                responses_by_invocation[inv_id] = ev

        if raw_record is not None and raw_record.get("tool_call_count") != len(dispatched_requests):
            return self._fault(observation, "action_count_mismatch")
        if raw_record is not None and isinstance(raw_record.get("events"), list):
            raw_events = raw_record["events"]
            if len(raw_events) != len(agent_events) or any(
                not isinstance(revent, dict)
                or revent.get("kind") != ev.kind
                or revent.get("run_id") != ev.data.get("run_id")
                or revent.get("invocation_id") != ev.data.get("invocation_id")
                or revent.get("tool_name") != ev.name
                or revent.get("arguments_sha256") != ev.data.get("arguments_sha256")
                or revent.get("sequence_index") != ev.data.get("sequence_index")
                for revent, ev in zip(raw_events, agent_events)
            ):
                return self._fault(observation, "raw_trace_mismatch")

        raw_dispatched_args = (
            result.raw_output.get("dispatched_tool_arguments")
            if isinstance(result.raw_output, dict)
            else None
        )
        verified_dispatched_args: dict[str, tuple[str, str, dict[str, Any]]] = {}
        if raw_dispatched_args is not None:
            if not isinstance(raw_dispatched_args, dict):
                return self._fault(observation, "action_argument_hash_mismatch")
            for req in dispatched_requests:
                inv_id = req.data["invocation_id"]
                if inv_id not in raw_dispatched_args:
                    return self._fault(observation, "action_argument_hash_mismatch")
                entry = raw_dispatched_args[inv_id]
                if not isinstance(entry, tuple | list) or len(entry) != 3:
                    return self._fault(observation, "action_argument_hash_mismatch")
                e_name, e_hash, e_args = entry
                if (
                    e_name != req.name
                    or e_hash != req.data.get("arguments_sha256")
                    or not isinstance(e_args, dict)
                ):
                    return self._fault(observation, "action_argument_hash_mismatch")
                recomputed = sha256(
                    json.dumps(e_args, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                ).hexdigest()
                if recomputed != e_hash:
                    return self._fault(observation, "action_argument_hash_mismatch")
                verified_dispatched_args[inv_id] = (e_name, e_hash, dict(e_args))
            observation.metadata["secagent_verified_dispatched_arguments"] = verified_dispatched_args

        if not self.execution_scope:
            return observation

        if not result.success:
            # Failed, blocked, incomplete, or errored runs remain unverified / unavailable.
            return observation

        correlated_receipts: dict[str, HandlerReceipt] = {}
        if self.receipt_collector is not None and dispatched_requests:
            for req in dispatched_requests:
                inv_id = req.data["invocation_id"]
                arg_hash = req.data["arguments_sha256"]
                resp = responses_by_invocation.get(inv_id)
                result_hash = resp.data.get("result_sha256") if resp else None
                if not isinstance(result_hash, str) or not HEX64.fullmatch(result_hash):
                    return self._fault(observation, "handler_receipt_invalid")
                try:
                    receipt = self.receipt_collector.collect(
                        request_id=inv_id,
                        tool_name=req.name or "",
                        arguments_sha256=arg_hash,
                        result_sha256=result_hash,
                    )
                except (ValueError, OSError):
                    return self._fault(observation, "handler_receipt_invalid")
                if receipt is None:
                    return self._fault(observation, "handler_receipt_missing")
                if not self._validate_receipt(
                    receipt,
                    invocation_id=inv_id,
                    tool_name=req.name or "",
                    arguments_sha256=arg_hash,
                    result_sha256=result_hash,
                ):
                    return self._fault(observation, "handler_receipt_mismatch")
                correlated_receipts[inv_id] = receipt
                observation.evidence.append(Evidence(
                    kind="handler_receipt",
                    source="instrumented_handler_receipt",
                    name=req.name,
                    success=receipt.handler_status == "succeeded",
                    reference="handler-receipt/" + receipt.invocation_id,
                    data={
                        "testcase_id": self.testcase_id,
                        "target_id": self.target_id,
                        "execution_id": self.execution_id,
                        "request_id": receipt.request_id,
                        "invocation_id": receipt.invocation_id,
                        "arguments_sha256": receipt.arguments_sha256,
                        "result_sha256": receipt.result_sha256,
                        "receipt_sha256": receipt.receipt_sha256,
                        "handler_status": receipt.handler_status,
                        "provenance": receipt.provenance,
                        "source_provenance": "instrumented_target_lab",
                        "trace_completeness": receipt.trace_completeness,
                        "attribution": "agent_selected",
                        "execution_verified": False,
                        "execution_level": (
                            "simulated_execution"
                            if receipt.handler_status != "rejected"
                            else "tool_invocation"
                        ),
                    },
                ))

        use_handler = bool(correlated_receipts) and len(correlated_receipts) == len(dispatched_requests)
        trace_source = (
            "instrumented_handler_receipt"
            if use_handler
            else "asi05_agent_mcp_observer"
        )
        provenance = (
            "instrumented_target_handler"
            if use_handler
            else "secagent_observed_request"
        )
        source_provenance = (
            "instrumented_target_lab"
            if use_handler
            else "live_mcp_request"
        )
        common: dict[str, Any] = {
            "testcase_id": self.testcase_id,
            "target_id": self.target_id,
            "execution_id": self.execution_id,
            "attribution": "agent_selected",
            "provenance": provenance,
            "source_provenance": source_provenance,
            "correlation_status": "verified",
        }
        contiguous_seq = [ev.data.get("sequence_index") for ev in agent_events] == list(range(len(agent_events)))
        rejected_present = any(ev.kind == "rejected_tool_call" for ev in agent_events)
        all_responses_ok = (
            len(responses_by_invocation) == len(dispatched_requests)
            and all(resp.data.get("response_status") == "ok" for resp in responses_by_invocation.values())
        )
        intents_paired = len(intents) == len(dispatched_requests)
        request_trace_complete = (
            result.success is True
            and result.response_complete is True
            and raw_record is not None
            and raw_record.get("status") == "completed"
            and raw_record.get("response_complete") is True
            and raw_record.get("rejected_tool_call_count") == 0
            and type(raw_record.get("model_call_count")) is int
            and raw_record["model_call_count"] >= 1
            and isinstance(raw_record.get("events"), list)
            and not rejected_present
            and contiguous_seq
            and intents_paired
            and all_responses_ok
        )
        request_completeness = "complete" if request_trace_complete else "partial"
        secagent_rejected_count = sum(1 for ev in agent_events if ev.kind == "rejected_tool_call")
        target_rejected_count = sum(
            1
            for ev in agent_events
            if ev.kind == "target_mcp_response"
            and (ev.data.get("response_status") != "ok" or ev.data.get("target_reported_success") is False)
        )

        trace_data: dict[str, Any] = {
            **common,
            "trace_completeness": "partial",
            "request_trace_completeness": request_completeness,
            "observed_action_count": len(dispatched_requests),
            "dispatched_action_count": len(dispatched_requests),
            "secagent_rejected_count": secagent_rejected_count,
            "target_rejected_count": target_rejected_count,
        }
        if latest_stamp is not None:
            trace_data["observed_at"] = latest_stamp

        observation.evidence.append(Evidence(
            kind="asi05_execution_trace",
            source=trace_source,
            reference="asi05-trace/" + self.execution_id,
            data=trace_data,
        ))

        for req in dispatched_requests:
            inv_id = req.data["invocation_id"]
            arg_hash = req.data["arguments_sha256"]
            receipt = correlated_receipts.get(inv_id) if use_handler else None
            corr_resp = responses_by_invocation.get(inv_id)
            level = (
                "simulated_execution"
                if receipt is not None and receipt.handler_status != "rejected"
                else "tool_invocation"
            )
            handler_status = receipt.handler_status if receipt is not None else "unverified"
            action_data: dict[str, Any] = {
                **common,
                "invocation_id": inv_id,
                "arguments_sha256": arg_hash,
                "evidence_type": level,
                "execution_level": level,
                "handler_status": handler_status,
                "receipt_sha256": receipt.receipt_sha256 if receipt is not None else None,
                "observed_at": req.data.get("timestamp"),
                **({"target_reported_success": corr_resp.data["target_reported_success"]}
                   if corr_resp is not None and type(corr_resp.data.get("target_reported_success")) is bool else {}),
            }
            observation.evidence.append(Evidence(
                kind="asi05_execution_action",
                source=trace_source,
                name=req.name,
                success=(receipt.handler_status == "succeeded") if receipt is not None else False,
                reference="asi05-action/" + inv_id,
                data=action_data,
            ))

        observation.metadata["asi05_execution_observer_verified"] = True
        return observation
