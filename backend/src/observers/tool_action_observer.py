"""Correlate a direct MCP request with a separate, backend-owned effect record.

The MCP response is a target claim. Only a trusted fixture/observer writing to
the supplied local root can add a verified tool_call. No live target supplies
such a root in the current Workflow API.
"""

from hashlib import sha256
import json
from pathlib import Path
import re

from core.models import Evidence, ExecutionResult, Observation
from observers.response_observer import ResponseObserver


HEX32 = re.compile(r"[a-f0-9]{32}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")


class ToolActionObserver(ResponseObserver):
    """Read one independent fixture receipt and verify its effect artifact."""

    def __init__(self, root: Path, execution_id: str):
        if not HEX32.fullmatch(execution_id):
            raise ValueError("Invalid tool observation identity.")
        self.root = Path(root).resolve()
        self.execution_id = execution_id

    @staticmethod
    def _bounded(path: Path, maximum: int) -> bytes | None:
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
            raise ValueError("Unsafe tool observation artifact.")
        return path.read_bytes()

    def observe(self, result: ExecutionResult) -> Observation:
        observation = super().observe(result)
        requests = [e for e in observation.evidence if e.kind == "tool_request"
                    and e.source == "mcp_jsonrpc_adapter"
                    and e.data.get("provenance") == "secagent_request"]
        if not result.success or len(requests) != 1:
            return observation
        requested = requests[0]
        path = self.root / (self.execution_id + ".receipt.json")
        raw = self._bounded(path, 4096)
        if raw is None:
            return observation
        try:
            record = json.loads(raw)
        except (ValueError, UnicodeError):
            raise ValueError("Malformed tool observation receipt.") from None
        if (not isinstance(record, dict) or
                record.get("execution_id") != self.execution_id or
                not isinstance(record.get("invocation_id"), str) or
                not HEX32.fullmatch(record["invocation_id"]) or
                record.get("tool_name") != requested.name or
                type(record.get("request_id")) is not type(requested.data.get("request_id")) or
                record.get("request_id") != requested.data.get("request_id") or
                record.get("arguments_sha256") != requested.data.get("arguments_sha256") or
                record.get("status") not in {"succeeded", "failed"} or
                type(record.get("observation_complete")) is not bool or
                record.get("provenance") != "independent_observer"):
            raise ValueError("Tool observation does not match the request.")
        effect_hash = record.get("effect_sha256")
        if record["status"] == "succeeded":
            if not isinstance(effect_hash, str) or not HEX64.fullmatch(effect_hash):
                return observation
            effect = self._bounded(self.root / (self.execution_id + ".effect.json"), 4096)
            if effect is None or sha256(effect).hexdigest() != effect_hash:
                return observation
            if record.get("effect_identity_required") is True:
                try:
                    effect_record = json.loads(effect)
                except (ValueError, UnicodeError):
                    raise ValueError("Malformed correlated tool effect.") from None
                if (not isinstance(effect_record, dict)
                        or effect_record.get("execution_id") != self.execution_id
                        or effect_record.get("invocation_id") != record["invocation_id"]
                        or effect_record.get("request_id") != record["request_id"]
                        or effect_record.get("tool_name") != record["tool_name"]
                        or effect_record.get("arguments_sha256") != record["arguments_sha256"]
                        or effect_record.get("handler_invoked") is not True
                        or effect_record.get("synthetic_mock") is not True):
                    raise ValueError("Tool effect identity does not match the request.")
        elif effect_hash is not None:
            raise ValueError("Failed tool action cannot claim a verified effect.")
        data = {"provenance": "independent_observer", "execution_verified": True,
                "execution_id": self.execution_id,
                "invocation_id": record["invocation_id"],
                "arguments_sha256": record["arguments_sha256"],
                "scope": "direct_request",
                "completeness": "complete" if record["observation_complete"] else "partial"}
        # This observer reads a synthetic handler fixture. The legacy
        # execution_verified flag means the fixture receipt was verified; it
        # does not attest to an OS process or an external side effect.
        data.update(observation_scope="synthetic_handler_direct_request",
                    execution_semantics=("simulated_handler_effect" if effect_hash is not None
                                         else "simulated_handler_invocation"),
                    verification_status=("verified_simulated_effect" if effect_hash is not None
                                         else "verified_handler_invocation"),
                    synthetic_mock=True)
        if isinstance(requested.data.get("correlation_reference"), str):
            data["correlation_reference"] = requested.data["correlation_reference"]
        if effect_hash is not None:
            data["effect_sha256"] = effect_hash
        observation.evidence.append(Evidence(kind="tool_call", source="local_tool_fixture",
            name=requested.name, success=record["status"] == "succeeded",
            reference="tool-receipt/" + record["invocation_id"], data=data))
        observation.evidence.append(Evidence(kind="tool_trace", source="local_tool_fixture",
            reference="tool-trace/" + record["invocation_id"],
            data={"provenance": "independent_observer", "execution_verified": True,
                  "scope": "direct_request", "completeness": data["completeness"],
                  "observation_scope": "synthetic_handler_direct_request",
                  "execution_semantics": data["execution_semantics"],
                  "verification_status": data["verification_status"],
                  "synthetic_mock": True,
                  **({"correlation_reference": data["correlation_reference"]}
                     if "correlation_reference" in data else {})}))
        return observation
