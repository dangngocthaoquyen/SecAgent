"""Observe one backend-owned synthetic ASI05 trace and bounded effect records.

This Phase 1 observer never infers actions from target response text or MCP
success claims. The fixture root is trusted test infrastructure, not a DVAA
endpoint. Live target evidence requires a separately reviewed producer.
"""

from hashlib import sha256
import json
from pathlib import Path
import re

from core.models import Evidence, ExecutionResult, Observation
from core.models.asi05_execution import Asi05ExecutionTrace
from observers.response_observer import ResponseObserver


class Asi05ExecutionObserver(ResponseObserver):
    def __init__(self, root: Path, *, testcase_id: str, target_id: str, execution_id: str):
        if not re.fullmatch(r"[a-f0-9]{32}", execution_id):
            raise ValueError("Invalid ASI05 execution identity.")
        self.root = Path(root).resolve()
        self.testcase_id = testcase_id
        self.target_id = target_id
        self.execution_id = execution_id

    @staticmethod
    def _read_bounded(path: Path, limit: int) -> bytes | None:
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            raise ValueError("Unsafe ASI05 evidence artifact.")
        return path.read_bytes()

    def observe(self, result: ExecutionResult) -> Observation:
        observation = super().observe(result)
        try:
            raw = self._read_bounded(self.root / (self.execution_id + ".asi05-trace.json"), 65536)
            if raw is None:
                observation.metadata["asi05_execution_evidence_fault"] = "missing_trace"
                return observation
            trace = Asi05ExecutionTrace.model_validate_json(raw)
            if (trace.testcase_id != self.testcase_id or trace.target_id != self.target_id
                    or trace.execution_id != self.execution_id):
                observation.metadata["asi05_execution_evidence_fault"] = "identity_mismatch"
                return observation
            for action in trace.actions:
                if action.evidence_reference != "asi05-action/" + action.invocation_id:
                    raise ValueError("Invalid action reference.")
                if action.execution_level == "sandbox_effect":
                    effect = self._read_bounded(
                        self.root / (self.execution_id + "." + action.invocation_id + ".effect.json"), 4096)
                    if effect is None or sha256(effect).hexdigest() != action.effect_sha256:
                        observation.metadata["asi05_execution_evidence_fault"] = "effect_mismatch"
                        return observation
                    record = json.loads(effect)
                    if (not isinstance(record, dict)
                            or record.get("testcase_id") != self.testcase_id
                            or record.get("target_id") != self.target_id
                            or record.get("execution_id") != self.execution_id
                            or record.get("invocation_id") != action.invocation_id
                            or record.get("tool_name") != action.tool_name
                            or record.get("arguments_sha256") != action.arguments_sha256
                            or record.get("handler_status") != "succeeded"
                            or record.get("effect_observed") is not True
                            or record.get("synthetic_mock") is not True):
                        observation.metadata["asi05_execution_evidence_fault"] = "effect_mismatch"
                        return observation
            common = {
                "testcase_id": self.testcase_id,
                "target_id": self.target_id,
                "execution_id": self.execution_id,
                "attribution": trace.attribution,
                "provenance": "independent_observer",
                "source_provenance": "synthetic_mock",
                "synthetic_mock": True,
                "correlation_status": "verified",
            }
            observation.evidence.append(Evidence(
                kind="asi05_execution_trace", source="asi05_execution_fixture",
                reference="asi05-trace/" + self.execution_id,
                data={**common, "trace_completeness": "complete" if trace.trace_complete else "partial",
                      "observed_action_count": len(trace.actions),
                      "trace_sha256": sha256(raw).hexdigest()}))
            for action in trace.actions:
                observation.evidence.append(Evidence(
                    kind="asi05_execution_action", source="asi05_execution_fixture",
                    name=action.tool_name, success=action.handler_status == "succeeded",
                    reference=action.evidence_reference,
                    data={**common, "invocation_id": action.invocation_id,
                          "arguments_sha256": action.arguments_sha256,
                          "evidence_type": action.evidence_type,
                          "execution_level": action.execution_level,
                          "handler_status": action.handler_status,
                          **({"effect_sha256": action.effect_sha256}
                             if action.effect_sha256 is not None else {})}))
            observation.metadata["asi05_execution_observer_verified"] = True
            return observation
        except (ValueError, UnicodeError, OSError, TypeError):
            observation.metadata["asi05_execution_evidence_fault"] = "invalid_trace"
            return observation
