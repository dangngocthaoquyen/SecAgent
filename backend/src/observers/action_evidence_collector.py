"""Replaceable collector contract for action receipts outside target responses."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class HandlerReceipt:
    request_id: str
    execution_id: str
    invocation_id: str
    target_id: str
    tool_name: str
    arguments_sha256: str
    result_sha256: str
    handler_status: str
    receipt_sha256: str
    entered_at: str
    finished_at: str
    provenance: str
    trace_completeness: str


class ActionEvidenceCollector(Protocol):
    def collect(self, *, request_id: str, tool_name: str,
                arguments_sha256: str, result_sha256: str) -> HandlerReceipt | None: ...
