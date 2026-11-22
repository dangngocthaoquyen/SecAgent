"""Read handler-owned telemetry from a separate, instrumented DVAA lab mount.

This is target-origin telemetry. Correlation validation does not make it an
independent sandbox effect or evidence of autonomous Agent tool selection.
"""

from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
import re

from observers.action_evidence_collector import HandlerReceipt


HEX32 = re.compile(r"[a-f0-9]{32}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")


class DvaaInstrumentedReceiptCollector:
    def __init__(self, root: Path):
        self.root = Path(root)
        if not self.root.is_dir() or self.root.is_symlink():
            raise ValueError("Instrumented lab receipt directory is unavailable.")

    def collect(self, *, request_id: str, tool_name: str,
                arguments_sha256: str, result_sha256: str) -> HandlerReceipt | None:
        if (not HEX32.fullmatch(request_id)
                or not isinstance(tool_name, str) or not tool_name
                or not HEX64.fullmatch(arguments_sha256)
                or not HEX64.fullmatch(result_sha256)):
            raise ValueError("Invalid action receipt lookup identity.")
        path = self.root / (request_id + ".receipt.json")
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
            raise ValueError("Unsafe instrumented lab receipt.")
        raw = path.read_bytes()
        try:
            row = json.loads(raw)
        except (ValueError, UnicodeError):
            raise ValueError("Malformed instrumented lab receipt.") from None
        expected = {"schema_version", "target_id", "request_id", "execution_id",
            "invocation_id", "tool_name", "arguments_sha256", "attribution",
            "provenance", "source_provenance", "trace_completeness",
            "handler_entry", "handler_status", "entered_at", "handler_result",
            "result_sha256", "finished_at"}
        if (not isinstance(row, dict) or set(row) != expected
                or row["schema_version"] != "1.0"
                or row["target_id"] != "dvaa-toolbot"
                or row["request_id"] != request_id
                or row["execution_id"] != request_id
                or not isinstance(row["invocation_id"], str)
                or not HEX32.fullmatch(row["invocation_id"])
                or row["tool_name"] != tool_name
                or row["arguments_sha256"] != arguments_sha256
                or row["attribution"] != "direct_request"
                or row["provenance"] != "instrumented_target_handler"
                or row["source_provenance"] != "instrumented_dvaa_lab"
                or row["trace_completeness"] != "partial"
                or row["handler_entry"] is not True
                or row["handler_result"] is not True
                or not isinstance(row["handler_status"], str)
                or row["handler_status"] not in {"succeeded", "failed", "rejected"}
                or not isinstance(row["result_sha256"], str)
                or row["result_sha256"] != result_sha256):
            raise ValueError("Instrumented handler receipt does not match the request.")
        try:
            entered = datetime.fromisoformat(row["entered_at"])
            finished = datetime.fromisoformat(row["finished_at"])
            if entered.tzinfo is None or finished.tzinfo is None or finished < entered:
                raise ValueError
        except (TypeError, ValueError):
            raise ValueError("Instrumented receipt timestamps are invalid.") from None
        return HandlerReceipt(request_id=request_id, execution_id=request_id,
            invocation_id=row["invocation_id"], target_id=row["target_id"],
            tool_name=tool_name, arguments_sha256=arguments_sha256,
            result_sha256=result_sha256,
            handler_status=row["handler_status"], receipt_sha256=sha256(raw).hexdigest(),
            entered_at=row["entered_at"], finished_at=row["finished_at"],
            provenance="instrumented_target_handler", trace_completeness="partial")
