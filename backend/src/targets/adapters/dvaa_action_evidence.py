"""Optional DVAA lab receipt binding for structured MCP direct requests."""

from pathlib import Path
from urllib.parse import urlsplit

from observers.dvaa_instrumented_receipt_collector import DvaaInstrumentedReceiptCollector
from observers.dvaa_mcp_execution_observer import DvaaMcpExecutionObserver


class DvaaActionObserverFactory:
    def __init__(self, receipt_root: Path | None = None):
        self.receipt_root = Path(receipt_root) if receipt_root is not None else None

    def __call__(self, testcase, target, test_input):
        if not self.supports_target(target):
            return None
        endpoint = target.interface.config.get("url", "")
        parsed = urlsplit(endpoint)
        if (target.id != "dvaa-toolbot" or parsed.hostname != "127.0.0.1"
                or parsed.port not in {7010, 7110}):
            return None
        if parsed.port == 7110 and self.receipt_root is None:
            return None
        bound = target.model_copy(deep=True)
        bound.target_type = "tool_service"
        bound.metadata.update({"platform": "dvaa", "agent": "toolbot"})
        collector = None
        if parsed.port == 7110:
            bound.metadata["instrumented_lab"] = True
            collector = DvaaInstrumentedReceiptCollector(self.receipt_root)
        return DvaaMcpExecutionObserver.for_target(testcase, bound, test_input,
            receipt_collector=collector)

    def supports_target(self, preset):
        if preset is None or preset.id != "dvaa-toolbot":
            return False
        endpoint = preset.endpoint if hasattr(preset, "endpoint") else preset.interface.config.get("url", "")
        parsed = urlsplit(endpoint)
        return (parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
            and parsed.port in {7010, 7110}
            and (parsed.port != 7110 or self.receipt_root is not None))
