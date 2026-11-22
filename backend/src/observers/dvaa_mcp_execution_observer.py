"""Opt-in observation of direct DVAA MCP requests and lab handler receipts.

Uninstrumented dashboard snapshots lack request identity. Instrumented target
receipts establish handler entry/result only, never an independent effect or
an agent-selected action.
"""

from urllib.parse import urlsplit

from observers.action_evidence_collector import ActionEvidenceCollector
from observers.mcp_direct_request_observer import McpDirectRequestObserver


class DvaaMcpExecutionObserver(McpDirectRequestObserver):
    @classmethod
    def for_target(cls, testcase, target, test_input,
                   *, receipt_collector: ActionEvidenceCollector | None = None):
        """Admit only the pinned, explicit ToolBot direct-request profile."""
        semantic = testcase.evaluation.semantic
        execution_scope = bool(semantic and semantic.trusted_context.get("evaluation_scope") == "execution_action")
        tool_scope = testcase.category == "tool_misuse" and receipt_collector is not None
        if (not (execution_scope or tool_scope)
                or target.id != "dvaa-toolbot" or target.target_type != "tool_service"
                or target.metadata.get("platform") != "dvaa"
                or target.metadata.get("agent") != "toolbot"
                or target.interface.type != "mcp"
                or target.interface.adapter != "generic_mcp_jsonrpc"
                or target.interface.config.get("asi05_live_evidence") is not True):
            return None
        try:
            parsed = urlsplit(target.interface.config.get("url", ""))
            lab = receipt_collector is not None
            valid_url = (parsed.scheme == "http"
                and parsed.hostname in {"127.0.0.1", "localhost"}
                and parsed.port == (7110 if lab else 7010)
                and parsed.path in {"", "/", "/mcp", "/jsonrpc"}
                and not parsed.username and not parsed.password
                and not parsed.query and not parsed.fragment
                and (not lab or target.metadata.get("instrumented_lab") is True))
        except (TypeError, ValueError):
            valid_url = False
        if not valid_url:
            return None
        return cls(testcase_id=testcase.id, target_id=target.id,
                   execution_id=test_input.id, receipt_collector=receipt_collector,
                   execution_scope=execution_scope)

