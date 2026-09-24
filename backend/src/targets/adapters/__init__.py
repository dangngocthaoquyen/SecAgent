"""Target adapter abstractions and implementations."""

from targets.adapters.base import BaseTargetAdapter
from targets.adapters.http_adapter import HttpTargetAdapter, TargetAdapterError
from targets.adapters.mcp_jsonrpc_adapter import McpJsonRpcTargetAdapter

__all__ = [
    "BaseTargetAdapter",
    "HttpTargetAdapter",
    "McpJsonRpcTargetAdapter",
    "TargetAdapterError",
]
