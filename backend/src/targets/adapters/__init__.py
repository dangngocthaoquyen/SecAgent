"""Target adapter abstractions and implementations."""

from targets.adapters.base import BaseTargetAdapter
from targets.adapters.http_adapter import HttpTargetAdapter, TargetAdapterError

__all__ = ["BaseTargetAdapter", "HttpTargetAdapter", "TargetAdapterError"]
