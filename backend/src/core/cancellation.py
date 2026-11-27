"""Cooperative per-run cancellation primitives shared across Runner and Evaluator boundaries."""

from __future__ import annotations


class RunCancelledError(Exception):
    """Raised when an active canonical scan run is cancelled by an authorized operator.

    Must never be converted into a security verdict (PASS/FAIL) or technical ERROR verdict.
    """
