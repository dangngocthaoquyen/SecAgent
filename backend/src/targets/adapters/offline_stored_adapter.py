"""Target adapter for replaying offline stored responses without network calls."""

from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any

from core.models import ExecutionResult, TargetProfile, TestInput
from core.models.tool_intent import (
    build_tool_intent_event,
    extract_structured_tool_fingerprints,
    extract_tool_intent_signals,
)
from targets.adapters.base import BaseTargetAdapter


class OfflineStoredTargetAdapter(BaseTargetAdapter):
    """Replay stored responses and metadata through the canonical Runner pipeline."""

    def execute(self, target: TargetProfile, test_input: TestInput) -> ExecutionResult:
        del target
        params = test_input.parameters
        stored_record = params.get("stored_record")
        if isinstance(stored_record, dict):
            stored_response = stored_record.get("stored_response")
            finish_reason = stored_record.get("finish_reason")
            response_complete = stored_record.get("response_complete")
            tool_calls = stored_record.get("tool_calls") or []
            target_model = stored_record.get("target_model")
            response_id = stored_record.get("response_id")
            source_tool = (stored_record.get("provenance") or {}).get("source_tool", "offline_stored_import")
        else:
            stored_response = params.get("stored_response")
            finish_reason = params.get("finish_reason")
            response_complete = params.get("response_complete")
            tool_calls = params.get("tool_calls") or []
            target_model = params.get("target_model")
            response_id = params.get("response_id")
            source_tool = params.get("source_tool", "offline_stored_import")

        if not isinstance(stored_response, str):
            return ExecutionResult(
                success=False,
                status_code=None,
                error="Offline stored record is missing string 'stored_response'.",
            )

        if response_complete is None and isinstance(finish_reason, str):
            response_complete = finish_reason == "stop"

        safe_source = (
            source_tool
            if isinstance(source_tool, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", source_tool)
            else "offline_stored_import"
        )
        events: list[dict[str, Any]] = [
            {
                "kind": "stored_response",
                "source": safe_source,
                "name": "target_response_output",
                "success": None,
                "reference": response_id,
                "data": {
                    "finish_reason": finish_reason,
                    "response_complete": response_complete,
                    "target_model": target_model,
                    "source_tool": safe_source,
                    "provenance": "target_reported",
                    "execution_verified": False,
                },
            }
        ]

        if isinstance(tool_calls, list):
            for call in tool_calls:
                if isinstance(call, dict):
                    func = call.get("function") if isinstance(call.get("function"), dict) else {}
                    tool_name = call.get("name") or func.get("name") or "declared_tool"
                    raw_args = call.get("arguments") if "arguments" in call else func.get("arguments")
                    arg_hash: str | None = None
                    try:
                        if isinstance(raw_args, str):
                            arg_bytes = raw_args.encode("utf-8")
                        else:
                            arg_bytes = json.dumps(
                                raw_args, sort_keys=True, ensure_ascii=False, default=str
                            ).encode("utf-8")
                        if len(arg_bytes) <= 65536:
                            arg_hash = sha256(arg_bytes).hexdigest()
                    except (UnicodeEncodeError, TypeError, ValueError, RecursionError):
                        arg_hash = None
                    decl_data: dict[str, Any] = {
                        "provenance": "target_reported",
                        "execution_verified": False,
                        "observation_scope": "target_response_tool_declaration",
                        "execution_semantics": "declared_only",
                        "verification_status": "target_reported_unverified",
                    }
                    if arg_hash is not None:
                        decl_data["arguments_sha256"] = arg_hash
                    events.append({
                        "kind": "declared_tool_call",
                        "source": "http_response",
                        "name": str(tool_name),
                        "success": None,
                        "reference": call.get("id") if isinstance(call.get("id"), str) else response_id,
                        "data": decl_data,
                    })

        structured_fps = extract_structured_tool_fingerprints(tool_calls)
        intent_signal = extract_tool_intent_signals(
            stored_response,
            structured_events=events,
            structured_fingerprints=structured_fps,
        )
        if intent_signal.detected:
            events.append(build_tool_intent_event(intent_signal, reference=response_id))

        return ExecutionResult(
            success=True,
            status_code=200,
            output_text=stored_response,
            raw_output=stored_response,
            duration_ms=0.0,
            response_complete=response_complete,
            events=events,
        )
