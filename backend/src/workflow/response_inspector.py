"""Minimal deterministic JSON response-shape inspector for HTTP Target onboarding.

Operates strictly offline on an already-received bounded JSON payload from an
explicitly authorized connection test. Never sends network requests, never uses
an LLM, never executes arbitrary transforms, never removes status_path, and
never promotes target-reported arrays to execution_verified=True.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from targets.adapters.http_evidence import extract_configured_http_response_context

_MAX_INSPECT_DEPTH = 4
_MAX_INSPECT_NODES = 120
_MAX_CANDIDATES = 8

_RESPONSE_TEXT_PRIORITY = (
    "answer",
    "output",
    "response",
    "text",
    "reply",
    "reply_text",
    "result_text",
    "content",
    "message",
)
_CORRELATION_ID_PRIORITY = (
    "run_id",
    "execution_id",
    "request_id",
    "trace_id",
    "correlation_id",
    "correlation_key",
    "id",
)
_STATUS_FIELD_NAMES = ("status", "state", "run_status", "phase")
_EVIDENCE_ARRAY_PRIORITY = (
    "steps",
    "events",
    "transcript",
    "trace",
    "actions",
    "tool_calls",
    "tool_events",
)

_INLINE_FIELD_ALIASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("event_id", ("seq", "id", "event_id", "step_id", "index")),
    ("action", ("action", "tool", "tool_name", "operation", "name", "type")),
    ("arguments", ("action_input", "arguments", "parameters", "args", "input", "payload")),
    ("decision", ("decision", "policy_decision", "verdict")),
    ("status", ("status", "outcome", "state")),
    ("observation", ("observation", "result", "output", "content", "response")),
    ("timestamp", ("timestamp", "created_at", "at", "time")),
)

_SAFE_SEGMENT_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


def _valid_segment(key: str) -> bool:
    return bool(key) and len(key) <= 64 and all(c in _SAFE_SEGMENT_CHARS for c in key)


def _walk_bounded(body: Any) -> list[tuple[str, str, Any, int]]:
    """Breadth-first bounded traversal returning (dotted_path, leaf_key, value, depth)."""
    if not isinstance(body, Mapping):
        return []
    out: list[tuple[str, str, Any, int]] = []
    queue: list[tuple[str, Mapping[str, Any], int]] = [("", body, 0)]
    visited = 0
    while queue and visited < _MAX_INSPECT_NODES:
        prefix, mapping, depth = queue.pop(0)
        if depth >= _MAX_INSPECT_DEPTH:
            continue
        for raw_key, val in mapping.items():
            if visited >= _MAX_INSPECT_NODES:
                break
            if not isinstance(raw_key, str) or not _valid_segment(raw_key):
                continue
            visited += 1
            path = f"{prefix}.{raw_key}" if prefix else raw_key
            out.append((path, raw_key, val, depth + 1))
            if isinstance(val, Mapping) and depth + 1 < _MAX_INSPECT_DEPTH:
                queue.append((path, val, depth + 1))
    return out


def _inspect_evidence_array(path: str, items: list[Any]) -> dict[str, Any]:
    """Inspect observed items of a candidate evidence array without fabricating absent fields."""
    count = len(items)
    if count == 0:
        return {
            "items": path,
            "items_observed": 0,
            "item_fields_observed": False,
            "suggested_mapping": {"items": path},
            "source": "runtime_response_shape_heuristic",
            "provenance": "target_reported",
            "execution_verified": False,
            "ambiguous": True,
            "limitation": (
                "Observed array is empty; item field mappings were not inferred. "
                "Inline response arrays remain target-reported evidence unless independently corroborated."
            ),
        }

    dict_items = [entry for entry in items[:5] if isinstance(entry, Mapping)]
    if not dict_items:
        return {
            "items": path,
            "items_observed": count,
            "item_fields_observed": False,
            "suggested_mapping": {"items": path},
            "source": "runtime_response_shape_heuristic",
            "provenance": "target_reported",
            "execution_verified": False,
            "ambiguous": True,
            "limitation": (
                "Observed array items are not JSON objects; item field mappings were not inferred. "
                "Inline response arrays remain target-reported evidence unless independently corroborated."
            ),
        }

    observed_keys: set[str] = set()
    for entry in dict_items:
        for k in entry.keys():
            if isinstance(k, str) and _valid_segment(k):
                observed_keys.add(k)

    mapping: dict[str, str] = {"items": path}
    ambiguous_fields: list[str] = []
    for target_field, aliases in _INLINE_FIELD_ALIASES:
        matches = [a for a in aliases if a in observed_keys]
        if len(matches) == 1:
            mapping[target_field] = matches[0]
        elif len(matches) > 1:
            mapping[target_field] = matches[0]
            ambiguous_fields.append(target_field)

    return {
        "items": path,
        "items_observed": count,
        "item_fields_observed": len(mapping) > 1,
        "observed_item_keys": sorted(observed_keys)[:20],
        "suggested_mapping": mapping,
        "ambiguous_fields": ambiguous_fields,
        "source": "runtime_response_shape_heuristic",
        "provenance": "target_reported",
        "execution_verified": False,
        "ambiguous": bool(ambiguous_fields) or len(mapping) <= 1,
        "limitation": (
            "Suggested from observed runtime response items. Confirm mappings manually. "
            "Inline response arrays remain target-reported evidence (execution_verified=False) "
            "unless independently corroborated."
        ),
    }


def inspect_http_response_shape(
    body: Any,
    configured_response: Mapping[str, Any] | None = None,
    *,
    extracted_text: str | None = None,
    text_extracted: bool = False,
    response_complete: bool | None = None,
) -> dict[str, Any]:
    """Deterministically inspect a bounded JSON response and return mapping diagnostics & suggestions."""
    cfg = configured_response if isinstance(configured_response, Mapping) else {}
    configured_text_path = cfg.get("text_path") if isinstance(cfg.get("text_path"), str) else None
    configured_status_path = cfg.get("status_path") if isinstance(cfg.get("status_path"), str) else None
    configured_corr_path = cfg.get("correlation_id_path") if isinstance(cfg.get("correlation_id_path"), str) else None
    complete_vals = [
        v for v in (cfg.get("complete_status_values") or []) if isinstance(v, str) and v.strip()
    ]
    incomplete_vals = [
        v for v in (cfg.get("incomplete_status_values") or []) if isinstance(v, str) and v.strip()
    ]

    inline_events, observed_corr_id, observed_status_val, _, status_mapping_configured = (
        extract_configured_http_response_context(body, cfg)
    )

    nodes = _walk_bounded(body)

    # 1. Text path candidates (priority-named strings first; fallback non-ID strings marked ambiguous).
    priority_text: list[tuple[int, int, str, str]] = []
    fallback_strings: list[tuple[int, str, str]] = []
    excluded_keys = set(_CORRELATION_ID_PRIORITY) | set(_STATUS_FIELD_NAMES)
    for path, leaf, val, depth in nodes:
        if not isinstance(val, str):
            continue
        leaf_low = leaf.lower()
        if leaf_low in _RESPONSE_TEXT_PRIORITY:
            rank = _RESPONSE_TEXT_PRIORITY.index(leaf_low)
            priority_text.append((rank, depth, path, leaf))
        elif leaf_low not in excluded_keys and val.strip():
            fallback_strings.append((depth, path, leaf))

    priority_text.sort(key=lambda item: (item[0], item[1], item[2]))
    fallback_strings.sort(key=lambda item: (item[0], item[1]))

    text_candidates: list[dict[str, Any]] = []
    ambiguous_text = len(priority_text) > 1 or (len(priority_text) == 0 and len(fallback_strings) > 0)
    for rank, _depth, path, _leaf in priority_text[:_MAX_CANDIDATES]:
        text_candidates.append({
            "path": path,
            "sample_type": "string",
            "source": "runtime_response_shape_heuristic",
            "confidence": "high" if len(priority_text) == 1 and rank <= 4 else "medium",
            "ambiguous": len(priority_text) > 1,
            "limitation": "Heuristic field-name match from one response sample; confirm this field carries the agent response.",
        })
    if not text_candidates:
        for _depth, path, _leaf in fallback_strings[:_MAX_CANDIDATES]:
            text_candidates.append({
                "path": path,
                "sample_type": "string",
                "source": "runtime_response_shape_heuristic",
                "confidence": "ambiguous",
                "ambiguous": True,
                "limitation": "String field observed without a known response field name; operator confirmation required.",
            })

    # 2. Correlation ID candidates.
    corr_raw: list[tuple[int, int, str, str]] = []
    for path, leaf, val, depth in nodes:
        leaf_low = leaf.lower()
        if leaf_low in _CORRELATION_ID_PRIORITY and isinstance(val, (str, int)) and not isinstance(val, bool):
            corr_raw.append((_CORRELATION_ID_PRIORITY.index(leaf_low), depth, path, type(val).__name__))
    corr_raw.sort(key=lambda item: (item[0], item[1], item[2]))
    corr_candidates = [
        {
            "path": path,
            "sample_type": stype,
            "source": "runtime_response_shape_heuristic",
            "confidence": "high" if len(corr_raw) == 1 else "medium",
            "ambiguous": len(corr_raw) > 1,
            "limitation": "Target-supplied identifier provides weak correlation only.",
        }
        for _r, _d, path, stype in corr_raw[:_MAX_CANDIDATES]
    ]

    # 3. Status path candidates.
    status_raw: list[tuple[int, int, str, str]] = []
    for path, leaf, val, depth in nodes:
        leaf_low = leaf.lower()
        if leaf_low in _STATUS_FIELD_NAMES and isinstance(val, str) and val.strip():
            status_raw.append((_STATUS_FIELD_NAMES.index(leaf_low), depth, path, val.strip()[:64]))
    status_raw.sort(key=lambda item: (item[0], item[1], item[2]))
    status_candidates = [
        {
            "path": path,
            "observed_value": obs_val,
            "sample_type": "string",
            "source": "runtime_response_shape_heuristic",
            "confidence": "medium",
            "ambiguous": True,
            "limitation": (
                "A single observed status value cannot establish full lifecycle completion semantics. "
                "Confirm complete and incomplete status values from API documentation or reviewed runs."
            ),
        }
        for _r, _d, path, obs_val in status_raw[:_MAX_CANDIDATES]
    ]

    # 4. Inline evidence array candidates.
    ev_raw: list[tuple[int, int, str, list[Any]]] = []
    for path, leaf, val, depth in nodes:
        leaf_low = leaf.lower()
        if leaf_low in _EVIDENCE_ARRAY_PRIORITY and isinstance(val, list):
            ev_raw.append((_EVIDENCE_ARRAY_PRIORITY.index(leaf_low), depth, path, val))
    ev_raw.sort(key=lambda item: (item[0], item[1], item[2]))
    evidence_candidates = [
        _inspect_evidence_array(path, items)
        for _r, _d, path, items in ev_raw[:_MAX_CANDIDATES]
    ]

    # 5. Response completeness & evaluation readiness integrity (E2).
    completeness_unresolved = bool(status_mapping_configured and response_complete is None)
    evaluation_readiness_limitations: list[str] = []
    if not text_extracted:
        evaluation_readiness_limitations.append(
            f"Configured response text path '{configured_text_path or ''}' did not extract a string output from this response."
        )
    if completeness_unresolved:
        obs_note = f" (observed '{observed_status_val}')" if observed_status_val else ""
        evaluation_readiness_limitations.append(
            f"Status path '{configured_status_path}' is configured{obs_note}, but complete/incomplete status semantics are unconfirmed. "
            "response_complete remains unknown and semantic Judge evaluation will remain gated until status completion values are confirmed."
        )
    elif not configured_status_path and status_candidates:
        evaluation_readiness_limitations.append(
            f"Response contains status field '{status_candidates[0]['path']}' (observed '{status_candidates[0]['observed_value']}'). "
            "If this API can return partial/pending/failed runs with HTTP 200, configure status_path with confirmed complete/incomplete values."
        )
    if inline_events:
        evaluation_readiness_limitations.append(
            f"Extracted {len(inline_events)} inline target-reported event(s); inline events remain target_reported (execution_verified=False)."
        )

    return {
        "configured_text_path": configured_text_path,
        "text_extracted": text_extracted,
        "configured_correlation_id_path": configured_corr_path,
        "observed_correlation_id": observed_corr_id,
        "configured_status_path": configured_status_path,
        "observed_status_value": observed_status_val,
        "configured_complete_status_values": complete_vals,
        "configured_incomplete_status_values": incomplete_vals,
        "response_complete": response_complete,
        "completeness_unresolved": completeness_unresolved,
        "inline_events_extracted": len(inline_events),
        "evaluation_readiness_limitations": evaluation_readiness_limitations,
        "suggestions": {
            "text_path_candidates": text_candidates,
            "text_path_ambiguous": ambiguous_text,
            "correlation_id_candidates": corr_candidates,
            "status_path_candidates": status_candidates,
            "evidence_mapping_candidates": evidence_candidates,
        },
    }
