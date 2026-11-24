"""Bounded target-reported HTTP evidence, never verified execution events."""

from collections.abc import Mapping
import hashlib
import json
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit


_MAX_INLINE_EVENTS = 50
_MAX_HASH_BYTES = 524288  # 512 KiB full-value hashing cap; never emit truncated prefix hashes.
_SAFE_SCALAR_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,127}$")
_SAFE_ACTION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")
_SAFE_ARG_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_INLINE_DISCLOSURE_LIMITATION = (
    "Raw arguments and observation content omitted from public/Judge evidence; "
    "hashes provide integrity only and do not establish authorization or execution."
)


def _extract_optional_path(data: Any, path: str | None) -> Any:
    """Safely traverse a dotted object/index path; return None on any mismatch."""
    if not isinstance(path, str):
        return None
    cleaned = path.strip()
    if not cleaned:
        return data
    current = data
    for segment in cleaned.split("."):
        if isinstance(current, Mapping):
            if segment not in current:
                return None
            current = current[segment]
        elif isinstance(current, list):
            try:
                index = int(segment)
            except ValueError:
                return None
            if index < 0 or index >= len(current):
                return None
            current = current[index]
        else:
            return None
    return current


def _safe_scalar_text(value: Any, *, max_len: int = 128) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        text = str(value)
    elif isinstance(value, str):
        text = value.strip()
    else:
        return None
    if not text or len(text) > max_len or any(ord(ch) < 32 for ch in text):
        return None
    return text


def _hash_bounded_value(value: Any, *, max_bytes: int = _MAX_HASH_BYTES) -> tuple[str | None, bool]:
    """Hash a full serialized JSON value up to max_bytes without prefix truncation.

    Returns ``(sha256_hex, hash_incomplete)``. Oversized values exceeding
    ``max_bytes`` return ``(None, True)`` rather than a colliding prefix digest.
    """
    if value is None:
        return None, False
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        return None, True
    if len(encoded) > max_bytes:
        return None, True
    return hashlib.sha256(encoded).hexdigest(), False


def _stable_value_sha256(value: Any) -> str | None:
    digest, incomplete = _hash_bounded_value(value)
    return None if incomplete else digest


def _safe_argument_keys(value: Any) -> list[str]:
    """Extract safe bounded top-level argument key names only (never values)."""
    if not isinstance(value, Mapping):
        return []
    keys: list[str] = []
    for raw_k in value.keys():
        if isinstance(raw_k, str) and _SAFE_ARG_KEY_RE.fullmatch(raw_k):
            keys.append(raw_k)
        if len(keys) >= 16:
            break
    return sorted(keys)


def _value_type_label(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, list):
        return "array"
    return "other"


def build_event_fingerprint(
    *,
    event_id: str | None = None,
    action: str | None = None,
    arguments_sha256: str | None = None,
    decision: str | None = None,
    status: str | None = None,
    observation_sha256: str | None = None,
    timestamp: str | None = None,
    target_correlation_id: str | None = None,
    incomplete: bool = False,
) -> str | None:
    """Compute a deterministic fingerprint ONLY when stable identity justifies deduplication.

    Returns ``None`` (non-deduplicable) when ``event_id`` is absent or any hashed
    field was oversized/incomplete so repeated or unidentifiable actions are never
    silently collapsed.
    """
    if incomplete or not event_id:
        return None
    material = {
        "event_id": event_id,
        "action": action or "",
        "arguments_sha256": arguments_sha256 or "",
        "decision": decision or "",
        "status": status or "",
        "observation_sha256": observation_sha256 or "",
        "timestamp": timestamp or "",
        "target_correlation_id": target_correlation_id or "",
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def extract_configured_http_response_context(
    body: Any,
    response_config: Any,
) -> tuple[list[dict[str, Any]], str | None, str | None, bool | None, bool]:
    """Extract target-agnostic inline evidence, correlation ID, and configured status.

    Returns ``(inline_events, target_correlation_id, target_run_status,
    configured_status_complete, status_mapping_configured)``.
    All extracted events remain strictly ``target_reported`` and ``execution_verified=False``.
    """
    if not isinstance(response_config, Mapping) or body is None:
        return [], None, None, None, False

    target_corr_id: str | None = None
    corr_path = response_config.get("correlation_id_path")
    if isinstance(corr_path, str) and corr_path.strip():
        raw_corr = _extract_optional_path(body, corr_path)
        scalar_corr = _safe_scalar_text(raw_corr, max_len=128)
        if scalar_corr and _SAFE_SCALAR_ID_RE.fullmatch(scalar_corr):
            target_corr_id = scalar_corr

    target_run_status: str | None = None
    configured_status_complete: bool | None = None
    status_path = response_config.get("status_path")
    complete_vals_raw = response_config.get("complete_status_values")
    incomplete_vals_raw = response_config.get("incomplete_status_values")
    has_status_path = isinstance(status_path, str) and bool(status_path.strip())
    has_status_value_lists = bool(
        (isinstance(complete_vals_raw, list) and any(isinstance(v, str) and v.strip() for v in complete_vals_raw))
        or (isinstance(incomplete_vals_raw, list) and any(isinstance(v, str) and v.strip() for v in incomplete_vals_raw))
    )
    # Whenever status_path is configured, response completeness depends on explicit
    # status-value semantics; if no mapping lists exist or the status is unmapped,
    # completeness stays None (unknown) rather than assuming True.
    status_mapping_configured = has_status_path
    if has_status_path:
        raw_status = _extract_optional_path(body, status_path)
        target_run_status = _safe_scalar_text(raw_status, max_len=64)
        if has_status_value_lists and target_run_status is not None:
            norm_status = target_run_status.lower()
            complete_set = {
                v.strip().lower()
                for v in (complete_vals_raw or [])
                if isinstance(v, str) and v.strip()
            }
            incomplete_set = {
                v.strip().lower()
                for v in (incomplete_vals_raw or [])
                if isinstance(v, str) and v.strip()
            }
            if norm_status in incomplete_set:
                configured_status_complete = False
            elif norm_status in complete_set:
                configured_status_complete = True
            else:
                configured_status_complete = None

    events: list[dict[str, Any]] = []
    mapping = response_config.get("evidence_mapping")
    if isinstance(mapping, Mapping):
        items_path = mapping.get("items")
        raw_items = (
            _extract_optional_path(body, items_path)
            if isinstance(items_path, str)
            else None
        )
        if isinstance(raw_items, list):
            raw_limit = mapping.get("max_events")
            max_events = (
                max(1, min(_MAX_INLINE_EVENTS, int(raw_limit)))
                if isinstance(raw_limit, int) and not isinstance(raw_limit, bool)
                else _MAX_INLINE_EVENTS
            )
            truncated = len(raw_items) > max_events
            seen_fingerprints: set[str] = set()
            event_id_path = mapping.get("event_id") if isinstance(mapping.get("event_id"), str) else None
            action_path = (
                mapping.get("action")
                if isinstance(mapping.get("action"), str)
                else (mapping.get("tool") if isinstance(mapping.get("tool"), str) else None)
            )
            arguments_path = mapping.get("arguments") if isinstance(mapping.get("arguments"), str) else None
            decision_path = mapping.get("decision") if isinstance(mapping.get("decision"), str) else None
            status_item_path = mapping.get("status") if isinstance(mapping.get("status"), str) else None
            observation_path = (
                mapping.get("observation")
                if isinstance(mapping.get("observation"), str)
                else (mapping.get("result") if isinstance(mapping.get("result"), str) else None)
            )
            timestamp_path = mapping.get("timestamp") if isinstance(mapping.get("timestamp"), str) else None

            for idx, entry in enumerate(raw_items[:max_events]):
                if not isinstance(entry, Mapping):
                    continue
                ev_id = _safe_scalar_text(_extract_optional_path(entry, event_id_path), max_len=128) if event_id_path else None
                raw_action = _safe_scalar_text(_extract_optional_path(entry, action_path), max_len=128) if action_path else None
                safe_action = raw_action if (raw_action and _SAFE_ACTION_RE.fullmatch(raw_action)) else None
                raw_args = _extract_optional_path(entry, arguments_path) if arguments_path else None
                args_sha, args_incomplete = _hash_bounded_value(raw_args) if raw_args is not None else (None, False)
                arg_keys = _safe_argument_keys(raw_args)
                decision = _safe_scalar_text(_extract_optional_path(entry, decision_path), max_len=64) if decision_path else None
                item_status = _safe_scalar_text(_extract_optional_path(entry, status_item_path), max_len=64) if status_item_path else None
                raw_obs = _extract_optional_path(entry, observation_path) if observation_path else None
                obs_sha, obs_incomplete = _hash_bounded_value(raw_obs) if raw_obs is not None else (None, False)
                obs_type = _value_type_label(raw_obs)
                timestamp = _safe_scalar_text(_extract_optional_path(entry, timestamp_path), max_len=64) if timestamp_path else None

                if not any((ev_id, safe_action, args_sha, args_incomplete, decision, item_status, obs_sha, obs_incomplete, timestamp)):
                    continue

                fingerprint = build_event_fingerprint(
                    event_id=ev_id,
                    action=safe_action,
                    arguments_sha256=args_sha,
                    decision=decision,
                    status=item_status,
                    observation_sha256=obs_sha,
                    timestamp=timestamp,
                    target_correlation_id=target_corr_id,
                    incomplete=(args_incomplete or obs_incomplete),
                )
                if fingerprint is not None:
                    if fingerprint in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fingerprint)

                ev_data: dict[str, Any] = {
                    "provenance": "target_reported",
                    "execution_verified": False,
                    "observation_scope": "target_response_inline_evidence",
                    "execution_semantics": "target_reported_result",
                    "verification_status": "target_reported_unverified",
                    "disclosure_limitation": _INLINE_DISCLOSURE_LIMITATION,
                }
                if fingerprint is not None:
                    ev_data["event_fingerprint"] = fingerprint
                if target_corr_id is not None:
                    ev_data["target_correlation_id"] = target_corr_id
                if target_run_status is not None:
                    ev_data["target_run_status"] = target_run_status
                if ev_id is not None:
                    ev_data["event_id"] = ev_id
                if safe_action is not None:
                    ev_data["action"] = safe_action
                if decision is not None:
                    ev_data["decision"] = decision
                if item_status is not None:
                    ev_data["status"] = item_status
                if args_sha is not None:
                    ev_data["arguments_sha256"] = args_sha
                if args_incomplete:
                    ev_data["arguments_hash_incomplete"] = True
                if arg_keys:
                    ev_data["argument_keys"] = arg_keys
                if obs_sha is not None:
                    ev_data["observation_sha256"] = obs_sha
                if obs_incomplete:
                    ev_data["observation_hash_incomplete"] = True
                if obs_type is not None:
                    ev_data["observation_type"] = obs_type
                if timestamp is not None:
                    ev_data["timestamp"] = timestamp
                if truncated:
                    ev_data["inline_events_truncated"] = True

                items_label = items_path.strip() or "root"
                events.append({
                    "kind": "target_inline_event",
                    "source": "http_response",
                    "name": safe_action or ev_id or f"event-{idx}",
                    "reference": f"http.inline.{items_label}.{idx}",
                    "data": ev_data,
                })

    return (
        events,
        target_corr_id,
        target_run_status,
        configured_status_complete,
        status_mapping_configured,
    )


def _safe_url(value):
    if not isinstance(value, str) or len(value) > 2048:
        return None
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None):
            return "[redacted-url]"
        # Paths may contain private data, but are necessary for page identity.
        # Query/fragment and userinfo never leave raw_output.
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    except ValueError:
        return "[redacted-url]"


def reported_http_evidence(body):
    if not isinstance(body, dict):
        return []
    events = []
    choices = body.get("choices")
    choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
    message = choice.get("message")
    message = message if isinstance(message, dict) else {}
    calls = message.get("tool_calls")
    finish = choice.get("finish_reason")
    if finish is not None or isinstance(calls, list):
        data = {"provenance": "target_reported", "execution_verified": False}
        if "content" in message:
            data["assistant_content_present"] = isinstance(message["content"], str)
        if finish in ("stop", "length", "max_tokens", "tool_calls", "content_filter", "function_call"):
            data["finish_reason"] = finish
        if isinstance(calls, list):
            data["declared_tool_call_count"] = len(calls)
            data["tool_calls_truncated"] = len(calls) > 32
            # Completeness describes only the bounded declaration list, never
            # the target's tool actions or the assistant response.
            data["observation_scope"] = "target_response_tool_declarations"
            data["completeness"] = "partial" if len(calls) > 32 else "complete"
            data["verification_status"] = "target_reported_unverified"
        events.append(dict(kind="http_response_metadata", source="http_response",
            reference="http.choices.0", data=data))
    if isinstance(calls, list):
        for index, call in enumerate(calls[:32]):
            function = call.get("function") if isinstance(call, dict) else None
            name = function.get("name") if isinstance(function, dict) else None
            # Keep stable digests for correlation without exporting raw IDs or
            # arguments, either of which may contain credentials.
            safe_name = name if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) else None
            data = {"provenance": "target_reported", "execution_verified": False,
                    "observation_scope": "target_response_tool_declaration",
                    "execution_semantics": "declared_only",
                    "verification_status": "target_reported_unverified"}
            if isinstance(call, dict):
                call_id = call.get("id")
                if isinstance(call_id, str) and 0 < len(call_id) <= 4096:
                    data["correlation_reference"] = "sha256:" + hashlib.sha256(
                        ("openai-tool-call-id:" + call_id).encode()).hexdigest()
                arguments = function.get("arguments") if isinstance(function, dict) else None
                if isinstance(arguments, str):
                    try:
                        arg_bytes = arguments.encode("utf-8")
                    except UnicodeEncodeError:
                        arg_bytes = None
                    if arg_bytes is not None and len(arg_bytes) <= 65536:
                        data["arguments_sha256"] = hashlib.sha256(arg_bytes).hexdigest()
            events.append(dict(kind="declared_tool_call", source="http_response", name=safe_name,
                reference=f"http.choices.0.message.tool_calls.{index}",
                data=data))
    dvaa = body.get("dvaa")
    if isinstance(dvaa, dict) and any(k in dvaa for k in (
            "webFetchAttempted", "webFetchExecuted", "webFetchUrl", "webFetchSource", "error")):
        data = {"provenance": "target_reported", "execution_verified": False}
        for key in ("webFetchAttempted", "webFetchExecuted"):
            if type(dvaa.get(key)) is bool:
                data[key] = dvaa[key]
        if "webFetchUrl" in dvaa:
            data["webFetchUrl"] = _safe_url(dvaa["webFetchUrl"])
        if dvaa.get("webFetchSource") in ("live", "mock", "cache", "fallback", "cache-after-live-failed"):
            data["webFetchSource"] = dvaa["webFetchSource"]
        if "error" in dvaa:
            error = dvaa["error"]
            data["error_present"] = error is not None and error != ""
            text = error.lower() if isinstance(error, str) else ""
            data["error_category"] = ("none" if not data["error_present"] else
                "timeout" if "timeout" in text or "timed out" in text else
                "dns" if any(s in text for s in ("dns", "enotfound", "eai_again")) else
                "network" if any(s in text for s in ("network", "econn", "fetch failed")) else
                "target_reported_error")
        events.append(dict(kind="target_web_fetch", source="http_response", name="web_fetch",
            reference="http.dvaa.web_fetch", data=data))
    if isinstance(dvaa, dict) and any(key in dvaa for key in (
            "httpPostAttempted", "httpPostExecuted", "httpPostResult", "httpPostTargetUrl", "injectionKind")):
        data = {"provenance": "target_reported", "execution_verified": False}
        for key in ("httpPostAttempted", "httpPostExecuted"):
            if type(dvaa.get(key)) is bool:
                data[key] = dvaa[key]
        if dvaa.get("injectionKind") in ("url-exfiltration", "post-report"):
            data["injectionKind"] = dvaa["injectionKind"]
        url = _safe_url(dvaa.get("httpPostTargetUrl"))
        if url and url != "[redacted-url]":
            data["destination_id"] = "sha256:" + hashlib.sha256(url.encode()).hexdigest()
            match = re.fullmatch(r"/collector/([a-f0-9]{32})/[a-f0-9]{32}", urlsplit(url).path)
            if match:
                data["run_id"] = match.group(1)
        result = dvaa.get("httpPostResult")
        if isinstance(result, dict):
            if type(result.get("ok")) is bool:
                data["result_ok"] = result["ok"]
            if type(result.get("statusCode")) is int and 100 <= result["statusCode"] <= 599:
                data["result_status_code"] = result["statusCode"]
            error = result.get("error")
            if error is not None:
                text = error.lower() if isinstance(error, str) else ""
                data["error_category"] = ("timeout" if "timeout" in text else
                    "dns" if any(s in text for s in ("dns", "enotfound", "eai_again")) else
                    "network" if any(s in text for s in ("econn", "network", "request_error")) else
                    "target_reported_error")
        events.append(dict(kind="target_outbound_callback", source="http_response", name="http_post",
            reference="http.dvaa.outbound", data=data))
    bridge = body.get("secagent_bridge")
    if (isinstance(bridge, dict) and bridge.get("schema_version") == "1.0.0"
            and bridge.get("provenance") == "provider_reported"
            and bridge.get("execution_verified") is False
            and bridge.get("trace_completeness") == "partial"
            and isinstance(bridge.get("tool_calls"), list)
            and len(bridge["tool_calls"]) <= 3):
        events.append(dict(kind="agent_bridge_trace", source="http_response",
            reference="http.secagent_bridge", data={"provenance": "target_reported",
                "execution_verified": False, "trace_completeness": "partial",
                "tool_call_count": len(bridge["tool_calls"]),
                "verification_status": "provider_reported_unverified"}))
        for index, call in enumerate(bridge["tool_calls"]):
            if not isinstance(call, dict) or call.get("index") != index:
                continue
            name, digest = call.get("tool_name"), call.get("arguments_sha256")
            if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name)
                    or digest is not None and (not isinstance(digest, str)
                        or not re.fullmatch(r"[a-f0-9]{64}", digest))
                    or type(call.get("invoked")) is not bool
                    or type(call.get("mcp_response_present")) is not bool):
                continue
            events.append(dict(kind="agent_bridge_tool_call", source="http_response",
                name=name, reference=f"http.secagent_bridge.tool_calls.{index}",
                data={"provenance": "target_reported", "execution_verified": False,
                      "tool_name": name, "arguments_sha256": digest,
                      "assistant_selected_reported": True,
                      "mcp_request_dispatched_reported": call["invoked"],
                      "mcp_response_present_reported": call["mcp_response_present"],
                      "trace_completeness": "partial"}))
    return events


def structured_http_tool_calls(body):
    """Return raw structured choices[0].message.tool_calls list for canonical deduplication."""
    if not isinstance(body, dict):
        return []
    choices = body.get("choices")
    choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
    message = choice.get("message")
    message = message if isinstance(message, dict) else {}
    calls = message.get("tool_calls")
    return calls if isinstance(calls, list) else []
