"""Bounded target-reported HTTP evidence, never verified execution events."""

import re
import hashlib
from urllib.parse import urlsplit, urlunsplit


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
        if finish in ("stop", "length", "tool_calls", "content_filter", "function_call"):
            data["finish_reason"] = finish
        if isinstance(calls, list):
            data["declared_tool_call_count"] = len(calls)
            data["tool_calls_truncated"] = len(calls) > 32
        events.append(dict(kind="http_response_metadata", source="http_response",
            reference="http.choices.0", data=data))
    if isinstance(calls, list):
        for index, call in enumerate(calls[:32]):
            function = call.get("function") if isinstance(call, dict) else None
            name = function.get("name") if isinstance(function, dict) else None
            # Do not serialize IDs/arguments, which may contain credentials.
            safe_name = name if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) else None
            events.append(dict(kind="declared_tool_call", source="http_response", name=safe_name,
                reference=f"http.choices.0.message.tool_calls.{index}",
                data={"provenance": "target_reported", "execution_verified": False}))
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
    return events
