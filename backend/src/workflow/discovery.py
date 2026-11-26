"""Bounded, metadata-only discovery for explicitly authorized local targets.

This service never submits chat messages, follows redirects, resolves remote
references, or turns advertised capabilities into execution authorization.
Literal loopback IPs avoid DNS rebinding; nonlocal discovery needs a separately
reviewed network policy rather than a permissive URL fetcher.
"""

from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from pydantic import Field, model_validator

from targets.runtimes.mcp_agent import validate_restricted_tool_schema
from workflow.models import ClosedModel, Identifier


MAX_REQUESTS = 3
MAX_BYTES = 16384
MAX_OPENAPI_BYTES = 262144
MAX_OPENAPI_DEPTH = 24
MAX_OPENAPI_REF_DEPTH = 8
MAX_OPENAPI_CANDIDATES = 30
TIMEOUT_SECONDS = 3.0
METADATA_PATHS = ("/v1/models", "/openapi.json", "/.well-known/agent.json")
INPUT_PATHS = ("/", "/v1/chat/completions", "/chat/completions",
               "/openapi.json", "/.well-known/agent.json", "/mcp", "/jsonrpc")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/ -]{0,127}$")
SAFE_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}$")
SAFE_HTTP_PATH = re.compile(r"^/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]*$")
_INPUT_FIELD_PRIORITY = ("goal", "prompt", "message", "input", "query", "text", "instruction", "content")
_RESPONSE_TEXT_PRIORITY = ("answer", "output", "response", "text", "reply", "content", "message")
_CORRELATION_ID_PRIORITY = ("run_id", "execution_id", "request_id", "trace_id", "id")
_EVIDENCE_ARRAY_PRIORITY = ("steps", "events", "transcript", "trace", "actions", "tool_calls")


class DiscoveryRequest(ClosedModel):
    url: str = Field(min_length=1, max_length=256)
    authorization_confirmed: bool
    protocol_hint: str | None = None
    credential_alias: Identifier | None = None
    spec_url: str | None = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def confirmed(self):
        if self.authorization_confirmed is not True:
            raise ValueError("Explicit metadata discovery authorization required.")
        if self.protocol_hint not in {None, "openai-chat", "openapi-http", "http-json", "a2a", "mcp-jsonrpc"}:
            raise ValueError("Unsupported discovery protocol hint.")
        return self


class DiscoveryError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def canonical_input(raw: str, *, allow_custom_http_path: bool = False) -> tuple[str, str, str]:
    if any(ord(char) < 33 or char in "\\%" for char in raw) or raw != raw.strip():
        raise DiscoveryError("invalid_discovery_url")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except (ValueError, TypeError):
        raise DiscoveryError("invalid_discovery_url") from None
    if (parsed.scheme not in {"http", "https"} or not parsed.netloc or
            parsed.username is not None or parsed.password is not None or
            parsed.query or parsed.fragment or port is None):
        raise DiscoveryError("invalid_discovery_url")
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError:
        raise DiscoveryError("unsafe_discovery_destination") from None
    path = parsed.path or "/"
    if not address.is_loopback:
        raise DiscoveryError("unsafe_discovery_destination")
    if path not in INPUT_PATHS:
        if not (
            allow_custom_http_path
            and SAFE_HTTP_PATH.fullmatch(path)
            and "//" not in path
            and not any(seg in {".", ".."} for seg in path.split("/"))
        ):
            raise DiscoveryError("unsafe_discovery_destination")
    host = f"[{address.compressed}]" if address.version == 6 else str(address)
    origin = f"{parsed.scheme}://{host}:{port}"
    return origin, path, origin + path


def _check_json_depth(value: object, max_depth: int = MAX_OPENAPI_DEPTH) -> bool:
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > max_depth:
            return False
        if isinstance(cur, dict):
            stack.extend((v, depth + 1) for v in cur.values())
        elif isinstance(cur, list):
            stack.extend((v, depth + 1) for v in cur)
    return True


def _resolve_local_ref(doc: dict, schema: object, *, depth: int = 0, seen: frozenset[str] = frozenset()) -> dict | None:
    if not isinstance(schema, dict) or depth > MAX_OPENAPI_REF_DEPTH:
        return None
    ref = schema.get("$ref")
    if isinstance(ref, str):
        # Strictly reject remote/non-local refs; never fetch external URLs or files.
        if not ref.startswith("#/") or ref in seen:
            return None
        current: object = doc
        for part in ref[2:].split("/"):
            key = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, dict) or key not in current:
                return None
            current = current[key]
        return _resolve_local_ref(doc, current, depth=depth + 1, seen=seen | {ref})
    for combiner in ("anyOf", "oneOf"):
        variants = schema.get(combiner)
        if isinstance(variants, list):
            for variant in variants:
                resolved = _resolve_local_ref(doc, variant, depth=depth + 1, seen=seen)
                if isinstance(resolved, dict) and resolved.get("type") != "null":
                    return resolved
    return schema


def _classify_openapi_auth(
    doc: dict,
    op: dict,
    global_security_reqs: list,
    security_schemes: dict,
) -> tuple[bool, list[str], bool, str, list[str]]:
    """Classify OpenAPI operation authentication requirements, hints, and Bearer-alias compatibility.

    Returns ``(requires_auth, auth_schemes, auth_scheme_supported, auth_status, auth_hints)``.
    ``auth_status`` is one of ``"required"``, ``"may_be_required"``,
    ``"not_declared"``, or ``"unsupported"``.
    """
    raw_op_sec = op.get("security")
    if isinstance(raw_op_sec, list):
        effective_reqs = raw_op_sec
        op_declared_empty_sec = len(raw_op_sec) == 0
    else:
        effective_reqs = global_security_reqs
        op_declared_empty_sec = False

    auth_hints: list[str] = []
    has_anonymous_alt = False
    if effective_reqs:
        has_anonymous_alt = any(isinstance(req, dict) and len(req) == 0 for req in effective_reqs)
        requires_auth = not has_anonymous_alt
    else:
        requires_auth = False

    required_header_auth_names: list[str] = []
    optional_header_auth_names: list[str] = []
    if isinstance(op.get("parameters"), list):
        for p in op["parameters"][:50]:
            if (
                isinstance(p, dict)
                and p.get("in") == "header"
                and str(p.get("name") or "").lower() in {"authorization", "x-api-key"}
            ):
                hname = str(p.get("name") or "").lower()
                if p.get("required") is True:
                    required_header_auth_names.append(hname)
                else:
                    optional_header_auth_names.append(hname)
    if not requires_auth and required_header_auth_names:
        requires_auth = True

    def _scheme_supported(scheme_name: str) -> tuple[str, bool]:
        raw_def = security_schemes.get(scheme_name)
        resolved = _resolve_local_ref(doc, raw_def) if isinstance(raw_def, dict) else None
        if not isinstance(resolved, dict):
            # Scheme name referenced without components.securitySchemes definition;
            # keep compatibility with server-managed Bearer credential alias.
            return f"unspecified:{scheme_name[:40]}", True
        stype = str(resolved.get("type") or "").strip().lower()
        if stype == "http":
            scheme = str(resolved.get("scheme") or "").strip().lower()
            label = f"http:{scheme or 'unknown'}"
            return label, scheme == "bearer"
        if stype == "apikey":
            loc = str(resolved.get("in") or "").strip().lower()
            hdr_name = str(resolved.get("name") or "").strip().lower()
            label = f"apiKey:{loc or 'unknown'}" + (f":{hdr_name[:32]}" if hdr_name else "")
            valid_hdr = (
                loc == "header"
                and bool(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", hdr_name))
                and hdr_name not in {
                    "host", "content-type", "content-length", "cookie", "set-cookie",
                    "proxy-authorization", "transfer-encoding", "connection",
                }
            )
            return label, valid_hdr
        if stype == "basic":
            return "basic", False
        if stype in {"oauth2", "openidconnect", "mutualtls"}:
            return stype, False
        return stype or "unknown", False

    scheme_labels: list[str] = []
    any_alternative_supported = False
    has_typed_scheme_req = False

    for req in effective_reqs[:10]:
        if not isinstance(req, dict) or not req:
            continue
        has_typed_scheme_req = True
        alt_supported = True
        for sname in req.keys():
            if not isinstance(sname, str):
                alt_supported = False
                continue
            label, is_sup = _scheme_supported(sname)
            if label not in scheme_labels and len(scheme_labels) < 10:
                scheme_labels.append(label)
            if not is_sup:
                alt_supported = False
        if alt_supported:
            any_alternative_supported = True

    if not requires_auth:
        if optional_header_auth_names:
            for hname in optional_header_auth_names:
                lbl = f"optional_header:{hname}"
                if lbl not in auth_hints:
                    auth_hints.append(lbl)
        if has_anonymous_alt and has_typed_scheme_req:
            auth_hints.append("optional_security_requirement")
        if not op_declared_empty_sec and not effective_reqs and security_schemes:
            auth_hints.append("security_schemes_declared_in_spec")
            for sname in list(security_schemes.keys())[:5]:
                if isinstance(sname, str):
                    label, _ = _scheme_supported(sname)
                    if label not in scheme_labels and len(scheme_labels) < 10:
                        scheme_labels.append(label)
        auth_status = "may_be_required" if auth_hints else "not_declared"
        return False, scheme_labels, True, auth_status, auth_hints

    if not has_typed_scheme_req and required_header_auth_names:
        for hname in required_header_auth_names:
            lbl = f"header:{hname}"
            if lbl not in scheme_labels:
                scheme_labels.append(lbl)
            if hname in {"authorization", "x-api-key"}:
                any_alternative_supported = True

    auth_status = "required" if any_alternative_supported else "unsupported"
    return True, scheme_labels, any_alternative_supported, auth_status, auth_hints


def _find_nested_schema_paths(
    doc: dict,
    schema: dict,
    *,
    max_depth: int = 3,
    max_nodes: int = 40,
) -> list[tuple[str, str, dict, int]]:
    """Bounded BFS over object schema properties returning (dotted_path, leaf_name, resolved_prop_schema, depth)."""
    results: list[tuple[str, str, dict, int]] = []
    queue: list[tuple[str, dict, int]] = [("", schema, 0)]
    visited = 0
    while queue and visited < max_nodes:
        prefix, cur_schema, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        props = cur_schema.get("properties")
        if not isinstance(props, dict):
            continue
        for pname, pval in list(props.items())[:25]:
            if visited >= max_nodes:
                break
            if not isinstance(pname, str) or not pname or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,63}", pname):
                continue
            visited += 1
            resolved = _resolve_local_ref(doc, pval) or {}
            dotted = f"{prefix}.{pname}" if prefix else pname
            results.append((dotted, pname, resolved, depth + 1))
            if resolved.get("type") == "object" and isinstance(resolved.get("properties"), dict) and depth + 1 < max_depth:
                queue.append((dotted, resolved, depth + 1))
    return results


def _build_request_body_template(
    doc: dict,
    schema: dict,
    input_path: str,
    *,
    prefix: str = "",
    depth: int = 0,
    max_depth: int = 3,
) -> tuple[dict[str, object], list[str], list[dict[str, object]], list[dict[str, object]], bool]:
    """Recursively build a bounded JSON request body template and unresolved required field specs."""
    props = schema.get("properties")
    if not isinstance(props, dict) or depth > max_depth:
        return {}, [], [], [], False
    required_raw = schema.get("required")
    required_set = {r for r in required_raw if isinstance(r, str)} if isinstance(required_raw, list) else set()
    body_template: dict[str, object] = {}
    unresolved_required: list[str] = []
    unresolved_required_specs: list[dict[str, object]] = []
    optional_specs: list[dict[str, object]] = []
    prop_items = list(props.items())
    extraction_incomplete = len(prop_items) > 25
    covered_names: set[str] = set()

    for pname, pval in prop_items[:25]:
        if not isinstance(pname, str) or not pname:
            continue
        covered_names.add(pname)
        full_name = f"{prefix}.{pname}" if prefix else pname
        ps = _resolve_local_ref(doc, pval) or {}
        ptype = ps.get("type") if isinstance(ps.get("type"), str) else "string"

        if full_name == input_path:
            if full_name == "messages":
                body_template[pname] = [{"role": "user", "content": "{{input}}"}]
            else:
                body_template[pname] = "{{input}}"
            continue

        # Descend into nested objects that contain input_path or are required objects with properties.
        is_input_ancestor = input_path.startswith(full_name + ".")
        if (
            depth < max_depth
            and isinstance(ps.get("properties"), dict)
            and (is_input_ancestor or pname in required_set)
        ):
            sub_body, sub_unres, sub_specs, sub_opt, sub_inc = _build_request_body_template(
                doc, ps, input_path, prefix=full_name, depth=depth + 1, max_depth=max_depth
            )
            body_template[pname] = sub_body
            unresolved_required.extend(sub_unres)
            unresolved_required_specs.extend(sub_specs)
            optional_specs.extend(sub_opt)
            if sub_inc:
                extraction_incomplete = True
            continue

        if "default" in ps and isinstance(ps["default"], (str, int, float, bool)):
            body_template[pname] = ps["default"]
            if pname not in required_set:
                opt_entry: dict[str, object] = {"name": full_name, "type": ptype, "default": ps["default"]}
                optional_specs.append(opt_entry)
        elif pname in required_set:
            enum_vals = ps.get("enum")
            if isinstance(enum_vals, list) and len(enum_vals) == 1 and isinstance(enum_vals[0], (str, int, bool)):
                body_template[pname] = enum_vals[0]
            else:
                unresolved_required.append(full_name)
                spec_entry: dict[str, object] = {"name": full_name, "type": ptype, "location": "body"}
                if isinstance(enum_vals, list) and enum_vals and all(isinstance(v, (str, int, float, bool)) for v in enum_vals[:20]):
                    spec_entry["enum"] = list(enum_vals[:20])
                unresolved_required_specs.append(spec_entry)
                body_template[pname] = f"<REQUIRED:{full_name}>"
        else:
            # Optional parameter without an explicit scalar default is omitted from the request template.
            opt_entry = {"name": full_name, "type": ptype}
            enum_vals = ps.get("enum")
            if isinstance(enum_vals, list) and enum_vals and all(isinstance(v, (str, int, float, bool)) for v in enum_vals[:20]):
                opt_entry["enum"] = list(enum_vals[:20])
            optional_specs.append(opt_entry)

    # Ensure required fields beyond the 25-property cap or absent from properties are NEVER silently dropped.
    for req_name in sorted(required_set):
        full_name = f"{prefix}.{req_name}" if prefix else req_name
        if full_name == input_path or req_name in covered_names:
            continue
        extraction_incomplete = True
        ps = _resolve_local_ref(doc, props.get(req_name)) if req_name in props else None
        ptype = ps.get("type") if isinstance(ps, dict) and isinstance(ps.get("type"), str) else "unknown"
        unresolved_required.append(full_name)
        unresolved_required_specs.append({"name": full_name, "type": ptype, "location": "body"})
        body_template[req_name] = f"<REQUIRED:{full_name}>"

    return body_template, unresolved_required, unresolved_required_specs, optional_specs, extraction_incomplete


def _extract_openapi_candidates(doc: dict, origin: str, *, preferred_path: str | None = None) -> list[dict]:
    """Bounded, read-only extraction of POST JSON API candidates from an untrusted OpenAPI document."""
    paths = doc.get("paths")
    if not isinstance(paths, dict) or not _check_json_depth(doc):
        return []
    global_security_reqs = doc.get("security") if isinstance(doc.get("security"), list) else []
    components = doc.get("components")
    security_schemes: dict = {}
    if isinstance(components, dict) and isinstance(components.get("securitySchemes"), dict):
        security_schemes = components["securitySchemes"]
    elif isinstance(doc.get("securityDefinitions"), dict):
        security_schemes = doc["securityDefinitions"]
    candidates: list[dict] = []
    for raw_path, path_item in paths.items():
        if len(candidates) >= MAX_OPENAPI_CANDIDATES:
            break
        if (
            not isinstance(raw_path, str)
            or not SAFE_HTTP_PATH.fullmatch(raw_path)
            or "{" in raw_path
            or "}" in raw_path
            or "//" in raw_path
            or any(seg in {".", ".."} for seg in raw_path.split("/"))
            or not isinstance(path_item, dict)
        ):
            continue
        op = path_item.get("post")
        if not isinstance(op, dict):
            continue
        # Extract JSON request body schema (OpenAPI 3.x or Swagger 2.0 body parameter).
        req_schema: dict | None = None
        req_body = op.get("requestBody")
        if isinstance(req_body, dict):
            content = req_body.get("content")
            if isinstance(content, dict):
                app_json = content.get("application/json")
                if isinstance(app_json, dict):
                    req_schema = _resolve_local_ref(doc, app_json.get("schema"))
        if req_schema is None and isinstance(op.get("parameters"), list):
            for param in op["parameters"]:
                if isinstance(param, dict) and param.get("in") == "body":
                    req_schema = _resolve_local_ref(doc, param.get("schema"))
                    break
        if not isinstance(req_schema, dict):
            continue
        props = req_schema.get("properties")
        if not isinstance(props, dict) or not props:
            continue

        # Identify likely input text field (top-level or bounded nested object, or OpenAI messages array).
        input_field: str | None = None
        ambiguous_input_field = False
        if "messages" in props and raw_path in {"/v1/chat/completions", "/chat/completions"}:
            input_field = "messages"
        else:
            nested_req_nodes = _find_nested_schema_paths(doc, req_schema, max_depth=3, max_nodes=40)
            priority_matches: list[tuple[int, int, str]] = []
            for dotted, leaf, ps, depth in nested_req_nodes:
                if leaf in _INPUT_FIELD_PRIORITY and ps.get("type") in {None, "string"}:
                    priority_matches.append((_INPUT_FIELD_PRIORITY.index(leaf), depth, dotted))
            priority_matches.sort(key=lambda x: (x[1], x[0], x[2]))
            if priority_matches:
                # Prefer shallowest priority match; mark ambiguous if multiple priority matches exist at that depth.
                best_depth = priority_matches[0][1]
                same_depth = [m for m in priority_matches if m[1] == best_depth]
                input_field = same_depth[0][2]
                if len(same_depth) > 1:
                    ambiguous_input_field = True
            else:
                string_fields: list[str] = []
                for dotted, _leaf, ps, depth in nested_req_nodes:
                    if depth == 1 and ps.get("type") == "string":
                        string_fields.append(dotted)
                if not string_fields:
                    for dotted, _leaf, ps, _depth in nested_req_nodes:
                        if ps.get("type") == "string":
                            string_fields.append(dotted)
                if string_fields:
                    input_field = string_fields[0]
                    if len(string_fields) > 1:
                        ambiguous_input_field = True
        if input_field is None:
            continue

        (
            body_template,
            unresolved_required,
            unresolved_required_specs,
            optional_specs,
            extraction_incomplete,
        ) = _build_request_body_template(doc, req_schema, input_field)

        # Detect unsupported required query/header parameters (other than standard auth headers).
        unsupported_required_params: list[dict[str, str]] = []
        if isinstance(op.get("parameters"), list):
            for param in op["parameters"][:50]:
                if not isinstance(param, dict) or param.get("required") is not True:
                    continue
                loc = str(param.get("in") or "")
                pname = str(param.get("name") or "")
                if not pname or loc == "body":
                    continue
                if loc == "header" and pname.lower() in {"authorization", "x-api-key"}:
                    continue
                unsupported_required_params.append({"name": pname[:64], "in": loc[:32]})

        # Inspect 200/201 JSON response schema for text_path, correlation_id_path, status_path, and evidence_mapping.
        resp_schema: dict | None = None
        responses = op.get("responses")
        if isinstance(responses, dict):
            for code in ("200", "201", "default"):
                r_obj = responses.get(code)
                if not isinstance(r_obj, dict):
                    continue
                content = r_obj.get("content")
                if isinstance(content, dict) and isinstance(content.get("application/json"), dict):
                    resp_schema = _resolve_local_ref(doc, content["application/json"].get("schema"))
                    break
                if "schema" in r_obj:
                    resp_schema = _resolve_local_ref(doc, r_obj.get("schema"))
                    break

        text_path: str | None = "choices.0.message.content" if raw_path in {"/v1/chat/completions", "/chat/completions"} else None
        correlation_id_path: str | None = None
        status_path: str | None = None
        status_enum_values: list[str] = []
        evidence_mapping: dict | None = None
        if isinstance(resp_schema, dict) and isinstance(resp_schema.get("properties"), dict):
            nested_resp_nodes = _find_nested_schema_paths(doc, resp_schema, max_depth=3, max_nodes=40)
            if text_path is None:
                text_matches: list[tuple[int, int, str]] = []
                for dotted, leaf, ps, depth in nested_resp_nodes:
                    if leaf in _RESPONSE_TEXT_PRIORITY and ps.get("type") in {None, "string"}:
                        text_matches.append((_RESPONSE_TEXT_PRIORITY.index(leaf), depth, dotted))
                text_matches.sort(key=lambda x: (x[1], x[0], x[2]))
                if text_matches:
                    text_path = text_matches[0][2]
            corr_matches: list[tuple[int, int, str]] = []
            for dotted, leaf, _ps, depth in nested_resp_nodes:
                if leaf in _CORRELATION_ID_PRIORITY:
                    corr_matches.append((_CORRELATION_ID_PRIORITY.index(leaf), depth, dotted))
            corr_matches.sort(key=lambda x: (x[1], x[0], x[2]))
            if corr_matches:
                correlation_id_path = corr_matches[0][2]
            for dotted, leaf, ps, _depth in nested_resp_nodes:
                if leaf == "status":
                    status_path = dotted
                    raw_enum = ps.get("enum")
                    if isinstance(raw_enum, list):
                        status_enum_values = [str(v) for v in raw_enum[:12] if isinstance(v, str)]
                    break
            ev_matches: list[tuple[int, int, str, dict]] = []
            for dotted, leaf, ps, depth in nested_resp_nodes:
                if leaf in _EVIDENCE_ARRAY_PRIORITY and ps.get("type") == "array":
                    ev_matches.append((_EVIDENCE_ARRAY_PRIORITY.index(leaf), depth, dotted, ps))
            ev_matches.sort(key=lambda x: (x[1], x[0], x[2]))
            if ev_matches:
                _, _, ename, es = ev_matches[0]
                item_schema = _resolve_local_ref(doc, es.get("items"))
                item_props = item_schema.get("properties") if isinstance(item_schema, dict) and isinstance(item_schema.get("properties"), dict) else {}
                mapping: dict[str, object] = {"items": ename}
                for target_key, aliases in (
                    ("event_id", ("seq", "id", "event_id", "step_id")),
                    ("action", ("action", "tool", "operation", "name", "type")),
                    ("arguments", ("action_input", "arguments", "parameters", "args", "input")),
                    ("decision", ("decision",)),
                    ("status", ("status",)),
                    ("observation", ("observation", "result", "output", "content")),
                    ("timestamp", ("timestamp", "created_at", "at")),
                ):
                    found_key = next((a for a in aliases if a in item_props), None)
                    if found_key:
                        mapping[target_key] = found_key
                evidence_mapping = mapping

        requires_auth, auth_schemes, auth_scheme_supported, auth_status, auth_hints = _classify_openapi_auth(
            doc, op, global_security_reqs, security_schemes
        )

        limitations: list[str] = []
        if unresolved_required:
            limitations.append(
                f"Required request parameters unresolved: {', '.join(unresolved_required)}."
            )
        if unsupported_required_params:
            limitations.append(
                "Operation requires unsupported query/header parameters: "
                + ", ".join(f"{p['in']}:{p['name']}" for p in unsupported_required_params)
                + "."
            )
        if extraction_incomplete:
            limitations.append("Request schema exceeded bounded property extraction limit; review template manually.")
        if ambiguous_input_field:
            limitations.append("Multiple candidate string input fields exist; confirm which field receives '{{input}}'.")
        if text_path is None:
            limitations.append("Response text field was not reliably identified from schema; confirm response text path manually.")
        if status_path:
            limitations.append(
                f"Status field '{status_path}' was discovered, but completion semantics (complete/incomplete status values) are not declared in OpenAPI; confirm before semantic Judge evaluation."
            )
        if auth_status == "unsupported":
            limitations.append(
                "Operation requires an authentication scheme not supported by server-managed Bearer credential aliases."
            )
        elif auth_status == "required":
            limitations.append("Operation advertises authentication; select a server-managed credential alias before validating or saving.")
        elif auth_status == "may_be_required":
            limitations.append(
                "Authentication may be required (optional security/header hint or spec securitySchemes detected). Select a credential alias if the service enforces authentication."
            )
        else:
            limitations.append(
                "OpenAPI does not declare authentication for this operation; this does not verify anonymous access if middleware enforces auth."
            )

        summary = op.get("summary") if isinstance(op.get("summary"), str) else ""
        op_id = op.get("operationId") if isinstance(op.get("operationId"), str) else ""
        suggested_response: dict[str, object] = {"text_path": text_path or ""}
        if status_path:
            suggested_response["status_path"] = status_path
        if correlation_id_path:
            suggested_response["correlation_id_path"] = correlation_id_path
        if evidence_mapping:
            suggested_response["evidence_mapping"] = evidence_mapping

        candidates.append({
            "path": raw_path,
            "endpoint": origin + raw_path,
            "method": "POST",
            "operation_id": op_id[:128],
            "summary": summary[:200],
            "requires_auth": requires_auth,
            "auth_status": auth_status,
            "auth_schemes": auth_schemes,
            "auth_hints": auth_hints,
            "auth_scheme_supported": auth_scheme_supported,
            "input_field": input_field,
            "ambiguous_input_field": ambiguous_input_field,
            "extraction_incomplete": extraction_incomplete,
            "unresolved_required_fields": unresolved_required,
            "unresolved_required_field_specs": unresolved_required_specs,
            "optional_field_specs": optional_specs[:20],
            "unsupported_required_parameters": unsupported_required_params,
            "response_text_path_discovered": text_path is not None,
            "status_enum_values": status_enum_values,
            "mapping_provenance": "openapi_schema_heuristic",
            "limitations": limitations,
            "suggested_http_config": {
                "method": "POST",
                "body_template": body_template,
                "headers": {},
                "response": suggested_response,
            },
            "classification": "advertised_metadata",
            "runtime_verified": False,
            "operator_confirmed": False,
        })

    if preferred_path:
        candidates.sort(key=lambda c: (0 if c["path"] == preferred_path else 1, c["path"]))
    return candidates


def _short(value, pattern=SAFE_NAME) -> str | None:
    return value if isinstance(value, str) and pattern.fullmatch(value) else None


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return sha256(encoded).hexdigest()


class DiscoveryEngine:
    def __init__(self, data_dir: Path, *, transport: httpx.BaseTransport | None = None,
                 evidence_providers=()):
        self.root = Path(data_dir).resolve() / "discoveries"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink():
            raise DiscoveryError("unsafe_discovery_storage")
        self.transport = transport
        self.evidence_providers = tuple(evidence_providers)

    def _read_mcp_tools(self, client: httpx.Client, endpoint: str) -> tuple[str, list[dict]]:
        # tools/list is the only MCP discovery method. Never invoke a tool here.
        checked_origin, path, checked = canonical_input(endpoint)
        if checked != endpoint or path not in {"/", "/mcp", "/jsonrpc"}:
            raise DiscoveryError("unsafe_discovery_destination")
        try:
            with client.stream("POST", endpoint, headers={"Accept": "application/json",
                    "Content-Type": "application/json"}, json={"jsonrpc": "2.0",
                    "id": "secagent-discovery", "method": "tools/list", "params": {}}) as response:
                if 300 <= response.status_code < 400:
                    raise DiscoveryError("discovery_redirect_rejected")
                if response.status_code in {404, 405}:
                    return "missing", []
                if response.status_code != 200:
                    return "http_error", []
                parts, size = [], 0
                for part in response.iter_bytes():
                    size += len(part)
                    if size > MAX_BYTES:
                        raise DiscoveryError("discovery_response_too_large")
                    parts.append(part)
                try:
                    body = json.loads(b"".join(parts))
                except (ValueError, UnicodeError):
                    return "malformed", []
                if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or body.get("id") != "secagent-discovery":
                    return "malformed", []
                result = body.get("result")
                tools = result.get("tools") if isinstance(result, dict) else None
                if (not isinstance(tools, list) or len(tools) > 100 or
                        any(not isinstance(item, dict) or _short(item.get("name")) is None
                            for item in tools)):
                    return "malformed", []
                seen: set[str] = set()
                discovered: list[dict] = []
                for item in tools[:50]:
                    name = item["name"]
                    if name in seen:
                        continue
                    seen.add(name)
                    raw_desc = item.get("description")
                    description = raw_desc[:2048] if isinstance(raw_desc, str) else ""
                    if "inputSchema" in item:
                        raw_schema = item.get("inputSchema")
                    else:
                        raw_schema = item.get("input_schema")
                    if raw_schema is None:
                        input_schema = None
                        schema_sha256 = None
                        schema_compatible = False
                        schema_error = "missing_input_schema"
                    elif isinstance(raw_schema, dict):
                        schema_compatible, schema_error = validate_restricted_tool_schema(raw_schema)
                        input_schema = raw_schema
                        schema_sha256 = _canonical_sha256(raw_schema)
                    else:
                        input_schema = None
                        schema_sha256 = None
                        schema_compatible = False
                        schema_error = "invalid_input_schema"
                    discovered.append({
                        "name": name,
                        "description": description,
                        "input_schema": input_schema,
                        "schema_sha256": schema_sha256,
                        "schema_compatible": schema_compatible,
                        "schema_error": schema_error,
                        "source": endpoint,
                        "classification": "mcp_tools_list",
                    })
                return "advertised", discovered
        except httpx.TimeoutException:
            return "timeout", []
        except httpx.RequestError:
            return "connection_failure", []

    def _read_source(self, client: httpx.Client, origin: str, path: str, *, allow_spec_path: bool = False) -> tuple[str, dict | None]:
        # Revalidate at the connection boundary. Only literal loopback IPs are
        # accepted; there is no DNS resolution or redirect destination switch.
        if path not in METADATA_PATHS and not (allow_spec_path and SAFE_HTTP_PATH.fullmatch(path)):
            raise DiscoveryError("unsafe_discovery_destination")
        checked_origin, _, _ = canonical_input(origin + "/")
        if checked_origin != origin:
            raise DiscoveryError("unsafe_discovery_destination")
        byte_limit = MAX_OPENAPI_BYTES if (path == "/openapi.json" or allow_spec_path) else MAX_BYTES
        try:
            with client.stream("GET", origin + path, headers={"Accept": "application/json"}) as response:
                if 300 <= response.status_code < 400:
                    raise DiscoveryError("discovery_redirect_rejected")
                if response.status_code in {404, 405}:
                    return "missing", None
                if response.status_code != 200:
                    return "http_error", None
                parts, size = [], 0
                for part in response.iter_bytes():
                    size += len(part)
                    if size > byte_limit:
                        raise DiscoveryError("discovery_response_too_large")
                    parts.append(part)
                try:
                    body = json.loads(b"".join(parts))
                except (ValueError, UnicodeError):
                    return "malformed", None
                return ("advertised", body) if isinstance(body, dict) else ("malformed", None)
        except httpx.TimeoutException:
            return "timeout", None
        except httpx.RequestError:
            return "connection_failure", None

    def discover(self, request: DiscoveryRequest, *, allowed_aliases: set[str],
                 testcase_items: list[dict], text_case_ids: set[str]) -> dict:
        allow_custom_http = request.protocol_hint in {None, "openapi-http", "http-json"} or bool(request.spec_url)
        origin, input_path, canonical = canonical_input(request.url, allow_custom_http_path=allow_custom_http)
        spec_path: str | None = None
        if request.spec_url:
            spec_origin, spec_path, _ = canonical_input(request.spec_url, allow_custom_http_path=True)
            if spec_origin != origin:
                raise DiscoveryError("unsafe_discovery_destination")
        if request.credential_alias and request.credential_alias not in allowed_aliases:
            raise DiscoveryError("unknown_credential_alias")
        sources, models, agent, advertised_tools, advertised_skills = [], [], None, [], []
        mcp_tool_entries: list[dict] = []
        openapi_chat_path = None
        openapi_candidates: list[dict] = []
        adapter_hint = (next((hint for provider in self.evidence_providers
            if (hint := getattr(provider, "preferred_protocol", lambda **_: None)(
                origin=origin, input_path=input_path)) is not None), None)
            if request.protocol_hint is None and input_path == "/" else None)
        mcp_mode = (request.protocol_hint == "mcp-jsonrpc" or
                    input_path in {"/mcp", "/jsonrpc"} or adapter_hint == "mcp-jsonrpc")
        metadata_paths = (
            ()
            if mcp_mode
            else (
                tuple(dict.fromkeys((spec_path, *METADATA_PATHS)))[:MAX_REQUESTS]
                if spec_path
                else METADATA_PATHS
            )
        )
        client = httpx.Client(transport=self.transport, timeout=TIMEOUT_SECONDS,
                             follow_redirects=False, trust_env=False)
        try:
            if mcp_mode:
                status, mcp_tool_entries = self._read_mcp_tools(client, canonical)
                advertised_tools = [entry["name"] for entry in mcp_tool_entries]
                sources.append({"url": canonical, "status": status,
                    "classification": "mcp_tools_list" if status == "advertised" else "unverified"})
            for path in metadata_paths:
                is_spec = path == "/openapi.json" or (spec_path is not None and path == spec_path)
                status, body = self._read_source(client, origin, path, allow_spec_path=(spec_path is not None and path == spec_path))
                source = {"url": origin + path, "status": status,
                          "classification": "advertised_metadata" if status == "advertised" else "unverified"}
                sources.append(source)
                if status != "advertised" or body is None:
                    continue
                if path == "/v1/models":
                    data = body.get("data")
                    if isinstance(data, list) and len(data) <= 100:
                        models = list(dict.fromkeys(value for entry in data[:20]
                            if isinstance(entry, dict)
                            if (value := _short(entry.get("id"), SAFE_MODEL)) is not None))
                    else:
                        source["status"] = "malformed"
                        source["classification"] = "unverified"
                elif is_spec:
                    paths = body.get("paths")
                    if isinstance(paths, dict):
                        openapi_chat_path = next((candidate for candidate in
                            ("/v1/chat/completions", "/chat/completions")
                            if isinstance(paths.get(candidate), dict) and
                            isinstance(paths[candidate].get("post"), dict)), None)
                        preferred = input_path if input_path not in INPUT_PATHS else None
                        openapi_candidates = _extract_openapi_candidates(body, origin, preferred_path=preferred)
                    else:
                        source["status"] = "malformed"
                        source["classification"] = "unverified"
                else:
                    agent = _short(body.get("name"))
                    tools = body.get("tools")
                    skills = body.get("skills")
                    if isinstance(tools, list):
                        advertised_tools = [name for entry in tools[:20]
                            if isinstance(entry, dict)
                            if (name := _short(entry.get("name"))) is not None]
                    if isinstance(skills, list):
                        advertised_skills = [name for entry in skills[:20]
                            if isinstance(entry, dict)
                            if (name := _short(entry.get("name"))) is not None]
                    advertised_tools = list(dict.fromkeys(advertised_tools))[:20]
                    advertised_skills = list(dict.fromkeys(advertised_skills))[:20]
        finally:
            client.close()
        explicit_chat = input_path in {"/v1/chat/completions", "/chat/completions"}
        custom_path_supplied = input_path not in INPUT_PATHS
        # Never silently substitute /v1/chat/completions or another operation when
        # the operator explicitly supplied a specific custom REST endpoint path.
        chat_path = input_path if explicit_chat else (None if custom_path_supplied else openapi_chat_path)
        exact_custom_match = (
            next((c for c in openapi_candidates if c["path"] == input_path), None)
            if custom_path_supplied
            else None
        )
        matching_custom_candidate = (
            exact_custom_match
            if custom_path_supplied
            else (openapi_candidates[0] if len(openapi_candidates) == 1 and not chat_path else None)
        )
        candidate_ready = (
            matching_custom_candidate is not None
            and not matching_custom_candidate.get("unresolved_required_fields")
            and not matching_custom_candidate.get("unsupported_required_parameters")
            and not matching_custom_candidate.get("extraction_incomplete")
            and not matching_custom_candidate.get("ambiguous_input_field")
            and matching_custom_candidate.get("response_text_path_discovered") is True
            and not matching_custom_candidate.get("requires_auth")
        )
        # Separate candidate identification from configuration readiness:
        # an exact supplied endpoint path matching a supported OpenAPI operation is
        # automatically proposed as an unconfirmed review draft even when required
        # application parameters or authentication still need operator resolution.
        selected_custom_candidate = (
            exact_custom_match
            if exact_custom_match is not None
            else (matching_custom_candidate if candidate_ready else None)
        )
        is_http_json = selected_custom_candidate is not None and not (mcp_mode or (chat_path and not exact_custom_match))
        endpoint = (
            canonical
            if mcp_mode and sources[0]["status"] == "advertised"
            else (
                selected_custom_candidate["endpoint"]
                if is_http_json and selected_custom_candidate
                else (origin + chat_path if chat_path else None)
            )
        )
        protocol_candidates = []
        if mcp_mode and endpoint:
            protocol_candidates.append({"id": "mcp-jsonrpc", "classification": "observed_tools_list",
                "source": canonical, "runtime_verified": False})
        elif is_http_json and selected_custom_candidate:
            protocol_candidates.append({"id": "http-json", "classification": "advertised_metadata",
                "source": origin + (spec_path or "/openapi.json"),
                "runtime_verified": False})
        elif chat_path and endpoint:
            protocol_candidates.append({"id": "openai-chat", "classification":
                "operator_supplied" if explicit_chat else "advertised_metadata",
                "source": canonical if explicit_chat else origin + "/openapi.json",
                "runtime_verified": False})
        if any((row["url"].endswith("/openapi.json") or (spec_path and row["url"].endswith(spec_path))) and row["status"] == "advertised" for row in sources):
            protocol_candidates.append({"id": "openapi-http", "classification": "advertised_metadata",
                "source": origin + (spec_path or "/openapi.json"), "runtime_verified": False})
        if agent:
            protocol_candidates.append({"id": "a2a", "classification": "advertised_metadata",
                "source": origin + "/.well-known/agent.json", "runtime_verified": False})
        target_id = "local-agent-" + str(urlsplit(origin).port)
        if mcp_mode and endpoint:
            proposed = {"id": target_id, "name": "Local AI Agent", "platform_id": "local-agent",
                        "platform_name": "Local Agent", "endpoint": endpoint,
                        "protocol": "mcp-jsonrpc", "model": "mcp-service", "timeout_seconds": 30}
        elif is_http_json and selected_custom_candidate:
            slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", selected_custom_candidate["path"].strip("/")).strip("-")[:40] or "http-api"
            http_id = f"local-http-{urlsplit(origin).port}-{slug}"[:120]
            raw_summary = selected_custom_candidate.get("summary") or ""
            clean_name = re.sub(r"[^A-Za-z0-9 ._-]+", " ", raw_summary).strip()[:100]
            fallback_name = re.sub(r"[^A-Za-z0-9 ._-]+", " ", f"HTTP Agent {selected_custom_candidate['path']}").strip()[:100]
            proposed = {
                "id": http_id,
                "name": clean_name or fallback_name or "HTTP Agent",
                "platform_id": "local-agent",
                "platform_name": "Local Agent",
                "endpoint": selected_custom_candidate["endpoint"],
                "protocol": "http-json",
                "model": None,
                "timeout_seconds": 30,
                "http_config": selected_custom_candidate["suggested_http_config"],
            }
        elif chat_path and endpoint:
            proposed = {"id": target_id, "name": "Local AI Agent", "platform_id": "local-agent",
                        "platform_name": "Local Agent", "endpoint": endpoint,
                        "protocol": "openai-chat", "model": models[0] if models else "", "timeout_seconds": 30}
        else:
            proposed = None

        if is_http_json and selected_custom_candidate:
            if selected_custom_candidate.get("auth_scheme_supported") is False:
                configuration_readiness = "unsupported_authentication"
            elif candidate_ready:
                configuration_readiness = "ready_for_review"
            else:
                configuration_readiness = "incomplete_configuration"
        elif proposed is not None:
            configuration_readiness = "ready_for_review"
        elif openapi_candidates:
            configuration_readiness = "selection_required"
        else:
            configuration_readiness = "manual_configuration_required"

        has_non_chat_openapi = bool(openapi_candidates) and not chat_path
        if mcp_mode:
            unknown = (["model", "tool_execution", "handler_receipt", "trace_completeness",
                        "agent_selected_action"] + ([] if endpoint else ["mcp_endpoint"]))
        elif is_http_json or has_non_chat_openapi:
            unknown = ["runtime_http_contract", "tool_execution"]
            if not endpoint:
                unknown.append("http_endpoint")
            if selected_custom_candidate:
                if not selected_custom_candidate.get("response_text_path_discovered"):
                    unknown.append("response_text_path")
                if selected_custom_candidate.get("suggested_http_config", {}).get("response", {}).get("status_path"):
                    unknown.append("response_completion_semantics")
        else:
            unknown = [field for field, known in (("runtime_chat_contract", False),
                        ("tool_execution", False), ("model", bool(models)),
                        ("chat_endpoint", bool(endpoint))) if not known]
        if len(openapi_candidates) > 1 and not chat_path and exact_custom_match is None:
            unknown.append("ambiguous_openapi_operation_selection")
        relevant_candidates = [selected_custom_candidate] if selected_custom_candidate else openapi_candidates
        if any(c.get("unresolved_required_fields") for c in relevant_candidates):
            unknown.append("unresolved_required_request_parameters")
        if any(c.get("requires_auth") for c in relevant_candidates):
            unknown.append("authentication_credential_alias")
        warnings = ["Metadata and operator input do not verify runtime behavior or execution authorization."]
        for condition, message in (("timeout", "A metadata request timed out."),
                                   ("connection_failure", "A metadata request could not connect."),
                                   ("malformed", "A metadata response was malformed."),
                                   ("http_error", "A metadata endpoint returned an HTTP error.")):
            if any(row["status"] == condition for row in sources):
                warnings.append(message)
        if exact_custom_match is not None and not candidate_ready:
            warnings.append("Exact OpenAPI operation was matched as a review draft, but unresolved required parameters, authentication, or response mapping still require operator confirmation before saving or probing.")
        elif custom_path_supplied and exact_custom_match is None and openapi_candidates:
            warnings.append(f"The requested endpoint path '{input_path}' was not found as a supported POST JSON operation in the discovered OpenAPI specification. Select another discovered operation explicitly or configure manually.")
        elif openapi_candidates and proposed is None:
            warnings.append("OpenAPI candidates were discovered, but require explicit operator selection and confirmation of unresolved fields or authentication before saving.")
        elif not endpoint:
            warnings.append("No supported target endpoint was verified; configure the target manually.")
        if mcp_mode:
            warnings.append("MCP tools/list verifies tool metadata only; no tool was invoked or handler execution verified.")
        if request.credential_alias:
            warnings.append("Credential alias was recorded but no credential was sent during discovery.")
        if request.protocol_hint:
            warnings.append("Protocol hint is operator supplied; it does not verify a runtime protocol contract.")
        if adapter_hint:
            warnings.append("Adapter hint selected the MCP metadata probe; the tools/list response determines the proposal.")
        status = "metadata_found" if any(row["status"] == "advertised" for row in sources) else "manual_configuration_required"
        connection_status = ("reachable" if any(row["status"] in {"advertised", "missing", "malformed", "http_error"} for row in sources)
                             else "unavailable")
        evidence_candidates = []
        detected_protocol = "mcp-jsonrpc" if mcp_mode else ("http-json" if is_http_json else "openai-chat")
        for provider in self.evidence_providers:
            evidence_candidates.extend(provider.candidates(origin=origin, endpoint=endpoint,
                protocol=detected_protocol, connection_status=connection_status,
                tools=tuple(advertised_tools), models=tuple(models)))
        evidence_candidates = evidence_candidates[:20]
        recommendations = []
        for item in testcase_items:
            text_binding = item["id"] in text_case_ids
            recommendation = ("CONDITIONAL" if endpoint else "UNKNOWN") if text_binding else "UNSUPPORTED"
            recommendations.append({"testcase_id": item["id"],
                "asi_category": item["asi_category"], "status": recommendation,
                "reason": ("review_and_runtime_contract_required" if endpoint else "chat_endpoint_unknown")
                          if text_binding else "no_reviewed_execution_binding",
                "security_verdict": None})
        discovered_at = datetime.now(timezone.utc).isoformat()
        discovery_id = uuid4().hex
        advertised_tool_manifest_sha256 = (
            _canonical_sha256([
                {
                    "name": entry["name"],
                    "description": entry["description"],
                    "input_schema": entry["input_schema"],
                }
                for entry in mcp_tool_entries
            ])
            if mcp_mode and sources[0]["status"] == "advertised"
            else None
        )
        advertised_tool_rows = (
            [
                {
                    "name": entry["name"],
                    "source": canonical,
                    "classification": "mcp_tools_list",
                    "schema_compatible": entry["schema_compatible"],
                    "schema_sha256": entry["schema_sha256"],
                    "schema_error": entry["schema_error"],
                }
                for entry in mcp_tool_entries
            ]
            if mcp_mode
            else [
                {
                    "name": name,
                    "source": origin + "/.well-known/agent.json",
                    "classification": "advertised_metadata",
                }
                for name in advertised_tools
            ]
        )
        suggested_details = {
            "purpose": f"AI Agent service ({agent})" if agent else "",
            "features": ", ".join(advertised_skills),
            "available_tools": ", ".join(advertised_tools),
            "field_provenance": {
                **({"purpose": "suggested_unverified"} if agent else {}),
                **({"features": "suggested_unverified"} if advertised_skills else {}),
                **({"available_tools": "discovered_observed"} if advertised_tools else {}),
            },
            "operator_confirmed": False,
        }
        selected_text_path = (
            selected_custom_candidate.get("suggested_http_config", {}).get("response", {}).get("text_path")
            if selected_custom_candidate
            else None
        )
        possible_contracts = (
            [{"request": "mcp-tools-call-v1", "response": "mcp-jsonrpc-result-v1",
              "classification": "tools_list_only_action_unverified"}]
            if mcp_mode and endpoint
            else (
                [{"request": "http-json-template-v1", "response": selected_text_path or "unconfigured",
                  "classification": "advertised_metadata_unverified"}]
                if is_http_json and endpoint
                else (
                    [{"request": "openai-chat-user-message-v1",
                      "response": "choices.0.message.content",
                      "classification": "advertised_or_operator_supplied_unverified"}]
                    if chat_path and endpoint
                    else []
                )
            )
        )
        record = {"workflow_schema_version": "1.0.0", "discovery_id": discovery_id,
            "discovered_at": discovered_at,
            "input_url": canonical, "source_endpoint": canonical,
            "canonical_endpoint": endpoint,
            "status": status, "connection_status": connection_status,
            "configuration_readiness": configuration_readiness,
            "exact_match_path": exact_custom_match["path"] if exact_custom_match else None,
            "request_count": len(sources), "request_budget": MAX_REQUESTS,
            "metadata_sources": sources, "protocol_candidates": protocol_candidates,
            "openapi_candidates": openapi_candidates,
            "evidence_candidates": evidence_candidates,
            "advertised_models": [{"id": model, "source": origin + "/v1/models",
                                   "classification": "advertised_metadata"} for model in models],
            "advertised_agent": ({"name": agent, "source": origin + "/.well-known/agent.json",
                                  "classification": "advertised_metadata"} if agent else None),
            "advertised_tools": advertised_tool_rows,
            "advertised_tool_manifest_sha256": advertised_tool_manifest_sha256,
            "advertised_skills": [{"name": name, "source": origin + "/.well-known/agent.json",
                                   "classification": "advertised_metadata"} for name in advertised_skills],
            "suggested_application_details": suggested_details,
            "possible_contracts": possible_contracts,
            "unknown_fields": unknown, "warnings": warnings,
            "recommendations": recommendations,
            "proposed_profile": proposed, "credential_alias": request.credential_alias,
            "protocol_hint": request.protocol_hint,
            "adapter_protocol_hint": adapter_hint,
            "security_test_executed": False, "security_verdict": None,
            "profile_revision": None}
        if advertised_tool_manifest_sha256 is not None:
            self._save_mcp_capabilities({
                "workflow_schema_version": "1.0.0",
                "discovery_id": discovery_id,
                "source_endpoint": canonical,
                "discovered_at": discovered_at,
                "advertised_tool_manifest_sha256": advertised_tool_manifest_sha256,
                "tools": mcp_tool_entries,
            })
        self._save(record)
        return record

    def _path(self, discovery_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", discovery_id):
            raise DiscoveryError("invalid_discovery_id")
        return self.root / (discovery_id + ".json")

    def _mcp_capabilities_path(self, discovery_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", discovery_id):
            raise DiscoveryError("invalid_discovery_id")
        return self.root / (discovery_id + ".mcp-tools.json")

    def _write_json_atomic(self, path: Path, payload: dict) -> None:
        temporary = self.root / ("." + path.name + "." + uuid4().hex)
        try:
            with temporary.open("x", encoding="utf-8") as stream:
                json.dump(payload, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def _save(self, record: dict):
        self._write_json_atomic(self._path(record["discovery_id"]), record)

    def _save_mcp_capabilities(self, manifest: dict) -> None:
        self._write_json_atomic(self._mcp_capabilities_path(manifest["discovery_id"]), manifest)

    def load(self, discovery_id: str) -> dict:
        path = self._path(discovery_id)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            raise DiscoveryError("discovery_record_not_found")
        return json.loads(path.read_text(encoding="utf-8"))

    def load_mcp_capabilities(self, discovery_id: str) -> dict:
        """Load the bounded MCP tools/list metadata manifest recorded during discovery."""
        path = self._mcp_capabilities_path(discovery_id)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 131072:
            raise DiscoveryError("mcp_capabilities_not_found")
        return json.loads(path.read_text(encoding="utf-8"))

    def associate(self, discovery_id: str, profile: dict):
        record = self.validate_association(
            discovery_id,
            profile["endpoint"],
            profile["protocol"],
            credential_alias=profile.get("credential_alias"),
            session_auth=profile.get("session_auth"),
        )
        record["saved_target_id"] = profile["id"]
        record["profile_revision"] = profile["profile_revision"]
        record["associated_at"] = datetime.now(timezone.utc).isoformat()
        self._save(record)

    def validate_association(
        self,
        discovery_id: str,
        endpoint: str,
        protocol: str,
        *,
        credential_alias: str | None = None,
        session_auth: object | None = None,
    ) -> dict:
        record = self.load(discovery_id)
        if record["profile_revision"] is not None:
            raise DiscoveryError("discovery_profile_mismatch")
        if protocol == "http-json":
            candidates = record.get("openapi_candidates") or []
            matched = next(
                (c for c in candidates if isinstance(c, dict) and c.get("endpoint") == endpoint),
                None,
            )
            if matched is not None:
                if matched.get("requires_auth") is True:
                    if matched.get("auth_scheme_supported") is False:
                        raise DiscoveryError("unsupported_authentication_scheme")
                    has_alias = isinstance(credential_alias, str) and bool(credential_alias.strip())
                    has_session = session_auth is not None
                    if not (has_alias or has_session):
                        raise DiscoveryError("discovery_authentication_required")
                return record
        proposed = record.get("proposed_profile")
        if (
            isinstance(proposed, dict)
            and record.get("canonical_endpoint") == endpoint
            and proposed.get("protocol") == protocol
        ):
            return record
        raise DiscoveryError("discovery_profile_mismatch")
