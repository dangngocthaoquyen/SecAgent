"""Provider-agnostic, non-authoritative textual tool-intent signal normalization.

Extracts bounded model-reported tool-invocation markup (DeepSeek DSML and
alternative XML-style invocation formats) from response text while:
- Never treating textual markup as dispatched or verified execution
  (provenance="model_reported", execution_verified=False always).
- Filtering illustrative contexts (fenced Markdown code blocks, inline backtick
  spans, blockquotes, and quoted inline examples) to prevent false positives.
- Bounding response scan length, tag body length, and extracted invocation count
  to prevent crashes or catastrophic backtracking on malformed/oversized input.
- Suppressing exact duplicates against already-extracted structured
  declared_tool_call items without merging distinct invocations.
"""

from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any, Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field

MAX_SCAN_CHARS = 131_072
MAX_INVOCATIONS = 32
MAX_TAG_BODY_CHARS = 8_192
MAX_ARGUMENTS_BYTES = 65_536
MAX_JSON_DEPTH = 32

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:/-]{0,127}$")

# Non-backtracking/bounded patterns for masking illustrative contexts.
_FENCED_BLOCK_RE = re.compile(r"(?:```|~~~)[^\n]*\n[\s\S]*?(?:```|~~~|$)")
_INLINE_BACKTICK_RE = re.compile(r"`[^`\n]{1,4096}`")
_BLOCKQUOTE_LINE_RE = re.compile(r"(?m)^[ \t]*>.*$")
_QUOTED_MARKUP_RE = re.compile(
    r"""(?P<q>["'])\s*<(?P<tag>tool_call|function_calls|function_call|tool_use|invoke)\b[\s\S]{0,4096}?</(?P=tag)\s*>\s*(?P=q)""",
    re.IGNORECASE,
)
_QUOTED_DSML_RE = re.compile(
    r"""(?P<q>["'])\s*<[｜|]{1,2}\s*DSML\s*[｜|]{1,2}\s*(?P<tag>[a-zA-Z_][\w-]*)[\s\S]{0,4096}?</[｜|]{1,2}\s*DSML\s*[｜|]{1,2}\s*(?P=tag)\s*>\s*(?P=q)""",
    re.IGNORECASE,
)

# DeepSeek DSML patterns (preserving existing fullwidth and generic DSML recognition).
_DSML_FULLWIDTH_RE = re.compile(r"</?[｜|]{1,2}\s*DSML\s*[｜|]{1,2}\s*([a-zA-Z_][\w-]*)([^>]{0,512})>")
_DSML_GENERIC_RE = re.compile(r"<[^>]{0,256}DSML[^>]{0,256}>", re.IGNORECASE)
_DSML_INVOKE_BLOCK_RE = re.compile(
    r"""<(?:[｜|]{1,2}\s*DSML\s*[｜|]{1,2}\s*)?invoke\b[^>]{0,512}\bname\s*=\s*(?:"([^"]{1,128})"|'([^']{1,128})')[^>]{0,256}>([\s\S]{0,8192}?)</(?:[｜|]{1,2}\s*DSML\s*[｜|]{1,2}\s*)?invoke\s*>""",
    re.IGNORECASE,
)
_DSML_INVOKE_OPEN_RE = re.compile(
    r"""<[｜|]{1,2}\s*DSML\s*[｜|]{1,2}\s*invoke\b[^>]{0,512}\bname\s*=\s*(?:"([^"]{1,128})"|'([^']{1,128})')""",
    re.IGNORECASE,
)

# Alternative XML-style invocation formats (require matching closing tag to avoid truncated false positives).
_XML_TOOL_CALL_RE = re.compile(
    r"<tool_call\b([^>]{0,512})>([\s\S]{0,8192}?)</tool_call\s*>",
    re.IGNORECASE,
)
_XML_FUNCTION_CALL_RE = re.compile(
    r"<function_call\b([^>]{0,512})>([\s\S]{0,8192}?)</function_call\s*>",
    re.IGNORECASE,
)
_XML_TOOL_USE_RE = re.compile(
    r"<tool_use\b([^>]{0,512})>([\s\S]{0,8192}?)</tool_use\s*>",
    re.IGNORECASE,
)
_XML_INVOKE_RE = re.compile(
    r"<invoke\b([^>]{0,512})>([\s\S]{0,8192}?)</invoke\s*>",
    re.IGNORECASE,
)

_ATTR_NAME_RE = re.compile(r"""\bname\s*=\s*(?:"([^"]{1,128})"|'([^']{1,128})')""", re.IGNORECASE)
_CHILD_NAME_RE = re.compile(r"<(?:name|tool_name|function_name)\s*>([^<]{1,128})</(?:name|tool_name|function_name)\s*>", re.IGNORECASE)
_CHILD_ARGS_RE = re.compile(
    r"<(?:arguments|args|input|parameters)\s*>([\s\S]{0,4096}?)</(?:arguments|args|input|parameters)\s*>",
    re.IGNORECASE,
)
_UNCLOSED_XML_OPEN_RE = re.compile(
    r"<(?:tool_call|function_call|function_calls|tool_use|invoke)\b",
    re.IGNORECASE,
)

ToolIntentFormat = Literal[
    "deepseek_dsml_fullwidth",
    "dsml_tag",
    "xml_tool_call",
    "xml_function_calls",
    "xml_function_call",
    "xml_tool_use",
    "mixed_tool_intent_markup",
]


class ExtractedToolInvocation(BaseModel):
    """Single bounded non-authoritative textual tool invocation record."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    format: str
    arguments_sha256: str | None = None


class ToolIntentSignal(BaseModel):
    """Normalized model-reported textual tool-intent signal (never verified execution)."""

    model_config = ConfigDict(extra="forbid")

    detected: bool
    source: Literal["response_output_dsml", "response_output_tool_intent"] = "response_output_tool_intent"
    format: ToolIntentFormat | None = None
    formats: list[str] = Field(default_factory=list)
    tag_count: int = 0
    invoke_count: int = 0
    invoked_tool_names: list[str] = Field(default_factory=list)
    invocations: list[ExtractedToolInvocation] = Field(default_factory=list)
    truncated: bool = False
    malformed_markup_seen: bool = False
    deduplicated_against_structured_count: int = 0
    provenance: Literal["model_reported"] = "model_reported"
    execution_verified: Literal[False] = False


def _sanitize_tool_name(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    cleaned = raw.strip()
    if not cleaned or not _TOOL_NAME_RE.fullmatch(cleaned):
        return None
    return cleaned


def _safe_utf8_bytes(text: str, *, max_bytes: int | None = MAX_ARGUMENTS_BYTES) -> bytes | None:
    """Encode string as strict UTF-8, returning None on unpaired surrogates or oversized input."""
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if max_bytes is not None and len(encoded) > max_bytes:
        return None
    return encoded


def _exceeds_json_depth(value: Any, *, max_depth: int = MAX_JSON_DEPTH) -> bool:
    """Iteratively check whether a parsed JSON value exceeds max_depth nesting."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            return True
        if isinstance(current, dict):
            for v in current.values():
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
        elif isinstance(current, list):
            for v in current:
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
    return False


def canonical_arguments_fingerprint(raw_args: Any) -> tuple[str | None, bool]:
    """Compute one consistent, bounded canonical SHA-256 fingerprint across Live HTTP, Offline Replay, and XML/DSML.

    Returns (fingerprint_sha256_or_None, malformed_flag).
    Never raises on unpaired Unicode surrogates, malformed JSON, or excessive nesting.
    """
    if raw_args is None:
        return None, False
    if isinstance(raw_args, str):
        stripped = raw_args.strip()
        if not stripped:
            return None, False
        if _safe_utf8_bytes(stripped) is None:
            return None, True
        try:
            parsed = json.loads(stripped)
        except (ValueError, RecursionError):
            # Non-JSON argument string (e.g. DSML XML body): hash normalized UTF-8 bytes.
            raw_bytes = _safe_utf8_bytes(stripped)
            if raw_bytes is None:
                return None, True
            return sha256(raw_bytes).hexdigest(), False
        if _exceeds_json_depth(parsed):
            return None, True
        try:
            canonical = json.dumps(parsed, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError, RecursionError):
            return None, True
        encoded = _safe_utf8_bytes(canonical)
        if encoded is None:
            return None, True
        return sha256(encoded).hexdigest(), False
    if isinstance(raw_args, (dict, list, bool, int, float)):
        if _exceeds_json_depth(raw_args):
            return None, True
        try:
            canonical = json.dumps(raw_args, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError, RecursionError):
            return None, True
        encoded = _safe_utf8_bytes(canonical)
        if encoded is None:
            return None, True
        return sha256(encoded).hexdigest(), False
    return None, True


def _hash_arguments(raw_args: Any) -> tuple[str | None, bool]:
    return canonical_arguments_fingerprint(raw_args)


def _mask_illustrative_contexts(text: str) -> str:
    """Replace fenced code blocks, inline code spans, blockquotes, and quoted markup with spaces."""
    masked = _FENCED_BLOCK_RE.sub(lambda m: " " * len(m.group(0)), text)
    masked = _BLOCKQUOTE_LINE_RE.sub(lambda m: " " * len(m.group(0)), masked)
    masked = _INLINE_BACKTICK_RE.sub(lambda m: " " * len(m.group(0)), masked)
    masked = _QUOTED_MARKUP_RE.sub(lambda m: " " * len(m.group(0)), masked)
    masked = _QUOTED_DSML_RE.sub(lambda m: " " * len(m.group(0)), masked)
    return masked


def _parse_xml_invocation(attrs: str, body: str) -> tuple[str | None, str | None, bool]:
    """Extract (tool_name, canonical_arguments_sha256, malformed) from XML tag attributes and inner body."""
    attr_match = _ATTR_NAME_RE.search(attrs)
    attr_name = _sanitize_tool_name(attr_match.group(1) or attr_match.group(2)) if attr_match else None
    stripped_body = body.strip()

    # 1. Try JSON payload inside body: {"name": "...", "arguments": {...}} or {"function": {"name": ...}}
    if stripped_body.startswith("{") and stripped_body.endswith("}"):
        try:
            payload = json.loads(stripped_body)
        except (ValueError, RecursionError):
            payload = None
        if isinstance(payload, dict):
            func_obj = payload.get("function") if isinstance(payload.get("function"), dict) else None
            raw_name = payload.get("name") or payload.get("tool") or (func_obj.get("name") if func_obj else None)
            json_name = _sanitize_tool_name(raw_name)
            raw_args = (
                payload.get("arguments")
                if "arguments" in payload
                else (
                    payload.get("parameters")
                    if "parameters" in payload
                    else (
                        payload.get("input")
                        if "input" in payload
                        else (func_obj.get("arguments") if func_obj and "arguments" in func_obj else None)
                    )
                )
            )
            chosen_name = attr_name or json_name
            if chosen_name is None:
                return None, None, True
            arg_fp, arg_malformed = _hash_arguments(raw_args)
            if arg_malformed:
                # Malformed Unicode surrogate / unserializable / excessively nested args -> fail safely.
                return None, None, True
            return chosen_name, arg_fp, False
        # Malformed JSON inside tool tag without valid attribute name -> fail closed.
        return None, None, True

    # 2. Try nested XML <name>...</name> and optional <arguments>...</arguments>
    child_name_match = _CHILD_NAME_RE.search(body)
    child_name = _sanitize_tool_name(child_name_match.group(1)) if child_name_match else None
    chosen_name = attr_name or child_name
    if chosen_name is None:
        return None, None, True

    child_args_match = _CHILD_ARGS_RE.search(body)
    if child_args_match:
        arg_fp, arg_malformed = _hash_arguments(child_args_match.group(1))
        if arg_malformed:
            return None, None, True
        return chosen_name, arg_fp, False
    if stripped_body:
        arg_fp, arg_malformed = _hash_arguments(stripped_body)
        if arg_malformed:
            return None, None, True
        return chosen_name, arg_fp, False
    return chosen_name, None, False


def extract_structured_tool_fingerprints(
    tool_calls: Any,
) -> list[tuple[str, str | None]]:
    """Build bounded (tool_name, canonical_arguments_fingerprint) pairs from raw OpenAI/offline tool_calls."""
    if not isinstance(tool_calls, list):
        return []
    pairs: list[tuple[str, str | None]] = []
    for call in tool_calls[:MAX_INVOCATIONS]:
        if not isinstance(call, dict):
            continue
        func = call.get("function") if isinstance(call.get("function"), dict) else {}
        raw_name = call.get("name") or func.get("name")
        name = _sanitize_tool_name(raw_name)
        if name is None:
            continue
        raw_args = call.get("arguments") if "arguments" in call else func.get("arguments")
        arg_fp, arg_malformed = canonical_arguments_fingerprint(raw_args)
        pairs.append((name, None if arg_malformed else arg_fp))
    return pairs


def extract_tool_intent_signals(
    output_text: Any,
    *,
    structured_events: Sequence[dict[str, Any]] = (),
    structured_fingerprints: Sequence[tuple[str, str | None]] | None = None,
) -> ToolIntentSignal:
    """Extract normalized textual tool-intent signals from model response text.

    Always returns provenance="model_reported" and execution_verified=False.
    """
    if not isinstance(output_text, str) or not output_text:
        return ToolIntentSignal(detected=False)
    scan_truncated = len(output_text) > MAX_SCAN_CHARS
    bounded_text = output_text[:MAX_SCAN_CHARS]
    if _safe_utf8_bytes(bounded_text, max_bytes=None) is None:
        # Unpaired Unicode surrogate directly in raw text: fail safely without fabricating intent.
        return ToolIntentSignal(detected=False, truncated=scan_truncated, malformed_markup_seen=True)
    masked = _mask_illustrative_contexts(bounded_text)

    # Collect (start_pos, ExtractedToolInvocation) so invocations stay ordered and bounded.
    found: list[tuple[int, ExtractedToolInvocation]] = []
    formats_seen: list[str] = []
    tag_count = 0
    malformed_seen = False

    def _note_format(fmt: str) -> None:
        if fmt not in formats_seen:
            formats_seen.append(fmt)

    # 1. DeepSeek DSML detection (outside illustrative contexts)
    fullwidth_matches = _DSML_FULLWIDTH_RE.findall(masked)
    generic_dsml_matches = _DSML_GENERIC_RE.findall(masked)
    dsml_detected = bool(fullwidth_matches or generic_dsml_matches)
    dsml_spans: list[tuple[int, int]] = []
    if dsml_detected:
        dsml_fmt = "deepseek_dsml_fullwidth" if fullwidth_matches else "dsml_tag"
        _note_format(dsml_fmt)
        tag_count += len(fullwidth_matches) if fullwidth_matches else len(generic_dsml_matches)
        for m in _DSML_INVOKE_BLOCK_RE.finditer(masked):
            tname = _sanitize_tool_name(m.group(1) or m.group(2))
            if tname is not None:
                arg_fp, arg_malformed = _hash_arguments(m.group(3))
                if arg_malformed:
                    malformed_seen = True
                    continue
                found.append(
                    (
                        m.start(),
                        ExtractedToolInvocation(
                            tool_name=tname,
                            format=dsml_fmt,
                            arguments_sha256=arg_fp,
                        ),
                    )
                )
                dsml_spans.append((m.start(), m.end()))
            if len(found) > MAX_INVOCATIONS:
                break
        # Fallback for DSML invokes without matching closing tag (preserves existing DSML tolerance).
        if not found:
            for m in _DSML_INVOKE_OPEN_RE.finditer(masked):
                tname = _sanitize_tool_name(m.group(1) or m.group(2))
                if tname is not None:
                    found.append(
                        (
                            m.start(),
                            ExtractedToolInvocation(tool_name=tname, format=dsml_fmt),
                        )
                    )
                if len(found) > MAX_INVOCATIONS:
                    break

    def _overlaps_dsml(start: int, end: int) -> bool:
        return any(s <= start < e or s < end <= e for s, e in dsml_spans)

    # 2. Alternative XML-style invocation formats (strict closing tag + valid tool identifier)
    xml_patterns: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("xml_tool_call", _XML_TOOL_CALL_RE),
        ("xml_function_call", _XML_FUNCTION_CALL_RE),
        ("xml_tool_use", _XML_TOOL_USE_RE),
        ("xml_function_calls", _XML_INVOKE_RE),
    )
    for fmt, pattern in xml_patterns:
        for m in pattern.finditer(masked):
            if _overlaps_dsml(m.start(), m.end()):
                continue
            tname, arg_hash, inv_malformed = _parse_xml_invocation(m.group(1), m.group(2))
            if inv_malformed or tname is None:
                malformed_seen = True
                continue
            _note_format(fmt)
            tag_count += 1
            found.append(
                (
                    m.start(),
                    ExtractedToolInvocation(
                        tool_name=tname,
                        format=fmt,
                        arguments_sha256=arg_hash,
                    ),
                )
            )
            if len(found) > MAX_INVOCATIONS:
                break
        if len(found) > MAX_INVOCATIONS:
            break

    # Detect unclosed/truncated XML invocation openings without fabricating a tool invocation.
    if not found and not dsml_detected and _UNCLOSED_XML_OPEN_RE.search(masked):
        malformed_seen = True

    if not dsml_detected and not found:
        return ToolIntentSignal(
            detected=False,
            truncated=scan_truncated,
            malformed_markup_seen=malformed_seen,
        )

    found.sort(key=lambda pair: pair[0])
    truncated = scan_truncated or len(found) > MAX_INVOCATIONS
    bounded_invocations = [inv for _, inv in found[:MAX_INVOCATIONS]]

    # 3. Single-budget exact deduplication against structured declared_tool_call invocations.
    #    - Matches ONLY on exact (tool_name, canonical_arguments_fingerprint) with non-None fingerprint.
    #    - Never relies on tool-name equality alone when arguments are missing or uncertain.
    #    - Each structured invocation consumes at most ONE matching textual invocation.
    pair_budget: dict[tuple[str, str], int] = {}
    if structured_fingerprints is not None:
        for sname, sfp in structured_fingerprints:
            clean_name = _sanitize_tool_name(sname)
            if clean_name is not None and isinstance(sfp, str) and sfp:
                key = (clean_name, sfp)
                pair_budget[key] = pair_budget.get(key, 0) + 1
    else:
        for ev in structured_events:
            if not isinstance(ev, dict) or ev.get("kind") != "declared_tool_call":
                continue
            sname = _sanitize_tool_name(ev.get("name"))
            if sname is None:
                continue
            sdata = ev.get("data") if isinstance(ev.get("data"), dict) else {}
            shash = sdata.get("canonical_arguments_sha256") or sdata.get("arguments_sha256")
            if isinstance(shash, str) and shash:
                key = (sname, shash)
                pair_budget[key] = pair_budget.get(key, 0) + 1

    deduped_count = 0
    if pair_budget:
        remaining: list[ExtractedToolInvocation] = []
        for inv in bounded_invocations:
            if inv.arguments_sha256 is not None:
                key = (inv.tool_name, inv.arguments_sha256)
                avail = pair_budget.get(key, 0)
                if avail > 0:
                    pair_budget[key] = avail - 1
                    deduped_count += 1
                    continue
            remaining.append(inv)
        bounded_invocations = remaining

    # If every textual invocation was an exact duplicate of structured declared_tool_call, suppress duplicate event.
    if deduped_count > 0 and not bounded_invocations:
        return ToolIntentSignal(
            detected=False,
            truncated=truncated,
            malformed_markup_seen=malformed_seen,
            deduplicated_against_structured_count=deduped_count,
        )

    is_dsml_only = bool(formats_seen) and all(f in {"deepseek_dsml_fullwidth", "dsml_tag"} for f in formats_seen)
    source: Literal["response_output_dsml", "response_output_tool_intent"] = (
        "response_output_dsml" if is_dsml_only else "response_output_tool_intent"
    )
    if len(formats_seen) == 1:
        primary_format: ToolIntentFormat = formats_seen[0]  # type: ignore[assignment]
    elif len(formats_seen) > 1:
        primary_format = "mixed_tool_intent_markup"
    else:
        primary_format = "dsml_tag"

    return ToolIntentSignal(
        detected=True,
        source=source,
        format=primary_format,
        formats=formats_seen[:8],
        tag_count=min(tag_count, 200),
        invoke_count=len(bounded_invocations),
        invoked_tool_names=[inv.tool_name for inv in bounded_invocations],
        invocations=bounded_invocations,
        truncated=truncated,
        malformed_markup_seen=malformed_seen,
        deduplicated_against_structured_count=deduped_count,
        provenance="model_reported",
        execution_verified=False,
    )


def build_tool_intent_event(
    signal: ToolIntentSignal,
    *,
    reference: str | None = None,
) -> dict[str, Any]:
    """Build a normalized model_reported_tool_intent Evidence event dict."""
    is_dsml = signal.source == "response_output_dsml"
    data: dict[str, Any] = {
        "provenance": "model_reported",
        "execution_verified": False,
        "observation_scope": "model_response_text",
        "execution_semantics": "model_text_intent",
        "verification_status": "model_reported_unverified",
        "format": signal.format,
        "formats": list(signal.formats),
        "tag_count": signal.tag_count,
        "invoke_count": signal.invoke_count,
        "invoked_tool_names": list(signal.invoked_tool_names),
    }
    if signal.truncated:
        data["truncated"] = True
    if signal.deduplicated_against_structured_count > 0:
        data["deduplicated_against_structured_count"] = signal.deduplicated_against_structured_count
    return {
        "kind": "model_reported_tool_intent",
        "source": signal.source,
        "name": "dsml_tool_invocation_markup" if is_dsml else "xml_tool_invocation_markup",
        "success": None,
        "reference": reference,
        "data": data,
    }
