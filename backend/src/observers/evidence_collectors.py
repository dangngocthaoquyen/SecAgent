"""Generic plugin/adapter Evidence Collection for Gate 3.

Supports response metadata, structured tool calls, HTTP callbacks, sandbox
command logs, file system artifacts, MCP handler receipts, and custom audit
logs within strictly configured scopes.

Guarantees:
- Distinguishes: model_reported, target_reported, adapter_observed,
  independently_verified.
- Never treats target-written logs as independently verified proof.
- Enforces run_id / case_id / execution_id / request_id / session_id
  correlation; uncorrelated items remain 'uncorrelated' (execution_verified=False).
- Tolerates collector failure/unavailability without crashing response-first
  evaluation.
- Rejects paths or URLs outside configured scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import urlparse

import httpx

from core.models.evidence import Evidence
from targets.validator import (
    ENV_CREDENTIAL_PATTERN,
    parse_header_credential_placeholder,
)
import os
import stat

ProvenanceTier = Literal[
    "model_reported",
    "target_reported",
    "adapter_observed",
    "independently_verified",
]


@dataclass(frozen=True)
class CollectorContext:
    run_id: str
    case_id: str
    execution_id: str
    target_id: str
    request_id: str | None = None
    session_id: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    allowed_roots: tuple[Path, ...] = ()
    allowed_endpoints: tuple[str, ...] = ()


@dataclass(frozen=True)
class CollectorDiagnostic:
    collector_id: str
    collector_kind: str
    status: Literal["collected", "empty", "uncorrelated", "unavailable", "error", "scope_rejected"]
    matched_count: int = 0
    uncorrelated_count: int = 0
    reason: str = ""


@dataclass
class CollectedEvidenceOutput:
    evidence: list[Evidence] = field(default_factory=list)
    diagnostics: list[CollectorDiagnostic] = field(default_factory=list)


class EvidenceCollector(Protocol):
    collector_id: str
    collector_kind: str

    def collect(self, context: CollectorContext) -> CollectedEvidenceOutput:
        """Collect and correlate evidence within configured scope."""


def _has_symlink_or_reparse(path: Path, stop_at: Path | None = None) -> bool:
    stop_resolved = stop_at.resolve() if stop_at is not None else None
    for part in (path, *path.parents):
        try:
            if part.is_symlink():
                return True
            if part.exists() and (getattr(part.stat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                return True
        except OSError:
            return True
        if stop_resolved is not None:
            try:
                if part.resolve() == stop_resolved:
                    break
            except OSError:
                return True
    return False


def _resolve_scoped_path(raw_path: str, allowed_roots: tuple[Path, ...]) -> Path:
    if not allowed_roots:
        raise PermissionError("No allowed filesystem roots configured for file/log collector.")
    raw_candidate = Path(raw_path)
    if not raw_candidate.is_absolute():
        raw_candidate = allowed_roots[0] / raw_candidate
    matched_root: Path | None = None
    candidate = raw_candidate.resolve()
    for root in allowed_roots:
        if _has_symlink_or_reparse(root):
            continue
        root_resolved = root.resolve()
        if candidate.is_relative_to(root_resolved):
            matched_root = root
            break
    if matched_root is None:
        raise PermissionError("Configured collector path escapes allowed sandbox roots.")
    if _has_symlink_or_reparse(raw_candidate, stop_at=matched_root):
        raise PermissionError("Symlink or reparse point in collector path is forbidden.")
    return candidate


def _validate_scoped_url(raw_url: str, allowed_endpoints: tuple[str, ...]) -> str:
    if not allowed_endpoints:
        raise PermissionError("No allowed endpoints configured for HTTP collector.")
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise PermissionError("Invalid HTTP collector URL.")
    normalized = raw_url.rstrip("/")
    allowed_norm = {ep.rstrip("/") for ep in allowed_endpoints}
    if normalized not in allowed_norm and f"{parsed.scheme}://{parsed.netloc}" not in allowed_norm:
        raise PermissionError("Collector endpoint is outside configured target scope.")
    return raw_url


def _resolve_auth_headers(headers: dict[str, str]) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for key, val in headers.items():
        if not isinstance(key, str) or not isinstance(val, str):
            raise PermissionError("Collector header names and values must be strings.")
        try:
            parsed = parse_header_credential_placeholder(val)
        except ValueError as exc:
            raise PermissionError(str(exc)) from exc
        if parsed is not None:
            prefix, env_name = parsed
            secret = os.environ.get(env_name)
            if secret is None or not secret.strip():
                raise PermissionError(f"Collector credential {env_name!r} unavailable.")
            clean_secret = secret.strip() if prefix else secret
            if "\r" in clean_secret or "\n" in clean_secret:
                raise PermissionError(f"Collector credential {env_name!r} contains invalid control characters.")
            resolved[key] = f"{prefix}{clean_secret}"
        else:
            resolved[key] = val
    return resolved


def _correlate_record(
    entry: dict[str, Any],
    context: CollectorContext,
    correlation_fields: tuple[str, ...],
) -> tuple[bool, str, str | None, Literal["none", "weak", "strong"]]:
    """Correlate a structured record against CollectorContext.

    Rules:
    - Reject immediately if ANY provided correlation identifier conflicts with
      the non-empty context value for that field (cross-run / cross-case /
      cross-execution / cross-request / cross-session contradiction).
    - Weak correlation: exactly 1 field matches with zero conflicts. Can never
      be promoted to ``independently_verified`` or ``execution_verified=True``.
    - Strong correlation: >= 2 distinct fields match with zero conflicts,
      requiring ``run_id`` plus at least one of (``case_id``, ``execution_id``,
      ``request_id``, ``session_id``) whenever ``run_id`` is in scope.
    """
    expected: dict[str, str | None] = {
        "run_id": context.run_id,
        "case_id": context.case_id,
        "execution_id": context.execution_id,
        "request_id": context.request_id,
        "session_id": context.session_id,
    }
    fields_to_check = tuple(dict.fromkeys([*correlation_fields, *expected.keys()]))
    matched_pairs: list[tuple[str, str]] = []
    for field_name in fields_to_check:
        exp = expected.get(field_name)
        actual = entry.get(field_name)
        if isinstance(actual, str) and actual.strip():
            actual_clean = actual.strip()
            if exp and actual_clean != exp:
                return False, f"mismatched_{field_name}", actual_clean, "none"
            if exp and actual_clean == exp and field_name in correlation_fields:
                matched_pairs.append((field_name, actual_clean))
    if not matched_pairs:
        return False, "missing_correlation_id", None, "none"

    matched_keys = {k for k, _ in matched_pairs}
    has_run = "run_id" in matched_keys or "run_id" not in correlation_fields
    strength: Literal["weak", "strong"] = (
        "strong" if (len(matched_pairs) >= 2 and has_run) else "weak"
    )
    mech_str = ",".join(f"{k}={v}" for k, v in matched_pairs)
    return True, mech_str, matched_pairs[0][1], strength


def _normalized_provenance(configured: str, *, can_verify_independently: bool) -> tuple[ProvenanceTier, bool]:
    # Target-written logs/callbacks are never promoted to independently_verified unless
    # the collector itself represents a trusted independent/sandbox verifier.
    if configured == "independently_verified" and can_verify_independently:
        return "independently_verified", True
    if configured == "adapter_observed":
        return "adapter_observed", False
    if configured == "model_reported":
        return "model_reported", False
    return "target_reported", False


def _load_json_or_jsonl_rows(raw_bytes: bytes) -> list[dict[str, Any]]:
    text = raw_bytes.decode("utf-8-sig").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except ValueError:
        rows: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            if isinstance(item, dict):
                rows.append(item)
        return rows
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    if isinstance(parsed, dict):
        for list_key in ("items", "events", "records", "logs", "entries"):
            if isinstance(parsed.get(list_key), list):
                return [item for item in parsed[list_key] if isinstance(item, dict)]
        return [parsed]
    return []


class SandboxLogFileCollector:
    """Collects generic JSON/JSONL sandbox command logs, custom audit logs, or MCP receipts."""

    def __init__(
        self,
        *,
        collector_id: str,
        collector_kind: str = "sandbox_command_log",
        file_path: str,
        provenance: ProvenanceTier = "target_reported",
        independent_verifier: bool = False,
        correlation_fields: tuple[str, ...] = ("run_id", "case_id", "execution_id", "request_id", "session_id"),
        action_field: str = "action",
        claimed_action_field: str = "claimed_action",
        timestamp_field: str = "timestamp",
        source_name: str = "sandbox_log_collector",
    ) -> None:
        self.collector_id = collector_id
        self.collector_kind = collector_kind
        self._file_path = file_path
        self._provenance = provenance
        self._independent_verifier = independent_verifier
        self._correlation_fields = correlation_fields
        self._action_field = action_field
        self._claimed_action_field = claimed_action_field
        self._timestamp_field = timestamp_field
        self._source_name = source_name

    def collect(self, context: CollectorContext) -> CollectedEvidenceOutput:
        try:
            scoped = _resolve_scoped_path(self._file_path, context.allowed_roots)
        except PermissionError as exc:
            return CollectedEvidenceOutput(
                diagnostics=[CollectorDiagnostic(self.collector_id, self.collector_kind, "scope_rejected", reason=str(exc))]
            )
        if not scoped.is_file():
            return CollectedEvidenceOutput(
                diagnostics=[CollectorDiagnostic(self.collector_id, self.collector_kind, "unavailable", reason="Configured log file not found.")]
            )
        try:
            raw_bytes = scoped.read_bytes()
            rows = _load_json_or_jsonl_rows(raw_bytes)
        except (OSError, UnicodeError, ValueError) as exc:
            return CollectedEvidenceOutput(
                diagnostics=[CollectorDiagnostic(self.collector_id, self.collector_kind, "error", reason=f"Log parse failed: {type(exc).__name__}")]
            )
        if not rows:
            return CollectedEvidenceOutput(
                diagnostics=[CollectorDiagnostic(self.collector_id, self.collector_kind, "empty", reason="Log file contained no entries.")]
            )

        file_sha = sha256(raw_bytes).hexdigest()
        ev_items: list[Evidence] = []
        matched = 0
        uncorrelated = 0
        prov_tier, default_verified = _normalized_provenance(
            self._provenance, can_verify_independently=self._independent_verifier
        )
        for idx, row in enumerate(rows[:200]):
            is_match, mech, _corr_val, corr_strength = _correlate_record(row, context, self._correlation_fields)
            observed_action = row.get(self._action_field) or row.get("command") or row.get("tool") or row.get("observed_action")
            claimed_action = row.get(self._claimed_action_field)
            ts = row.get(self._timestamp_field)
            entry_sha = sha256(json.dumps(row, sort_keys=True, default=str).encode("utf-8")).hexdigest()
            explicit_exec = (
                row.get("executed") is True
                or row.get("execution_verified") is True
                or row.get("success") is True
            )
            if is_match:
                matched += 1
                if corr_strength == "strong" and default_verified:
                    tier = prov_tier
                    exec_verified = explicit_exec
                    corr_status = "matched"
                    ver_status = "verified" if exec_verified else f"{tier}_unverified"
                elif default_verified:
                    # Single-ID correlation is insufficient for independently_verified proof.
                    tier = "adapter_observed"
                    exec_verified = False
                    corr_status = "matched"
                    ver_status = "weak_correlation_not_verified"
                else:
                    tier = prov_tier
                    exec_verified = False
                    corr_status = "matched"
                    ver_status = f"{tier}_unverified"
            else:
                uncorrelated += 1
                exec_verified = False
                corr_status = "uncorrelated"
                tier = "target_reported" if prov_tier == "independently_verified" else prov_tier
                ver_status = "uncorrelated_not_verified"
            ev_items.append(
                Evidence(
                    kind="collected_evidence",
                    source=self._source_name,
                    name=self.collector_id,
                    success=bool(row.get("success")) if is_match and isinstance(row.get("success"), bool) else None,
                    reference=f"{self.collector_id}:{idx}:{entry_sha[:16]}",
                    data={
                        "collector_id": self.collector_id,
                        "collector_kind": self.collector_kind,
                        "provenance": tier,
                        "execution_verified": exec_verified,
                        "correlation_status": corr_status,
                        "correlation_strength": corr_strength,
                        "correlation_mechanism": str(mech),
                        "verification_status": ver_status,
                        "claimed_action": str(claimed_action) if claimed_action is not None else "",
                        "observed_action": str(observed_action) if observed_action is not None else "",
                        "timestamp": str(ts) if ts is not None else "",
                        "integrity_reference": f"sha256:{file_sha}",
                        "run_id": context.run_id if is_match else "",
                        "case_id": context.case_id if is_match else "",
                    },
                )
            )
        status: Literal["collected", "uncorrelated"] = "collected" if matched > 0 else "uncorrelated"
        return CollectedEvidenceOutput(
            evidence=ev_items,
            diagnostics=[
                CollectorDiagnostic(
                    self.collector_id,
                    self.collector_kind,
                    status,
                    matched_count=matched,
                    uncorrelated_count=uncorrelated,
                    reason="Matched correlated log records." if matched else "No log records matched current run/case.",
                )
            ],
        )


class FileArtifactCollector:
    """Checks a scoped file system artifact produced during execution."""

    def __init__(
        self,
        *,
        collector_id: str,
        file_path: str,
        provenance: ProvenanceTier = "independently_verified",
        independent_verifier: bool = True,
    ) -> None:
        self.collector_id = collector_id
        self.collector_kind = "file_artifact"
        self._file_path = file_path
        self._provenance = provenance
        self._independent_verifier = independent_verifier

    def collect(self, context: CollectorContext) -> CollectedEvidenceOutput:
        try:
            scoped = _resolve_scoped_path(self._file_path, context.allowed_roots)
        except PermissionError as exc:
            return CollectedEvidenceOutput(
                diagnostics=[CollectorDiagnostic(self.collector_id, self.collector_kind, "scope_rejected", reason=str(exc))]
            )
        if not scoped.is_file():
            return CollectedEvidenceOutput(
                diagnostics=[CollectorDiagnostic(self.collector_id, self.collector_kind, "empty", reason="Configured artifact path does not exist.")]
            )
        raw_bytes = scoped.read_bytes()
        digest = sha256(raw_bytes).hexdigest()
        text_preview = raw_bytes.decode("utf-8", errors="ignore")
        base_tier, allow_verified = _normalized_provenance(
            self._provenance, can_verify_independently=self._independent_verifier
        )

        # Plain text marker/ID occurrences are NEVER sufficient to mark execution_verified=True.
        # Verified execution requires:
        # 1) trusted independent verifier configuration,
        # 2) structured JSON attestation with strong correlation (>=2 non-conflicting context IDs incl. run_id),
        # 3) explicit verified effect/execution + observed effect description (and digest match if declared).
        parsed_obj: dict[str, Any] | None = None
        try:
            loaded = json.loads(raw_bytes.decode("utf-8-sig"))
            if isinstance(loaded, dict):
                parsed_obj = loaded
        except (UnicodeError, ValueError):
            parsed_obj = None

        corr_strength: Literal["none", "weak", "strong"] = "none"
        corr_status = "uncorrelated"
        corr_mech = "missing_correlation_id"
        tier: ProvenanceTier = "target_reported" if base_tier == "target_reported" else "adapter_observed"
        exec_verified = False
        ver_status = "uncorrelated_not_verified"
        observed_effect = scoped.name

        if parsed_obj is not None:
            is_match, mech, _val, corr_strength = _correlate_record(
                parsed_obj,
                context,
                ("run_id", "case_id", "execution_id", "request_id", "session_id"),
            )
            corr_mech = str(mech)
            effect_flag = (
                parsed_obj.get("effect_verified") is True
                or parsed_obj.get("execution_verified") is True
                or parsed_obj.get("executed") is True
            )
            effect_desc = parsed_obj.get("observed_effect") or parsed_obj.get("action") or parsed_obj.get("command")
            has_effect_desc = isinstance(effect_desc, str) and bool(effect_desc.strip())
            if has_effect_desc:
                observed_effect = effect_desc.strip()

            artifact_ok = True
            declared_target = parsed_obj.get("artifact_path")
            declared_sha = parsed_obj.get("artifact_sha256")
            if isinstance(declared_target, str) and declared_target.strip():
                try:
                    art_path = _resolve_scoped_path(declared_target.strip(), context.allowed_roots)
                    if not art_path.is_file():
                        artifact_ok = False
                    elif isinstance(declared_sha, str) and declared_sha.strip():
                        actual_art_sha = sha256(art_path.read_bytes()).hexdigest()
                        if actual_art_sha != declared_sha.strip().lower():
                            artifact_ok = False
                except PermissionError:
                    artifact_ok = False

            if is_match:
                corr_status = "matched"
                if allow_verified and corr_strength == "strong" and effect_flag and has_effect_desc and artifact_ok:
                    tier = "independently_verified"
                    exec_verified = True
                    ver_status = "verified_artifact"
                elif allow_verified:
                    tier = "adapter_observed"
                    exec_verified = False
                    ver_status = (
                        "weak_correlation_not_verified"
                        if corr_strength != "strong"
                        else "artifact_observed_unverified"
                    )
                else:
                    tier = "target_reported" if base_tier == "target_reported" else "adapter_observed"
                    exec_verified = False
                    ver_status = "target_reported_unverified"
            else:
                tier = "target_reported" if base_tier == "target_reported" else "adapter_observed"
                ver_status = "uncorrelated_not_verified"
        else:
            has_token = any(
                token and token in text_preview
                for token in (context.run_id, context.case_id, context.execution_id, context.request_id)
            )
            corr_mech = "plain_marker_token_only" if has_token else "missing_correlation_id"
            ver_status = "marker_only_not_verified" if has_token else "artifact_observed_unverified"
            tier = "target_reported" if base_tier == "target_reported" else "adapter_observed"

        matched_diag = corr_status == "matched"
        ev = Evidence(
            kind="collected_evidence",
            source="file_artifact_collector",
            name=self.collector_id,
            success=True if exec_verified else None,
            reference=f"{self.collector_id}:sha256:{digest[:16]}",
            data={
                "collector_id": self.collector_id,
                "collector_kind": self.collector_kind,
                "provenance": tier,
                "execution_verified": exec_verified,
                "correlation_status": corr_status,
                "correlation_strength": corr_strength,
                "correlation_mechanism": corr_mech,
                "verification_status": ver_status,
                "observed_action": observed_effect,
                "artifact_file": scoped.name,
                "integrity_reference": f"sha256:{digest}",
            },
        )
        return CollectedEvidenceOutput(
            evidence=[ev],
            diagnostics=[
                CollectorDiagnostic(
                    self.collector_id,
                    self.collector_kind,
                    "collected" if matched_diag else "uncorrelated",
                    matched_count=1 if matched_diag else 0,
                    uncorrelated_count=0 if matched_diag else 1,
                    reason="" if matched_diag else f"Artifact not independently verified ({corr_mech}).",
                )
            ],
        )


class HttpCallbackCollector:
    """Fetches scoped HTTP callback / target audit endpoints and correlates rows."""

    def __init__(
        self,
        *,
        collector_id: str,
        url: str,
        headers: dict[str, str] | None = None,
        timeout_seconds: float = 3.0,
        provenance: ProvenanceTier = "target_reported",
        independent_verifier: bool = False,
        correlation_fields: tuple[str, ...] = ("run_id", "case_id", "execution_id", "request_id", "session_id"),
        client: httpx.Client | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.collector_id = collector_id
        self.collector_kind = "http_callback"
        self._url = url
        self._headers = dict(headers or {})
        self._timeout = timeout_seconds
        self._provenance = provenance
        self._independent_verifier = independent_verifier
        self._correlation_fields = correlation_fields
        self._client = client
        self._transport = transport

    def collect(self, context: CollectorContext) -> CollectedEvidenceOutput:
        try:
            url = _validate_scoped_url(self._url, context.allowed_endpoints)
            resolved_headers = _resolve_auth_headers(self._headers)
        except PermissionError as exc:
            return CollectedEvidenceOutput(
                diagnostics=[CollectorDiagnostic(self.collector_id, self.collector_kind, "scope_rejected", reason=str(exc))]
            )
        try:
            if self._client is not None:
                resp = self._client.get(url, headers=resolved_headers, timeout=self._timeout)
            else:
                with httpx.Client(transport=self._transport, trust_env=False, follow_redirects=False) as client:
                    resp = client.get(url, headers=resolved_headers, timeout=self._timeout)
            if resp.status_code >= 400:
                return CollectedEvidenceOutput(
                    diagnostics=[CollectorDiagnostic(self.collector_id, self.collector_kind, "unavailable", reason=f"HTTP {resp.status_code}")]
                )
            rows = _load_json_or_jsonl_rows(resp.content)
        except Exception as exc:
            return CollectedEvidenceOutput(
                diagnostics=[CollectorDiagnostic(self.collector_id, self.collector_kind, "error", reason=f"HTTP collector error: {type(exc).__name__}")]
            )
        if not rows:
            return CollectedEvidenceOutput(
                diagnostics=[CollectorDiagnostic(self.collector_id, self.collector_kind, "empty", reason="HTTP callback endpoint returned zero records.")]
            )

        tier, default_verified = _normalized_provenance(self._provenance, can_verify_independently=self._independent_verifier)
        ev_items: list[Evidence] = []
        matched = 0
        uncorrelated = 0
        for idx, row in enumerate(rows[:200]):
            is_match, mech, _corr_val, corr_strength = _correlate_record(row, context, self._correlation_fields)
            entry_sha = sha256(json.dumps(row, sort_keys=True, default=str).encode("utf-8")).hexdigest()
            explicit_exec = (
                row.get("executed") is True
                or row.get("execution_verified") is True
                or row.get("success") is True
            )
            if is_match:
                matched += 1
                if corr_strength == "strong" and default_verified:
                    row_tier = tier
                    exec_verified = explicit_exec
                    ver_status = "verified_callback" if exec_verified else f"{tier}_unverified"
                elif default_verified:
                    row_tier = "adapter_observed"
                    exec_verified = False
                    ver_status = "weak_correlation_not_verified"
                else:
                    row_tier = tier
                    exec_verified = False
                    ver_status = "target_reported_unverified"
            else:
                uncorrelated += 1
                row_tier = "target_reported" if tier == "independently_verified" else tier
                exec_verified = False
                ver_status = "uncorrelated_not_verified"
            ev_items.append(
                Evidence(
                    kind="collected_evidence",
                    source="http_callback_collector",
                    name=self.collector_id,
                    success=bool(row.get("success")) if is_match and isinstance(row.get("success"), bool) else None,
                    reference=f"{self.collector_id}:{idx}:{entry_sha[:16]}",
                    data={
                        "collector_id": self.collector_id,
                        "collector_kind": self.collector_kind,
                        "provenance": row_tier,
                        "execution_verified": exec_verified,
                        "correlation_status": "matched" if is_match else "uncorrelated",
                        "correlation_strength": corr_strength,
                        "correlation_mechanism": str(mech),
                        "verification_status": ver_status,
                        "observed_action": str(row.get("action") or row.get("method") or row.get("path") or ""),
                        "timestamp": str(row.get("timestamp") or ""),
                        "integrity_reference": f"sha256:{entry_sha}",
                    },
                )
            )
        return CollectedEvidenceOutput(
            evidence=ev_items,
            diagnostics=[
                CollectorDiagnostic(
                    self.collector_id,
                    self.collector_kind,
                    "collected" if matched else "uncorrelated",
                    matched_count=matched,
                    uncorrelated_count=uncorrelated,
                )
            ],
        )


def build_collector_from_spec(spec: dict[str, Any]) -> EvidenceCollector:
    """Instantiate a declarative collector config from TargetProfile.evidence_sources."""
    kind = str(spec.get("kind") or "").strip()
    cid = str(spec.get("id") or kind or "collector")
    prov = spec.get("provenance", "target_reported")
    independent = bool(spec.get("independent_verifier", False))
    corr_fields = tuple(spec.get("correlation_fields") or ("run_id", "case_id", "execution_id", "request_id", "session_id"))

    if kind in {"sandbox_command_log", "custom_audit_log", "mcp_handler_receipt"}:
        source_map = {
            "sandbox_command_log": "sandbox_log_collector",
            "custom_audit_log": "custom_audit_log_collector",
            "mcp_handler_receipt": "mcp_receipt_collector",
        }
        return SandboxLogFileCollector(
            collector_id=cid,
            collector_kind=kind,
            file_path=str(spec["path"]),
            provenance=prov,
            independent_verifier=independent,
            correlation_fields=corr_fields,
            action_field=str(spec.get("action_field", "action")),
            claimed_action_field=str(spec.get("claimed_action_field", "claimed_action")),
            timestamp_field=str(spec.get("timestamp_field", "timestamp")),
            source_name=source_map[kind],
        )
    if kind == "file_artifact":
        return FileArtifactCollector(
            collector_id=cid,
            file_path=str(spec["path"]),
            provenance=prov,
            independent_verifier=independent,
        )
    if kind == "http_callback":
        return HttpCallbackCollector(
            collector_id=cid,
            url=str(spec["url"]),
            headers=spec.get("headers") if isinstance(spec.get("headers"), dict) else None,
            timeout_seconds=float(spec.get("timeout_seconds", 3.0)),
            provenance=prov,
            independent_verifier=independent,
            correlation_fields=corr_fields,
        )
    raise ValueError(f"Unsupported evidence collector kind: {kind!r}")


def collect_target_evidence(
    collectors: list[EvidenceCollector],
    context: CollectorContext,
) -> CollectedEvidenceOutput:
    """Execute optional collectors fault-tolerantly without failing response evaluation."""
    combined = CollectedEvidenceOutput()
    for collector in collectors:
        try:
            out = collector.collect(context)
            combined.evidence.extend(out.evidence)
            combined.diagnostics.extend(out.diagnostics)
        except Exception as exc:
            combined.diagnostics.append(
                CollectorDiagnostic(
                    collector_id=getattr(collector, "collector_id", "unknown"),
                    collector_kind=getattr(collector, "collector_kind", "unknown"),
                    status="error",
                    reason=f"Collector raised unhandled error: {type(exc).__name__}",
                )
            )
    return combined
