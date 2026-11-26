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

from core.models.evidence import (
    BOUNDED_EXECUTION_SEMANTICS,
    Evidence,
    NEGATIVE_CORRELATION_STATUSES,
    NEGATIVE_CORRELATION_STRENGTHS,
    NEGATIVE_VERIFICATION_STATUSES,
    NON_EXECUTION_SEMANTICS,
)
from targets.adapters.http_evidence import (
    _extract_optional_path,
    _hash_bounded_value,
    _safe_scalar_text,
    build_event_fingerprint,
)
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
    target_correlation_id: str | None = None
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


def _evaluate_execution_flags(
    row: dict[str, Any], *, include_effect_verified: bool = False
) -> tuple[bool, bool]:
    """Evaluate explicit execution verification flags separately from action success.

    Rules:
    - Execution and action success are distinct concepts: an action can execute
      and subsequently fail (executed=True, success=False -> verified execution
      with unsuccessful action outcome).
    - Explicit negative execution assertions (executed=False,
      execution_verified=False, or effect_verified=False) fail closed and are
      never overridden by success=True or another positive execution flag.
    - Malformed non-boolean execution fields fail closed with conflict=True.
    - Generic success=True alone does not prove execution without an explicit
      execution verification field.

    Returns (execution_confirmed, has_conflict).
    """
    exec_keys = (
        ("effect_verified", "execution_verified", "executed")
        if include_effect_verified
        else ("execution_verified", "executed")
    )
    for k in exec_keys:
        val = row.get(k)
        if val is not None and type(val) is not bool:
            return False, True
    has_explicit_false = any(row.get(k) is False for k in exec_keys)
    has_explicit_true = any(row.get(k) is True for k in exec_keys)
    if has_explicit_false:
        has_conflict = has_explicit_true or (row.get("success") is True)
        return False, has_conflict
    if has_explicit_true:
        return True, False
    return False, False


def _extract_execution_semantics(row: dict[str, Any]) -> tuple[str | None, bool, bool]:
    """Extract bounded execution_semantics without crashing on malformed types.

    Returns (bounded_semantics, is_non_execution_semantics, is_malformed).
    """
    raw = row.get("execution_semantics")
    if raw is None:
        return None, False, False
    if not isinstance(raw, str):
        return None, False, True
    clean = raw.strip()
    if not clean:
        return None, False, False
    norm = clean.lower()
    if norm in NON_EXECUTION_SEMANTICS:
        return norm, True, False
    if clean in BOUNDED_EXECUTION_SEMANTICS:
        return clean, False, False
    return None, False, False


def _inspect_row_verification_constraints(
    row: dict[str, Any], *, is_effect_collector: bool
) -> dict[str, Any]:
    """Inspect negative, contradictory, or malformed verification/correlation fields on a collector row.

    Contract-specific semantics:
    - Malformed non-scalar types (e.g., effect_observed=[], correlation_valid="true",
      verification_status=[]) always fail closed with conflicting_execution_metadata.
    - Explicit correlation_valid=False or negative correlation_status/correlation_strength
      fail closed and are preserved rather than overwritten by normalization.
    - Explicit negative verification_status (e.g., conflicting_execution_metadata,
      *_unverified, *_not_verified) fails closed and is preserved.
    - Explicit effect_verified=False is preserved and prevents verified-execution promotion
      (conflicting_execution_metadata for FileArtifactCollector; effect_not_verified for
      command/callback log collectors).
    - Boolean effect_observed=False and success=False do NOT block verified execution in
      command/callback logs (SandboxLogFileCollector / HttpCallbackCollector), whereas
      effect_observed=False contradicts verified effect in FileArtifactCollector.
    """
    malformed = False
    for bool_key in ("correlation_valid", "effect_observed", "effect_verified", "synthetic_mock"):
        val = row.get(bool_key)
        if val is not None and type(val) is not bool:
            malformed = True
    for str_key in ("verification_status", "correlation_status", "correlation_strength"):
        val = row.get(str_key)
        if val is not None and not isinstance(val, str):
            malformed = True

    neg_corr_valid = row.get("correlation_valid") is False
    raw_cs = row.get("correlation_status")
    neg_corr_status = (
        isinstance(raw_cs, str) and raw_cs.strip().lower() in NEGATIVE_CORRELATION_STATUSES
    )
    raw_cstr = row.get("correlation_strength")
    neg_corr_strength = (
        isinstance(raw_cstr, str) and raw_cstr.strip().lower() in NEGATIVE_CORRELATION_STRENGTHS
    )

    raw_vs = row.get("verification_status")
    neg_ver_status: str | None = None
    if isinstance(raw_vs, str) and raw_vs.strip():
        norm_vs = raw_vs.strip().lower()
        if (
            norm_vs in NEGATIVE_VERIFICATION_STATUSES
            or norm_vs.endswith("_unverified")
            or norm_vs.endswith("_not_verified")
            or norm_vs.startswith("conflicting_")
        ):
            neg_ver_status = raw_vs.strip()[:128]

    effect_verified_false = row.get("effect_verified") is False
    effect_observed_false_blocked = is_effect_collector and row.get("effect_observed") is False

    blocked = (
        malformed
        or neg_corr_valid
        or neg_corr_status
        or neg_corr_strength
        or neg_ver_status is not None
        or effect_verified_false
        or effect_observed_false_blocked
    )
    return {
        "blocked": blocked,
        "malformed": malformed,
        "neg_corr_valid": neg_corr_valid,
        "neg_corr_status": neg_corr_status,
        "neg_corr_strength": neg_corr_strength,
        "neg_ver_status": neg_ver_status,
        "effect_verified_false": effect_verified_false,
        "effect_observed_false_blocked": effect_observed_false_blocked,
    }


def _load_json_or_jsonl_rows(
    raw_bytes: bytes,
    *,
    items_path: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    text = raw_bytes.decode("utf-8-sig").strip()
    if not text:
        return [], None
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
        return rows, None
    root_obj = parsed if isinstance(parsed, dict) else None
    if isinstance(items_path, str) and items_path.strip():
        nested = _extract_optional_path(parsed, items_path.strip())
        if isinstance(nested, list):
            return [item for item in nested if isinstance(item, dict)], root_obj
        if isinstance(nested, dict):
            return [nested], root_obj
        return [], root_obj
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)], None
    if isinstance(parsed, dict):
        for list_key in ("items", "events", "records", "logs", "entries"):
            if isinstance(parsed.get(list_key), list):
                return [item for item in parsed[list_key] if isinstance(item, dict)], root_obj
        return [parsed], root_obj
    return [], None


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
            rows, _ = _load_json_or_jsonl_rows(raw_bytes)
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
            explicit_exec, exec_conflict = _evaluate_execution_flags(
                row, include_effect_verified=False
            )
            exec_sem, is_non_exec_sem, sem_malformed = _extract_execution_semantics(row)
            constraints = _inspect_row_verification_constraints(row, is_effect_collector=False)
            if sem_malformed or constraints["malformed"]:
                explicit_exec = False
                exec_conflict = True
            elif constraints["blocked"]:
                explicit_exec = False
            elif is_non_exec_sem:
                explicit_exec = False
            elif exec_sem == "simulated_handler_effect" and row.get("synthetic_mock") is not True:
                explicit_exec = False
            if is_match:
                matched += 1
                if corr_strength == "strong" and default_verified:
                    if explicit_exec:
                        tier = prov_tier
                        exec_verified = True
                        ver_status = (
                            "verified_simulated_effect"
                            if exec_sem == "simulated_handler_effect"
                            else "verified"
                        )
                        corr_status = "matched"
                    else:
                        # Unverified independent collector observations downgrade conservatively
                        # from independently_verified while preserving correlation and status.
                        exec_verified = False
                        if constraints["neg_corr_valid"] or constraints["neg_corr_status"]:
                            tier = "target_reported"
                            corr_status = "uncorrelated"
                            ver_status = constraints["neg_ver_status"] or "uncorrelated_not_verified"
                        elif constraints["neg_corr_strength"]:
                            tier = "adapter_observed"
                            corr_status = "matched"
                            ver_status = constraints["neg_ver_status"] or "weak_correlation_not_verified"
                        else:
                            tier = "adapter_observed"
                            corr_status = "matched"
                            if exec_conflict:
                                ver_status = "conflicting_execution_metadata"
                            elif constraints["neg_ver_status"] is not None:
                                ver_status = constraints["neg_ver_status"]
                            elif constraints["effect_verified_false"]:
                                ver_status = "effect_not_verified"
                            elif exec_sem == "simulated_handler_invocation":
                                ver_status = "handler_invocation_not_verified_effect"
                            elif is_non_exec_sem:
                                ver_status = "declared_not_verified_execution"
                            else:
                                ver_status = "sandbox_log_unverified"
                elif default_verified:
                    # Single-ID correlation is insufficient for independently_verified proof.
                    tier = "adapter_observed"
                    exec_verified = False
                    corr_status = (
                        "uncorrelated"
                        if (constraints["neg_corr_valid"] or constraints["neg_corr_status"])
                        else "matched"
                    )
                    ver_status = (
                        constraints["neg_ver_status"]
                        or ("uncorrelated_not_verified" if corr_status == "uncorrelated" else "weak_correlation_not_verified")
                    )
                else:
                    tier = prov_tier
                    exec_verified = False
                    corr_status = (
                        "uncorrelated"
                        if (constraints["neg_corr_valid"] or constraints["neg_corr_status"])
                        else "matched"
                    )
                    ver_status = (
                        "conflicting_execution_metadata"
                        if exec_conflict
                        else (constraints["neg_ver_status"] or f"{tier}_unverified")
                    )
            else:
                uncorrelated += 1
                exec_verified = False
                corr_status = "uncorrelated"
                tier = "target_reported" if prov_tier == "independently_verified" else prov_tier
                ver_status = "uncorrelated_not_verified"
            item_data: dict[str, Any] = {
                "collector_id": self.collector_id,
                "collector_kind": self.collector_kind,
                "provenance": tier,
                "execution_verified": exec_verified,
                "correlation_status": corr_status,
                "correlation_strength": "none" if corr_status == "uncorrelated" else corr_strength,
                "correlation_mechanism": str(mech),
                "verification_status": ver_status,
                "claimed_action": str(claimed_action) if claimed_action is not None else "",
                "observed_action": str(observed_action) if observed_action is not None else "",
                "timestamp": str(ts) if ts is not None else "",
                "integrity_reference": f"sha256:{file_sha}",
                "run_id": context.run_id if is_match else "",
                "case_id": context.case_id if is_match else "",
            }
            if exec_sem is not None:
                item_data["execution_semantics"] = exec_sem
            if row.get("synthetic_mock") is True:
                item_data["synthetic_mock"] = True
            if constraints["effect_verified_false"]:
                item_data["effect_verified"] = False
            if constraints["neg_corr_valid"]:
                item_data["correlation_valid"] = False
            ev_items.append(
                Evidence(
                    kind="collected_evidence",
                    source=self._source_name,
                    name=self.collector_id,
                    success=bool(row.get("success")) if is_match and isinstance(row.get("success"), bool) else None,
                    reference=f"{self.collector_id}:{idx}:{entry_sha[:16]}",
                    data=item_data,
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
            effect_flag, exec_conflict = _evaluate_execution_flags(
                parsed_obj, include_effect_verified=True
            )
            exec_sem, non_effect_semantics, sem_malformed = _extract_execution_semantics(parsed_obj)
            constraints = _inspect_row_verification_constraints(parsed_obj, is_effect_collector=True)
            if sem_malformed or constraints["malformed"]:
                effect_flag = False
                exec_conflict = True
            if constraints["effect_observed_false_blocked"]:
                if effect_flag:
                    exec_conflict = True
                effect_flag = False
            if constraints["blocked"]:
                effect_flag = False
            if non_effect_semantics:
                effect_flag = False
            elif exec_sem == "simulated_handler_effect" and parsed_obj.get("synthetic_mock") is not True:
                effect_flag = False
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
                corr_status = (
                    "uncorrelated"
                    if (constraints["neg_corr_valid"] or constraints["neg_corr_status"])
                    else "matched"
                )
                if allow_verified and corr_status == "matched" and corr_strength == "strong" and effect_flag and has_effect_desc and artifact_ok:
                    tier = "independently_verified"
                    exec_verified = True
                    ver_status = "verified_artifact"
                elif allow_verified:
                    tier = "target_reported" if corr_status == "uncorrelated" else "adapter_observed"
                    exec_verified = False
                    if corr_status == "uncorrelated":
                        ver_status = constraints["neg_ver_status"] or "uncorrelated_not_verified"
                    elif exec_conflict:
                        ver_status = "conflicting_execution_metadata"
                    elif constraints["neg_ver_status"] is not None:
                        ver_status = constraints["neg_ver_status"]
                    elif corr_strength != "strong" or constraints["neg_corr_strength"]:
                        ver_status = "weak_correlation_not_verified"
                    elif non_effect_semantics:
                        ver_status = "handler_invocation_not_verified_effect"
                    else:
                        ver_status = "artifact_observed_unverified"
                else:
                    tier = "target_reported" if base_tier == "target_reported" else "adapter_observed"
                    exec_verified = False
                    ver_status = (
                        "conflicting_execution_metadata"
                        if exec_conflict
                        else "target_reported_unverified"
                    )
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
        action_success = (
            bool(parsed_obj.get("success"))
            if parsed_obj is not None and matched_diag and isinstance(parsed_obj.get("success"), bool)
            else (True if exec_verified else None)
        )
        fa_data: dict[str, Any] = {
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
        }
        if parsed_obj is not None:
            for corr_key in ("run_id", "case_id", "execution_id", "request_id", "session_id"):
                raw_corr_val = parsed_obj.get(corr_key)
                if isinstance(raw_corr_val, str) and raw_corr_val.strip():
                    fa_data[corr_key] = raw_corr_val.strip()
            fa_sem, _, _ = _extract_execution_semantics(parsed_obj)
            if fa_sem is not None:
                fa_data["execution_semantics"] = fa_sem
            if parsed_obj.get("synthetic_mock") is True:
                fa_data["synthetic_mock"] = True
            if parsed_obj.get("effect_verified") is False:
                fa_data["effect_verified"] = False
            if parsed_obj.get("correlation_valid") is False:
                fa_data["correlation_valid"] = False
        ev = Evidence(
            kind="collected_evidence",
            source="file_artifact_collector",
            name=self.collector_id,
            success=action_success,
            reference=f"{self.collector_id}:sha256:{digest[:16]}",
            data=fa_data,
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
        mapping: dict[str, Any] | None = None,
        max_response_bytes: int = 262144,
        max_events: int = 200,
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
        self._mapping = dict(mapping) if isinstance(mapping, dict) else {}
        self._max_response_bytes = max(256, min(1048576, int(max_response_bytes)))
        self._max_events = max(1, min(500, int(max_events)))
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
            def _read_bounded_stream(http_client: httpx.Client) -> tuple[int, bytes | None]:
                if hasattr(http_client, "stream"):
                    with http_client.stream("GET", url, headers=resolved_headers, timeout=self._timeout) as resp:
                        if 300 <= resp.status_code < 400:
                            return resp.status_code, None
                        if resp.status_code >= 400:
                            return resp.status_code, b""
                        buf = bytearray()
                        for chunk in resp.iter_bytes():
                            if len(buf) + len(chunk) > self._max_response_bytes:
                                return -1, None
                            buf.extend(chunk)
                        return resp.status_code, bytes(buf)
                resp = http_client.get(url, headers=resolved_headers, timeout=self._timeout)
                if 300 <= resp.status_code < 400:
                    return resp.status_code, None
                if resp.status_code >= 400:
                    return resp.status_code, b""
                if len(resp.content) > self._max_response_bytes:
                    return -1, None
                return resp.status_code, resp.content

            if self._client is not None:
                status_code, raw_content = _read_bounded_stream(self._client)
            else:
                with httpx.Client(transport=self._transport, trust_env=False, follow_redirects=False) as client:
                    status_code, raw_content = _read_bounded_stream(client)
            if status_code == -1:
                return CollectedEvidenceOutput(
                    diagnostics=[CollectorDiagnostic(self.collector_id, self.collector_kind, "error", reason="HTTP collector response exceeded max_response_bytes.")]
                )
            if 300 <= status_code < 400 or raw_content is None:
                return CollectedEvidenceOutput(
                    diagnostics=[CollectorDiagnostic(self.collector_id, self.collector_kind, "scope_rejected", reason=f"HTTP redirect rejected ({status_code}).")]
                )
            if status_code >= 400:
                return CollectedEvidenceOutput(
                    diagnostics=[CollectorDiagnostic(self.collector_id, self.collector_kind, "unavailable", reason=f"HTTP {status_code}")]
                )
            items_path = self._mapping.get("items") if isinstance(self._mapping.get("items"), str) else None
            rows, root_obj = _load_json_or_jsonl_rows(raw_content, items_path=items_path)
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
        map_event_id = self._mapping.get("event_id") if isinstance(self._mapping.get("event_id"), str) else None
        map_request_id = self._mapping.get("request_id") if isinstance(self._mapping.get("request_id"), str) else None
        map_corr_id = (
            self._mapping.get("correlation_id")
            if isinstance(self._mapping.get("correlation_id"), str)
            else None
        )
        map_inv_id = self._mapping.get("invocation_id") if isinstance(self._mapping.get("invocation_id"), str) else None
        map_ts = self._mapping.get("timestamp") if isinstance(self._mapping.get("timestamp"), str) else None
        map_tool = (
            self._mapping.get("tool")
            if isinstance(self._mapping.get("tool"), str)
            else (self._mapping.get("action") if isinstance(self._mapping.get("action"), str) else None)
        )
        map_content = (
            self._mapping.get("content")
            if isinstance(self._mapping.get("content"), str)
            else (self._mapping.get("observation") if isinstance(self._mapping.get("observation"), str) else None)
        )
        map_args = self._mapping.get("arguments") if isinstance(self._mapping.get("arguments"), str) else None
        map_decision = self._mapping.get("decision") if isinstance(self._mapping.get("decision"), str) else None
        map_status = self._mapping.get("status") if isinstance(self._mapping.get("status"), str) else None
        # Configurable target correlation path ONLY (never hardcoded 'run_id').
        root_target_corr = (
            _safe_scalar_text(_extract_optional_path(root_obj, map_corr_id), max_len=128)
            if (map_corr_id and isinstance(root_obj, dict))
            else None
        )

        for idx, row in enumerate(rows[: self._max_events]):
            corr_row = dict(row)
            req_conflict = False
            if map_request_id:
                mapped_req = _safe_scalar_text(_extract_optional_path(row, map_request_id), max_len=128)
                existing_req = _safe_scalar_text(row.get("request_id"), max_len=128)
                if mapped_req and existing_req and mapped_req != existing_req:
                    req_conflict = True
                elif mapped_req and "request_id" not in corr_row:
                    corr_row["request_id"] = mapped_req

            sec_match, sec_mech, _corr_val, sec_strength = _correlate_record(
                corr_row, context, self._correlation_fields
            )
            sec_mismatch = (not sec_match) and str(sec_mech).startswith("mismatched_")

            # Strictly separate target correlation ID from SecAgent request/run IDs.
            # Never fall back from map_request_id to target correlation, and never
            # inherit context.target_correlation_id when target correlation is missing.
            event_target_corr = (
                _safe_scalar_text(_extract_optional_path(row, map_corr_id), max_len=128)
                if map_corr_id
                else None
            )
            target_corr_conflict = (
                event_target_corr is not None
                and root_target_corr is not None
                and event_target_corr != root_target_corr
            )
            row_target_corr = event_target_corr or root_target_corr
            target_corr_match = (
                not target_corr_conflict
                and row_target_corr is not None
                and context.target_correlation_id is not None
                and row_target_corr == context.target_correlation_id
            )
            target_corr_mismatch = (
                not target_corr_conflict
                and row_target_corr is not None
                and context.target_correlation_id is not None
                and row_target_corr != context.target_correlation_id
            )

            matched_via_target_corr_only = False
            if req_conflict:
                is_match = False
                mech = "conflicting_request_id"
                corr_strength = "none"
            elif target_corr_conflict:
                is_match = False
                mech = "conflicting_target_correlation_id"
                corr_strength = "none"
            elif target_corr_mismatch:
                is_match = False
                mech = "mismatched_target_correlation_id"
                corr_strength = "none"
            elif sec_mismatch:
                is_match = False
                mech = str(sec_mech)
                corr_strength = "none"
            elif sec_match:
                is_match = True
                corr_strength = sec_strength
                mech = (
                    f"{sec_mech},target_correlation_id={row_target_corr}"
                    if target_corr_match
                    else str(sec_mech)
                )
            elif target_corr_match:
                # Target-reported run association only: always weak and never promotable
                # to independently_verified or execution_verified=True.
                is_match = True
                corr_strength = "weak"
                mech = f"target_correlation_id={row_target_corr}"
                matched_via_target_corr_only = True
            else:
                is_match = False
                mech = str(sec_mech)
                corr_strength = "none"
            entry_sha = sha256(json.dumps(row, sort_keys=True, default=str).encode("utf-8")).hexdigest()
            explicit_exec, exec_conflict = _evaluate_execution_flags(
                row, include_effect_verified=False
            )
            exec_sem, is_non_exec_sem, sem_malformed = _extract_execution_semantics(row)
            constraints = _inspect_row_verification_constraints(row, is_effect_collector=False)
            if sem_malformed or constraints["malformed"]:
                explicit_exec = False
                exec_conflict = True
            elif constraints["blocked"]:
                explicit_exec = False
            elif is_non_exec_sem:
                explicit_exec = False
            elif exec_sem == "simulated_handler_effect" and row.get("synthetic_mock") is not True:
                explicit_exec = False
            if is_match:
                matched += 1
                if matched_via_target_corr_only:
                    # Target-reported correlation match must NEVER establish
                    # independently_verified provenance or execution_verified=True.
                    row_tier = "target_reported"
                    exec_verified = False
                    corr_status_cb = (
                        "uncorrelated"
                        if (constraints["neg_corr_valid"] or constraints["neg_corr_status"])
                        else "matched"
                    )
                    ver_status = (
                        "conflicting_execution_metadata"
                        if exec_conflict
                        else (constraints["neg_ver_status"] or "target_reported_unverified")
                    )
                elif corr_strength == "strong" and default_verified:
                    if explicit_exec:
                        row_tier = tier
                        exec_verified = True
                        corr_status_cb = "matched"
                        ver_status = (
                            "verified_simulated_effect"
                            if exec_sem == "simulated_handler_effect"
                            else "verified_callback"
                        )
                    else:
                        exec_verified = False
                        if constraints["neg_corr_valid"] or constraints["neg_corr_status"]:
                            row_tier = "target_reported"
                            corr_status_cb = "uncorrelated"
                            ver_status = constraints["neg_ver_status"] or "uncorrelated_not_verified"
                        elif constraints["neg_corr_strength"]:
                            row_tier = "adapter_observed"
                            corr_status_cb = "matched"
                            ver_status = constraints["neg_ver_status"] or "weak_correlation_not_verified"
                        else:
                            row_tier = "adapter_observed"
                            corr_status_cb = "matched"
                            if exec_conflict:
                                ver_status = "conflicting_execution_metadata"
                            elif constraints["neg_ver_status"] is not None:
                                ver_status = constraints["neg_ver_status"]
                            elif constraints["effect_verified_false"]:
                                ver_status = "effect_not_verified"
                            elif exec_sem == "simulated_handler_invocation":
                                ver_status = "handler_invocation_not_verified_effect"
                            elif is_non_exec_sem:
                                ver_status = "declared_not_verified_execution"
                            else:
                                ver_status = "callback_unverified"
                elif default_verified:
                    row_tier = "adapter_observed"
                    exec_verified = False
                    corr_status_cb = (
                        "uncorrelated"
                        if (constraints["neg_corr_valid"] or constraints["neg_corr_status"])
                        else "matched"
                    )
                    ver_status = (
                        constraints["neg_ver_status"]
                        or ("uncorrelated_not_verified" if corr_status_cb == "uncorrelated" else "weak_correlation_not_verified")
                    )
                else:
                    row_tier = tier
                    exec_verified = False
                    corr_status_cb = (
                        "uncorrelated"
                        if (constraints["neg_corr_valid"] or constraints["neg_corr_status"])
                        else "matched"
                    )
                    ver_status = (
                        "conflicting_execution_metadata"
                        if exec_conflict
                        else (constraints["neg_ver_status"] or "target_reported_unverified")
                    )
            else:
                uncorrelated += 1
                row_tier = "target_reported" if tier == "independently_verified" else tier
                exec_verified = False
                corr_status_cb = "uncorrelated"
                ver_status = "uncorrelated_not_verified"

            mapped_action = (
                _safe_scalar_text(_extract_optional_path(row, map_tool), max_len=128)
                if map_tool
                else None
            ) or str(row.get("action") or row.get("method") or row.get("path") or "")
            mapped_ts = (
                _safe_scalar_text(_extract_optional_path(row, map_ts), max_len=64)
                if map_ts
                else None
            ) or str(row.get("timestamp") or "")
            mapped_ev_id = (
                _safe_scalar_text(_extract_optional_path(row, map_event_id), max_len=128)
                if map_event_id
                else (_safe_scalar_text(_extract_optional_path(row, map_inv_id), max_len=128) if map_inv_id else None)
            )
            mapped_args = _extract_optional_path(row, map_args) if map_args else None
            mapped_obs = _extract_optional_path(row, map_content) if map_content else None
            args_sha, args_inc = _hash_bounded_value(mapped_args) if mapped_args is not None else (None, False)
            obs_sha, obs_inc = _hash_bounded_value(mapped_obs) if mapped_obs is not None else (None, False)
            mapped_dec = _safe_scalar_text(_extract_optional_path(row, map_decision), max_len=64) if map_decision else None
            mapped_st = _safe_scalar_text(_extract_optional_path(row, map_status), max_len=64) if map_status else None
            # Only fingerprint events with explicit event_id and complete hashes,
            # using the event's OWN correlation ID (never falling back to context).
            fp = (
                build_event_fingerprint(
                    event_id=mapped_ev_id,
                    action=mapped_action or None,
                    arguments_sha256=args_sha,
                    decision=mapped_dec,
                    status=mapped_st,
                    observation_sha256=obs_sha,
                    timestamp=mapped_ts or None,
                    target_correlation_id=row_target_corr,
                    incomplete=(args_inc or obs_inc),
                )
                if self._mapping
                else None
            )

            cb_data: dict[str, Any] = {
                "collector_id": self.collector_id,
                "collector_kind": self.collector_kind,
                "provenance": row_tier,
                "execution_verified": exec_verified,
                "correlation_status": corr_status_cb,
                "correlation_strength": "none" if corr_status_cb == "uncorrelated" else corr_strength,
                "correlation_mechanism": str(mech),
                "verification_status": ver_status,
                "observed_action": mapped_action,
                "timestamp": mapped_ts,
                "integrity_reference": f"sha256:{entry_sha}",
            }
            if mapped_ev_id is not None:
                cb_data["event_id"] = mapped_ev_id
            for corr_key in ("run_id", "case_id", "execution_id", "request_id", "session_id"):
                raw_corr_val = row.get(corr_key)
                if isinstance(raw_corr_val, str) and raw_corr_val.strip():
                    cb_data[corr_key] = raw_corr_val.strip()
            if row_target_corr is not None:
                cb_data["target_correlation_id"] = row_target_corr
            if fp is not None:
                cb_data["event_fingerprint"] = fp
            if exec_sem is not None:
                cb_data["execution_semantics"] = exec_sem
            if row.get("synthetic_mock") is True:
                cb_data["synthetic_mock"] = True
            if constraints["effect_verified_false"]:
                cb_data["effect_verified"] = False
            if constraints["neg_corr_valid"]:
                cb_data["correlation_valid"] = False
            ev_items.append(
                Evidence(
                    kind="collected_evidence",
                    source="http_callback_collector",
                    name=self.collector_id,
                    success=bool(row.get("success")) if is_match and isinstance(row.get("success"), bool) else None,
                    reference=f"{self.collector_id}:{idx}:{entry_sha[:16]}",
                    data=cb_data,
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
            mapping=spec.get("mapping") if isinstance(spec.get("mapping"), dict) else None,
            max_response_bytes=int(spec.get("max_response_bytes", 262144)),
            max_events=int(spec.get("max_events", 200)),
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
