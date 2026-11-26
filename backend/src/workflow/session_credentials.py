"""Process-memory-only session credential store for authorized local HTTP targets.

Credentials stored here live strictly in Backend RAM, are bound to an explicit
scope (target, discovery, or draft) and exact validated destination origin
(scheme://host:port), are never persisted to disk or catalogs, never echoed in
responses, and never fall back to os.environ.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import re
import secrets
from threading import RLock
from typing import Literal
from urllib.parse import urlsplit

from targets.adapters.http_adapter import format_bearer_header_value

MAX_SESSION_CREDENTIALS = 64
MAX_SECRET_LENGTH = 4096
SESSION_REF_PATTERN = re.compile(r"^sess_[a-f0-9]{24}$")
SUPPORTED_API_KEY_HEADER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")

DISALLOWED_API_KEY_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "content-type",
    "content-length",
    "host",
    "connection",
    "transfer-encoding",
    "accept",
    "accept-encoding",
    "user-agent",
    "origin",
    "referer",
    "sec-fetch-site",
    "x-secagent-operator",
    "x-secagent-validation",
})


class SessionCredentialError(ValueError):
    """Raised when session credential validation, binding, or resolution fails closed."""

    def __init__(self, code: str, message: str | None = None) -> None:
        super().__init__(message or code)
        self.code = code


def validate_api_key_header_name(header_name: str) -> str:
    """Validate an operator-supplied API key header name (e.g. X-API-Key)."""
    if not isinstance(header_name, str):
        raise SessionCredentialError("invalid_session_credential_header", "API key header name must be a string.")
    cleaned = header_name.strip()
    if not SUPPORTED_API_KEY_HEADER_RE.fullmatch(cleaned):
        raise SessionCredentialError(
            "invalid_session_credential_header",
            "API key header name must contain only ASCII letters, digits, and hyphens.",
        )
    if cleaned.lower() in DISALLOWED_API_KEY_HEADERS:
        raise SessionCredentialError(
            "invalid_session_credential_header",
            f"Header '{cleaned}' is not permitted as an API key header.",
        )
    return cleaned


def canonical_bound_origin(endpoint: str) -> str:
    """Validate an authorized local/private HTTP endpoint and return exact scheme://host:port."""
    if not isinstance(endpoint, str) or not endpoint.strip() or len(endpoint) > 256:
        raise SessionCredentialError("invalid_session_credential_origin", "Endpoint URL is invalid.")
    raw = endpoint.strip()
    parts = urlsplit(raw)
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or "?" in raw
        or "#" in raw
        or "%" in raw
        or not parts.path.startswith("/")
        or "//" in parts.path
        or any(seg in {".", ".."} for seg in parts.path.split("/"))
    ):
        raise SessionCredentialError("invalid_session_credential_origin", "Endpoint URL is not a valid local target URL.")

    hostname = parts.hostname.lower()
    try:
        host_ip = ipaddress.ip_address(hostname)
        safe = (
            (host_ip.is_loopback or host_ip.is_private)
            and not host_ip.is_link_local
            and not host_ip.is_multicast
            and not host_ip.is_unspecified
        )
        formatted_host = f"[{host_ip.compressed}]" if host_ip.version == 6 else host_ip.compressed
    except ValueError:
        safe = hostname == "localhost"
        formatted_host = hostname

    if not safe:
        raise SessionCredentialError(
            "unsafe_session_credential_origin",
            "Session credentials may only bind to authorized loopback, localhost, or private IP origins.",
        )

    try:
        port = parts.port
    except ValueError as exc:
        raise SessionCredentialError("invalid_session_credential_origin", "Invalid port in endpoint URL.") from exc
    effective_port = port if port is not None else (443 if parts.scheme == "https" else 80)
    return f"{parts.scheme.lower()}://{formatted_host}:{effective_port}"


def _redaction_variants(auth_type: Literal["bearer", "api_key"], raw_secret: str) -> list[str]:
    variants: list[str] = []
    cleaned = raw_secret.strip()
    for item in (raw_secret, cleaned):
        if item and item not in variants:
            variants.append(item)
    if auth_type == "bearer" and cleaned:
        stripped = re.sub(r"(?i)^Bearer\s+", "", cleaned).strip()
        if stripped and stripped not in variants:
            variants.append(stripped)
        try:
            formatted = format_bearer_header_value(cleaned)
            if formatted and formatted not in variants:
                variants.append(formatted)
        except ValueError:
            pass
    return variants


@dataclass(frozen=True)
class _SessionCredentialRecord:
    ref_id: str
    scope_kind: Literal["target", "discovery", "draft"]
    scope_id: str
    bound_origin: str
    auth_type: Literal["bearer", "api_key"]
    header_name: str
    secret_value: str
    generation: str
    updated_at: str

    def public_metadata(self) -> dict[str, object]:
        return {
            "ref_id": self.ref_id,
            "scope_kind": self.scope_kind,
            "scope_id": self.scope_id,
            "bound_origin": self.bound_origin,
            "auth_type": self.auth_type,
            "header_name": self.header_name,
            "available": True,
            "source": "session_memory",
            "generation": self.generation,
            "updated_at": self.updated_at,
        }


class SessionCredentialStore:
    """Thread-safe, bounded, process-memory-only credential store."""

    def __init__(self, *, max_entries: int = MAX_SESSION_CREDENTIALS) -> None:
        self._lock = RLock()
        self._max_entries = max(1, int(max_entries))
        self._records: dict[str, _SessionCredentialRecord] = {}

    def set_credential(
        self,
        *,
        scope_kind: Literal["target", "discovery", "draft"],
        scope_id: str,
        endpoint: str,
        auth_type: Literal["bearer", "api_key"],
        secret_value: str,
        header_name: str | None = None,
        ref_id: str | None = None,
    ) -> dict[str, object]:
        if scope_kind not in {"target", "discovery", "draft"}:
            raise SessionCredentialError("invalid_session_credential_scope")
        if not isinstance(scope_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", scope_id):
            raise SessionCredentialError("invalid_session_credential_scope")
        bound_origin = canonical_bound_origin(endpoint)
        if auth_type not in {"bearer", "api_key"}:
            raise SessionCredentialError("invalid_session_credential_type")
        if auth_type == "bearer":
            resolved_header = "Authorization"
            if header_name is not None and header_name.strip().lower() != "authorization":
                raise SessionCredentialError("invalid_session_credential_header")
        else:
            resolved_header = validate_api_key_header_name(header_name or "X-API-Key")

        if not isinstance(secret_value, str) or not secret_value.strip():
            raise SessionCredentialError("invalid_session_credential_value", "Credential value must not be empty.")
        if len(secret_value) > MAX_SECRET_LENGTH:
            raise SessionCredentialError("session_credential_too_large", "Credential value exceeds maximum size.")
        if any(ord(c) < 32 or ord(c) == 127 for c in secret_value):
            raise SessionCredentialError("invalid_session_credential_value", "Credential value contains invalid control characters.")
        cleaned_secret = secret_value.strip()
        if auth_type == "bearer":
            try:
                format_bearer_header_value(cleaned_secret)
            except ValueError as exc:
                raise SessionCredentialError("invalid_session_credential_value", str(exc)) from exc

        with self._lock:
            if ref_id is not None:
                if not isinstance(ref_id, str) or not SESSION_REF_PATTERN.fullmatch(ref_id):
                    raise SessionCredentialError("invalid_session_credential_ref")
                existing = self._records.get(ref_id)
                if existing is not None and (existing.scope_kind != scope_kind or existing.scope_id != scope_id):
                    raise SessionCredentialError("session_credential_scope_mismatch")
                resolved_ref = ref_id
            else:
                resolved_ref = f"sess_{secrets.token_hex(12)}"

            if resolved_ref not in self._records and len(self._records) >= self._max_entries:
                raise SessionCredentialError(
                    "session_credential_capacity_exceeded",
                    "Session credential store capacity reached; clear unused session credentials first.",
                )

            rec = _SessionCredentialRecord(
                ref_id=resolved_ref,
                scope_kind=scope_kind,
                scope_id=scope_id,
                bound_origin=bound_origin,
                auth_type=auth_type,
                header_name=resolved_header,
                secret_value=cleaned_secret,
                generation=secrets.token_hex(16),
                updated_at=datetime.now(timezone.utc).isoformat(),
            )
            self._records[resolved_ref] = rec
            return rec.public_metadata()

    def clear_credential(
        self,
        ref_id: str,
        *,
        scope_id: str | None = None,
        scope_kind: Literal["target", "discovery", "draft"] | None = None,
    ) -> bool:
        if not isinstance(ref_id, str) or not SESSION_REF_PATTERN.fullmatch(ref_id):
            return False
        with self._lock:
            existing = self._records.get(ref_id)
            if existing is None:
                return False
            if scope_kind is not None and existing.scope_kind != scope_kind:
                raise SessionCredentialError("session_credential_scope_mismatch")
            if scope_id is not None and existing.scope_id != scope_id:
                raise SessionCredentialError("session_credential_scope_mismatch")
            self._records.pop(ref_id, None)
            return True

    def clear_for_scope(self, scope_kind: Literal["target", "discovery", "draft"], scope_id: str) -> int:
        with self._lock:
            to_remove = [
                rid
                for rid, rec in self._records.items()
                if rec.scope_kind == scope_kind and rec.scope_id == scope_id
            ]
            for rid in to_remove:
                self._records.pop(rid, None)
            return len(to_remove)

    def count(self) -> int:
        with self._lock:
            return len(self._records)

    def snapshot_record(self, ref_id: str) -> _SessionCredentialRecord | None:
        with self._lock:
            return self._records.get(ref_id)

    def restore_record(self, ref_id: str, snapshot: _SessionCredentialRecord | None) -> None:
        with self._lock:
            if snapshot is None:
                self._records.pop(ref_id, None)
            else:
                self._records[ref_id] = snapshot

    def validate_rebind_to_target(
        self,
        ref_id: str,
        *,
        endpoint: str,
        expected_auth_type: Literal["bearer", "api_key"],
        expected_header_name: str,
        allowed_scope_ids: set[str] | None = None,
        allowed_scopes: set[tuple[str, str]] | None = None,
    ) -> bool:
        """Read-only validation of credential ownership, scope kind/id, origin, and header before committing."""
        if not isinstance(ref_id, str) or not SESSION_REF_PATTERN.fullmatch(ref_id):
            raise SessionCredentialError("invalid_session_credential_ref")
        target_origin = canonical_bound_origin(endpoint)
        with self._lock:
            existing = self._records.get(ref_id)
            if existing is None:
                return False
            if allowed_scopes is not None:
                if (existing.scope_kind, existing.scope_id) not in allowed_scopes:
                    raise SessionCredentialError("session_credential_scope_mismatch")
            elif allowed_scope_ids is not None and existing.scope_id not in allowed_scope_ids:
                raise SessionCredentialError("session_credential_scope_mismatch")
            if existing.bound_origin != target_origin:
                raise SessionCredentialError("session_credential_origin_mismatch")
            if existing.auth_type != expected_auth_type or existing.header_name.lower() != expected_header_name.lower():
                raise SessionCredentialError("session_credential_header_mismatch")
            return True

    def rebind_to_target(
        self,
        ref_id: str,
        *,
        target_id: str,
        endpoint: str,
        expected_auth_type: Literal["bearer", "api_key"],
        expected_header_name: str,
        allowed_scope_ids: set[str] | None = None,
        allowed_scopes: set[tuple[str, str]] | None = None,
    ) -> dict[str, object] | None:
        """Bind a discovery/draft/target session credential strictly to a saved target and exact origin."""
        target_origin = canonical_bound_origin(endpoint)
        with self._lock:
            present = self.validate_rebind_to_target(
                ref_id,
                endpoint=endpoint,
                expected_auth_type=expected_auth_type,
                expected_header_name=expected_header_name,
                allowed_scope_ids=allowed_scope_ids,
                allowed_scopes=allowed_scopes,
            )
            if not present:
                # Allow saving/re-saving a target whose session credential is currently unavailable
                # (e.g., after Backend restart); runtime requests still fail closed until re-supplied.
                return None
            existing = self._records[ref_id]
            updated = _SessionCredentialRecord(
                ref_id=existing.ref_id,
                scope_kind="target",
                scope_id=target_id,
                bound_origin=target_origin,
                auth_type=existing.auth_type,
                header_name=expected_header_name,
                secret_value=existing.secret_value,
                generation=existing.generation,
                updated_at=existing.updated_at,
            )
            self._records[ref_id] = updated
            return updated.public_metadata()

    def _matched_record(
        self,
        ref_id: str,
        *,
        endpoint: str,
        scope_id: str | None = None,
        scope_kind: Literal["target", "discovery", "draft"] | None = None,
        expected_auth_type: Literal["bearer", "api_key"] | None = None,
        expected_header_name: str | None = None,
    ) -> _SessionCredentialRecord | None:
        if not isinstance(ref_id, str) or not SESSION_REF_PATTERN.fullmatch(ref_id):
            return None
        try:
            expected_origin = canonical_bound_origin(endpoint)
        except SessionCredentialError:
            return None
        with self._lock:
            rec = self._records.get(ref_id)
            if rec is None:
                return None
            if rec.bound_origin != expected_origin:
                return None
            if scope_kind is not None and rec.scope_kind != scope_kind:
                return None
            if scope_id is not None and rec.scope_id != scope_id:
                return None
            if expected_auth_type is not None and rec.auth_type != expected_auth_type:
                return None
            if expected_header_name is not None and rec.header_name.lower() != expected_header_name.lower():
                return None
            return rec

    def availability(
        self,
        ref_id: str,
        *,
        endpoint: str,
        scope_id: str | None = None,
        scope_kind: Literal["target", "discovery", "draft"] | None = None,
        expected_auth_type: Literal["bearer", "api_key"] | None = None,
        expected_header_name: str | None = None,
    ) -> Literal["available", "unavailable"]:
        rec = self._matched_record(
            ref_id,
            endpoint=endpoint,
            scope_id=scope_id,
            scope_kind=scope_kind,
            expected_auth_type=expected_auth_type,
            expected_header_name=expected_header_name,
        )
        return "available" if rec is not None else "unavailable"

    def generation(
        self,
        ref_id: str,
        *,
        endpoint: str,
        scope_id: str | None = None,
        scope_kind: Literal["target", "discovery", "draft"] | None = None,
    ) -> str | None:
        rec = self._matched_record(ref_id, endpoint=endpoint, scope_id=scope_id, scope_kind=scope_kind)
        return rec.generation if rec is not None else None

    def resolve(
        self,
        ref_id: str,
        *,
        endpoint: str,
        scope_id: str | None = None,
        scope_kind: Literal["target", "discovery", "draft"] | None = None,
        expected_auth_type: Literal["bearer", "api_key"] | None = None,
        expected_header_name: str | None = None,
    ) -> tuple[str, str, list[str]]:
        """Resolve a session credential fail-closed with strict origin and scope binding."""
        if not isinstance(ref_id, str) or not SESSION_REF_PATTERN.fullmatch(ref_id):
            raise SessionCredentialError("invalid_session_credential_ref")
        expected_origin = canonical_bound_origin(endpoint)
        with self._lock:
            rec = self._records.get(ref_id)
            if rec is None:
                raise SessionCredentialError("session_credential_unavailable")
            if rec.bound_origin != expected_origin:
                raise SessionCredentialError("session_credential_origin_mismatch")
            if scope_kind is not None and rec.scope_kind != scope_kind:
                raise SessionCredentialError("session_credential_scope_mismatch")
            if scope_id is not None and rec.scope_id != scope_id:
                raise SessionCredentialError("session_credential_scope_mismatch")
            if expected_auth_type is not None and rec.auth_type != expected_auth_type:
                raise SessionCredentialError("session_credential_header_mismatch")
            if expected_header_name is not None and rec.header_name.lower() != expected_header_name.lower():
                raise SessionCredentialError("session_credential_header_mismatch")
            return rec.header_name, rec.secret_value, _redaction_variants(rec.auth_type, rec.secret_value)

    def secrets_for_redaction(self, ref_id: str | None = None) -> list[str]:
        """Return secret variants for redaction only; never expose directly in API responses."""
        with self._lock:
            out: list[str] = []
            records = (
                [self._records[ref_id]]
                if ref_id is not None and ref_id in self._records
                else list(self._records.values())
            )
            for rec in records:
                for variant in _redaction_variants(rec.auth_type, rec.secret_value):
                    if variant not in out:
                        out.append(variant)
            return out
