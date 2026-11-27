"""Shared in-process Target Execution Lock Registry for canonical and legacy workflows.

Prevents concurrent live executions against the same logical target ID OR the same
canonical physical HTTP/MCP endpoint across GenericRunService, GenerateAndRunOrchestrator,
GenericImportedBatchWorkflow, and McpActionWorkflow, while allowing independent targets
on distinct logical IDs and physical endpoints to run concurrently.

Scope & Limitation:
- Enforces thread-safe mutual exclusion within a single Workflow API process.
- Does NOT provide cross-process locking across separate server processes sharing a
  filesystem; multi-process coordination is outside G15-P0A scope.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import secrets
from threading import RLock
from typing import Any, Iterable
from urllib.parse import urlsplit


def canonical_endpoint_key(url: str | None) -> str | None:
    """Normalize an HTTP/HTTPS endpoint URL to a canonical physical lock key.

    Equates primary local loopback forms that commonly reach the same Windows/dual-stack
    listener (``localhost``, ``localhost.``, ``127.0.0.1``, ``[::1]`` / expanded IPv6
    loopback, and IPv4-mapped ``[::ffff:127.0.0.1]``), resolves default ports (80/443),
    lowercases scheme and host, strips trailing slashes on non-root paths, and omits
    query/fragment. Returns ``None`` if ``url`` is empty or not a valid HTTP(S) URL.

    Intentionally performs NO DNS resolution and does NOT equate aliases that cannot be
    proven equivalent offline (e.g., ``127.0.0.2``, ``*.localhost`` subdomains,
    ``host.docker.internal``, custom ``/etc/hosts``/DNS names, LAN IPs, or reverse proxies).
    """
    if not isinstance(url, str):
        return None
    raw = url.strip()
    if not raw:
        return None
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return None
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return None
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return None
    if hostname in {"localhost", "localhost."}:
        norm_host = "127.0.0.1"
    else:
        try:
            addr = ipaddress.ip_address(hostname)
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
                addr = addr.ipv4_mapped
            if addr == ipaddress.IPv4Address("127.0.0.1") or addr == ipaddress.IPv6Address("::1"):
                norm_host = "127.0.0.1"
            else:
                norm_host = str(addr)
        except ValueError:
            norm_host = hostname
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is None:
        port = 443 if scheme == "https" else 80
    path = parsed.path or "/"
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    host_display = f"[{norm_host}]" if ":" in norm_host else norm_host
    return f"endpoint:{scheme}://{host_display}:{port}{path}"


def logical_target_key(target_id: str | None) -> str | None:
    if not isinstance(target_id, str):
        return None
    clean = target_id.strip()
    return f"target:{clean}" if clean else None


class TargetExecutionConflictError(ValueError):
    """Raised when a live execution reservation conflicts with an active target lock."""

    def __init__(self, code: str, conflict: dict[str, Any]) -> None:
        super().__init__(code)
        self.code = code
        self.conflict = dict(conflict)


class TargetLockHandle:
    """Server-owned, unforgeable in-process capability handle for live target ownership.

    Never serialized to HTTP responses and never constructible from untrusted payloads.
    """

    __slots__ = (
        "_registry_id",
        "_capability_token",
        "_target_ids",
        "_endpoints",
        "_keys",
        "_adopted_run_id",
        "_released",
    )

    def __init__(
        self,
        *,
        registry_id: int,
        capability_token: str,
        target_ids: tuple[str, ...],
        endpoints: tuple[str, ...],
        keys: tuple[str, ...],
    ) -> None:
        self._registry_id = registry_id
        self._capability_token = capability_token
        self._target_ids = target_ids
        self._endpoints = endpoints
        self._keys = keys
        self._adopted_run_id: str | None = None
        self._released: bool = False

    @property
    def target_ids(self) -> tuple[str, ...]:
        return self._target_ids

    @property
    def target_id(self) -> str:
        return self._target_ids[0] if self._target_ids else ""

    @property
    def endpoints(self) -> tuple[str, ...]:
        return self._endpoints

    @property
    def keys(self) -> tuple[str, ...]:
        return self._keys

    @property
    def adopted(self) -> bool:
        return self._adopted_run_id is not None

    @property
    def adopted_run_id(self) -> str | None:
        return self._adopted_run_id

    @property
    def released(self) -> bool:
        return self._released

    def __repr__(self) -> str:
        return (
            f"<TargetLockHandle target_ids={self._target_ids!r} "
            f"endpoints={len(self._endpoints)} adopted={self.adopted}>"
        )


class TargetExecutionLockRegistry:
    """Single-lock, deadlock-free in-process registry for logical + physical target locks."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._entries_by_key: dict[str, dict[str, Any]] = {}
        self._entries_by_token: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _build_keys(
        target_ids: Iterable[str | None],
        endpoints: Iterable[str | None],
    ) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
        clean_tids: list[str] = []
        clean_eps: list[str] = []
        keys: set[str] = set()
        for tid in target_ids:
            k = logical_target_key(tid)
            if k is not None:
                clean = str(tid).strip()
                if clean not in clean_tids:
                    clean_tids.append(clean)
                keys.add(k)
        for ep in endpoints:
            ek = canonical_endpoint_key(ep)
            if ek is not None:
                if ek not in clean_eps:
                    clean_eps.append(ek)
                keys.add(ek)
        return tuple(clean_tids), tuple(clean_eps), tuple(sorted(keys))

    @staticmethod
    def _public_entry(entry: dict[str, Any], *, conflict_scope: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "target_id": entry.get("target_id"),
            "owner_kind": entry.get("owner_kind"),
            "workflow_id": entry.get("workflow_id"),
            "run_id": entry.get("run_id"),
            "reserved_at": entry.get("reserved_at"),
        }
        if conflict_scope is not None:
            payload["conflict_scope"] = conflict_scope
        return payload

    def reserve(
        self,
        target_ids: Iterable[str | None],
        *,
        endpoints: Iterable[str | None] = (),
        owner_kind: str = "generic_run",
        workflow_id: str | None = None,
        run_id: str | None = None,
        conflict_code: str = "generic_target_execution_in_progress",
    ) -> TargetLockHandle:
        """Atomically reserve all logical target IDs and canonical physical endpoints."""
        clean_tids, clean_eps, keys = self._build_keys(target_ids, endpoints)
        if not keys:
            raise ValueError("generic_invalid_target_id")
        now_iso = datetime.now(timezone.utc).isoformat()
        cap_token = secrets.token_hex(32)
        with self._lock:
            for key in keys:
                existing = self._entries_by_key.get(key)
                if existing is not None:
                    scope = "physical_endpoint" if key.startswith("endpoint:") else "target_id"
                    raise TargetExecutionConflictError(
                        conflict_code,
                        self._public_entry(existing, conflict_scope=scope),
                    )
            handle = TargetLockHandle(
                registry_id=id(self),
                capability_token=cap_token,
                target_ids=clean_tids,
                endpoints=clean_eps,
                keys=keys,
            )
            entry = {
                "target_id": clean_tids[0] if clean_tids else None,
                "target_ids": clean_tids,
                "endpoints": clean_eps,
                "keys": keys,
                "handle": handle,
                "capability_token": cap_token,
                "owner_kind": owner_kind,
                "workflow_id": workflow_id,
                "run_id": run_id,
                "adopted_by_run_id": run_id if owner_kind == "generic_run" and run_id else None,
                "reserved_at": now_iso,
            }
            if entry["adopted_by_run_id"] is not None:
                handle._adopted_run_id = entry["adopted_by_run_id"]
            self._entries_by_token[cap_token] = entry
            for key in keys:
                self._entries_by_key[key] = entry
            return handle

    def _validate_handle_locked(self, handle: TargetLockHandle | None) -> dict[str, Any] | None:
        if (
            not isinstance(handle, TargetLockHandle)
            or handle._registry_id != id(self)
            or handle._released
        ):
            return None
        entry = self._entries_by_token.get(handle._capability_token)
        if entry is None or entry.get("handle") is not handle:
            return None
        if not secrets.compare_digest(
            str(entry.get("capability_token") or ""),
            handle._capability_token,
        ):
            return None
        return entry

    def adopt(
        self,
        handle: TargetLockHandle,
        *,
        run_id: str,
        target_ids: Iterable[str | None] = (),
        endpoints: Iterable[str | None] = (),
        conflict_code: str = "generic_target_execution_in_progress",
    ) -> bool:
        """Atomically adopt a pre-reserved handle for ``run_id`` and bind any additional keys."""
        with self._lock:
            entry = self._validate_handle_locked(handle)
            if entry is None:
                return False
            if entry.get("adopted_by_run_id") is not None or handle._adopted_run_id is not None:
                return False
            extra_tids, extra_eps, extra_keys = self._build_keys(target_ids, endpoints)
            new_keys = [k for k in extra_keys if k not in entry["keys"]]
            for key in new_keys:
                existing = self._entries_by_key.get(key)
                if existing is not None and existing is not entry:
                    scope = "physical_endpoint" if key.startswith("endpoint:") else "target_id"
                    raise TargetExecutionConflictError(
                        conflict_code,
                        self._public_entry(existing, conflict_scope=scope),
                    )
            if new_keys:
                merged_tids = tuple(dict.fromkeys((*entry["target_ids"], *extra_tids)))
                merged_eps = tuple(dict.fromkeys((*entry["endpoints"], *extra_eps)))
                merged_keys = tuple(sorted(set(entry["keys"]) | set(new_keys)))
                entry["target_ids"] = merged_tids
                entry["endpoints"] = merged_eps
                entry["keys"] = merged_keys
                handle._target_ids = merged_tids
                handle._endpoints = merged_eps
                handle._keys = merged_keys
                for key in new_keys:
                    self._entries_by_key[key] = entry
            entry["run_id"] = run_id
            entry["adopted_by_run_id"] = run_id
            handle._adopted_run_id = run_id
            return True

    def rollback_adoption(self, handle: TargetLockHandle, *, run_id: str) -> None:
        """Undo adoption of ``handle`` if worker initialization failed after adopt()."""
        with self._lock:
            entry = self._validate_handle_locked(handle)
            if entry is None:
                return
            if entry.get("run_id") == run_id:
                entry["run_id"] = None
            if entry.get("adopted_by_run_id") == run_id:
                entry["adopted_by_run_id"] = None
            if handle._adopted_run_id == run_id:
                handle._adopted_run_id = None

    def release(self, handle: TargetLockHandle | None) -> bool:
        """Release all logical and physical keys owned by ``handle`` atomically."""
        with self._lock:
            entry = self._validate_handle_locked(handle)
            if entry is None:
                return False
            for key in entry["keys"]:
                if self._entries_by_key.get(key) is entry:
                    self._entries_by_key.pop(key, None)
            self._entries_by_token.pop(handle._capability_token, None)
            handle._released = True
            return True

    def get_reservation(
        self,
        *,
        target_id: str | None = None,
        endpoint: str | None = None,
    ) -> dict[str, Any] | None:
        with self._lock:
            tkey = logical_target_key(target_id)
            if tkey is not None and tkey in self._entries_by_key:
                return self._public_entry(self._entries_by_key[tkey])
            ekey = canonical_endpoint_key(endpoint)
            if ekey is not None and ekey in self._entries_by_key:
                return self._public_entry(self._entries_by_key[ekey])
            return None

    def is_reserved(
        self,
        *,
        target_id: str | None = None,
        endpoint: str | None = None,
    ) -> bool:
        return self.get_reservation(target_id=target_id, endpoint=endpoint) is not None

    def has_active_reservations(self) -> bool:
        with self._lock:
            return bool(self._entries_by_token)

    def list_reservations(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._public_entry(v) for v in self._entries_by_token.values()]
