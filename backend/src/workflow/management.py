"""Local operator-owned target catalog, revision-bound review, and benign probe."""
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import httpx
from threading import RLock
from urllib.parse import urlsplit

from pydantic import Field, model_validator
from typing import Literal

from workflow.catalog import CatalogError, TargetCatalog, make_profile, read_json
from workflow.models import (CatalogConfig, ClosedModel, ConnectionCheckResult,
                             Identifier, ModelName, Preset)
from workflow.plans import ROOT


class ManagedProfile(ClosedModel):
    id: Identifier
    name: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9 ._-]+$")
    platform_id: Identifier
    platform_name: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9 ._-]+$")
    endpoint: str = Field(min_length=1, max_length=256)
    protocol: str = "openai-chat"
    model: ModelName
    timeout_seconds: int = Field(ge=1, le=60)


class SaveProfile(ClosedModel):
    profile: ManagedProfile
    expected_profile_revision: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    discovery_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    platform_change_confirmed: bool = False


class ReviewProfile(ClosedModel):
    target_id: Identifier
    profile_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_ref: Identifier
    endpoint: str = Field(min_length=1, max_length=256)
    protocol: str
    model: ModelName
    capabilities: list[str]
    authorization_confirmed: bool

    @model_validator(mode="after")
    def confirmed(self):
        if self.authorization_confirmed is not True:
            raise ValueError("Explicit authorization confirmation is required.")
        return self


class ReviewRecord(ClosedModel):
    target_id: Identifier
    profile_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_ref: Identifier
    endpoint: str
    scope: str = "configured_secagent_tests"
    reviewed_at: datetime = Field(strict=False)


class ArchiveTarget(ClosedModel):
    target_id: Identifier
    profile_revision: str = Field(pattern=r"^[a-f0-9]{64}$")


class ArchiveTargetsRequest(ClosedModel):
    targets: list[ArchiveTarget] = Field(min_length=1, max_length=50)
    archive_confirmed: Literal[True]

    @model_validator(mode="after")
    def unique(self):
        if len({item.target_id for item in self.targets}) != len(self.targets):
            raise ValueError("Duplicate archive target.")
        return self


class RestoreTargetRequest(ClosedModel):
    target_id: Identifier
    profile_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    restore_confirmed: Literal[True]


class ArchivedTarget(ClosedModel):
    target_id: Identifier
    profile_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    archived_at: datetime = Field(strict=False)


class ManagedState(ClosedModel):
    schema_version: str = "1.0.0"
    catalog: CatalogConfig
    reviews: list[ReviewRecord] = Field(default_factory=list, max_length=50)
    revision_names: dict[Identifier, str] = Field(default_factory=dict)
    archived: list[ArchivedTarget] = Field(default_factory=list, max_length=50)
    platform_sources: dict[Identifier, Literal["seed_configured", "discovery_suggested", "operator_declared"]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def safe_state(self):
        if self.schema_version != "1.0.0" or any(p.reviewed for p in self.catalog.targets):
            raise ValueError("Stored target reviews must be separate from profiles.")
        if len({r.target_id for r in self.reviews}) != len(self.reviews):
            raise ValueError("Duplicate review identity.")
        target_ids = {p.id for p in self.catalog.targets}
        if any(target_id not in target_ids or not re.fullmatch(r"[A-Za-z0-9 ._-]{1,100}", name)
               for target_id, name in self.revision_names.items()):
            raise ValueError("Invalid display-name revision basis.")
        if (len({row.target_id for row in self.archived}) != len(self.archived)
                or any(row.target_id not in target_ids for row in self.archived)
                or any(target_id not in target_ids for target_id in self.platform_sources)):
            raise ValueError("Invalid archived target or platform provenance.")
        return self


def _revision(config: CatalogConfig, preset: Preset, revision_name: str | None = None) -> str:
    material = {"policy": config.policy_ref,
                "preset": preset.model_copy(update={"name": revision_name}).model_dump(
                    exclude={"platform_id", "platform_name"}) if revision_name is not None
                    else preset.model_dump(exclude={"platform_id", "platform_name"}),
                "credential_binding": config.credential_aliases.get(preset.credential_alias)}
    return sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _data_root(path: Path) -> Path:
    raw = str(path)
    if not path.is_absolute() or raw.startswith(("\\\\", "//")):
        raise CatalogError("Target data directory must be a local absolute path.")
    resolved = path.resolve(strict=False)
    if resolved.is_relative_to(ROOT.resolve()):
        raise CatalogError("Target data directory must be outside the repository.")
    for parent in (path, *path.parents):
        if parent.is_symlink() or (parent.exists() and getattr(parent.stat(), "st_file_attributes", 0)
                                  & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise CatalogError("Linked target data directories are unsupported.")
    if os.name == "nt":
        import ctypes
        if ctypes.windll.kernel32.GetDriveTypeW(str(path.anchor)) == 4:
            raise CatalogError("Network target data directories are unsupported.")
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise CatalogError("Invalid target data directory.")
    return path


class ManagedTargetCatalog(TargetCatalog):
    def __init__(self, seed: CatalogConfig, data_dir: Path, *, probe_transport=None,
                 local_single_user=False):
        self._lock = RLock()
        self.local_single_user = local_single_user
        self.data_dir = _data_root(Path(data_dir))
        self.state_file = self.data_dir / "target-catalog.json"
        self.probe_transport = probe_transport
        if self.state_file.is_symlink():
            raise CatalogError("Linked target catalog is unsupported.")
        if self.state_file.exists():
            if not self.state_file.is_file() or self.state_file.stat().st_size > 262144:
                raise CatalogError("Invalid stored target catalog.")
            state = ManagedState.model_validate(read_json(self.state_file.read_bytes()))
            if state.catalog.policy_ref != seed.policy_ref or state.catalog.credential_aliases != seed.credential_aliases:
                raise CatalogError("Stored catalog policy or credential bindings differ from startup configuration.")
        else:
            unreviewed = [p.model_copy(update={"reviewed": False}) for p in seed.targets]
            state = ManagedState(catalog=seed.model_copy(update={"targets": unreviewed}),
                platform_sources={p.id: "seed_configured" for p in seed.targets})
        self._install(state)

    def _install(self, state: ManagedState):
        revisions = {p.id: _revision(state.catalog, p, state.revision_names.get(p.id))
                     for p in state.catalog.targets}
        reviews = {r.target_id: r for r in state.reviews}
        for target_id, review in reviews.items():
            preset = next((p for p in state.catalog.targets if p.id == target_id), None)
            if (preset is None or review.profile_revision != revisions[target_id]
                    or review.policy_ref != state.catalog.policy_ref or review.endpoint != preset.endpoint):
                raise CatalogError("Stored review does not match the exact profile revision and policy.")
        archived_ids = {row.target_id for row in state.archived}
        for row in state.archived:
            if row.profile_revision != revisions[row.target_id]:
                raise CatalogError("Archived target revision changed.")
        effective = state.catalog.model_copy(update={"targets": [
            p.model_copy(update={"reviewed": p.id in reviews}) for p in state.catalog.targets
            if p.id not in archived_ids]})
        prepared = TargetCatalog(effective)
        self._state = state
        self._config, self._targets, self._revisions = prepared._config, prepared._targets, revisions

    def _save(self, state: ManagedState):
        # Validate the complete replacement before publishing it to disk or memory.
        for p in state.catalog.targets:
            make_profile(p, p.default_model, p.timeout_default)
        raw = (json.dumps(state.model_dump(mode="json"), sort_keys=True, indent=2) + "\n").encode()
        if len(raw) > 262144 or self.state_file.is_symlink():
            raise CatalogError("Target catalog is unsafe or oversized.")
        temporary = self.data_dir / (".target-catalog-" + secrets.token_hex(16) + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.state_file)
        finally:
            if temporary.exists():
                temporary.unlink()
        self._install(state)

    def public_targets(self):
        with self._lock:
            rows = super().public_targets()
            for row in rows:
                preset = self._targets[row["id"]]
                safe_probe = self._probe_supported(preset)
                supported = preset.reviewed and safe_probe
                row["connection_probe"] = {
                    "status": "supported" if supported else "requires_confirmation"
                              if self.local_single_user and safe_probe else "unsupported",
                    "reason": "reviewed_exact_endpoint" if supported else "authorization_confirmation_required"
                              if self.local_single_user and safe_probe else "operator_review_required"
                              if not preset.reviewed else "safe_probe_not_verified",
                    "active_probe_authorized": supported,
                    "security_execution_authorized": False}
                row["limitations"] = (["Configured MCP tool capability is not runtime verification.",
                    "A tools/list probe does not invoke a tool or verify handler execution.",
                    "Target review does not create a testcase execution grant."]
                    if preset.protocol == "mcp-jsonrpc" else
                    ["Configured chat capability is not runtime verification.",
                     "Target review does not create a testcase execution grant."])
                review = next((r for r in self._state.reviews if r.target_id == row["id"]), None)
                row["reviewed_at"] = review.reviewed_at.isoformat() if review else None
                row["platform_provenance"] = self._state.platform_sources.get(row["id"], "legacy_unknown")
            return rows

    def archived_targets(self):
        with self._lock:
            records = {row.target_id: row for row in self._state.archived}
            return [{"id": p.id, "name": p.name, "platform_id": p.platform_id,
                     "platform_name": p.platform_name, "endpoint": p.endpoint,
                     "protocol": p.protocol, "profile_revision": records[p.id].profile_revision,
                     "archived_at": records[p.id].archived_at.isoformat()}
                    for p in self._state.catalog.targets if p.id in records]

    def archive_targets(self, request: ArchiveTargetsRequest):
        with self._lock:
            for item in request.targets:
                if (item.target_id not in self._targets
                        or self._revisions.get(item.target_id) != item.profile_revision):
                    raise ValueError("Archive target is missing, stale or already archived.")
            now = datetime.now(timezone.utc)
            archived = [*self._state.archived,
                *(ArchivedTarget(target_id=item.target_id,
                    profile_revision=item.profile_revision, archived_at=now)
                  for item in request.targets)]
            self._save(self._state.model_copy(update={"archived": archived}))
            return self.archived_targets()

    def restore_target(self, request: RestoreTargetRequest):
        with self._lock:
            record = next((row for row in self._state.archived
                if row.target_id == request.target_id), None)
            preset = next((p for p in self._state.catalog.targets
                if p.id == request.target_id), None)
            if record is None or preset is None or record.profile_revision != request.profile_revision:
                raise ValueError("Restore target is missing or stale.")
            if any(p.endpoint == preset.endpoint and p.protocol == preset.protocol
                   for p in self._targets.values()):
                raise ValueError("Active target already uses the archived endpoint.")
            self._save(self._state.model_copy(update={"archived": [row
                for row in self._state.archived if row.target_id != request.target_id]}))
            return next(row for row in self.public_targets() if row["id"] == request.target_id)

    @staticmethod
    def _probe_supported(preset: Preset) -> bool:
        try:
            host = urlsplit(preset.endpoint).hostname
            address = ipaddress.ip_address(host or "")
            return ((preset.protocol == "mcp-jsonrpc" and address.is_loopback)
                    or (preset.protocol == "openai-chat" and (address.is_private or address.is_loopback)
                    and not address.is_link_local and not address.is_multicast and not address.is_unspecified))
        except ValueError:
            return False

    def validate(self, draft):
        with self._lock:
            return super().validate(draft)

    def _preset(self, profile: ManagedProfile, *, existing: Preset | None = None) -> Preset:
        if profile.protocol not in {"openai-chat", "mcp-jsonrpc"}:
            raise ValueError("Unsupported target protocol.")
        preset = Preset(id=profile.id, name=profile.name, platform_id=profile.platform_id,
            platform_name=profile.platform_name, endpoint=profile.endpoint, protocol=profile.protocol,
            models=[profile.model], default_model=profile.model,
            timeout_min=existing.timeout_min if existing else 1,
            timeout_max=existing.timeout_max if existing else 60,
            timeout_default=profile.timeout_seconds,
            credential_alias=existing.credential_alias if existing else None, reviewed=False)
        make_profile(preset, preset.default_model, preset.timeout_default)
        return preset

    def validate_profile(self, profile: ManagedProfile, *, update=False):
        with self._lock:
            existing = self._targets.get(profile.id)
            if (update and existing is None) or (not update and existing is not None):
                raise ValueError("Target identity is missing or already exists.")
            if any(p.id != profile.id and p.endpoint == profile.endpoint
                   and p.protocol == profile.protocol for p in self._state.catalog.targets):
                # Legacy duplicates remain readable; a metadata-only edit of one
                # must not create or silently repair historical identity.
                if not update or existing is None or (existing.endpoint, existing.protocol) != (profile.endpoint, profile.protocol):
                    raise ValueError("duplicate_target_endpoint")
            candidate = self._preset(profile, existing=existing)
            targets = [candidate if p.id == profile.id else p for p in self._state.catalog.targets]
            if not update:
                targets.append(candidate)
            CatalogConfig.model_validate(self._state.catalog.model_dump() | {
                "targets": [p.model_dump() for p in targets]})
            return candidate

    def save_profile(self, request: SaveProfile, *, update=False):
        with self._lock:
            profile = request.profile
            existing = self._targets.get(profile.id)
            if update:
                if existing is None or request.expected_profile_revision != self._revisions[profile.id]:
                    raise ValueError("Missing or stale target profile.")
            elif existing is not None or request.expected_profile_revision is not None:
                raise ValueError("Duplicate target identity or unexpected revision.")
            candidate = self.validate_profile(profile, update=update)
            platform_changed = bool(update and existing and
                (existing.platform_id, existing.platform_name) !=
                (candidate.platform_id, candidate.platform_name))
            if platform_changed and request.platform_change_confirmed is not True:
                raise ValueError("platform_change_confirmation_required")
            targets = [candidate if p.id == profile.id else p for p in self._state.catalog.targets]
            if not update:
                targets.append(candidate)
            config = CatalogConfig.model_validate(self._state.catalog.model_dump() | {
                "targets": [p.model_dump() for p in targets]})
            metadata_only = (update and existing is not None and
                candidate.model_dump(exclude={"name", "platform_id", "platform_name", "reviewed"}) ==
                existing.model_dump(exclude={"name", "platform_id", "platform_name", "reviewed"}))
            revision_names = dict(self._state.revision_names)
            if metadata_only and profile.id not in revision_names:
                revision_names[profile.id] = existing.name
            reviews = (list(self._state.reviews) if metadata_only else
                       [r for r in self._state.reviews if r.target_id != profile.id])
            platform_sources = dict(self._state.platform_sources)
            if platform_changed or not update:
                platform_sources[profile.id] = ("operator_declared"
                    if platform_changed or not request.discovery_id or request.platform_change_confirmed
                    else "discovery_suggested")
            self._save(ManagedState(catalog=config, reviews=reviews,
                                    revision_names=revision_names,
                                    archived=list(self._state.archived),
                                    platform_sources=platform_sources))
            return next(r for r in self.public_targets() if r["id"] == profile.id)

    def review_profile(self, request: ReviewProfile):
        with self._lock:
            p = self._targets.get(request.target_id)
            if (p is None or request.profile_revision != self._revisions[p.id]
                    or request.policy_ref != self._config.policy_ref or request.endpoint != p.endpoint
                    or request.protocol != p.protocol or request.model != p.default_model
                    or request.capabilities != (["tool_call"] if p.protocol == "mcp-jsonrpc" else ["chat"])):
                raise ValueError("Review does not match the current target and policy.")
            record = ReviewRecord(target_id=p.id, profile_revision=self._revisions[p.id],
                                  policy_ref=self._config.policy_ref, endpoint=p.endpoint,
                                  reviewed_at=datetime.now(timezone.utc))
            reviews = [r for r in self._state.reviews if r.target_id != p.id] + [record]
            self._save(ManagedState(catalog=self._state.catalog, reviews=reviews,
                                    revision_names=self._state.revision_names,
                                    archived=list(self._state.archived),
                                    platform_sources=dict(self._state.platform_sources)))
            return next(r for r in self.public_targets() if r["id"] == p.id)

    def connection_check(self, selection):
        with self._lock:
            p = self._targets.get(selection.target_id)
            if p is None:
                return ConnectionCheckResult(connection_status="rejected", reason="unknown_target"), 404
            if selection.profile_revision != self._revisions[p.id] or selection.policy_ref != self._config.policy_ref:
                return ConnectionCheckResult(connection_status="rejected", reason="stale_profile_or_policy"), 409
            if not p.reviewed:
                return ConnectionCheckResult(connection_status="requires_approval", reason="operator_review_required"), 403
            if not self._probe_supported(p):
                return ConnectionCheckResult(connection_status="unsupported", reason="safe_probe_not_verified"), 200
        return self._probe_preset(p)

    def probe_candidate(self, profile: ManagedProfile):
        """One authorized connection check for an unsaved discovery proposal.

        The API binds the endpoint and protocol to a discovery ID first. This
        method validates the proposal independently of saved target identities.
        A discovered ID can already exist; a probe never writes or reviews it.
        """
        with self._lock:
            candidate = self._preset(profile)
            CatalogConfig.model_validate(self._config.model_dump() | {
                "targets": [candidate.model_dump()]})
            if not self._probe_supported(candidate):
                return ConnectionCheckResult(connection_status="unsupported", reason="safe_probe_not_verified"), 200
        return self._probe_preset(candidate)

    def _probe_preset(self, p: Preset):
        endpoint, model, timeout, protocol = p.endpoint, p.default_model, p.timeout_default, p.protocol
        credential_name = self._config.credential_aliases.get(p.credential_alias)
        # No lock across network I/O. The API holds the dispatcher lock when
        # dispatch is enabled; a concurrent profile edit is otherwise rejected
        # by the API's shared management operation lock.
        from workflow.dispatch import OneRequestHttpClient
        from tools.http import HttpClientError
        headers = {"Content-Type": "application/json"}
        if credential_name:
            credential = os.environ.get(credential_name)
            if not credential:
                return ConnectionCheckResult(connection_status="unavailable", reason="credential_unavailable"), 200
            headers["Authorization"] = credential
        client = OneRequestHttpClient(endpoint, timeout, transport=self.probe_transport, max_bytes=16384)
        try:
            payload = ({"jsonrpc": "2.0", "id": "secagent-connection-check",
                        "method": "tools/list", "params": {}} if protocol == "mcp-jsonrpc" else
                       {"model": model, "messages": [{"role": "user",
                        "content": "Reply with one word: ready."}], "stream": False})
            response = client.request(method="POST", url=endpoint, headers=headers,
                json_body=payload, timeout=timeout)
        except (HttpClientError, ValueError) as exc:
            cause = exc.__cause__
            reason = ("connection_timeout" if isinstance(cause, httpx.TimeoutException) else
                      "connection_refused_or_unreachable" if isinstance(cause, httpx.ConnectError) else
                      "response_too_large_or_bounded" if isinstance(exc, HttpClientError)
                          and "size limit" in str(exc) else "request_failed_or_bounded")
            return ConnectionCheckResult(connection_status="unavailable", reason=reason,
                target_request_count=client.used, connection_reachable=None,
                runtime_protocol_compatible=None), 200
        body = response.json_body
        if response.status_code in {401, 403}:
            return ConnectionCheckResult(connection_status="unavailable", reason="authentication_required",
                target_request_count=client.used, connection_reachable=True,
                runtime_protocol_compatible=None, http_status=response.status_code), 200
        compatible = (response.status_code == 200 and isinstance(body, dict) and
            body.get("jsonrpc") == "2.0" and body.get("id") == "secagent-connection-check" and
            isinstance(body.get("result"), dict) and isinstance(body["result"].get("tools"), list)
            if protocol == "mcp-jsonrpc" else response.status_code == 200 and isinstance(body, dict)
            and isinstance(body.get("choices"), list) and bool(body["choices"])
            and isinstance(body["choices"][0], dict)
            and isinstance(body["choices"][0].get("message"), dict)
            and isinstance(body["choices"][0]["message"].get("content"), str))
        return ConnectionCheckResult(connection_status="succeeded" if compatible else "incompatible",
            reason=("mcp_tools_list_response" if protocol == "mcp-jsonrpc" else "openai_chat_response") if compatible else
                   "http_request_rejected" if response.status_code != 200 else "response_contract_unverified",
            target_request_count=client.used, connection_reachable=True,
            runtime_protocol_compatible=compatible, http_status=response.status_code), 200
