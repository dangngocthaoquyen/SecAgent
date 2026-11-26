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

from workflow.catalog import (
    CatalogError,
    TargetCatalog,
    make_profile,
    read_json,
    serialize_preset_for_revision,
)
from workflow.models import (
    CapabilityProvenanceLiteral,
    CapabilityStateLiteral,
    CatalogConfig,
    ClosedModel,
    ConnectionCheckResult,
    DeclarableCapabilityProvenanceLiteral,
    HttpContractConfig,
    Identifier,
    ModelName,
    Preset,
    SessionAuthReference,
)
from workflow.catalog import ROOT
from workflow.session_credentials import SessionCredentialError, SessionCredentialStore


class ManagedProfile(ClosedModel):
    id: Identifier
    name: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9 ._-]+$")
    platform_id: Identifier
    platform_name: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9 ._-]+$")
    endpoint: str = Field(min_length=1, max_length=256)
    protocol: str = "openai-chat"
    model: ModelName | None = None
    timeout_seconds: int = Field(ge=1, le=600)
    credential_alias: Identifier | None = None
    session_auth: SessionAuthReference | None = None
    http_config: HttpContractConfig | None = None
    capability_states: dict[Identifier, CapabilityStateLiteral] | None = None
    capability_provenance: dict[Identifier, DeclarableCapabilityProvenanceLiteral] | None = None

    @model_validator(mode="after")
    def validate_managed_fields(self):
        if self.session_auth is not None and self.credential_alias is not None:
            raise ValueError("Conflicting authentication configuration: cannot combine credential_alias and session_auth.")
        if self.protocol != "http-json" and self.credential_alias is not None:
            raise ValueError("credential_alias cannot be supplied directly on legacy managed profiles.")
        if self.protocol != "http-json" and self.session_auth is not None:
            raise ValueError("session_auth is only allowed for http-json profiles.")
        if self.protocol != "http-json" and self.http_config is not None:
            raise ValueError("http_config is only allowed for http-json profiles.")
        if self.protocol == "http-json" and self.http_config is None:
            raise ValueError("http-json profile requires http_config.")
        if self.protocol == "http-json" and self.session_auth is not None and self.http_config is not None:
            auth_hdr = self.session_auth.header_name.lower()
            if any(k.lower() == auth_hdr for k in self.http_config.headers):
                raise ValueError("Custom HTTP header conflicts with session authentication header.")
        if self.protocol != "http-json" and not self.model:
            raise ValueError("model is required for this protocol.")
        if self.protocol != "http-json" and self.timeout_seconds > 60:
            raise ValueError("timeout_seconds exceeds protocol limit.")
        return self


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
    model: ModelName | None = None
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


class DeleteTargetRequest(ClosedModel):
    target_id: Identifier
    profile_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    delete_confirmed: Literal[True]


class ManagedState(ClosedModel):
    schema_version: str = "1.0.0"
    catalog: CatalogConfig
    reviews: list[ReviewRecord] = Field(default_factory=list, max_length=50)
    revision_names: dict[Identifier, str] = Field(default_factory=dict)
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
        if any(target_id not in target_ids for target_id in self.platform_sources):
            raise ValueError("Invalid platform provenance.")
        return self


def _revision(config: CatalogConfig, preset: Preset, revision_name: str | None = None) -> str:
    effective_preset = (
        preset.model_copy(update={"name": revision_name})
        if revision_name is not None
        else preset
    )
    material = {
        "policy": config.policy_ref,
        "preset": serialize_preset_for_revision(
            effective_preset, exclude={"platform_id", "platform_name"}
        ),
        "credential_binding": config.credential_aliases.get(preset.credential_alias),
    }
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
                 local_single_user=False, allow_additive_credential_aliases: bool = False,
                 session_credentials: SessionCredentialStore | None = None):
        self._lock = RLock()
        self.local_single_user = local_single_user
        self.session_credentials = session_credentials if session_credentials is not None else SessionCredentialStore()
        self.data_dir = _data_root(Path(data_dir))
        self.state_file = self.data_dir / "target-catalog.json"
        self.legacy_backup_file = self.data_dir / "target-catalog.legacy-archived.backup.json"
        self.probe_transport = probe_transport
        if self.state_file.is_symlink() or self.legacy_backup_file.is_symlink():
            raise CatalogError("Linked target catalog is unsupported.")
        if self.state_file.exists():
            if not self.state_file.is_file() or self.state_file.stat().st_size > 262144:
                raise CatalogError("Invalid stored target catalog.")
            raw_bytes = self.state_file.read_bytes()
            raw_state = read_json(raw_bytes)
            migrated_legacy_archive = False
            if isinstance(raw_state, dict) and "archived" in raw_state:
                archived_rows = raw_state.get("archived")
                legacy_archived_ids = {
                    row.get("target_id")
                    for row in (archived_rows if isinstance(archived_rows, list) else [])
                    if isinstance(row, dict) and isinstance(row.get("target_id"), str)
                }
                raw_state = {k: v for k, v in raw_state.items() if k != "archived"}
                if legacy_archived_ids:
                    if not self.legacy_backup_file.exists():
                        self.legacy_backup_file.write_bytes(raw_bytes)
                    if isinstance(raw_state.get("reviews"), list):
                        raw_state["reviews"] = [
                            r for r in raw_state["reviews"]
                            if not (isinstance(r, dict) and r.get("target_id") in legacy_archived_ids)
                        ]
                    rev_names = dict(raw_state.get("revision_names") or {})
                    cat_obj = dict(raw_state.get("catalog") or {})
                    updated_targets = []
                    suffix = " - Legacy Archived"
                    for preset_row in cat_obj.get("targets") or []:
                        if isinstance(preset_row, dict) and preset_row.get("id") in legacy_archived_ids:
                            tid = preset_row["id"]
                            orig_name = str(preset_row.get("name") or tid)
                            rev_names.setdefault(tid, orig_name)
                            if not orig_name.endswith(suffix):
                                max_base = 100 - len(suffix)
                                preset_row = {
                                    **preset_row,
                                    "name": f"{orig_name[:max_base].rstrip()}{suffix}",
                                }
                        updated_targets.append(preset_row)
                    cat_obj["targets"] = updated_targets
                    raw_state["catalog"] = cat_obj
                    raw_state["revision_names"] = rev_names
                migrated_legacy_archive = True
            state = ManagedState.model_validate(raw_state)
            if state.catalog.policy_ref != seed.policy_ref:
                raise CatalogError("Stored catalog policy differs from startup configuration.")
            migrated_credential_aliases = False
            if state.catalog.credential_aliases != seed.credential_aliases:
                stored_aliases = state.catalog.credential_aliases
                seed_aliases = seed.credential_aliases
                removed_or_changed = any(
                    seed_aliases.get(alias) != env_ref
                    for alias, env_ref in stored_aliases.items()
                )
                if removed_or_changed or not allow_additive_credential_aliases:
                    raise CatalogError("Stored catalog policy or credential bindings differ from startup configuration.")
                # Strictly additive alias registration: validate merged CatalogConfig,
                # preserve all existing targets/reviews/revisions, write atomic backup first.
                merged_catalog = CatalogConfig.model_validate(
                    state.catalog.model_dump() | {"credential_aliases": dict(seed_aliases)}
                )
                updated_state = state.model_copy(update={"catalog": merged_catalog})
                self._write_recovery_backup(raw_bytes, prefix="target-catalog.credential-aliases")
                state = updated_state
                migrated_credential_aliases = True
            if migrated_legacy_archive or migrated_credential_aliases:
                self._save(state)
            else:
                self._install(state)
        else:
            unreviewed = [p.model_copy(update={"reviewed": False}) for p in seed.targets]
            state = ManagedState(catalog=seed.model_copy(update={"targets": unreviewed}),
                platform_sources={p.id: "seed_configured" for p in seed.targets})
            self._install(state)

    def _write_recovery_backup(self, raw_bytes: bytes, *, prefix: str) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = self.data_dir / f"{prefix}-{stamp}-{secrets.token_hex(4)}.backup.json"
        if backup_path.is_symlink():
            raise CatalogError("Linked target catalog backup is unsupported.")
        temporary = self.data_dir / (".target-catalog-backup-" + secrets.token_hex(16) + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, backup_path)
        finally:
            if temporary.exists():
                temporary.unlink()
        return backup_path

    def _install(self, state: ManagedState):
        revisions = {p.id: _revision(state.catalog, p, state.revision_names.get(p.id))
                     for p in state.catalog.targets}
        reviews = {r.target_id: r for r in state.reviews}
        for target_id, review in reviews.items():
            preset = next((p for p in state.catalog.targets if p.id == target_id), None)
            if (preset is None or review.profile_revision != revisions[target_id]
                    or review.policy_ref != state.catalog.policy_ref or review.endpoint != preset.endpoint):
                raise CatalogError("Stored review does not match the exact profile revision and policy.")
        effective = state.catalog.model_copy(update={"targets": [
            p.model_copy(update={"reviewed": p.id in reviews}) for p in state.catalog.targets]})
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
                    ["Configured HTTP JSON contract is not runtime verification.",
                     "Unknown API semantics, authorization boundaries, and evidence trust remain unverified until established.",
                     "Target review does not create a testcase execution grant."]
                    if preset.protocol == "http-json" else
                    ["Configured chat capability is not runtime verification.",
                     "Target review does not create a testcase execution grant."])
                if preset.name.endswith(" - Legacy Archived"):
                    row["limitations"].append(
                        "Migrated from legacy archived state with review revoked; review to re-authorize or Delete Permanently to purge."
                    )
                review = next((r for r in self._state.reviews if r.target_id == row["id"]), None)
                row["reviewed_at"] = review.reviewed_at.isoformat() if review else None
                row["platform_provenance"] = self._state.platform_sources.get(row["id"], "legacy_unknown")
            return rows

    def _validate_and_prepare_legacy_backup_purge(self, target_id: str) -> tuple[str, bytes | None]:
        if not self.legacy_backup_file.exists() and not self.legacy_backup_file.is_symlink():
            return "noop", None
        try:
            if (
                self.legacy_backup_file.is_symlink()
                or not self.legacy_backup_file.is_file()
                or self.legacy_backup_file.stat().st_size > 262144
            ):
                raise CatalogError("legacy_backup_corrupted")
            raw_backup = read_json(self.legacy_backup_file.read_bytes())
        except CatalogError:
            raise
        except Exception as exc:
            raise CatalogError("legacy_backup_corrupted") from exc

        if not isinstance(raw_backup, dict):
            raise CatalogError("legacy_backup_corrupted")
        cat_obj = raw_backup.get("catalog")
        if (
            not isinstance(cat_obj, dict)
            or not isinstance(cat_obj.get("targets"), list)
            or any(not isinstance(t, dict) or not isinstance(t.get("id"), str) for t in cat_obj["targets"])
        ):
            raise CatalogError("legacy_backup_corrupted")
        archived_list = raw_backup.get("archived")
        if (
            not isinstance(archived_list, list)
            or any(not isinstance(a, dict) or not isinstance(a.get("target_id"), str) for a in archived_list)
        ):
            raise CatalogError("legacy_backup_corrupted")
        reviews_list = raw_backup.get("reviews", [])
        if (
            not isinstance(reviews_list, list)
            or any(not isinstance(r, dict) or not isinstance(r.get("target_id"), str) for r in reviews_list)
        ):
            raise CatalogError("legacy_backup_corrupted")
        rev_names = raw_backup.get("revision_names", {})
        if (
            not isinstance(rev_names, dict)
            or any(not isinstance(k, str) or not isinstance(v, str) for k, v in rev_names.items())
        ):
            raise CatalogError("legacy_backup_corrupted")
        plat_sources = raw_backup.get("platform_sources", {})
        if (
            not isinstance(plat_sources, dict)
            or any(not isinstance(k, str) or not isinstance(v, str) for k, v in plat_sources.items())
        ):
            raise CatalogError("legacy_backup_corrupted")

        updated_backup = dict(raw_backup)
        remaining_targets = [t for t in cat_obj["targets"] if t.get("id") != target_id]
        updated_backup["catalog"] = {**cat_obj, "targets": remaining_targets}
        remaining_archived = [a for a in archived_list if a.get("target_id") != target_id]
        updated_backup["archived"] = remaining_archived
        if "reviews" in updated_backup:
            updated_backup["reviews"] = [r for r in reviews_list if r.get("target_id") != target_id]
        if "revision_names" in updated_backup:
            updated_backup["revision_names"] = {k: v for k, v in rev_names.items() if k != target_id}
        if "platform_sources" in updated_backup:
            updated_backup["platform_sources"] = {k: v for k, v in plat_sources.items() if k != target_id}

        if not remaining_targets and not remaining_archived and not updated_backup.get("reviews"):
            return "unlink", None
        encoded = (json.dumps(updated_backup, sort_keys=True, indent=2) + "\n").encode("utf-8")
        if len(encoded) > 262144:
            raise CatalogError("legacy_backup_corrupted")
        return "write", encoded

    def _apply_legacy_backup_purge(self, action: str, encoded: bytes | None) -> None:
        if action == "noop":
            return
        if action == "unlink":
            self.legacy_backup_file.unlink(missing_ok=True)
            return
        if action == "write" and encoded is not None:
            temporary = self.data_dir / (".target-catalog-backup-" + secrets.token_hex(16) + ".tmp")
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.legacy_backup_file)
            finally:
                if temporary.exists():
                    temporary.unlink()

    def delete_target(self, request: DeleteTargetRequest):
        with self._lock:
            target_id = request.target_id
            if (target_id not in self._targets
                    or self._revisions.get(target_id) != request.profile_revision):
                raise ValueError("Delete target is missing or stale.")
            backup_action, backup_bytes = self._validate_and_prepare_legacy_backup_purge(target_id)
            remaining_targets = [p for p in self._state.catalog.targets if p.id != target_id]
            remaining_reviews = [r for r in self._state.reviews if r.target_id != target_id]
            remaining_rev_names = {k: v for k, v in self._state.revision_names.items() if k != target_id}
            remaining_platforms = {k: v for k, v in self._state.platform_sources.items() if k != target_id}
            config = CatalogConfig.model_validate(self._state.catalog.model_dump() | {
                "targets": [p.model_dump() for p in remaining_targets]})
            self._save(ManagedState(
                catalog=config,
                reviews=remaining_reviews,
                revision_names=remaining_rev_names,
                platform_sources=remaining_platforms,
            ))
            self._apply_legacy_backup_purge(backup_action, backup_bytes)
            return self.public_targets()

    @staticmethod
    def _probe_supported(preset: Preset) -> bool:
        try:
            host = urlsplit(preset.endpoint).hostname
            address = ipaddress.ip_address(host or "")
            local_or_private = (
                (address.is_private or address.is_loopback)
                and not address.is_link_local
                and not address.is_multicast
                and not address.is_unspecified
            )
            return (
                (preset.protocol == "mcp-jsonrpc" and address.is_loopback)
                or (preset.protocol == "openai-chat" and local_or_private)
                or (preset.protocol == "http-json" and local_or_private and preset.http_config is not None)
            )
        except ValueError:
            return False

    def validate(self, draft):
        with self._lock:
            return super().validate(draft)

    def _preset(self, profile: ManagedProfile, *, existing: Preset | None = None) -> Preset:
        if profile.protocol not in {"openai-chat", "http-json", "mcp-jsonrpc"}:
            raise ValueError("Unsupported target protocol.")
        if profile.protocol == "http-json":
            models = [profile.model] if profile.model else []
            default_model = profile.model
            cred_alias = profile.credential_alias
        else:
            if not profile.model:
                raise ValueError("Model identifier is required for this protocol.")
            models = [profile.model]
            default_model = profile.model
            cred_alias = (
                profile.credential_alias
                if profile.credential_alias is not None
                else (existing.credential_alias if existing else None)
            )
        if cred_alias is not None and cred_alias not in self._state.catalog.credential_aliases:
            raise ValueError("Unregistered credential alias.")
        preset = Preset(
            id=profile.id,
            name=profile.name,
            platform_id=profile.platform_id,
            platform_name=profile.platform_name,
            endpoint=profile.endpoint,
            protocol=profile.protocol,
            models=models,
            default_model=default_model,
            timeout_min=existing.timeout_min if existing else 1,
            timeout_max=(
                max(existing.timeout_max, profile.timeout_seconds, 600)
                if profile.protocol == "http-json" and existing
                else (600 if profile.protocol == "http-json" else (existing.timeout_max if existing else 60))
            ),
            timeout_default=profile.timeout_seconds,
            credential_alias=cred_alias,
            session_auth=profile.session_auth if profile.protocol == "http-json" else None,
            http_config=profile.http_config,
            capability_states=profile.capability_states,
            capability_provenance=profile.capability_provenance,
            reviewed=False,
        )
        make_profile(preset, preset.default_model, preset.timeout_default,
                     self._state.catalog.credential_aliases.get(preset.credential_alias),
                     session_auth=preset.session_auth)
        return preset

    @staticmethod
    def _effective_invocation_signature(preset: Preset) -> tuple:
        """Generic invocation contract identity for duplicate detection.

        Legacy openai-chat and mcp-jsonrpc keep (endpoint, protocol) uniqueness.
        Generic http-json profiles sharing one REST endpoint are distinct when
        their effective invocation contract (body_template, headers, response
        contract, credential_alias, or session_auth) differs.
        """
        if preset.protocol == "http-json":
            http_blob = (
                json.dumps(preset.http_config.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
                if preset.http_config is not None
                else ""
            )
            sess_sig = (
                f"session:{preset.session_auth.auth_type}:{preset.session_auth.header_name.lower()}:{preset.session_auth.ref_id}"
                if preset.session_auth is not None
                else ""
            )
            return (preset.endpoint, preset.protocol, preset.credential_alias or "", sess_sig, http_blob)
        return (preset.endpoint, preset.protocol)

    def validate_profile(self, profile: ManagedProfile, *, update=False):
        with self._lock:
            existing = self._targets.get(profile.id)
            if (update and existing is None) or (not update and existing is not None):
                raise ValueError("Target identity is missing or already exists.")
            candidate = self._preset(profile, existing=existing)
            cand_sig = self._effective_invocation_signature(candidate)
            if any(
                p.id != profile.id and self._effective_invocation_signature(p) == cand_sig
                for p in self._state.catalog.targets
            ):
                # Legacy duplicates remain readable; a metadata-only edit of one
                # must not create or silently repair historical identity.
                if not update or existing is None or self._effective_invocation_signature(existing) != cand_sig:
                    raise ValueError("duplicate_target_endpoint")
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
                                    platform_sources=platform_sources))
            return next(r for r in self.public_targets() if r["id"] == profile.id)

    def review_profile(self, request: ReviewProfile):
        with self._lock:
            p = self._targets.get(request.target_id)
            expected_caps = (
                ["tool_call"]
                if p and p.protocol == "mcp-jsonrpc"
                else (["http_json"] if p and p.protocol == "http-json" else ["chat"])
            )
            req_model = request.model or None
            preset_model = (p.default_model or None) if p is not None else None
            if (p is None or request.profile_revision != self._revisions[p.id]
                    or request.policy_ref != self._config.policy_ref or request.endpoint != p.endpoint
                    or request.protocol != p.protocol or req_model != preset_model
                    or request.capabilities != expected_caps):
                raise ValueError("Review does not match the current target and policy.")
            record = ReviewRecord(target_id=p.id, profile_revision=self._revisions[p.id],
                                  policy_ref=self._config.policy_ref, endpoint=p.endpoint,
                                  reviewed_at=datetime.now(timezone.utc))
            reviews = [r for r in self._state.reviews if r.target_id != p.id] + [record]
            self._save(ManagedState(catalog=self._state.catalog, reviews=reviews,
                                    revision_names=self._state.revision_names,
                                    platform_sources=dict(self._state.platform_sources)))
            return next(r for r in self.public_targets() if r["id"] == p.id)

    def connection_check(self, selection):
        with self._lock:
            p = self._targets.get(selection.target_id)
            if p is None:
                return ConnectionCheckResult(connection_status="rejected", reason="unknown_target",
                    diagnostic_category="configuration_validation_failure", verification_state="configuration_invalid"), 404
            if selection.profile_revision != self._revisions[p.id] or selection.policy_ref != self._config.policy_ref:
                return ConnectionCheckResult(connection_status="rejected", reason="stale_profile_or_policy",
                    diagnostic_category="configuration_validation_failure", verification_state="configuration_invalid"), 409
            if not p.reviewed:
                return ConnectionCheckResult(connection_status="requires_approval", reason="operator_review_required",
                    diagnostic_category="configuration_validation_failure", verification_state="configuration_invalid"), 403
            if p.protocol == "http-json" and (
                getattr(selection, "authorization_confirmed", False) is not True
                or getattr(selection, "endpoint", None) != p.endpoint
            ):
                return ConnectionCheckResult(connection_status="requires_approval", reason="probe_authorization_required",
                    diagnostic_category="configuration_validation_failure", verification_state="configuration_invalid"), 403
            if not self._probe_supported(p):
                return ConnectionCheckResult(connection_status="unsupported", reason="safe_probe_not_verified",
                    diagnostic_category="configuration_validation_failure", verification_state="unsupported"), 200
        return self._probe_preset(p, sample_input=getattr(selection, "sample_input", None))

    def probe_candidate(
        self,
        profile: ManagedProfile,
        *,
        sample_input: str | None = None,
        discovery_id: str | None = None,
    ):
        """One authorized connection check for an unsaved discovery proposal.

        The API binds the endpoint and protocol to a discovery ID first. This
        method validates the proposal independently of saved target identities.
        A discovered ID can already exist; a probe never writes or reviews it.
        When an http-json draft has a resolved request contract but an unresolved
        response text_path, a bounded sample probe is still permitted so the
        Response Shape Inspector can suggest mappings from the observed response
        without marking the Target fully verified.
        """
        unresolved_text_path = (
            profile.protocol == "http-json"
            and profile.http_config is not None
            and profile.http_config.response.text_path == ""
        )
        effective_profile = profile
        if unresolved_text_path and profile.http_config is not None:
            effective_profile = profile.model_copy(
                update={
                    "http_config": profile.http_config.model_copy(
                        update={
                            "response": profile.http_config.response.model_copy(
                                update={"text_path": "__secagent_unresolved_text_path__"}
                            )
                        }
                    )
                }
            )
        with self._lock:
            candidate = self._preset(effective_profile)
            CatalogConfig.model_validate(self._config.model_dump() | {
                "targets": [candidate.model_dump()]})
            if not self._probe_supported(candidate):
                return ConnectionCheckResult(connection_status="unsupported", reason="safe_probe_not_verified",
                    diagnostic_category="configuration_validation_failure", verification_state="unsupported"), 200
        return self._probe_preset(
            candidate,
            sample_input=sample_input,
            unresolved_text_path=unresolved_text_path,
            discovery_id=discovery_id,
        )

    @staticmethod
    def _redacted_request_preview(
        method: str,
        url: str,
        headers: dict[str, str] | None,
        body: object,
        secrets_to_redact: list[str],
        *,
        secret_header_names: set[str] | None = None,
    ) -> dict:
        from reporting.redaction import Redactor
        cleaner = Redactor(secrets_to_redact)
        sensitive_headers = {"authorization", "proxy-authorization", "x-api-key", "api-key", "x-auth-token", "cookie"}
        if secret_header_names:
            sensitive_headers |= {h.lower() for h in secret_header_names}
        safe_headers: dict[str, str] = {}
        for k, v in (headers or {}).items():
            if k.lower() in sensitive_headers:
                safe_headers[k] = "Bearer [REDACTED]" if v.lower().startswith("bearer ") else "[REDACTED]"
            else:
                safe_headers[k] = cleaner.clean(v, limit=256, opaque=False) or ""
        try:
            body_text = json.dumps(body, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            body_text = str(body)
        redacted_body_text = cleaner.clean(body_text, limit=1536, opaque=False) or ""
        return {
            "method": method,
            "url": url,
            "headers": safe_headers,
            "body_preview": redacted_body_text,
        }

    @staticmethod
    def _redacted_text_preview(raw_text: str | None, secrets_to_redact: list[str], *, limit: int = 2048) -> str | None:
        if raw_text is None:
            return None
        from reporting.redaction import Redactor
        cleaner = Redactor(secrets_to_redact)
        return cleaner.clean(raw_text, limit=limit, opaque=False)

    _TRUSTED_DIAGNOSTIC_KEYS = frozenset({
        "configured_text_path", "text_extracted", "configured_correlation_id_path",
        "observed_correlation_id", "configured_status_path", "observed_status_value",
        "configured_complete_status_values", "configured_incomplete_status_values",
        "response_complete", "completeness_unresolved", "inline_events_extracted",
        "evaluation_readiness_limitations", "suggestions", "text_path_candidates",
        "text_path_ambiguous", "correlation_id_candidates", "status_path_candidates",
        "evidence_mapping_candidates", "path", "sample_type", "source", "confidence",
        "ambiguous", "limitation", "observed_value", "items", "items_observed",
        "item_fields_observed", "observed_item_keys", "suggested_mapping",
        "ambiguous_fields", "provenance", "execution_verified",
        "event_id", "action", "arguments", "decision", "status", "observation",
        "timestamp", "max_events",
    })

    @staticmethod
    def _sanitize_diagnostic_tree(
        value: object,
        secrets_to_redact: list[str],
        *,
        opaque: bool = False,
        field: str | None = None,
        preserve_trusted_keys: bool = True,
    ):
        from reporting.redaction import Redactor
        cleaner = Redactor(secrets_to_redact)
        # Runtime-observed value fields apply opaque-token scrubbing too; structural
        # path fields keep opaque=False so dotted JSON path names stay intact while
        # still redacting exact secrets, Bearer/JWT/sk- tokens, and URLs.
        opaque_value_fields = {"observed_correlation_id", "observed_status_value", "observed_value"}
        if isinstance(value, str):
            use_opaque = opaque or (field in opaque_value_fields)
            return cleaner.clean(value, limit=2048, opaque=use_opaque)
        if isinstance(value, dict):
            sanitized_dict = {}
            for raw_k, raw_v in value.items():
                if preserve_trusted_keys and isinstance(raw_k, str) and raw_k in ManagedTargetCatalog._TRUSTED_DIAGNOSTIC_KEYS:
                    clean_k = raw_k
                else:
                    clean_k = (
                        cleaner.clean(raw_k, limit=128, opaque=False)
                        if isinstance(raw_k, str)
                        else str(raw_k)
                    )
                    if clean_k in sanitized_dict:
                        idx = 2
                        while f"{clean_k}#{idx}" in sanitized_dict:
                            idx += 1
                        clean_k = f"{clean_k}#{idx}"
                sanitized_dict[clean_k] = ManagedTargetCatalog._sanitize_diagnostic_tree(
                    raw_v,
                    secrets_to_redact,
                    opaque=opaque,
                    field=raw_k if isinstance(raw_k, str) else None,
                    preserve_trusted_keys=preserve_trusted_keys,
                )
            return sanitized_dict
        if isinstance(value, list):
            return [
                ManagedTargetCatalog._sanitize_diagnostic_tree(
                    item,
                    secrets_to_redact,
                    opaque=opaque,
                    field=field,
                    preserve_trusted_keys=preserve_trusted_keys,
                )
                for item in value
            ]
        return value

    @staticmethod
    def _redacted_json_sample(body: object, secrets_to_redact: list[str], *, max_bytes: int = 16384) -> dict | None:
        if not isinstance(body, dict):
            return None
        cleaned = ManagedTargetCatalog._sanitize_diagnostic_tree(
            body, secrets_to_redact, opaque=True, preserve_trusted_keys=False
        )
        if not isinstance(cleaned, dict):
            return None
        try:
            encoded = json.dumps(cleaned, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            return None
        if len(encoded) > max_bytes:
            return None
        return cleaned

    def _probe_preset(
        self,
        p: Preset,
        *,
        sample_input: str | None = None,
        unresolved_text_path: bool = False,
        discovery_id: str | None = None,
    ):
        endpoint, timeout, protocol = p.endpoint, p.timeout_default, p.protocol
        credential_name = self._config.credential_aliases.get(p.credential_alias)
        session_auth = getattr(p, "session_auth", None)
        # No lock across network I/O. The API holds the dispatcher lock when
        # dispatch is enabled; a concurrent profile edit is otherwise rejected
        # by the API's shared management operation lock.
        from core.models import TestInput
        from targets.adapters.base import TargetAdapterError
        from targets.adapters.http_adapter import HttpTargetAdapter, format_bearer_header_value
        from workflow.dispatch import OneRequestHttpClient
        from workflow.response_inspector import inspect_http_response_shape
        from tools.http import HttpClientError

        secrets_to_redact: list[str] = []
        secret_header_names: set[str] = set()
        if credential_name:
            raw_secret = os.environ.get(credential_name)
            if raw_secret and raw_secret.strip():
                cleaned_secret = raw_secret.strip()
                secrets_to_redact.append(cleaned_secret)
                stripped_token = re.sub(r"(?i)^Bearer\s+", "", cleaned_secret).strip()
                if stripped_token:
                    secrets_to_redact.append(stripped_token)

        session_resolver = None
        if session_auth is not None:
            secret_header_names.add(session_auth.header_name.lower())
            expected_scope_kind = "discovery" if discovery_id is not None else "target"
            expected_scope_id = discovery_id if discovery_id is not None else p.id
            try:
                _, resolved_session_secret, session_variants = self.session_credentials.resolve(
                    session_auth.ref_id,
                    endpoint=endpoint,
                    scope_id=expected_scope_id,
                    scope_kind=expected_scope_kind,
                    expected_auth_type=session_auth.auth_type,
                    expected_header_name=session_auth.header_name,
                )
            except SessionCredentialError as exc:
                guidance_msg = (
                    "The session credential is bound to a different origin or target scope. "
                    "Supply a session credential bound to this exact Target endpoint."
                    if exc.code in {"session_credential_origin_mismatch", "session_credential_scope_mismatch", "session_credential_header_mismatch"}
                    else "Session credential is unavailable in Backend memory (for example after a Backend restart). "
                    "Supply the session credential in Target Authentication and try again."
                )
                return ConnectionCheckResult(
                    connection_status="unavailable",
                    reason="credential_unavailable",
                    diagnostic_category="missing_credentials",
                    verification_state="credentials_missing",
                    guidance=guidance_msg,
                ), 200
            for variant in session_variants:
                if variant not in secrets_to_redact:
                    secrets_to_redact.append(variant)

            def _resolve_session(ref: str, _expected_ref=session_auth.ref_id, _secret=resolved_session_secret) -> str | None:
                if ref != _expected_ref:
                    return None
                return _secret

            session_resolver = _resolve_session

        if protocol == "mcp-jsonrpc":
            headers = {"Content-Type": "application/json"}
            if credential_name:
                credential = os.environ.get(credential_name)
                if not credential or not credential.strip():
                    return ConnectionCheckResult(connection_status="unavailable", reason="credential_unavailable",
                        diagnostic_category="missing_credentials", verification_state="credentials_missing",
                        guidance=f"Required server credential for alias '{p.credential_alias}' is not set in the Workflow service environment."), 200
                try:
                    headers["Authorization"] = format_bearer_header_value(credential)
                except ValueError:
                    return ConnectionCheckResult(connection_status="unavailable", reason="credential_unavailable",
                        diagnostic_category="missing_credentials", verification_state="credentials_missing"), 200
            client = OneRequestHttpClient(endpoint, timeout, transport=self.probe_transport, max_bytes=16384)
            try:
                payload = {"jsonrpc": "2.0", "id": "secagent-connection-check", "method": "tools/list", "params": {}}
                response = client.request(method="POST", url=endpoint, headers=headers, json_body=payload, timeout=timeout)
            except (HttpClientError, ValueError) as exc:
                cause = exc.__cause__
                is_timeout = isinstance(cause, httpx.TimeoutException)
                reason = ("connection_timeout" if is_timeout else
                          "connection_refused_or_unreachable" if isinstance(cause, httpx.ConnectError) else
                          "response_too_large_or_bounded" if isinstance(exc, HttpClientError)
                              and "size limit" in str(exc) else "request_failed_or_bounded")
                return ConnectionCheckResult(connection_status="unavailable", reason=reason,
                    target_request_count=client.used, connection_reachable=None,
                    runtime_protocol_compatible=None,
                    diagnostic_category="timeout" if is_timeout else "network_connection_failure",
                    verification_state="transport_failed"), 200
            body = response.json_body
            if response.status_code == 401:
                return ConnectionCheckResult(connection_status="unavailable", reason="authentication_required",
                    target_request_count=client.used, connection_reachable=True,
                    runtime_protocol_compatible=None, http_status=401,
                    diagnostic_category="http_authentication_failure", verification_state="authentication_failed",
                    guidance="Target returned HTTP 401 Unauthorized. Select a registered credential alias or verify the configured token."), 200
            if response.status_code == 403:
                return ConnectionCheckResult(connection_status="unavailable", reason="authentication_required",
                    target_request_count=client.used, connection_reachable=True,
                    runtime_protocol_compatible=None, http_status=403,
                    diagnostic_category="http_permission_failure", verification_state="permission_denied",
                    guidance="Target returned HTTP 403 Forbidden. Verify the authenticated user or token has permission to access this endpoint."), 200
            compatible = (response.status_code == 200 and isinstance(body, dict) and
                body.get("jsonrpc") == "2.0" and body.get("id") == "secagent-connection-check" and
                isinstance(body.get("result"), dict) and isinstance(body["result"].get("tools"), list))
            return ConnectionCheckResult(connection_status="succeeded" if compatible else "incompatible",
                reason="mcp_tools_list_response" if compatible else (
                    "http_request_rejected" if response.status_code != 200 else "response_contract_unverified"),
                target_request_count=client.used, connection_reachable=True,
                runtime_protocol_compatible=compatible, http_status=response.status_code,
                diagnostic_category="response_extraction_succeeded" if compatible else (
                    "http_error" if response.status_code != 200 else "invalid_response_format"),
                verification_state="connection_verified" if compatible else "response_mapping_unresolved"), 200

        # Shared HTTP path for both http-json and openai-chat:
        # Build the exact same TargetProfile and prepare request via HttpTargetAdapter.
        try:
            target_profile = make_profile(
                p,
                p.default_model,
                timeout,
                credential_name,
                session_auth=session_auth,
            )
        except ValueError as exc:
            return ConnectionCheckResult(
                connection_status="rejected",
                reason="invalid_probe_configuration",
                diagnostic_category="configuration_validation_failure",
                verification_state="configuration_invalid",
                guidance=f"Target HTTP configuration is invalid: {exc}",
            ), 200

        if protocol == "openai-chat":
            prompt_text = "Reply with one word: ready."
            # Preserve stream=False on OpenAI-compatible chat probes.
            target_profile.interface.config["body"] = {
                **dict(target_profile.interface.config.get("body") or {}),
                "stream": False,
            }
        else:
            cleaned_sample = sample_input.strip() if isinstance(sample_input, str) and sample_input.strip() else None
            prompt_text = cleaned_sample or "Hello. Please reply with a brief status confirmation."

        try:
            method, url, headers, request_body, resolved_timeout = HttpTargetAdapter.prepare_request(
                target_profile,
                TestInput(id="secagent-connection-probe", prompt=prompt_text),
                credential_resolver=session_resolver,
            )
        except TargetAdapterError as exc:
            msg = str(exc)
            if "credential" in msg.lower():
                guidance_msg = (
                    "Required session credential is unavailable in Backend memory. Supply it again and retry."
                    if session_auth is not None
                    else f"Required credential for alias '{p.credential_alias}' is unavailable in the Workflow service environment."
                )
                return ConnectionCheckResult(
                    connection_status="unavailable",
                    reason="credential_unavailable",
                    diagnostic_category="missing_credentials",
                    verification_state="credentials_missing",
                    guidance=guidance_msg,
                ), 200
            return ConnectionCheckResult(
                connection_status="rejected",
                reason="invalid_probe_configuration",
                diagnostic_category="configuration_validation_failure",
                verification_state="configuration_invalid",
                guidance=self._redacted_text_preview(msg, secrets_to_redact, limit=240),
            ), 200

        include_previews = protocol == "http-json"
        req_preview = (
            self._redacted_request_preview(
                method,
                url,
                headers,
                request_body,
                secrets_to_redact,
                secret_header_names=secret_header_names,
            )
            if include_previews
            else None
        )
        max_bytes = 65536 if protocol == "http-json" else 16384
        client = OneRequestHttpClient(endpoint, timeout, transport=self.probe_transport, max_bytes=max_bytes)
        try:
            response = client.request(
                method=method,
                url=url,
                headers=headers,
                json_body=request_body,
                timeout=int(resolved_timeout) if resolved_timeout is not None else timeout,
            )
        except (HttpClientError, ValueError) as exc:
            cause = exc.__cause__
            is_timeout = isinstance(cause, httpx.TimeoutException)
            is_connect = isinstance(cause, httpx.ConnectError)
            is_oversize = isinstance(exc, HttpClientError) and "size limit" in str(exc)
            reason = (
                "connection_timeout" if is_timeout else
                "connection_refused_or_unreachable" if is_connect else
                "response_too_large_or_bounded" if is_oversize else
                "request_failed_or_bounded"
            )
            guidance = (
                f"Connection test timed out after {timeout}s without retrying. "
                "Note: a client-side timeout does not imply that the remote Agent stopped executing. "
                "Increase Target timeout in Advanced Configuration if your local Agent needs more time."
                if is_timeout else
                "Could not connect to the local endpoint. Verify the Target service is running and listening on the configured host and port."
                if is_connect else
                f"Target response exceeded the {max_bytes}-byte connection-test safety limit."
                if is_oversize else
                "The bounded connection-test request failed."
            )
            return ConnectionCheckResult(
                connection_status="unavailable",
                reason=reason,
                target_request_count=client.used,
                connection_reachable=None,
                runtime_protocol_compatible=None,
                diagnostic_category="timeout" if is_timeout else "network_connection_failure",
                verification_state="transport_failed",
                guidance=guidance,
                request_preview=req_preview,
            ), 200

        resp_preview = (
            self._redacted_text_preview(response.text, secrets_to_redact, limit=2048)
            if include_previews
            else None
        )

        if response.status_code == 401:
            return ConnectionCheckResult(
                connection_status="unavailable",
                reason="authentication_required",
                target_request_count=client.used,
                connection_reachable=True,
                runtime_protocol_compatible=None,
                http_status=401,
                diagnostic_category="http_authentication_failure",
                verification_state="authentication_failed",
                guidance=(
                    "Target returned HTTP 401 Unauthorized. Select a registered credential alias or verify that the "
                    "server-side credential environment variable contains a valid token."
                ),
                request_preview=req_preview,
                response_preview=resp_preview,
            ), 200

        if response.status_code == 403:
            return ConnectionCheckResult(
                connection_status="unavailable",
                reason="permission_denied" if protocol == "http-json" else "authentication_required",
                target_request_count=client.used,
                connection_reachable=True,
                runtime_protocol_compatible=None,
                http_status=403,
                diagnostic_category="http_permission_failure",
                verification_state="permission_denied",
                guidance=(
                    "Target returned HTTP 403 Forbidden. The request reached the service, but the current credentials "
                    "lack permission for this endpoint or resource."
                ),
                request_preview=req_preview,
                response_preview=resp_preview,
            ), 200

        if response.status_code in {400, 422}:
            return ConnectionCheckResult(
                connection_status="incompatible",
                reason="http_request_validation_failed" if protocol == "http-json" else "http_request_rejected",
                target_request_count=client.used,
                connection_reachable=True,
                runtime_protocol_compatible=False,
                http_status=response.status_code,
                diagnostic_category="http_request_validation_failure",
                verification_state="request_rejected",
                guidance=(
                    f"Target returned HTTP {response.status_code} validating the request payload. "
                    "Review required fields, parameter types, and request JSON structure in the response preview."
                ),
                request_preview=req_preview,
                response_preview=resp_preview,
            ), 200

        if not (200 <= response.status_code < 300):
            return ConnectionCheckResult(
                connection_status="incompatible",
                reason="http_request_rejected",
                target_request_count=client.used,
                connection_reachable=True,
                runtime_protocol_compatible=False,
                http_status=response.status_code,
                diagnostic_category="http_error",
                verification_state="request_rejected",
                guidance=f"Target returned HTTP {response.status_code}. Inspect the bounded response preview and Target logs.",
                request_preview=req_preview,
                response_preview=resp_preview,
            ), 200

        # 2xx HTTP transport succeeded: extract response via the shared HttpTargetAdapter logic.
        response_cfg = target_profile.interface.config.get("response")
        if response.json_body is None or not isinstance(response.json_body, dict):
            return ConnectionCheckResult(
                connection_status="incompatible",
                reason="invalid_response_format" if protocol == "http-json" else "response_contract_unverified",
                target_request_count=client.used,
                connection_reachable=True,
                runtime_protocol_compatible=False,
                http_status=response.status_code,
                diagnostic_category="invalid_response_format",
                verification_state="response_mapping_unresolved",
                guidance="Target returned HTTP 2xx, but the body was not a JSON object.",
                request_preview=req_preview,
                response_preview=resp_preview,
            ), 200

        exec_result = HttpTargetAdapter._to_execution_result(
            response,
            response_cfg,
            response_only_completion=True,
        )

        if protocol == "openai-chat":
            compatible = bool(exec_result.success and isinstance(exec_result.output_text, str))
            return ConnectionCheckResult(
                connection_status="succeeded" if compatible else "incompatible",
                reason="openai_chat_response" if compatible else "response_contract_unverified",
                target_request_count=client.used,
                connection_reachable=True,
                runtime_protocol_compatible=compatible,
                http_status=response.status_code,
                diagnostic_category="response_extraction_succeeded" if compatible else "response_extraction_failure",
                verification_state="connection_verified" if compatible else "response_mapping_unresolved",
            ), 200

        # Generic http-json: distinguish transport success from response extraction & mapping readiness.
        effective_response_cfg = (
            {**dict(response_cfg), "text_path": ""}
            if unresolved_text_path and isinstance(response_cfg, dict)
            else response_cfg
        )
        text_extracted = (not unresolved_text_path) and bool(exec_result.success and isinstance(exec_result.output_text, str))
        mapping_diag = self._sanitize_diagnostic_tree(
            inspect_http_response_shape(
                response.json_body,
                effective_response_cfg,
                extracted_text=exec_result.output_text if text_extracted else None,
                text_extracted=text_extracted,
                response_complete=exec_result.response_complete if text_extracted else None,
            ),
            secrets_to_redact,
            opaque=False,
        )
        resp_sample = self._redacted_json_sample(response.json_body, secrets_to_redact)

        if not text_extracted:
            raw_guidance = (
                f"HTTP {response.status_code} transport succeeded, but response text path is not yet configured. "
                "Apply a suggested path below and verify against this bounded response sample without sending another request."
                if unresolved_text_path
                else (
                    f"HTTP {response.status_code} transport succeeded, but response text extraction failed "
                    f"({exec_result.error or 'configured text_path did not match a string'}). "
                    "Review the response preview and suggested response text paths below."
                )
            )
            return ConnectionCheckResult(
                connection_status="incompatible",
                reason="response_extraction_failed",
                target_request_count=client.used,
                connection_reachable=True,
                runtime_protocol_compatible=False,
                http_status=response.status_code,
                diagnostic_category="response_extraction_failure",
                verification_state="response_mapping_unresolved",
                guidance=self._redacted_text_preview(raw_guidance, secrets_to_redact, limit=512),
                request_preview=req_preview,
                response_preview=resp_preview,
                response_sample=resp_sample,
                extracted_output=None,
                mapping_diagnostics=mapping_diag,
            ), 200

        extracted_preview = self._redacted_text_preview(exec_result.output_text, secrets_to_redact, limit=1024)
        raw_ok_guidance = (
            "Connection verified and response text extracted via shared generic_http adapter. "
            "Note: status completion semantics remain unresolved; confirm complete/incomplete status values before semantic Judge evaluation."
            if mapping_diag.get("completeness_unresolved")
            else "Connection verified and response text extracted via shared generic_http adapter. Security testing remains separately authorized."
        )
        return ConnectionCheckResult(
            connection_status="succeeded",
            reason="http_json_response",
            target_request_count=client.used,
            connection_reachable=True,
            runtime_protocol_compatible=True,
            http_status=response.status_code,
            diagnostic_category="response_extraction_succeeded",
            verification_state="connection_verified",
            guidance=self._redacted_text_preview(raw_ok_guidance, secrets_to_redact, limit=512),
            request_preview=req_preview,
            response_preview=resp_preview,
            response_sample=resp_sample,
            extracted_output=extracted_preview,
            mapping_diagnostics=mapping_diag,
        ), 200
