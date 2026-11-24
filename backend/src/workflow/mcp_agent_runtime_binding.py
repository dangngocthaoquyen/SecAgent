"""Reviewed two-target runtime bindings and production ExecutionGuard for GENERIC-MCP-AGENT."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
from threading import RLock
from typing import Callable, Literal
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.models.asi05_execution import ActionSignature, ProhibitedAction, ToolArgumentPredicate
from reporting.artifacts import ArchiveReader, _json, _no_links
from targets.runtimes import (
    EnvironmentAuthorizationScope,
    ExecutionGuard,
    GuardCheckContext,
    GuardDecision,
    McpAgentRuntimeConfig,
    ReviewedToolSpec,
    compute_text_sha256,
    compute_tool_catalog_sha256,
)
from workflow.asi03_contracts import _hash
from workflow.batch import _write_atomic
from workflow.models import Identifier, ModelName


MAX_AGENT_REQUEST_BUDGET = 7


class HostedMcpAgentCatalog(BaseModel):
    """Reusable reviewed static MCP tool catalog definition loaded from disk."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    catalog_id: Identifier
    catalog_version: str = Field(min_length=1, max_length=32)
    target_composition: Literal["hosted_mcp_agent"] = "hosted_mcp_agent"
    target_description: str = Field(min_length=1, max_length=1024)
    mcp_target_id: Identifier
    mcp_source_evidence: tuple[str, ...] = Field(min_length=1, max_length=32)
    reviewed_tools: tuple[ReviewedToolSpec, ...] = Field(min_length=1, max_length=64)
    catalog_sha256: str | None = None

    @model_validator(mode="after")
    def validate_unique_tools(self):
        names = [tool.name for tool in self.reviewed_tools]
        if len(set(names)) != len(names):
            raise ValueError("hosted_mcp_catalog_duplicate_tool_name")
        return self


def load_hosted_mcp_agent_catalog(path: Path) -> HostedMcpAgentCatalog:
    """Load and validate a reusable hosted MCP tool catalog JSON without executing code."""
    catalog_path = Path(path)
    if not catalog_path.is_file() or catalog_path.is_symlink() or catalog_path.stat().st_size > 131072:
        raise ValueError("hosted_mcp_catalog_unavailable")
    raw = catalog_path.read_bytes()
    payload = _json(raw)
    if not isinstance(payload, dict):
        raise ValueError("hosted_mcp_catalog_invalid")
    catalog = HostedMcpAgentCatalog.model_validate(payload)
    digest = compute_tool_catalog_sha256(catalog.reviewed_tools)
    return catalog.model_copy(update={"catalog_sha256": digest})


class ReviewedAgentRuntimeDraft(BaseModel):
    """Operator-configured binding pairing one LLM target, one MCP target, and reviewed limits."""

    model_config = ConfigDict(extra="forbid")

    llm_target_id: Identifier
    mcp_target_id: Identifier
    catalog_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    catalog_revision_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    model: ModelName
    system_prompt: str = Field(min_length=1, max_length=32768)
    reviewed_tools: tuple[ReviewedToolSpec, ...] = Field(min_length=1, max_length=64)
    target_composition: Literal["hosted_mcp_agent"] = "hosted_mcp_agent"
    environment_scope: EnvironmentAuthorizationScope | None = None
    max_model_calls: int = Field(default=4, ge=1, le=4)
    max_tool_calls: int = Field(default=3, ge=0, le=3)
    max_nested_requests: Literal[0] = 0
    llm_timeout_seconds: float = Field(default=15.0, gt=0.0, le=60.0)
    mcp_timeout_seconds: float = Field(default=10.0, gt=0.0, le=60.0)
    total_timeout_seconds: float = Field(default=45.0, gt=0.0, le=120.0)
    max_response_bytes: int = Field(default=131072, ge=1024, le=1048576)
    authorized_actions: tuple[ActionSignature, ...] = Field(default=(), max_length=64)
    prohibited_actions: tuple[ProhibitedAction, ...] = Field(default=(), max_length=64)
    authorized_predicates: tuple[ToolArgumentPredicate, ...] = Field(default=(), max_length=32)
    prohibited_predicates: tuple[ToolArgumentPredicate, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def validate_semantics(self):
        if not self.system_prompt.strip():
            raise ValueError("mcp_agent_system_prompt_required")
        if self.llm_target_id == self.mcp_target_id:
            raise ValueError("mcp_agent_targets_must_be_distinct")
        names = [tool.name for tool in self.reviewed_tools]
        if len(set(names)) != len(names):
            raise ValueError("mcp_agent_duplicate_tool_name")
        allowed = {(a.tool_name, a.arguments_sha256) for a in self.authorized_actions}
        prohibited = {(a.tool_name, a.arguments_sha256) for a in self.prohibited_actions}
        if (
            allowed & prohibited
            or len(allowed) != len(self.authorized_actions)
            or len(prohibited) != len(self.prohibited_actions)
        ):
            raise ValueError("mcp_agent_action_policy_conflict")
        auth_p = {p.predicate_id for p in self.authorized_predicates}
        prohib_p = {p.predicate_id for p in self.prohibited_predicates}
        if (
            auth_p & prohib_p
            or len(auth_p) != len(self.authorized_predicates)
            or len(prohib_p) != len(self.prohibited_predicates)
        ):
            raise ValueError("mcp_agent_predicate_policy_conflict")
        return self


class McpAgentRuntimeBindingStore:
    """Server-owned immutable store of reviewed LLM+MCP agent runtime bindings."""

    def __init__(self, catalog, *, tool_catalog_store=None) -> None:
        if not hasattr(catalog, "data_dir"):
            raise ValueError("MCP Agent runtime binding store requires a managed target catalog.")
        self.catalog = catalog
        self.tool_catalog_store = tool_catalog_store
        self.root = Path(catalog.data_dir) / "mcp-agent-bindings"
        _no_links(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.reader = ArchiveReader(self.root)
        self.lock = RLock()

    def _path(self, binding_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", binding_id):
            raise ValueError("Invalid MCP Agent binding identifier.")
        return self.reader.path(f"{binding_id}.json")

    def _binding_snapshot(self, draft: ReviewedAgentRuntimeDraft) -> dict:
        llm = self.catalog._targets.get(draft.llm_target_id)
        mcp = self.catalog._targets.get(draft.mcp_target_id)
        if llm is None or mcp is None:
            raise ValueError("mcp_agent_target_unavailable")
        if llm.protocol != "openai-chat" or mcp.protocol != "mcp-jsonrpc":
            raise ValueError("mcp_agent_target_protocol_mismatch")
        if draft.model not in llm.models:
            raise ValueError("mcp_agent_model_not_approved")
        aliases = self.catalog._config.credential_aliases
        llm_cred = aliases.get(llm.credential_alias)
        mcp_cred = aliases.get(mcp.credential_alias)
        if llm_cred is not None and mcp_cred == llm_cred:
            raise ValueError("mcp_agent_credentials_must_be_isolated")
        # Validate concrete McpAgentRuntimeConfig invariants eagerly.
        prompt_sha = compute_text_sha256(draft.system_prompt)
        catalog_sha = compute_tool_catalog_sha256(draft.reviewed_tools)
        McpAgentRuntimeConfig(
            llm_target_id=llm.id,
            llm_profile_revision=self.catalog._revisions[llm.id],
            llm_endpoint=llm.endpoint,
            model=draft.model,
            credential_env=llm_cred,
            system_prompt=draft.system_prompt,
            system_prompt_sha256=prompt_sha,
            mcp_target_id=mcp.id,
            mcp_profile_revision=self.catalog._revisions[mcp.id],
            mcp_endpoint=mcp.endpoint,
            mcp_credential_env=mcp_cred,
            reviewed_tools=draft.reviewed_tools,
            tool_catalog_sha256=catalog_sha,
            target_composition=draft.target_composition,
            environment_scope=draft.environment_scope,
            max_model_calls=draft.max_model_calls,
            max_tool_calls=draft.max_tool_calls,
            max_nested_requests=0,
            llm_timeout_seconds=draft.llm_timeout_seconds,
            mcp_timeout_seconds=draft.mcp_timeout_seconds,
            total_timeout_seconds=draft.total_timeout_seconds,
            max_response_bytes=draft.max_response_bytes,
        )
        snapshot = {
            "llm_target_profile_revision": self.catalog._revisions[llm.id],
            "llm_endpoint_sha256": sha256(llm.endpoint.encode("utf-8")).hexdigest(),
            "llm_model": draft.model,
            "llm_credential_alias": llm.credential_alias,
            "mcp_target_profile_revision": self.catalog._revisions[mcp.id],
            "mcp_endpoint_sha256": sha256(mcp.endpoint.encode("utf-8")).hexdigest(),
            "mcp_credential_alias": mcp.credential_alias,
            "target_policy_ref": self.catalog._config.policy_ref,
            "system_prompt_sha256": prompt_sha,
            "tool_catalog_sha256": catalog_sha,
            "case_request_budget": draft.max_model_calls + draft.max_tool_calls,
        }
        if draft.catalog_id is not None:
            if self.tool_catalog_store is None:
                raise ValueError("mcp_agent_catalog_unavailable")
            cat = self.tool_catalog_store.load(draft.catalog_id)
            if cat is None:
                raise ValueError("mcp_agent_catalog_unavailable")
            if cat["draft"]["mcp_target_id"] != draft.mcp_target_id:
                raise ValueError("mcp_agent_catalog_target_mismatch")
            if cat["binding"]["tool_catalog_sha256"] != catalog_sha:
                raise ValueError("mcp_agent_catalog_mismatch")
            if (
                draft.catalog_revision_sha256 is not None
                and cat["revision_sha256"] != draft.catalog_revision_sha256
            ):
                raise ValueError("mcp_agent_catalog_stale")
            snapshot["catalog_id"] = cat["catalog_id"]
            snapshot["catalog_revision_sha256"] = cat["revision_sha256"]
        return snapshot

    def create(self, draft: ReviewedAgentRuntimeDraft) -> dict:
        with self.lock:
            material = {
                "binding_version": "1.0.0",
                "draft": draft.model_dump(mode="json"),
                "binding": self._binding_snapshot(draft),
            }
            record = {
                **material,
                "binding_id": uuid4().hex,
                "revision_sha256": _hash(material),
                "review_status": "draft",
                "reviewed_revision_sha256": None,
            }
            _write_atomic(self._path(record["binding_id"]), record)
            return self.status(record)

    def load(self, binding_id: str) -> dict | None:
        try:
            raw = self.reader.read(self._path(binding_id), 131072)
            if raw is None:
                return None
            record = _json(raw)
            if (
                set(record) != {
                    "binding_version",
                    "draft",
                    "binding",
                    "binding_id",
                    "revision_sha256",
                    "review_status",
                    "reviewed_revision_sha256",
                }
                or record["binding_id"] != binding_id
                or record["binding_version"] != "1.0.0"
                or record["review_status"] not in {"draft", "reviewed"}
            ):
                return None
            ReviewedAgentRuntimeDraft.model_validate(record["draft"])
            material = {key: record[key] for key in ("binding_version", "draft", "binding")}
            if (
                record["revision_sha256"] != _hash(material)
                or (
                    record["review_status"] == "reviewed"
                    and record["reviewed_revision_sha256"] != record["revision_sha256"]
                )
            ):
                return None
            return record
        except (OSError, ValueError, TypeError, KeyError):
            return None

    def status(self, record: dict) -> dict:
        draft = ReviewedAgentRuntimeDraft.model_validate(record["draft"])
        blockers: list[str] = []
        try:
            if self._binding_snapshot(draft) != record["binding"]:
                blockers.append("mcp_agent_binding_stale")
            llm = self.catalog._targets[draft.llm_target_id]
            mcp = self.catalog._targets[draft.mcp_target_id]
            if not llm.reviewed:
                blockers.append("mcp_agent_llm_not_reviewed")
            if not mcp.reviewed:
                blockers.append("mcp_agent_mcp_not_reviewed")
            if draft.catalog_id is not None:
                cat = self.tool_catalog_store.load(draft.catalog_id) if self.tool_catalog_store else None
                if cat is None:
                    blockers.append("mcp_agent_binding_stale")
                else:
                    cat_status = self.tool_catalog_store.status(cat)
                    if cat_status["review_status"] == "stale":
                        blockers.append("mcp_agent_binding_stale")
                    elif cat_status["review_status"] != "reviewed":
                        blockers.append("mcp_agent_catalog_not_reviewed")
        except (ValueError, KeyError):
            blockers.append("mcp_agent_binding_stale")
        if record["review_status"] != "reviewed":
            blockers.append("mcp_agent_binding_not_reviewed")
        return {
            **record,
            "review_status": "stale" if "mcp_agent_binding_stale" in blockers else record["review_status"],
            "readiness_blockers": blockers,
            "runtime_binding_ready": not blockers,
        }

    def review(self, binding_id: str, expected_revision: str, *, confirmed: bool) -> dict:
        with self.lock:
            record = self.load(binding_id)
            if record is None:
                raise ValueError("mcp_agent_binding_unavailable")
            if not confirmed or record["revision_sha256"] != expected_revision:
                raise ValueError("mcp_agent_review_confirmation_or_revision_required")
            blockers = [
                b for b in self.status(record)["readiness_blockers"]
                if b != "mcp_agent_binding_not_reviewed"
            ]
            if blockers:
                raise ValueError(blockers[0])
            record["review_status"] = "reviewed"
            record["reviewed_revision_sha256"] = record["revision_sha256"]
            _write_atomic(self._path(binding_id), record)
            return self.status(record)

    def for_targets(self, llm_target_id: str, mcp_target_id: str) -> dict | None:
        with self.lock:
            matches = []
            for path in sorted(self.root.glob("*.json"), key=lambda p: (p.stat().st_mtime_ns, p.name)):
                record = self.load(path.stem)
                if (
                    record
                    and record["draft"]["llm_target_id"] == llm_target_id
                    and record["draft"]["mcp_target_id"] == mcp_target_id
                ):
                    matches.append(self.status(record))
            return matches[-1] if matches else None

    def list_all(self) -> list[dict]:
        """List all saved MCP agent runtime bindings with live staleness/readiness status."""
        with self.lock:
            items = []
            for path in sorted(self.root.glob("*.json"), key=lambda p: (p.stat().st_mtime_ns, p.name)):
                record = self.load(path.stem)
                if record:
                    items.append(self.status(record))
            return items

    def build_runtime_config(self, record: dict) -> McpAgentRuntimeConfig:
        checked = self.status(record)
        if not checked["runtime_binding_ready"]:
            raise ValueError(checked["readiness_blockers"][0])
        draft = ReviewedAgentRuntimeDraft.model_validate(checked["draft"])
        binding = checked["binding"]
        llm = self.catalog._targets[draft.llm_target_id]
        mcp = self.catalog._targets[draft.mcp_target_id]
        aliases = self.catalog._config.credential_aliases
        return McpAgentRuntimeConfig(
            llm_target_id=llm.id,
            llm_profile_revision=self.catalog._revisions[llm.id],
            llm_endpoint=llm.endpoint,
            model=draft.model,
            credential_env=aliases.get(llm.credential_alias),
            system_prompt=draft.system_prompt,
            system_prompt_sha256=binding["system_prompt_sha256"],
            mcp_target_id=mcp.id,
            mcp_profile_revision=self.catalog._revisions[mcp.id],
            mcp_endpoint=mcp.endpoint,
            mcp_credential_env=aliases.get(mcp.credential_alias),
            reviewed_tools=draft.reviewed_tools,
            tool_catalog_sha256=binding["tool_catalog_sha256"],
            target_composition=draft.target_composition,
            environment_scope=draft.environment_scope,
            max_model_calls=draft.max_model_calls,
            max_tool_calls=draft.max_tool_calls,
            max_nested_requests=0,
            llm_timeout_seconds=draft.llm_timeout_seconds,
            mcp_timeout_seconds=draft.mcp_timeout_seconds,
            total_timeout_seconds=draft.total_timeout_seconds,
            max_response_bytes=draft.max_response_bytes,
        )

    @staticmethod
    def build_case_execution_policy(record: dict, testcase_id: str) -> dict:
        draft = ReviewedAgentRuntimeDraft.model_validate(record["draft"])
        material = {
            "schema_version": "1.0",
            "policy_id": f"ASI05-AGENT-{record['binding_id'][:12]}",
            "policy_version": "1.0.0",
            "review_status": "reviewed" if record.get("review_status") == "reviewed" else "draft",
            "testcase_id": testcase_id,
            "target_id": draft.llm_target_id,
            "subject": "agent_run",
            "authorized_actions": [item.model_dump(mode="json") for item in draft.authorized_actions],
            "prohibited_actions": [item.model_dump(mode="json") for item in draft.prohibited_actions],
        }
        if draft.authorized_predicates:
            material["authorized_predicates"] = [item.model_dump(mode="json") for item in draft.authorized_predicates]
        if draft.prohibited_predicates:
            material["prohibited_predicates"] = [item.model_dump(mode="json") for item in draft.prohibited_predicates]
        material["revision_sha256"] = sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return material


def _path_in_allowed_prefixes(raw_path: str, allowed_prefixes: tuple[str, ...] | list[str]) -> bool:
    if (
        not isinstance(raw_path, str)
        or not raw_path
        or "\x00" in raw_path
        or "\\" in raw_path
        or raw_path.startswith(("/", "~"))
        or (len(raw_path) >= 2 and raw_path[1] == ":")
    ):
        return False
    segments = [seg for seg in raw_path.split("/") if seg]
    if ".." in segments or "." in segments:
        return False
    normalized = "/".join(segments)
    return any(normalized.startswith(prefix.lstrip("./")) for prefix in allowed_prefixes)


def _url_in_allowed_hosts(raw_url: str, allowed_hosts: tuple[str, ...] | list[str]) -> bool:
    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host or parsed.username or parsed.password:
        return False
    for entry in allowed_hosts:
        candidate = entry.lower()
        if candidate.startswith("*.") and host.endswith(candidate[1:]):
            return True
        if host == candidate:
            return True
    return False


class WorkflowAgentExecutionGuard(ExecutionGuard):
    """Fail-closed per-step ExecutionGuard tying McpAgentRuntime to Batch & ExecutionGrant."""

    def __init__(
        self,
        *,
        expected_config_digest: str,
        llm_endpoint: str,
        mcp_endpoint: str,
        allowed_tools: frozenset[str],
        max_model_calls: int,
        max_tool_calls: int,
        grant_expires_at: datetime,
        cancellation_check: Callable[[], bool],
        ownership_and_grant_check: Callable[[], str | None],
        drift_check: Callable[[], str | None],
        environment_scope: EnvironmentAuthorizationScope | None = None,
    ) -> None:
        self._expected_config_digest = expected_config_digest
        self._llm_endpoint = llm_endpoint
        self._mcp_endpoint = mcp_endpoint
        self._allowed_tools = allowed_tools
        self._max_model_calls = max_model_calls
        self._max_tool_calls = max_tool_calls
        self._case_request_budget = max_model_calls + max_tool_calls
        self._grant_expires_at = grant_expires_at
        self._cancellation_check = cancellation_check
        self._ownership_and_grant_check = ownership_and_grant_check
        self._drift_check = drift_check
        self._environment_scope = environment_scope
        self.cancelled = False
        self.denial_reason: str | None = None

    def _deny(self, reason: str, *, cancelled: bool = False) -> GuardDecision:
        if cancelled:
            self.cancelled = True
        self.denial_reason = reason
        return GuardDecision(allowed=False, cancelled=cancelled, reason=reason)

    def check(self, context: GuardCheckContext) -> GuardDecision:
        if self._cancellation_check():
            return self._deny("operator_cancelled", cancelled=True)

        ownership_err = self._ownership_and_grant_check()
        if ownership_err is not None:
            return self._deny(ownership_err)

        if datetime.now(timezone.utc) >= self._grant_expires_at:
            return self._deny("grant_expired")

        if context.config_digest != self._expected_config_digest:
            return self._deny("runtime_config_drift")

        drift_err = self._drift_check()
        if drift_err is not None:
            return self._deny(drift_err)

        if context.model_calls_used > self._max_model_calls or context.tool_calls_used > self._max_tool_calls:
            return self._deny("step_budget_exceeded")
        if context.model_calls_used + context.tool_calls_used >= self._case_request_budget:
            return self._deny("case_request_budget_exhausted")

        if context.step_kind == "llm_completion":
            if context.target_endpoint != self._llm_endpoint:
                return self._deny("unauthorized_llm_endpoint")
        elif context.step_kind == "mcp_tool_call":
            if context.target_endpoint != self._mcp_endpoint:
                return self._deny("unauthorized_mcp_endpoint")
            if context.tool_name not in self._allowed_tools:
                return self._deny("unauthorized_tool")
            if self._environment_scope is not None:
                claims = dict(context.tool_scope_claims or ())
                if (
                    self._environment_scope.allowed_write_path_prefixes is not None
                    and context.tool_name in self._environment_scope.write_scoped_tools
                    and not _path_in_allowed_prefixes(
                        claims.get("path", ""),
                        self._environment_scope.allowed_write_path_prefixes,
                    )
                ):
                    return self._deny("outside_authorized_environment_scope")
                if (
                    self._environment_scope.allowed_fetch_hosts is not None
                    and context.tool_name in self._environment_scope.fetch_scoped_tools
                    and not _url_in_allowed_hosts(
                        claims.get("url", ""),
                        self._environment_scope.allowed_fetch_hosts,
                    )
                ):
                    return self._deny("outside_authorized_environment_scope")
        else:
            return self._deny("unknown_step_kind")

        return GuardDecision(allowed=True)
