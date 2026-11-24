"""HTTP API routes for Generic MCP Tool Catalogs and Hosted MCP Agent Bindings (Stage 3D.6)."""

from __future__ import annotations

import secrets

from flask import jsonify, request
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from core.models.asi05_execution import ActionSignature, ProhibitedAction, ToolArgumentPredicate
from targets.runtimes import EnvironmentAuthorizationScope, ReviewedToolSpec
from workflow.catalog import read_json
from workflow.mcp_agent_runtime_binding import ReviewedAgentRuntimeDraft
from workflow.mcp_tool_catalog import McpToolCatalogDraft
from workflow.models import Identifier, ModelName


class McpToolCatalogCreateRequest(BaseModel):
    """Create a server-owned MCP Tool Catalog draft from discovery or manual schemas."""

    model_config = ConfigDict(extra="forbid")

    mcp_target_id: Identifier
    catalog_name: str = Field(default="Reviewed MCP Tool Catalog", min_length=1, max_length=128)
    discovery_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    selected_tool_names: tuple[str, ...] | None = Field(default=None, max_length=64)
    reviewed_tools: tuple[ReviewedToolSpec, ...] | None = Field(default=None, min_length=1, max_length=64)


class OnboardingReviewRequest(BaseModel):
    """Explicit operator review confirmation tied to an exact server revision digest."""

    model_config = ConfigDict(extra="forbid")

    expected_revision_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    review_confirmed: bool


class AgentBindingCreateRequest(BaseModel):
    """Create an unreviewed Hosted MCP Agent Binding draft pairing LLM + MCP + Policy."""

    model_config = ConfigDict(extra="forbid")

    llm_target_id: Identifier
    mcp_target_id: Identifier
    catalog_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    catalog_revision_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    model: ModelName
    system_prompt: str = Field(min_length=1, max_length=32768)
    reviewed_tools: tuple[ReviewedToolSpec, ...] | None = Field(default=None, min_length=1, max_length=64)
    environment_scope: EnvironmentAuthorizationScope | None = None
    max_model_calls: int = Field(default=4, ge=1, le=4)
    max_tool_calls: int = Field(default=3, ge=0, le=3)
    llm_timeout_seconds: float = Field(default=15.0, gt=0.0, le=60.0)
    mcp_timeout_seconds: float = Field(default=10.0, gt=0.0, le=60.0)
    total_timeout_seconds: float = Field(default=45.0, gt=0.0, le=120.0)
    max_response_bytes: int = Field(default=131072, ge=1024, le=1048576)
    authorized_actions: tuple[ActionSignature, ...] = Field(default=(), max_length=64)
    prohibited_actions: tuple[ProhibitedAction, ...] = Field(default=(), max_length=64)
    authorized_predicates: tuple[ToolArgumentPredicate, ...] = Field(default=(), max_length=32)
    prohibited_predicates: tuple[ToolArgumentPredicate, ...] = Field(default=(), max_length=32)


def _public_binding(row: dict) -> dict:
    """Ensure API binding payloads never leak credential aliases or secret values."""
    binding = dict(row.get("binding") or {})
    llm_has_cred = bool(binding.pop("llm_credential_alias", None))
    mcp_has_cred = bool(binding.pop("mcp_credential_alias", None))
    binding["has_llm_credential"] = llm_has_cred
    binding["has_mcp_credential"] = mcp_has_cred
    return {**row, "binding": binding}


def register_agent_onboarding_routes(app, ctx) -> None:
    """Register Generic MCP Tool Catalog & Hosted MCP Agent Binding routes."""

    nonce = ctx.nonce
    admin_lock = ctx.admin_lock
    mcp_tool_catalogs = ctx.mcp_tool_catalogs
    mcp_agent_bindings = ctx.mcp_agent_bindings
    fail = ctx.fail
    operator_authorized = ctx.operator_authorized

    def read_auth():
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        return None

    def write_auth():
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        supplied = request.headers.get("X-SecAgent-Validation", "")
        if not secrets.compare_digest(supplied, nonce):
            return fail("validation_nonce_required", 403)
        return None

    @app.get("/api/testing/mcp-catalogs")
    def mcp_catalog_list():
        denied = read_auth()
        if denied:
            return denied
        if mcp_tool_catalogs is None:
            return fail("mcp_catalog_managed_catalog_required", 403)
        with admin_lock:
            return jsonify(workflow_schema_version="1.0.0", catalogs=mcp_tool_catalogs.list_all())

    @app.get("/api/testing/mcp-catalogs/target/<target_id>")
    def mcp_catalog_for_target(target_id):
        denied = read_auth()
        if denied:
            return denied
        if mcp_tool_catalogs is None:
            return fail("mcp_catalog_managed_catalog_required", 403)
        with admin_lock:
            return jsonify(workflow_schema_version="1.0.0", catalogs=mcp_tool_catalogs.for_target(target_id))

    @app.post("/api/testing/mcp-catalogs/drafts")
    def mcp_catalog_draft():
        denied = write_auth()
        if denied:
            return denied
        if mcp_tool_catalogs is None:
            return fail("mcp_catalog_managed_catalog_required", 403)
        try:
            body = McpToolCatalogCreateRequest.model_validate(read_json(request.get_data()))
            with admin_lock:
                if body.reviewed_tools is not None:
                    draft = McpToolCatalogDraft(
                        mcp_target_id=body.mcp_target_id,
                        discovery_id=body.discovery_id,
                        catalog_name=body.catalog_name,
                        reviewed_tools=body.reviewed_tools,
                    )
                    created = mcp_tool_catalogs.create(draft)
                elif body.discovery_id is not None:
                    created = mcp_tool_catalogs.create_from_discovery(
                        mcp_target_id=body.mcp_target_id,
                        discovery_id=body.discovery_id,
                        selected_tool_names=body.selected_tool_names,
                        catalog_name=body.catalog_name,
                    )
                else:
                    return fail("mcp_catalog_tools_or_discovery_required", 400)
            return jsonify(workflow_schema_version="1.0.0", catalog=created), 201
        except ValidationError:
            return fail("mcp_catalog_invalid", 400)
        except ValueError as exc:
            code = str(exc) or "mcp_catalog_rejected"
            status = 400 if code in {
                "mcp_tool_schema_incompatible",
                "missing_input_schema",
                "unsupported_schema_keyword",
                "schema_nesting_too_deep",
                "unsupported_root_schema_type",
                "invalid_input_schema",
                "mcp_catalog_no_compatible_tools",
                "mcp_catalog_selected_tool_not_discovered",
            } else 409
            return fail(code, status)

    @app.get("/api/testing/mcp-catalogs/<catalog_id>")
    def mcp_catalog_read(catalog_id):
        denied = read_auth()
        if denied:
            return denied
        if mcp_tool_catalogs is None:
            return fail("mcp_catalog_managed_catalog_required", 403)
        try:
            with admin_lock:
                record = mcp_tool_catalogs.load(catalog_id)
                if record is None:
                    return fail("mcp_catalog_unavailable", 404)
                return jsonify(workflow_schema_version="1.0.0", catalog=mcp_tool_catalogs.status(record))
        except ValueError as exc:
            return fail(str(exc), 404)

    @app.post("/api/testing/mcp-catalogs/<catalog_id>/review")
    def mcp_catalog_review(catalog_id):
        denied = write_auth()
        if denied:
            return denied
        if mcp_tool_catalogs is None:
            return fail("mcp_catalog_managed_catalog_required", 403)
        try:
            req = OnboardingReviewRequest.model_validate(read_json(request.get_data()))
            with admin_lock:
                reviewed = mcp_tool_catalogs.review(
                    catalog_id,
                    req.expected_revision_sha256,
                    confirmed=req.review_confirmed,
                )
            return jsonify(workflow_schema_version="1.0.0", catalog=reviewed)
        except ValidationError:
            return fail("mcp_catalog_invalid", 400)
        except ValueError as exc:
            code = str(exc) or "mcp_catalog_review_rejected"
            status = 404 if code in {"mcp_catalog_unavailable", "mcp_catalog_invalid_id"} else 409
            return fail(code, status)

    @app.get("/api/testing/agent-bindings")
    def agent_binding_list():
        denied = read_auth()
        if denied:
            return denied
        if mcp_agent_bindings is None:
            return fail("mcp_agent_managed_catalog_required", 403)
        with admin_lock:
            rows = [_public_binding(row) for row in mcp_agent_bindings.list_all()]
            return jsonify(workflow_schema_version="1.0.0", bindings=rows)

    @app.post("/api/testing/agent-bindings/drafts")
    def agent_binding_draft():
        denied = write_auth()
        if denied:
            return denied
        if mcp_agent_bindings is None:
            return fail("mcp_agent_managed_catalog_required", 403)
        try:
            body = AgentBindingCreateRequest.model_validate(read_json(request.get_data()))
            with admin_lock:
                resolved_tools = body.reviewed_tools
                catalog_revision = body.catalog_revision_sha256
                if body.catalog_id is not None:
                    if mcp_tool_catalogs is None:
                        return fail("mcp_agent_catalog_unavailable", 409)
                    cat = mcp_tool_catalogs.load(body.catalog_id)
                    if cat is None:
                        return fail("mcp_agent_catalog_unavailable", 409)
                    cat_status = mcp_tool_catalogs.status(cat)
                    if cat_status["review_status"] != "reviewed":
                        return fail(
                            "mcp_agent_catalog_stale"
                            if cat_status["review_status"] == "stale"
                            else "mcp_agent_catalog_not_reviewed",
                            409,
                        )
                    if cat["draft"]["mcp_target_id"] != body.mcp_target_id:
                        return fail("mcp_agent_catalog_target_mismatch", 409)
                    if catalog_revision is not None and cat["revision_sha256"] != catalog_revision:
                        return fail("mcp_agent_catalog_stale", 409)
                    catalog_revision = cat["revision_sha256"]
                    if resolved_tools is None:
                        resolved_tools = tuple(ReviewedToolSpec.model_validate(t) for t in cat["draft"]["reviewed_tools"])
                if not resolved_tools:
                    return fail("mcp_agent_tools_or_catalog_required", 400)
                draft = ReviewedAgentRuntimeDraft(
                    llm_target_id=body.llm_target_id,
                    mcp_target_id=body.mcp_target_id,
                    catalog_id=body.catalog_id,
                    catalog_revision_sha256=catalog_revision,
                    model=body.model,
                    system_prompt=body.system_prompt,
                    reviewed_tools=resolved_tools,
                    environment_scope=body.environment_scope,
                    max_model_calls=body.max_model_calls,
                    max_tool_calls=body.max_tool_calls,
                    llm_timeout_seconds=body.llm_timeout_seconds,
                    mcp_timeout_seconds=body.mcp_timeout_seconds,
                    total_timeout_seconds=body.total_timeout_seconds,
                    max_response_bytes=body.max_response_bytes,
                    authorized_actions=body.authorized_actions,
                    prohibited_actions=body.prohibited_actions,
                    authorized_predicates=body.authorized_predicates,
                    prohibited_predicates=body.prohibited_predicates,
                )
                created = _public_binding(mcp_agent_bindings.create(draft))
            return jsonify(workflow_schema_version="1.0.0", binding=created), 201
        except ValidationError:
            return fail("mcp_agent_binding_invalid", 400)
        except ValueError as exc:
            return fail(str(exc) or "mcp_agent_binding_rejected", 409)

    @app.get("/api/testing/agent-bindings/<binding_id>")
    def agent_binding_read(binding_id):
        denied = read_auth()
        if denied:
            return denied
        if mcp_agent_bindings is None:
            return fail("mcp_agent_managed_catalog_required", 403)
        try:
            with admin_lock:
                record = mcp_agent_bindings.load(binding_id)
                if record is None:
                    return fail("mcp_agent_binding_unavailable", 404)
                return jsonify(workflow_schema_version="1.0.0", binding=_public_binding(mcp_agent_bindings.status(record)))
        except ValueError as exc:
            return fail(str(exc), 404)

    @app.post("/api/testing/agent-bindings/<binding_id>/review")
    def agent_binding_review(binding_id):
        denied = write_auth()
        if denied:
            return denied
        if mcp_agent_bindings is None:
            return fail("mcp_agent_managed_catalog_required", 403)
        try:
            req = OnboardingReviewRequest.model_validate(read_json(request.get_data()))
            with admin_lock:
                reviewed = _public_binding(
                    mcp_agent_bindings.review(
                        binding_id,
                        req.expected_revision_sha256,
                        confirmed=req.review_confirmed,
                    )
                )
            return jsonify(workflow_schema_version="1.0.0", binding=reviewed)
        except ValidationError:
            return fail("mcp_agent_binding_invalid", 400)
        except ValueError as exc:
            code = str(exc) or "mcp_agent_review_rejected"
            status = 404 if code == "mcp_agent_binding_unavailable" else 409
            return fail(code, status)
