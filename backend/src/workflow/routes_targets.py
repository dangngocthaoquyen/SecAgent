"""Target, discovery, application-context, and evidence-source routes for Workflow API."""

from contextlib import nullcontext
from typing import Literal

from flask import jsonify, request
from pydantic import Field, ValidationError

from workflow.application_context import SaveApplicationContext
from workflow.asi01_batch import TEXT_CASES
from workflow.catalog import read_json
from workflow.discovery import DiscoveryError, DiscoveryRequest
from workflow.evidence_sources import CollectEvidenceSource, EvidenceSourceError, SaveEvidenceSource
from workflow.management import (
    ArchiveTargetsRequest,
    ManagedProfile,
    RestoreTargetRequest,
    ReviewProfile,
    SaveProfile,
)
from workflow.models import ClosedModel, ConnectionCheckRequest, TargetDraft


class LocalProbeRequest(ConnectionCheckRequest):
    endpoint: str | None = None
    authorization_confirmed: bool = False


class DiscoveryProbeRequest(ClosedModel):
    discovery_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    profile: ManagedProfile
    authorization_confirmed: Literal[True]


def register_target_routes(app, ctx) -> None:
    """Register target, discovery, application-context, and evidence routes on app."""

    catalog = ctx.catalog
    managed = ctx.managed
    local_single_user = ctx.local_single_user
    dispatcher = ctx.dispatcher
    admin_lock = ctx.admin_lock
    discovery = ctx.discovery
    imported_service = ctx.imported_service
    application_contexts = ctx.application_contexts
    evidence_sources = ctx.evidence_sources
    inventory = ctx.inventory
    fail = ctx.fail
    operator_authorized = ctx.operator_authorized

    def managed_auth():
        if not managed:
            return fail("target_management_disabled", 403)
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        return None

    @app.get("/api/testing/targets")
    def targets():
        rows = catalog.public_targets()
        if imported_service is not None:
            for row in rows:
                row["connection_verification"] = imported_service.connection_state(catalog._targets[row["id"]])
        return jsonify(
            workflow_schema_version="1.0.0",
            targets=rows,
            protocols=[
                {"id": "openai-chat", "state": "offline_configuration_supported"},
                {"id": "mcp-jsonrpc", "state": "local_discovery_and_review_supported"},
                {"id": "a2a", "state": "unsupported"},
            ],
        )

    @app.post("/api/testing/target-drafts/validate")
    def validate():
        try:
            draft = TargetDraft.model_validate(read_json(request.get_data()))
        except (ValueError, TypeError, ValidationError):
            return fail("invalid_draft", 400)
        errors = catalog.validate(draft)
        return jsonify(
            workflow_schema_version="1.0.0",
            configuration_status="invalid" if errors else "valid",
            errors=errors,
            target_id=draft.target_id,
            profile_revision=draft.profile_revision,
            connection_reachable=None,
            runtime_protocol_compatible=None,
            target_execution_performed=False,
            security_verdict=None,
        )

    @app.post("/api/testing/connection-checks")
    def connection_check():
        if managed and not operator_authorized():
            return fail("operator_authentication_required", 403)
        try:
            selection = (LocalProbeRequest if local_single_user else ConnectionCheckRequest).model_validate(
                read_json(request.get_data())
            )
        except (ValueError, TypeError, ValidationError):
            return fail("invalid_connection_selection", 400)
        with admin_lock, dispatcher._lock if dispatcher else nullcontext():
            if dispatcher and dispatcher._active:
                return fail("run_active", 409)
            if local_single_user:
                preset = catalog._targets.get(selection.target_id)
                if preset is not None and not preset.reviewed:
                    if (
                        selection.authorization_confirmed is not True
                        or selection.endpoint != preset.endpoint
                        or selection.profile_revision != catalog._revisions[preset.id]
                        or selection.policy_ref != catalog._config.policy_ref
                    ):
                        return fail("probe_authorization_required", 403)
                    try:
                        catalog.review_profile(
                            ReviewProfile(
                                target_id=preset.id,
                                profile_revision=selection.profile_revision,
                                policy_ref=selection.policy_ref,
                                endpoint=preset.endpoint,
                                protocol=preset.protocol,
                                model=preset.default_model,
                                capabilities=["tool_call"] if preset.protocol == "mcp-jsonrpc" else ["chat"],
                                authorization_confirmed=True,
                            )
                        )
                    except (ValueError, OSError, ValidationError):
                        return fail("probe_authorization_rejected", 409)
            result, status = catalog.connection_check(selection)
            if imported_service is not None:
                preset = catalog._targets.get(selection.target_id)
                if preset is not None:
                    imported_service.record_connection_check(preset, result)
        return jsonify(result.model_dump()), status

    @app.get("/api/testing/evidence-sources/target/<target_id>")
    def evidence_list(target_id):
        denied = managed_auth()
        if denied:
            return denied
        try:
            return jsonify(
                workflow_schema_version="1.0.0",
                sources=evidence_sources.list(target_id),
                allowed_endpoints=[p.model_dump() for p in evidence_sources.policy.allowed_endpoints],
                source_types=["http_json"],
                collection_modes=["snapshot"],
                action_verification_supported=False,
            )
        except (ValueError, OSError):
            return fail("evidence_storage_unavailable", 409)

    @app.post("/api/testing/evidence-sources/save")
    def evidence_save():
        denied = managed_auth()
        if denied:
            return denied
        try:
            selection = SaveEvidenceSource.model_validate(read_json(request.get_data()))
            with admin_lock:
                source = evidence_sources.save(selection.profile, selection.source_id, selection.expected_revision)
            return jsonify(workflow_schema_version="1.0.0", source=source)
        except EvidenceSourceError as exc:
            return fail(str(exc), 409)
        except (ValueError, OSError):
            return fail("invalid_evidence_source", 400)

    @app.post("/api/testing/evidence-sources/collect")
    def evidence_collect():
        denied = managed_auth()
        if denied:
            return denied
        try:
            selection = CollectEvidenceSource.model_validate(read_json(request.get_data()))
            with admin_lock, (dispatcher._lock if dispatcher else nullcontext()):
                if dispatcher and dispatcher._active:
                    return fail("active_run_blocks_source_collection", 409)
                capture = evidence_sources.collect(
                    selection.source_id, selection.expected_revision, selection.authorization_confirmed
                )
            return jsonify(workflow_schema_version="1.0.0", capture=capture)
        except EvidenceSourceError as exc:
            return fail(str(exc), 409)
        except (ValueError, OSError):
            return fail("invalid_evidence_collection", 400)

    @app.get("/api/testing/evidence-captures/<capture_id>")
    def evidence_capture(capture_id):
        denied = managed_auth()
        if denied:
            return denied
        try:
            return jsonify(workflow_schema_version="1.0.0", capture=evidence_sources.capture(capture_id))
        except (ValueError, OSError):
            return fail("evidence_capture_unavailable", 409)

    @app.get("/api/testing/managed-targets")
    def managed_targets():
        denied = managed_auth()
        if denied:
            return denied
        rows = catalog.public_targets()
        if imported_service is not None:
            for row in rows:
                row["connection_verification"] = imported_service.connection_state(catalog._targets[row["id"]])
        return jsonify(workflow_schema_version="1.0.0", targets=rows, policy_ref=catalog._config.policy_ref)

    @app.get("/api/testing/managed-targets/archived")
    def managed_archived_targets():
        denied = managed_auth()
        if denied:
            return denied
        return jsonify(workflow_schema_version="1.0.0", targets=catalog.archived_targets())

    @app.post("/api/testing/managed-targets/archive")
    def managed_archive_targets():
        denied = managed_auth()
        if denied:
            return denied
        try:
            item = ArchiveTargetsRequest.model_validate(read_json(request.get_data()))
            with admin_lock, dispatcher._lock if dispatcher else nullcontext():
                if dispatcher and dispatcher._active:
                    return fail("run_active", 409)
                archived = catalog.archive_targets(item)
        except (ValueError, TypeError, ValidationError, OSError):
            return fail("archive_target_rejected", 409)
        return jsonify(workflow_schema_version="1.0.0", archived=archived, active_targets=catalog.public_targets())

    @app.post("/api/testing/managed-targets/restore")
    def managed_restore_target():
        denied = managed_auth()
        if denied:
            return denied
        try:
            item = RestoreTargetRequest.model_validate(read_json(request.get_data()))
            with admin_lock, dispatcher._lock if dispatcher else nullcontext():
                if dispatcher and dispatcher._active:
                    return fail("run_active", 409)
                profile = catalog.restore_target(item)
        except (ValueError, TypeError, ValidationError, OSError):
            return fail("restore_target_rejected", 409)
        return jsonify(workflow_schema_version="1.0.0", profile=profile)

    @app.get("/api/testing/application-contexts/target/<target_id>")
    def read_application_context(target_id):
        denied = managed_auth()
        if denied:
            return denied
        try:
            with admin_lock:
                row = application_contexts.read(target_id)
                current = catalog._revisions.get(target_id)
            return jsonify(
                workflow_schema_version="1.0.0",
                context=row,
                binding_status="current" if row is None or row["draft"]["target_revision"] == current else "stale",
            )
        except (ValueError, OSError, ValidationError, TypeError, KeyError):
            return fail("application_context_unavailable", 409)

    @app.post("/api/testing/application-contexts/save")
    def save_application_context():
        denied = managed_auth()
        if denied:
            return denied
        try:
            item = SaveApplicationContext.model_validate(read_json(request.get_data()))
            with admin_lock:
                row = application_contexts.save(item)
            return jsonify(workflow_schema_version="1.0.0", context=row, binding_status="current")
        except (ValueError, OSError, ValidationError, TypeError, KeyError):
            return fail("application_context_rejected", 409)

    @app.post("/api/testing/discoveries")
    def discover_target():
        denied = managed_auth()
        if denied:
            return denied
        try:
            item = DiscoveryRequest.model_validate(read_json(request.get_data()))
            with admin_lock, dispatcher._lock if dispatcher else nullcontext():
                if dispatcher and dispatcher._active:
                    return fail("run_active", 409)
                result = discovery.discover(
                    item,
                    allowed_aliases=set(catalog._config.credential_aliases),
                    testcase_items=inventory.items,
                    text_case_ids=set(TEXT_CASES),
                )
            return jsonify(result)
        except (ValueError, TypeError, ValidationError) as exc:
            if isinstance(exc, DiscoveryError):
                return fail(
                    exc.code,
                    {
                        "invalid_discovery_url": 400,
                        "unknown_credential_alias": 400,
                        "unsafe_discovery_destination": 403,
                        "discovery_response_too_large": 413,
                    }.get(exc.code, 409),
                )
            return fail("invalid_discovery_request", 400)
        except OSError:
            return fail("discovery_storage_unavailable", 500)

    @app.get("/api/testing/discoveries/<discovery_id>")
    def read_discovery(discovery_id):
        denied = managed_auth()
        if denied:
            return denied
        try:
            return jsonify(discovery.load(discovery_id))
        except DiscoveryError as exc:
            return fail(exc.code, 404)

    @app.post("/api/testing/discovery-probes")
    def probe_discovery_candidate():
        denied = managed_auth()
        if denied:
            return denied
        try:
            item = DiscoveryProbeRequest.model_validate(read_json(request.get_data()))
            with admin_lock, dispatcher._lock if dispatcher else nullcontext():
                if dispatcher and dispatcher._active:
                    return fail("run_active", 409)
                discovery.validate_association(item.discovery_id, item.profile.endpoint, item.profile.protocol)
                result, status = catalog.probe_candidate(item.profile)
            return jsonify(result.model_dump()), status
        except DiscoveryError as exc:
            return fail(exc.code, 409)
        except (ValueError, TypeError, ValidationError):
            return fail("invalid_discovery_probe", 400)

    @app.post("/api/testing/managed-targets/validate")
    def managed_validate():
        denied = managed_auth()
        if denied:
            return denied
        try:
            item = SaveProfile.model_validate(read_json(request.get_data()))
            update = item.expected_profile_revision is not None
            if update and catalog._revisions.get(item.profile.id) != item.expected_profile_revision:
                return fail("stale_profile_revision", 409)
            catalog.validate_profile(item.profile, update=update)
        except (ValueError, TypeError, ValidationError):
            return fail("invalid_managed_profile", 400)
        return jsonify(
            workflow_schema_version="1.0.0",
            configuration_status="valid",
            target_request_count=0,
            target_execution_performed=False,
        )

    def managed_write(update=False, review=False):
        denied = managed_auth()
        if denied:
            return denied
        try:
            item = (ReviewProfile if review else SaveProfile).model_validate(read_json(request.get_data()))
        except (ValueError, TypeError, ValidationError):
            return fail("invalid_managed_profile", 400)
        try:
            with admin_lock, dispatcher._lock if dispatcher else nullcontext():
                if dispatcher and dispatcher._active:
                    return fail("run_active", 409)
                if not review and item.discovery_id:
                    discovery.validate_association(item.discovery_id, item.profile.endpoint, item.profile.protocol)
                profile = (
                    catalog.review_profile(item) if review else catalog.save_profile(item, update=update)
                )
                if not review and item.discovery_id:
                    discovery.associate(item.discovery_id, profile)
        except DiscoveryError as exc:
            return fail(exc.code, 409)
        except (ValueError, OSError, ValidationError):
            return fail("profile_change_rejected", 409)
        return jsonify(workflow_schema_version="1.0.0", profile=profile)

    @app.post("/api/testing/managed-targets/create")
    def managed_create():
        return managed_write()

    @app.post("/api/testing/managed-targets/update")
    def managed_update():
        return managed_write(update=True)

    @app.post("/api/testing/managed-targets/review")
    def managed_review():
        return managed_write(review=True)
