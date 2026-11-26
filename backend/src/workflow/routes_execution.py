"""Batch orchestration (Hosted MCP Agent / Imported) and structured MCP action routes."""

import secrets

from flask import jsonify, request
from pydantic import ValidationError

from workflow.batch import BatchRejected
from workflow.catalog import read_json
from workflow.generic_imported_batch import (
    GenericImportedBatchWorkflow,
    ImportedBatchSelection,
    ImportedBatchStart,
)
from workflow.mcp_actions import McpActionRejected, McpActionRunRequest


def register_execution_routes(app, ctx) -> None:
    """Register imported/MCP-agent batch orchestration and structured MCP action routes."""

    nonce = ctx.nonce
    services = ctx.services
    mcp_action_service = ctx.mcp_action_service
    fail = ctx.fail
    operator_authorized = ctx.operator_authorized

    def batch_auth():
        if not services:
            return fail("offline_batch_disabled", 403)
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        supplied = request.headers.get("X-SecAgent-Validation", "")
        if not secrets.compare_digest(supplied, nonce):
            return fail("validation_nonce_required", 403)
        return None

    def selected_batch_service(raw):
        if not isinstance(raw, dict):
            raise BatchRejected("workflow_selection_required")
        workflow_id = raw.pop("workflow_id", None)
        if workflow_id is None and len(services) == 1:
            workflow_id = next(iter(services))
        if workflow_id not in services:
            raise BatchRejected("workflow_selection_required")
        return services[workflow_id], raw

    def stored_batch_service(batch_run_id):
        for service in services.values():
            try:
                return service, service.orchestrator.state(batch_run_id)
            except BatchRejected:
                continue
        raise BatchRejected("batch_not_found")

    @app.post("/api/testing/batches/preview")
    def batch_preview():
        denied = batch_auth()
        if denied:
            return denied
        service = None
        try:
            service, raw = selected_batch_service(read_json(request.get_data()))
            selection = ImportedBatchSelection.model_validate(raw)
            return jsonify(service.preview(selection))
        except BatchRejected as exc:
            if str(exc) == "workflow_selection_required":
                return fail("workflow_selection_required", 400)
            if isinstance(service, GenericImportedBatchWorkflow):
                return fail(str(exc), 409)
            return fail("batch_preview_rejected", 409)
        except ValidationError:
            return fail("invalid_batch_selection", 400)
        except (ValueError, TypeError, OSError):
            return fail("server_side_preview_error", 500)

    @app.post("/api/testing/batches")
    def batch_start():
        denied = batch_auth()
        if denied:
            return denied
        service = None
        try:
            service, raw = selected_batch_service(read_json(request.get_data()))
            item = ImportedBatchStart.model_validate(raw)
            if any(
                other is not service and getattr(other, "_worker", None) is not None and other._worker.is_alive()
                for other in services.values()
            ):
                return fail("another_workflow_active", 409)
            return jsonify(service.start(item)), 202
        except (ValueError, TypeError, ValidationError, BatchRejected, OSError) as exc:
            if isinstance(exc, BatchRejected) and str(exc) == "workflow_selection_required":
                return fail("workflow_selection_required", 400)
            if isinstance(service, GenericImportedBatchWorkflow) and isinstance(exc, BatchRejected):
                return fail(str(exc), 409)
            return fail("batch_start_rejected", 409)

    def batch_state(batch_run_id):
        denied = batch_auth()
        if denied:
            return None, denied
        try:
            return stored_batch_service(batch_run_id), None
        except BatchRejected:
            return None, fail("batch_not_found", 404)

    @app.get("/api/testing/batches/<batch_run_id>")
    def batch_status(batch_run_id):
        located, denied = batch_state(batch_run_id)
        if denied:
            return denied
        _, state = located
        active = next(
            (case for case in state["snapshot"]["cases"] if case["testcase_id"] == state["active_testcase_id"]), None
        )
        current_stage = (
            state["events"][-1]["stage"] if state["events"] and state["status"] in {"preparing", "running"} else None
        )
        return jsonify(
            workflow_schema_version="1.0.0",
            batch_run_id=batch_run_id,
            status=state["status"],
            total=state["total"],
            processed=state["processed"],
            progress_percent=state["processed"] * 100 // state["total"],
            remaining_count=state["total"] - state["processed"],
            target_request_count=state["target_request_count"],
            request_budget_consumed=state["request_budget_consumed"],
            request_count_unknown=state["request_count_unknown"],
            active_testcase_id=state["active_testcase_id"],
            active_testcase_name=active["name"] if active else None,
            active_asi_category=active["asi_category"] if active else None,
            current_stage=current_stage,
            snapshot_sha256=state["snapshot_sha256"],
            aggregate_report_sha256=state.get("aggregate_report_sha256"),
            counts={
                name: sum(row["status"] == name for row in state["results"])
                for name in ("completed", "error", "blocked", "unsupported", "skipped", "cancelled")
            },
            verdict_counts={
                name: sum(row["verdict"] == name for row in state["results"])
                for name in ("PASS", "FAIL", "INCONCLUSIVE", "ERROR")
            },
        )

    @app.get("/api/testing/batches/<batch_run_id>/events")
    def batch_events(batch_run_id):
        located, denied = batch_state(batch_run_id)
        if denied:
            return denied
        _, state = located
        return jsonify(workflow_schema_version="1.0.0", batch_run_id=batch_run_id, events=state["events"])

    @app.get("/api/testing/batches/<batch_run_id>/results")
    def batch_results(batch_run_id):
        located, denied = batch_state(batch_run_id)
        if denied:
            return denied
        _, state = located
        return jsonify(
            workflow_schema_version="1.0.0",
            batch_run_id=batch_run_id,
            snapshot=state["snapshot"],
            results=state["results"],
            aggregate_report_sha256=state.get("aggregate_report_sha256"),
        )

    @app.post("/api/testing/batches/<batch_run_id>/cancel")
    def batch_cancel(batch_run_id):
        located, denied = batch_state(batch_run_id)
        if denied:
            return denied
        service, state = located
        try:
            service.orchestrator.cancel_remaining(batch_run_id)
        except (BatchRejected, OSError):
            return fail("batch_cancel_rejected", 409)
        return jsonify(
            workflow_schema_version="1.0.0",
            batch_run_id=batch_run_id,
            cancellation_requested=state["status"] in {"preparing", "running"},
            active_testcase_id_at_request=state["active_testcase_id"],
            active_request_cancelled=False,
        )

    @app.get("/api/testing/mcp-actions")
    def mcp_actions():
        if mcp_action_service is None:
            return fail("mcp_action_workflow_disabled", 403)
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        return jsonify(
            workflow_schema_version="1.0.0",
            catalog_sha256=mcp_action_service.catalog_sha256,
            cases=mcp_action_service.public_cases(),
            hybrid_configured=mcp_action_service.hybrid_config is not None,
        )

    @app.post("/api/testing/mcp-actions/run")
    def run_mcp_action():
        if mcp_action_service is None:
            return fail("mcp_action_workflow_disabled", 403)
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        try:
            item = McpActionRunRequest.model_validate(read_json(request.get_data()))
            result = mcp_action_service.run(
                case_id=item.testcase_id,
                target_id=item.target_id,
                profile_revision=item.profile_revision,
                catalog_sha256=item.catalog_sha256,
                authorization_confirmed=item.authorization_confirmed,
                evaluation_mode=item.evaluation_mode,
                evidence_configuration=item.evidence_configuration,
            )
        except (ValueError, TypeError, ValidationError) as exc:
            code = str(exc) if isinstance(exc, McpActionRejected) else "mcp_action_request_invalid"
            return fail(code, 409)
        return jsonify(workflow_schema_version="1.0.0", result=result)
