"""Execution, batch orchestration, grant, MCP action, and lab-attempt routes."""

from datetime import datetime, timedelta, timezone
import json
import os
import secrets
from typing import Literal
from uuid import uuid4

from flask import jsonify, request
from pydantic import Field, ValidationError

from workflow.admission import AdmissionRequest, ExecutionGrant
from workflow.asi01_batch import Asi01BatchSelection, Asi01BatchStart, Asi01BatchWorkflow, TextTargetRejected
from workflow.batch import BatchRejected
from workflow.catalog import read_json
from workflow.dispatch import DispatchRejected
from workflow.generic_imported_batch import (
    GenericImportedBatchWorkflow,
    ImportedBatchSelection,
    ImportedBatchStart,
)
from workflow.lab_attachment import LabAttemptReference, LabPreparationError
from workflow.mcp_actions import McpActionRejected, McpActionRunRequest
from workflow.offline_batch import OfflineBatchSelection, OfflineBatchStart
from workflow.plans import ASI, PlanSelection
from workflow.toolbot_lab_batch import ToolBotLabBatchWorkflow
from workflow.web_live_batch import WebLabPreviewRejected


class OperatorGrantRequest(AdmissionRequest):
    authorization_confirmed: Literal[True]


class RunSelectedRequest(AdmissionRequest):
    authorization_confirmed: Literal[True]
    submission_id: str = Field(pattern=r"^[a-f0-9]{32}$")


def register_execution_routes(app, ctx) -> None:
    """Register planning, dispatch, batch, grant, MCP action, and lab routes."""

    catalog = ctx.catalog
    managed = ctx.managed
    local_single_user = ctx.local_single_user
    nonce = ctx.nonce
    admin_lock = ctx.admin_lock
    dispatcher = ctx.dispatcher
    inventory = ctx.inventory
    admission = ctx.admission
    services = ctx.services
    mcp_action_service = ctx.mcp_action_service
    lab_preparer = ctx.lab_preparer
    fail = ctx.fail
    operator_authorized = ctx.operator_authorized

    @app.get("/api/testing/categories")
    def categories():
        return jsonify(workflow_schema_version="1.0.0", items=[{"id": v[0], "name": v[1]} for v in ASI.values()])

    @app.get("/api/testing/testcases")
    def testcases():
        return jsonify(
            workflow_schema_version="1.0.0",
            items=inventory.items,
            invalid_records=inventory.invalid_records,
        )

    @app.post("/api/testing/compatibility/preview")
    @app.post("/api/testing/plans/preview")
    def preview():
        try:
            selection = PlanSelection.model_validate(read_json(request.get_data()))
            result = inventory.preview(selection, catalog, plan=request.path.endswith("/plans/preview"))
        except (ValueError, TypeError):
            return fail("invalid_or_stale_plan_selection", 400)
        return jsonify(result)

    @app.post("/api/testing/readiness/preview")
    @app.post("/api/testing/admissions")
    def readiness():
        try:
            selection = AdmissionRequest.model_validate(read_json(request.get_data()))
            result = (
                dispatcher.readiness(selection, admit=request.path.endswith("/admissions"))
                if dispatcher
                else admission.assess(selection, admit=request.path.endswith("/admissions"))
            )
            if lab_preparer is not None and selection.testcase_ids == ["GH-WEB-001"]:
                result["lab_preflight_status"] = "not_checked"
                result["dispatch_available"] = False
        except (ValueError, TypeError):
            return fail("invalid_admission_request", 400)
        return jsonify(result)

    @app.post("/api/testing/runs")
    def run():
        if dispatcher is None:
            return fail("execution_disabled", 403)
        if not dispatcher.authorized(request.headers.get("X-SecAgent-Operator", "")):
            return fail("operator_authentication_required", 403)
        try:
            selection = AdmissionRequest.model_validate(read_json(request.get_data()))
            result = dispatcher.run(selection)
        except (ValueError, TypeError, DispatchRejected):
            return fail("run_rejected", 409)
        return jsonify(result)

    def issue_scoped_grant(selection, preview_result):
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        grant = ExecutionGrant(
            authorization_id=uuid4().hex,
            target_id=selection.target.target_id,
            profile_revision=selection.target.profile_revision,
            policy_ref=selection.target.policy_ref,
            testcase_id="GH-C01",
            asset_sha256=preview_result["asset_sha256"]["GH-C01"],
            scope="security_test_execution",
            expires_at=expires,
        )
        record = {
            "grant_id": grant.authorization_id,
            "target_id": grant.target_id,
            "profile_revision": grant.profile_revision,
            "policy_ref": grant.policy_ref,
            "testcase_id": grant.testcase_id,
            "asset_sha256": grant.asset_sha256,
            "scope": grant.scope,
            "expires_at": expires.isoformat(),
            "target_request_budget": 1,
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }
        with (dispatcher.output_root / ("operator-grant-" + grant.authorization_id + ".json")).open(
            "x", encoding="utf-8"
        ) as stream:
            json.dump(record, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        dispatcher.policy = dispatcher.policy.model_copy(update={"grants": [*dispatcher.policy.grants, grant]})
        return grant, expires

    @app.post("/api/testing/run-selected")
    def run_selected():
        if not local_single_user or not managed or dispatcher is None:
            return fail("local_controlled_execution_disabled", 403)
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        try:
            item = RunSelectedRequest.model_validate(read_json(request.get_data()))
            if (
                item.testcase_ids != ["GH-C01"]
                or item.asi_categories != ["ASI01"]
                or item.target_request_budget != 1
                or item.expected_plan_id is None
            ):
                return fail("unsupported_execution_scope", 409)
            selection = AdmissionRequest.model_validate(item.model_dump(exclude={"authorization_confirmed", "submission_id"}))
        except (ValueError, TypeError, ValidationError):
            return fail("invalid_run_selection", 400)
        if not admin_lock.acquire(blocking=False):
            return fail("run_active", 409)
        try:
            if not dispatcher._lock.acquire(blocking=False):
                return fail("run_active", 409)
            try:
                if dispatcher._active:
                    return fail("run_active", 409)
                submission_path = dispatcher.output_root / ("submission-" + item.submission_id + ".json")
                if submission_path.exists():
                    return fail("duplicate_submission", 409)
                preview_result = dispatcher._admission(selection).assess(selection)
                blockers = set(preview_result["blockers"]) | {
                    code for row in preview_result["items"] for code in row["blockers"]
                }
                if preview_result["plan_id"] != item.expected_plan_id:
                    return (
                        jsonify(
                            workflow_schema_version="1.0.0",
                            execution_status="blocked",
                            blockers=["stale_plan_identity"],
                            target_request_count=0,
                        ),
                        409,
                    )
                if blockers - {"execution_authorization_missing_or_expired"}:
                    return (
                        jsonify(
                            workflow_schema_version="1.0.0",
                            execution_status="blocked",
                            blockers=sorted(blockers),
                            target_request_count=0,
                        ),
                        409,
                    )
                admitted = dispatcher.readiness(selection, admit=True)
                if not admitted["dispatch_available"] and len(dispatcher.policy.grants) >= 20:
                    return fail("grant_budget_exhausted", 409)
                record = {
                    "submission_id": item.submission_id,
                    "target_id": selection.target.target_id,
                    "profile_revision": selection.target.profile_revision,
                    "policy_ref": selection.target.policy_ref,
                    "testcase_id": "GH-C01",
                    "plan_id": item.expected_plan_id,
                    "evaluation_mode": selection.evaluation_mode,
                    "target_request_budget": 1,
                    "authorization_confirmed": True,
                    "submitted_at": datetime.now(timezone.utc).isoformat(),
                }
                with submission_path.open("x", encoding="utf-8") as stream:
                    json.dump(record, stream, sort_keys=True)
                    stream.flush()
                    os.fsync(stream.fileno())
                if not admitted["dispatch_available"]:
                    issue_scoped_grant(selection, preview_result)
                    admitted = dispatcher.readiness(selection, admit=True)
                if not admitted["dispatch_available"]:
                    return fail("admission_rejected", 409)
                result = dispatcher.run(selection)
                return jsonify(result)
            finally:
                dispatcher._lock.release()
        except (ValueError, TypeError, ValidationError, OSError, KeyError, DispatchRejected):
            return fail("run_rejected", 409)
        finally:
            admin_lock.release()

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
            selection = (
                ImportedBatchSelection
                if isinstance(service, GenericImportedBatchWorkflow)
                else Asi01BatchSelection if isinstance(service, Asi01BatchWorkflow) else OfflineBatchSelection
            ).model_validate(raw)
            if selection.transport_mode is not None and not isinstance(service, GenericImportedBatchWorkflow):
                return fail("invalid_batch_selection", 400)
            return jsonify(service.preview(selection))
        except TextTargetRejected as exc:
            return fail(exc.code, 409)
        except WebLabPreviewRejected as exc:
            return fail(exc.code, 409)
        except BatchRejected as exc:
            if str(exc) == "workflow_selection_required":
                return fail("workflow_selection_required", 400)
            if isinstance(service, ToolBotLabBatchWorkflow) and str(exc).startswith("toolbot_lab_"):
                return fail(str(exc), 409)
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
            item = (
                ImportedBatchStart
                if isinstance(service, GenericImportedBatchWorkflow)
                else Asi01BatchStart if isinstance(service, Asi01BatchWorkflow) else OfflineBatchStart
            ).model_validate(raw)
            if item.transport_mode is not None and not isinstance(service, GenericImportedBatchWorkflow):
                return fail("invalid_batch_selection", 400)
            if any(
                other is not service and getattr(other, "_worker", None) is not None and other._worker.is_alive()
                for other in services.values()
            ):
                return fail("another_workflow_active", 409)
            return jsonify(service.start(item)), 202
        except TextTargetRejected as exc:
            return fail(exc.code, 409)
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

    @app.post("/api/testing/execution-grants")
    def execution_grant():
        if not managed or dispatcher is None:
            return fail("controlled_execution_not_enabled", 403)
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        try:
            item = OperatorGrantRequest.model_validate(read_json(request.get_data()))
            if (
                item.testcase_ids != ["GH-C01"]
                or item.asi_categories != ["ASI01"]
                or item.target_request_budget != 1
                or item.expected_plan_id is None
            ):
                return fail("grant_scope_rejected", 409)
            selection = AdmissionRequest.model_validate(item.model_dump(exclude={"authorization_confirmed"}))
            with admin_lock, dispatcher._lock:
                if dispatcher._active:
                    return fail("run_active", 409)
                # A grant can satisfy only the missing authorization blocker.
                # All profile, asset, binding and policy checks run first.
                preview_result = dispatcher._admission(selection).assess(selection)
                blockers = set(preview_result["blockers"]) | {
                    code for row in preview_result["items"] for code in row["blockers"]
                }
                if (
                    preview_result["plan_id"] != item.expected_plan_id
                    or blockers != {"execution_authorization_missing_or_expired"}
                    or len(dispatcher.policy.grants) >= 20
                ):
                    return fail("grant_prerequisites_unmet", 409)
                grant, expires = issue_scoped_grant(selection, preview_result)
        except (ValueError, TypeError, ValidationError, OSError, KeyError):
            return fail("grant_rejected", 409)
        return jsonify(
            workflow_schema_version="1.0.0",
            grant_id=grant.authorization_id,
            expires_at=expires.isoformat(),
            testcase_id="GH-C01",
            target_request_budget=1,
            plan_id=preview_result["plan_id"],
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

    @app.post("/api/testing/lab-attempts/preview")
    def lab_preview():
        if lab_preparer is None:
            return fail("lab_preparation_disabled", 403)
        try:
            selection = AdmissionRequest.model_validate(read_json(request.get_data()))
            return jsonify(lab_preparer.preview(selection))
        except (ValueError, TypeError, LabPreparationError):
            return fail("lab_preparation_rejected", 400)

    @app.post("/api/testing/lab-attempts/prepare")
    def lab_prepare():
        if lab_preparer is None:
            return fail("lab_preparation_disabled", 403)
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        try:
            selection = AdmissionRequest.model_validate(read_json(request.get_data()))
            return jsonify(lab_preparer.prepare(selection))
        except (ValueError, TypeError, LabPreparationError, OSError):
            return fail("lab_preparation_rejected", 409)

    @app.post("/api/testing/lab-attempts/preflight")
    def lab_preflight():
        if lab_preparer is None:
            return fail("lab_preparation_disabled", 403)
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        try:
            reference = LabAttemptReference.model_validate(read_json(request.get_data()))
            return jsonify(lab_preparer.preflight(reference.attempt_id))
        except (ValueError, TypeError, LabPreparationError, OSError):
            return fail("lab_preflight_rejected", 409)
