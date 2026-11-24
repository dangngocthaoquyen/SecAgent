"""Loopback workflow API; target dispatch requires explicit operator opt-in."""
import argparse
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import secrets
import re
import subprocess
import sys

from flask import Flask, jsonify, request
from pydantic import ValidationError
from werkzeug.exceptions import HTTPException

from workflow.catalog import CatalogError, load_catalog, read_json
from workflow.management import ManagedTargetCatalog
from workflow.application_context import ApplicationContextStore
from workflow.discovery import DiscoveryEngine
from targets.adapters.discovery_providers import evidence_discovery_providers
from workflow.evidence_sources import EvidenceSourceStore, load_evidence_policy
from workflow.plans import TestcaseCatalog
from workflow.admission import AdmissionService, AdmissionPolicy
from workflow.dispatch import ControlledDispatcher
from workflow.offline_batch import OfflineBatchWorkflow
from workflow.asi01_batch import Asi01BatchWorkflow
from workflow.web_live_batch import ResearchBotWebBatchWorkflow
from workflow.web_lab_runtime import DockerWebLabRuntime
from workflow.toolbot_lab_batch import ToolBotLabBatchWorkflow
from workflow.generic_imported_batch import GenericImportedBatchWorkflow
from workflow.mcp_actions import McpActionWorkflow
from workflow.dataset_repository import DatasetRepository
from workflow.asi03_contracts import ASI03ContractStore, ASI03TargetPolicyStore
from workflow.asi05_policy import ASI05PolicyStore
from testing import RunnerEvaluationConfig
from testing.evaluation_config import LiveJudgeConfigurationError, validate_live_pi_config
from workflow.plans import ROOT
from workflow.lab_attachment import LabAttemptPreparer, ReviewedImages
from workflow.mcp_agent_runtime_binding import McpAgentRuntimeBindingStore
from workflow.mcp_tool_catalog import McpToolCatalogStore
from workflow.routes_agent_onboarding import register_agent_onboarding_routes
from workflow.routes_datasets_policies import register_dataset_policy_routes
from workflow.routes_execution import (OperatorGrantRequest, RunSelectedRequest,
    register_execution_routes)
from workflow.response_policies import ResponsePolicyStore
from workflow.routes_generic_runner import GenericRunService, register_generic_runner_routes
from workflow.routes_targets import (DiscoveryProbeRequest, LocalProbeRequest,
    register_target_routes)


@dataclass(frozen=True)
class WorkflowApiContext:
    """Application-scoped dependencies shared across Workflow API route groups."""

    catalog: object
    managed: bool
    local_single_user: bool
    nonce: str
    admin_lock: object
    dispatcher: object
    discovery: object
    inventory: object
    admission: object
    services: dict[str, object]
    asi01_service: object
    imported_service: object
    dataset_repo: object
    asi03_contracts: object
    asi03_policies: object
    asi05_policies: object
    application_contexts: object
    evidence_sources: object
    mcp_tool_catalogs: object
    mcp_agent_bindings: object
    mcp_action_service: object
    lab_preparer: object
    fail: object
    operator_authorized: object
    generic_run_service: object | None = None


def create_app(catalog, *, port=8092, testcase_catalog=None, admission_policy=None,
               dispatcher=None, lab_preparer=None, operator_secret=None,
               local_single_user=False, batch_service: OfflineBatchWorkflow | Asi01BatchWorkflow | ResearchBotWebBatchWorkflow | ToolBotLabBatchWorkflow | GenericImportedBatchWorkflow | None = None,
               batch_services: dict[str, object] | None = None,
               discovery_transport=None, dataset_repository: DatasetRepository | None = None,
               evidence_policy=None, evidence_transport=None,
               mcp_action_service: McpActionWorkflow | None = None,
               response_policy_dir: Path | None = None,
               generic_runs_dir: Path | None = None,
               generic_run_service: GenericRunService | None = None):
    if lab_preparer is not None and dispatcher is None and (not isinstance(operator_secret,str) or len(operator_secret)<32):
        raise ValueError('Lab preparation requires a separate operator secret.')
    managed = isinstance(catalog, ManagedTargetCatalog)
    if local_single_user and (not managed or not catalog.local_single_user):
        raise ValueError('Local single-user mode requires the managed catalog.')
    if managed and dispatcher is not None and dispatcher.catalog is not catalog:
        raise ValueError('Managed target and dispatcher catalogs must be identical.')
    if mcp_action_service is not None and (not managed or dispatcher is None
            or mcp_action_service.catalog is not catalog):
        raise ValueError('MCP action workflow requires the managed controlled catalog.')
    if batch_service is not None and batch_services:
        raise ValueError('Use one batch registration interface.')
    services = dict(batch_services or {})
    if batch_service is not None:
        service_name = ('imported' if isinstance(batch_service, GenericImportedBatchWorkflow) else
                        'asi01' if isinstance(batch_service, Asi01BatchWorkflow) else
                        'web_lab' if isinstance(batch_service, ResearchBotWebBatchWorkflow) else
                        'toolbot_lab' if isinstance(batch_service, ToolBotLabBatchWorkflow) else 'offline')
        services[service_name] = batch_service
    if any(name not in {'imported', 'asi01', 'web_lab', 'toolbot_lab', 'offline'} or
           service.dispatcher is not dispatcher or dispatcher is None or
           (isinstance(service, (Asi01BatchWorkflow, ResearchBotWebBatchWorkflow,
                                 ToolBotLabBatchWorkflow, GenericImportedBatchWorkflow)) and
            (not managed or not local_single_user)) for name, service in services.items()):
        raise ValueError('Batch must use the reviewed controlled dispatcher and catalog.')
    imported_service = next((s for s in services.values() if isinstance(s, GenericImportedBatchWorkflow)), None)
    asi01_service = next((s for s in services.values() if isinstance(s, Asi01BatchWorkflow)), None)
    if managed and dispatcher is None and (not isinstance(operator_secret, str) or len(operator_secret) < 32):
        raise ValueError('Target management requires a separate operator secret.')
    app = Flask(__name__, static_folder=None)
    app.config.update(MAX_CONTENT_LENGTH=5 * 1024 * 1024, DEBUG=False, PROPAGATE_EXCEPTIONS=False)
    nonce = secrets.token_urlsafe(32)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    inventory = testcase_catalog if testcase_catalog is not None else TestcaseCatalog()
    if imported_service is not None:
        # Discovery and connection checks in this offline session also stay in-process.
        discovery_transport = imported_service.dispatcher.transport or imported_service.mock_live_transport
        catalog.probe_transport = imported_service.dispatcher.transport or imported_service.mock_live_transport
    discovery = (DiscoveryEngine(catalog.data_dir, transport=discovery_transport,
                 evidence_providers=evidence_discovery_providers())
                 if managed else None)
    admission = AdmissionService(catalog, admission_policy)
    from threading import RLock
    admin_lock = RLock()
    dataset_repo = dataset_repository if dataset_repository is not None else (
        imported_service.dataset_repository if imported_service is not None
        else DatasetRepository(catalog.data_dir if managed else ROOT / "data")
    )
    asi03_contracts = ASI03ContractStore(dataset_repo, catalog) if managed else None
    asi03_policies = ASI03TargetPolicyStore(catalog) if managed else None
    asi05_policies = ASI05PolicyStore(catalog) if managed else None
    application_contexts = ApplicationContextStore(catalog) if managed else None
    evidence_sources = EvidenceSourceStore(catalog, policy=evidence_policy,
        transport=evidence_transport) if managed else None
    mcp_tool_catalogs = McpToolCatalogStore(catalog, discovery=discovery) if managed else None
    if managed:
        if imported_service is not None and imported_service.agent_bindings is not None:
            mcp_agent_bindings = imported_service.agent_bindings
            mcp_agent_bindings.tool_catalog_store = mcp_tool_catalogs
        else:
            mcp_agent_bindings = McpAgentRuntimeBindingStore(catalog, tool_catalog_store=mcp_tool_catalogs)
    else:
        mcp_agent_bindings = None

    def fail(code, status):
        preview_messages = {
            'evidence_endpoint_not_allowed': 'This exact URL and credential reference are not in the server evidence allowlist.',
            'evidence_authorization_required': 'Confirm authorization for one read-only evidence snapshot.',
            'evidence_source_stale': 'The source changed or is disabled. Reload its current configuration.',
            'evidence_target_stale': 'The target profile changed. Edit and save the source binding before collection.',
            'evidence_credential_unavailable': 'The configured server credential reference is unavailable.',
            'capture_quota_exceeded': 'The local capture quota is full. Archive captures through an operator-reviewed retention process.',
            "invalid_discovery_url": "Enter a complete HTTP or HTTPS URL without user information, query, fragment, or encoded path.",
            "invalid_discovery_request": "Confirm the bounded discovery scope and choose a supported protocol hint.",
            "unsafe_discovery_destination": "Discovery currently accepts only an explicitly authorized literal loopback IP and a supported metadata or chat path.",
            "discovery_redirect_rejected": "A metadata endpoint redirected. Discovery stopped without following it.",
            "discovery_response_too_large": "A metadata response exceeded the 16 KiB limit.",
            "unknown_credential_alias": "The credential alias is not registered in server configuration.",
            "discovery_profile_mismatch": "The saved endpoint differs from the discovery candidate. Start a new discovery or save manually.",
            "discovery_record_not_found": "Discovery record unavailable in this local workspace.",
            "discovery_storage_unavailable": "Discovery metadata could not be saved in the operator data directory.",
            "operator_authentication_required": "Operator authentication is required for target discovery and management.",
            "asi01_target_not_found": "Target is not in the active catalog. Reload Targets and select a saved DVAA text target.",
            "asi01_target_not_reviewed": "Review this target's current profile revision before previewing the ASI01 text batch.",
            "asi01_target_revision_mismatch": "Target revision or policy changed. Reload, validate, and review the current profile.",
            "asi01_target_configuration_invalid": "The selected target settings differ from the reviewed profile. Reload and validate the current target.",
            "asi01_target_not_supported": "This target has no reviewed ASI01 text batch binding. Select the exact DVAA SecureBot or ResearchBot profile.",
            "asi01_target_endpoint_mismatch": "The selected DVAA text target endpoint does not match its reviewed runtime binding. Edit, save, and review the exact endpoint.",
            "asi01_target_protocol_mismatch": "The ASI01 text batch requires HTTP OpenAI-compatible chat.",
            "asi01_target_model_mismatch": "The selected DVAA text target model does not match its reviewed runtime binding.",
            "asi01_target_timeout_exceeded": "The ASI01 text batch timeout must be at most 30 seconds.",
            "asi01_target_credentials_unsupported": "The reviewed DVAA text batch does not support a target credential binding.",
            "asi01_hybrid_judge_unavailable": "Hybrid evaluation is not enabled with a ready one-call-per-testcase Judge configuration. Use Rule-only or restart the ASI01 batch with an approved Judge configuration.",
            "asi01_hybrid_skill_unavailable": "The trusted goal-hijacking evaluation skill is unavailable. Restore the reviewed skill bundle before using Hybrid evaluation.",
            "asi01_evaluation_mode_unsupported": "Select Rule-only or Hybrid evaluation for the ASI01 text batch.",
            "web_lab_target_not_found": "Target not found in the active catalog. Reload Targets and select a saved Web Lab target.",
            "web_lab_target_mismatch": "Select the reviewed ResearchBot Web Lab target for this assessment.",
            "web_lab_profile_revision_mismatch": "The target profile changed. Reload and review its current revision.",
            "web_lab_target_not_reviewed": "Review the current Web Lab target revision before running tests.",
            "web_lab_endpoint_mismatch": "Web Lab endpoint mismatch. Edit the target to use http://127.0.0.1:17016/v1/chat/completions, save, and review the new revision.",
            "web_lab_protocol_mismatch": "The Web Lab target must use the HTTP OpenAI-compatible chat protocol.",
            "web_lab_credentials_unsupported": "The restricted Web Lab target must not use a credential binding.",
            "web_lab_model_mismatch": "The Web Lab target model must be researchbot.",
            "web_lab_timeout_exceeded": "The Web Lab target timeout must be at most 30 seconds.",
            "web_lab_target_configuration_invalid": "The saved Web Lab target does not match its reviewed configuration. Reload and validate it.",
            "web_lab_request_budget_invalid": "This assessment requires exactly two target-request slots.",
            "web_lab_assets_unavailable": "Reviewed Web testcase assets are unavailable on this server.",
            "toolbot_lab_target_unsupported": "Select the exact managed DVAA ToolBot Lab profile.",
            "toolbot_lab_target_unreviewed": "Review the current ToolBot Lab profile revision before running TM-002.",
            "toolbot_lab_contract_mismatch": "ToolBot Lab requires the exact offline MCP endpoint and profile identifier. Save and review the corrected profile.",
            "toolbot_lab_revision_or_configuration_invalid": "The ToolBot Lab profile or revision changed. Reload, validate and review it again.",
            "toolbot_lab_request_budget_invalid": "TM-002 permits exactly one synthetic target request.",
            "invalid_batch_selection": "Batch selection is malformed. Reload the target and select testcases again.",
            "server_side_preview_error": "The server could not produce a batch preview. Check the local Workflow API startup and logs.",
            "empty_file": "Uploaded dataset file is empty.",
            "file_too_large": "Uploaded dataset file exceeds the 5 MB limit.",
            "malformed_json": "Uploaded file is not valid JSON.",
            "invalid_envelope": "Dataset object must contain a 'testcases' list.",
            "promptfoo_report_not_supported": "Promptfoo evaluation reports cannot be imported as testcase datasets. Upload a testcase definition file instead.",
            "empty_testcases": "Dataset must contain at least one testcase.",
            "too_many_testcases": "Dataset contains more than 100 testcases.",
            "duplicate_testcase_id": "Duplicate testcase ID detected in dataset.",
            "missing_prompt": "Testcase is missing a prompt string.",
            "dataset_not_found": "Dataset not found in the local library.",
            "imported_target_not_found": "Selected target not found. Reload Targets and select a valid target.",
            "imported_target_not_reviewed": "Review the selected target before running imported testcases.",
            "imported_target_protocol_mismatch": "Imported direct-chat testcases require an HTTP OpenAI-compatible chat target.",
            "imported_target_capability_missing": "The target must support the 'chat' capability.",
            "imported_transport_choice_required": "Choose Offline Mock or Live Local before previewing.",
            "imported_live_mode_disabled": "Live Local imported execution is disabled at startup.",
            "imported_offline_mode_disabled": "Offline Mock imported execution is disabled at startup.",
            "imported_live_chat_profile_required": "Live Local requires a reviewed OpenAI-compatible chat profile without a credential binding.",
            "imported_live_loopback_endpoint_required": "Live Local requires a literal loopback IP and the exact /v1/chat/completions path.",
            "imported_live_connection_check_required": "Use Test Connection on this reviewed target revision before Live Local execution.",
            "imported_live_connection_check_expired": "The compatible connection check expired. Return to Targets and run Test Connection again.",
            "imported_live_connection_check_stale": "The target endpoint, model or reviewed revision changed after its connection check. Return to Targets and test the current profile again.",
            "imported_request_budget_invalid": "Request budget must equal the selected testcase count; one request is allowed per testcase.",
            "asi03_contract_invalid": "The ASI03 contract draft is malformed or contains unsupported fields.",
            "asi03_contract_unavailable": "The reviewed ASI03 contract is unavailable or failed integrity validation.",
            "asi03_contract_stale": "The dataset case or reviewed target revision changed. Create and review a new ASI03 contract.",
            "asi03_contract_not_reviewed": "Review this exact ASI03 contract before using Hybrid Judge evaluation.",
            "asi03_review_confirmation_or_revision_required": "Confirm the current ASI03 contract revision explicitly before review.",
            "asi03_action_runtime_unavailable": "Privileged-action ASI03 evaluation needs an independent agent action observer and authorization baseline.",
            "asi03_delivery_surface_unsupported": "This imported workflow supports only direct chat delivery; use a reviewed fixture for other surfaces.",
            "asi03_policy_not_reviewed": "Review the target's ASI03 identity policy before Hybrid evaluation.",
            "asi03_policy_stale": "The target profile changed. Save and review a new ASI03 identity policy.",
            "asi03_policy_unavailable": "The ASI03 target policy is unavailable or failed integrity validation.",
            "asi03_policy_fields_required": "Provide the agent identity, allowed roles, a prohibited claim boundary and expected response boundary.",
            "asi03_hybrid_mode_required": "Select Hybrid Judge to evaluate ASI03 response claims.",
            "asi05_policy_not_reviewed": "Review the target's ASI05 response policy before Hybrid evaluation.",
            "asi05_policy_stale": "The target profile changed. Save and review a new ASI05 response policy.",
            "asi05_policy_unavailable": "The ASI05 target policy is unavailable or failed integrity validation.",
            "asi05_policy_fields_required": "Provide prohibited command behavior, allowed benign context and expected response boundary.",
            "asi05_hybrid_mode_required": "Select Hybrid Judge to evaluate ASI05 response artifacts.",
            "mcp_agent_binding_unavailable": "Review and configure an MCP Agent runtime binding pairing the LLM and MCP targets first.",
            "mcp_agent_binding_not_reviewed": "Approve the current MCP Agent runtime binding revision before starting execution.",
            "mcp_agent_binding_stale": "Target profiles or runtime settings changed. Create and review a new MCP Agent runtime binding.",
            "mcp_agent_llm_not_reviewed": "Review the selected LLM target profile before running the MCP Agent path.",
            "mcp_agent_mcp_not_reviewed": "Review the selected MCP target profile before running the MCP Agent path.",
            "mcp_agent_mcp_target_required": "Select a reviewed MCP JSON-RPC target for the MCP Agent runtime path.",
            "mcp_agent_mcp_endpoint_required": "MCP Agent live local execution requires a loopback MCP JSON-RPC URL.",
            "legacy_backup_corrupted": "Legacy archived target backup is unreadable or corrupted; inspect the local backup file before deleting targets.",
            "generic_no_executable_cases": "No ready executable testcases remain after filtering unsupported or blocked cases.",
            "generic_collector_root_not_allowed": "Requested evidence collector directory is outside the server's approved collector roots.",
            "generic_submission_conflict": "This submission ID was already used with different scan parameters. Generate a new preview before starting a different scan.",
            "generic_submission_in_progress": "A scan request with this submission ID is already initializing on the server. Verify its submission status without resending.",
            "generic_submission_init_failed": "The initial submission failed before creating a Run record; verify status and preview again before retrying.",
            "generic_submission_record_unavailable": "The submission mapping exists on disk, but the Run record is temporarily unavailable. Retry GET verification without starting a duplicate scan.",
            "judge_provider_unavailable": "Hybrid LLM Judge is unavailable or missing credentials. Configure Judge credentials on the server or switch to Deterministic Rules / Evidence Only.",
        }
        message = preview_messages.get(code) or ("Controlled run request rejected; inspect the local run record before retrying."
                   if request.path == "/api/testing/runs" else
                   "Workflow request rejected; inspect the current target status and operator configuration.")
        return jsonify(workflow_schema_version="1.0.0", error={"code": code,
            "message": message}), status

    @app.before_request
    def boundary():
        try:
            local = ipaddress.ip_address(request.remote_addr or "").is_loopback
        except ValueError:
            local = False
        if not local or request.host not in allowed_hosts:
            return fail("local_only", 403)
        origin = request.headers.get("Origin")
        if origin not in {None, "http://" + request.host} or request.headers.get("Sec-Fetch-Site") == "cross-site":
            return fail("origin_rejected", 403)
        if request.query_string or request.headers.get("Transfer-Encoding"):
            return fail("invalid_request", 400)
        routes = {"/api/testing/health": "GET", "/api/testing/targets": "GET",
                  "/api/testing/target-drafts/validate": "POST",
                  "/api/testing/connection-checks": "POST",
                  "/api/testing/managed-targets": "GET",
                  "/api/testing/managed-targets/validate": "POST",
                  "/api/testing/managed-targets/create": "POST",
                  "/api/testing/managed-targets/update": "POST",
                  "/api/testing/managed-targets/review": "POST",
                  "/api/testing/managed-targets/delete": "POST",
                  "/api/testing/discoveries": "POST",
                  "/api/testing/discovery-probes": "POST",
                  "/api/testing/application-contexts/save": "POST",
                  "/api/testing/execution-grants": "POST",
                  "/api/testing/run-selected": "POST",
                  "/api/testing/batches/preview": "POST",
                  "/api/testing/batches": "POST",
                  "/api/testing/categories": "GET", "/api/testing/testcases": "GET",
                  "/api/testing/compatibility/preview": "POST", "/api/testing/plans/preview": "POST",
                  "/api/testing/readiness/preview": "POST", "/api/testing/admissions": "POST",
                  "/api/testing/runs": "POST",
                  "/api/testing/lab-attempts/preview": "POST",
                  "/api/testing/lab-attempts/prepare": "POST",
                  "/api/testing/lab-attempts/preflight": "POST",
                  "/api/testing/datasets": "GET",
                  "/api/testing/datasets/validate": "POST",
                  "/api/testing/datasets/import": "POST"}
        routes['/api/testing/mcp-actions'] = 'GET'
        routes['/api/testing/mcp-actions/run'] = 'POST'
        routes["/api/testing/asi03-contracts/drafts"] = "POST"
        routes["/api/testing/asi03-policies/drafts"] = "POST"
        routes["/api/testing/asi05-policies/drafts"] = "POST"
        routes['/api/testing/evidence-sources/save'] = 'POST'
        routes['/api/testing/evidence-sources/collect'] = 'POST'
        routes["/api/testing/mcp-catalogs"] = "GET"
        routes["/api/testing/mcp-catalogs/drafts"] = "POST"
        routes["/api/testing/agent-bindings"] = "GET"
        routes["/api/testing/agent-bindings/drafts"] = "POST"
        routes["/api/testing/response-policies/drafts"] = "POST"
        routes["/api/testing/generic-runs"] = "GET"
        routes["/api/testing/generic-runs/preview"] = "POST"
        routes["/api/testing/generic-runs/start"] = "POST"
        if re.fullmatch(r'/api/testing/evidence-sources/target/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', request.path):
            routes[request.path] = 'GET'
        if re.fullmatch(r'/api/testing/application-contexts/target/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', request.path):
            routes[request.path] = 'GET'
        if re.fullmatch(r'/api/testing/evidence-captures/[a-f0-9]{32}', request.path):
            routes[request.path] = 'GET'
        if re.fullmatch(r"/api/testing/batches/[a-f0-9]{32}(?:/(?:events|results|cancel))?", request.path):
            routes[request.path] = ("POST" if request.path.endswith("/cancel") else "GET")
        if re.fullmatch(r"/api/testing/discoveries/[a-f0-9]{32}(?:/mcp-tools)?", request.path):
            routes[request.path] = "GET"
        if re.fullmatch(r"/api/testing/datasets/[a-f0-9]{32}", request.path):
            routes[request.path] = "GET"
        if re.fullmatch(r"/api/testing/asi03-contracts/[a-f0-9]{32}(?:/review)?", request.path):
            routes[request.path] = "POST" if request.path.endswith("/review") else "GET"
        if re.fullmatch(r"/api/testing/asi03-contracts/lookup/[a-f0-9]{32}/import-[a-f0-9]{24}/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", request.path):
            routes[request.path] = "GET"
        if re.fullmatch(r"/api/testing/asi03-policies/[a-f0-9]{32}(?:/review)?", request.path):
            routes[request.path] = "POST" if request.path.endswith("/review") else "GET"
        if re.fullmatch(r"/api/testing/asi03-policies/target/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", request.path):
            routes[request.path] = "GET"
        if re.fullmatch(r"/api/testing/asi05-policies/[a-f0-9]{32}(?:/review)?", request.path):
            routes[request.path] = "POST" if request.path.endswith("/review") else "GET"
        if re.fullmatch(r"/api/testing/asi05-policies/target/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", request.path):
            routes[request.path] = "GET"
        if re.fullmatch(r"/api/testing/mcp-catalogs/[a-f0-9]{32}(?:/review)?", request.path):
            routes[request.path] = "POST" if request.path.endswith("/review") else "GET"
        if re.fullmatch(r"/api/testing/mcp-catalogs/target/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", request.path):
            routes[request.path] = "GET"
        if re.fullmatch(r"/api/testing/agent-bindings/[a-f0-9]{32}(?:/review)?", request.path):
            routes[request.path] = "POST" if request.path.endswith("/review") else "GET"
        if re.fullmatch(r"/api/testing/response-policies/target/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", request.path):
            routes[request.path] = "GET"
        if re.fullmatch(r"/api/testing/response-policies/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}/review", request.path):
            routes[request.path] = "POST"
        if re.fullmatch(r"/api/testing/generic-runs/[a-f0-9]{32}(?:/report\.json)?", request.path):
            routes[request.path] = "GET"
        if re.fullmatch(r"/api/testing/generic-runs/submission/[a-f0-9]{32}", request.path):
            routes[request.path] = "GET"
        if request.path not in routes:
            return fail("not_found", 404)
        if request.method != routes[request.path]:
            return fail("method_not_allowed", 405)
        if request.method == "GET" and request.content_length:
            return fail("body_not_allowed", 400)
        large_onboarding = (
            request.path.startswith("/api/testing/mcp-catalogs")
            or request.path.startswith("/api/testing/agent-bindings")
        )
        max_body = (
            5 * 1024 * 1024
            if (request.path.startswith("/api/testing/datasets") or request.path.startswith("/api/testing/generic-runs"))
            else 65536 if large_onboarding else 8192
        )
        if request.content_length and request.content_length > max_body:
            return fail("payload_too_large", 413)
        if request.method == "POST":
            if origin != "http://" + request.host:
                return fail("origin_required", 403)
            if request.mimetype != "application/json":
                return fail("json_required", 415)
            supplied = request.headers.get("X-SecAgent-Validation", "")
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", supplied) or not secrets.compare_digest(supplied, nonce):
                return fail("validation_nonce_required", 403)

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.errorhandler(Exception)
    def error(exc):
        return fail("request_rejected" if isinstance(exc, HTTPException) else "internal_error",
                    exc.code if isinstance(exc, HTTPException) else 500)

    if generic_run_service is None:
        default_policy_dir = response_policy_dir or (
            (catalog.data_dir / "response_policies") if managed else (ROOT / "data" / "response_policies")
        )
        default_runs_dir = generic_runs_dir or (
            (catalog.data_dir / "generic-runs") if managed else (ROOT / "results" / "generic-runs")
        )
        controlled_root = getattr(dispatcher, "output_root", None) or (
            (catalog.data_dir / "runs") if managed else None
        )
        pi_cfg = (
            dispatcher.hybrid_config.pi
            if (dispatcher is not None and getattr(dispatcher, "hybrid_config", None) is not None)
            else None
        )
        generic_run_service = GenericRunService(
            catalog=catalog,
            dataset_repo=dataset_repo,
            inventory=inventory,
            policy_store=ResponsePolicyStore(default_policy_dir),
            runs_root=default_runs_dir,
            controlled_runs_root=controlled_root,
            pi_config=pi_cfg,
            application_contexts=application_contexts,
            evidence_source_store=evidence_sources,
        )

    @app.get("/api/testing/health")
    def health():
        # Anti-CSRF capability only; NOT operator auth or an execution token.
        # Never persist in the browser or log it.
        controlled = isinstance(dispatcher, ControlledDispatcher)
        hybrid_available = controlled and dispatcher.hybrid_config is not None
        custom_imported = imported_service is not None
        j_stat = generic_run_service.judge_status()
        pi_ready = bool(j_stat.get("judge_ready"))
        if os.environ.get('SECAGENT_JUDGE_SETUP_REASON') == 'credential_missing' or j_stat.get("reason") == "credential_missing":
            setup_reason = 'credential_missing'
        elif j_stat.get("reason") == "executable_missing" and not pi_ready:
            setup_reason = 'executable_missing'
        elif pi_ready or hybrid_available:
            setup_reason = 'ready_to_validate_at_run'
        else:
            setup_reason = 'judge_configuration_missing'
        return jsonify(workflow_schema_version="1.0.0", status="ok",
                       mode="controlled_execution_enabled" if controlled else "offline_configuration_only",
                       target_network_access=controlled and 'toolbot_lab' not in services
                           and (not custom_imported or (imported_service.execution_mode != "offline_mock"
                               and imported_service.mock_live_transport is None)),
                       evaluation_modes=['rule_only','hybrid'] if hybrid_available else ['rule_only'],
                       judge_configuration='configured_unverified' if hybrid_available else 'unavailable',
                       judge_setup_reason=setup_reason,
                       judge_status=j_stat,
                       mcp_action_setup_reason='configured' if mcp_action_service else 'catalog_missing',
                       lab_preparation_enabled=lab_preparer is not None,
                       offline_batch_enabled='offline' in services,
                       asi01_batch_enabled=asi01_service is not None,
                       asi01_text_targets=asi01_service.public_target_contracts() if asi01_service else [],
                       web_lab_batch_enabled='web_lab' in services,
                       toolbot_lab_batch_enabled='toolbot_lab' in services,
                       custom_imported_batch_enabled=custom_imported,
                       imported_live_local_enabled=custom_imported and imported_service.execution_mode in {"live_local_http", "both"},
                       imported_live_local_mocked=custom_imported and imported_service.mock_live_transport is not None,
                       generic_runner_enabled=True,
                       pi_judge_ready=pi_ready,
                       registered_workflows=list(services) + (['mcp_actions'] if mcp_action_service else []),
                       target_management_enabled=managed,
                       evidence_sources_enabled=managed,
                       evidence_collection_enabled=managed and bool(evidence_sources.policy.allowed_endpoints),
                       operator_mode='local_single_user' if local_single_user else 'authenticated',
                       validation_nonce=nonce)

    def operator_authorized():
        supplied = request.headers.get('X-SecAgent-Operator', '')
        if dispatcher is not None:
            return dispatcher.authorized(supplied)
        return bool(operator_secret and supplied and secrets.compare_digest(supplied, operator_secret))

    ctx = WorkflowApiContext(
        catalog=catalog,
        managed=managed,
        local_single_user=local_single_user,
        nonce=nonce,
        admin_lock=admin_lock,
        dispatcher=dispatcher,
        discovery=discovery,
        inventory=inventory,
        admission=admission,
        services=services,
        asi01_service=asi01_service,
        imported_service=imported_service,
        dataset_repo=dataset_repo,
        asi03_contracts=asi03_contracts,
        asi03_policies=asi03_policies,
        asi05_policies=asi05_policies,
        application_contexts=application_contexts,
        evidence_sources=evidence_sources,
        mcp_tool_catalogs=mcp_tool_catalogs,
        mcp_agent_bindings=mcp_agent_bindings,
        mcp_action_service=mcp_action_service,
        lab_preparer=lab_preparer,
        fail=fail,
        operator_authorized=operator_authorized,
        generic_run_service=generic_run_service,
    )
    register_target_routes(app, ctx)
    register_dataset_policy_routes(app, ctx)
    register_execution_routes(app, ctx)
    register_agent_onboarding_routes(app, ctx)
    register_generic_runner_routes(app, ctx)

    return app


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True)
    parser.add_argument('--target-data-dir', help='Operator-owned local directory for managed target profiles and reviews')
    parser.add_argument('--evidence-policy', help='Non-secret explicit HTTP evidence endpoint allowlist JSON; default denies collection')
    parser.add_argument("--port", type=int, default=8092)
    parser.add_argument('--admission-policy', help='Operator-owned execution grant JSON; default denies all')
    parser.add_argument('--enable-controlled-runs', action='store_true',
                        help='Explicitly enable the bounded GH-C01 Runner slice')
    parser.add_argument('--enable-asi01-controlled-batch', action='store_true',
                        help='Opt into reviewed ResearchBot ASI01 text batch with baseline gate')
    parser.add_argument('--enable-researchbot-web-lab-batch', action='store_true',
                        help='Opt into one reviewed GH-WEB-001 assessment in the guarded Docker lab')
    parser.add_argument('--enable-toolbot-lab-batch', action='store_true',
                        help='Opt into offline synthetic ToolBot Lab TM-002 only; never contacts DVAA')
    parser.add_argument('--enable-custom-imported-batch', action='store_true',
                        help='Opt into Generic Custom Imported Testcase batch (Offline Mock by default)')
    parser.add_argument('--enable-unified-runtime', action='store_true',
                        help='Register reviewed ASI01 and imported chat workflows together; per-run gates remain mandatory')
    parser.add_argument('--enable-imported-live-local', action='store_true',
                        help='Allow explicit Live Local execution of imported prompts against reviewed loopback chat targets')
    parser.add_argument('--mcp-action-catalog',
                        help='Opt in to structured MCP action cases from an operator-reviewed JSON file')
    parser.add_argument('--reviewed-mcp-catalog-sha256',
                        help='Exact operator-approved catalog hash required when a case claims reviewed action policy')
    parser.add_argument('--dvaa-mcp-receipt-root',
                        help='Optional instrumented DVAA lab receipt directory; never an independent effect')
    parser.add_argument('--web-lab-state-dir', help='Operator-owned Web Lab state directory outside the repository')
    parser.add_argument('--web-lab-dvaa-image', help='Reviewed immutable DVAA image ID')
    parser.add_argument('--web-lab-fixture-image', help='Reviewed immutable fixture image ID')
    parser.add_argument('--web-lab-proxy-image', help='Reviewed immutable proxy image ID')
    parser.add_argument('--web-lab-guard-base-image', help='Reviewed guard base repository digest')
    parser.add_argument('--run-output-dir', help='Fresh results directory for controlled runs')
    parser.add_argument('--enable-web-hybrid-judge', action='store_true',
                        help='Explicitly enable server-owned hybrid evaluation for controlled runs')
    parser.add_argument('--web-hybrid-config', help='Operator-owned RunnerEvaluationConfig JSON for Pi Judge')
    parser.add_argument('--enable-lab-preparation', action='store_true',
                        help='Prepare fresh GH-WEB-001 fixtures only; never enables live web dispatch')
    parser.add_argument('--lab-attempt-dir', help='Isolated results child for prepared lab attempts')
    parser.add_argument('--lab-dvaa-image', help='Operator-reviewed immutable DVAA image ID')
    parser.add_argument('--lab-python-image', help='Operator-reviewed Python repository digest')
    parser.add_argument('--lab-proxy-image', help='Operator-reviewed proxy repository digest')
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535.")
    try:
        policy=None
        if args.admission_policy:
            from workflow.plans import safe_file
            path=Path(args.admission_policy).absolute()
            safe_file(path,path.parent)
            policy=AdmissionPolicy.model_validate(read_json(path.read_bytes()))
        secret=os.environ.get('SECAGENT_WORKFLOW_OPERATOR_TOKEN','')
        local_single_user=os.environ.get('SECAGENT_LOCAL_SINGLE_USER')=='1'
        catalog=load_catalog(args.catalog)
        if args.target_data_dir:
            if len(secret) < 32:
                raise ValueError('Target management requires an operator secret.')
            catalog=ManagedTargetCatalog(catalog._config,Path(args.target_data_dir),
                                         local_single_user=local_single_user)
        hybrid_config=None
        if args.enable_web_hybrid_judge:
            if not args.enable_controlled_runs or not args.web_hybrid_config:
                raise ValueError('Web hybrid Judge requires controlled runs and explicit configuration.')
            path=Path(args.web_hybrid_config).absolute()
            from workflow.plans import safe_file
            safe_file(path,path.parent)
            hybrid_config=RunnerEvaluationConfig.model_validate(read_json(path.read_bytes()))
            validate_live_pi_config(hybrid_config)
        elif args.web_hybrid_config:
            raise ValueError('Web hybrid configuration requires explicit opt-in.')
        dispatcher=None
        if args.enable_unified_runtime and any((args.enable_asi01_controlled_batch,
                args.enable_researchbot_web_lab_batch, args.enable_toolbot_lab_batch,
                args.enable_custom_imported_batch)):
            raise ValueError('Unified runtime selects its own workflow registry.')
        if args.enable_imported_live_local and not (args.enable_custom_imported_batch or args.enable_unified_runtime):
            raise ValueError('Live Local requires the custom imported batch opt-in.')
        if args.enable_controlled_runs:
            if not args.run_output_dir or (policy is None and not args.target_data_dir):
                raise ValueError('Controlled runs require output directory and an operator policy or managed target catalog.')
            if policy is None:
                policy=AdmissionPolicy()  # Deny all until a scoped, authenticated UI grant.
            if args.enable_custom_imported_batch and not args.enable_imported_live_local:
                from workflow.generic_imported_batch import offline_chat_transport
                mock_transport = offline_chat_transport()
            elif args.enable_toolbot_lab_batch:
                import httpx
                mock_transport = httpx.MockTransport(lambda _: httpx.Response(403))
            else:
                mock_transport = None
            dispatcher=ControlledDispatcher(catalog,policy,Path(args.run_output_dir),
                operator_secret=secret,hybrid_config=hybrid_config,transport=mock_transport)
        elif args.run_output_dir:
            raise ValueError('Output directory requires controlled-run opt-in.')
        batch_service=None
        batch_services=None
        if sum((args.enable_asi01_controlled_batch, args.enable_researchbot_web_lab_batch,
                args.enable_toolbot_lab_batch, args.enable_custom_imported_batch)) > 1:
            raise ValueError('Batch modes are separate opt-ins.')
        if args.enable_unified_runtime:
            if (not args.enable_controlled_runs or dispatcher is None or not local_single_user
                    or not isinstance(catalog, ManagedTargetCatalog)):
                raise ValueError('Unified runtime requires local managed controlled-run startup.')
            dataset_repo = DatasetRepository(catalog.data_dir)
            batch_services = {
                'asi01': Asi01BatchWorkflow(dispatcher),
                'imported': GenericImportedBatchWorkflow(dispatcher, dataset_repo,
                    execution_mode='both')}
        if args.enable_custom_imported_batch:
            if (not args.enable_controlled_runs or dispatcher is None or not local_single_user
                    or not isinstance(catalog, ManagedTargetCatalog)):
                raise ValueError('Custom Imported batch requires local managed controlled-run startup.')
            dataset_dir = catalog.data_dir
            dataset_repo = DatasetRepository(dataset_dir)
            batch_service = GenericImportedBatchWorkflow(dispatcher, dataset_repo,
                execution_mode="both" if args.enable_imported_live_local else "offline_mock")
        if args.enable_toolbot_lab_batch:
            if (not args.enable_controlled_runs or dispatcher is None or not local_single_user
                    or not isinstance(catalog, ManagedTargetCatalog)):
                raise ValueError('ToolBot Lab requires local managed controlled-run startup.')
            batch_service = ToolBotLabBatchWorkflow(dispatcher)
        if args.enable_asi01_controlled_batch:
            if (not args.enable_controlled_runs or dispatcher is None or not local_single_user
                    or not isinstance(catalog, ManagedTargetCatalog)):
                raise ValueError('ASI01 batch requires local managed controlled-run startup.')
            batch_service=Asi01BatchWorkflow(dispatcher)
        if args.enable_researchbot_web_lab_batch:
            if (not args.enable_controlled_runs or dispatcher is None or not local_single_user
                    or not isinstance(catalog, ManagedTargetCatalog)
                    or not all((args.web_lab_state_dir, args.web_lab_dvaa_image,
                                args.web_lab_fixture_image, args.web_lab_proxy_image,
                                args.web_lab_guard_base_image))):
                raise ValueError('Web Lab batch requires explicit local managed startup and reviewed images.')
            web_runtime = DockerWebLabRuntime(Path(args.web_lab_state_dir),
                dvaa_image=args.web_lab_dvaa_image,
                fixture_image=args.web_lab_fixture_image,
                proxy_image=args.web_lab_proxy_image,
                guard_base_image=args.web_lab_guard_base_image)
            web_runtime.verify_startup()  # No chat request; verifies the actual guarded lab.
            batch_service=ResearchBotWebBatchWorkflow(dispatcher, web_runtime)
        elif any((args.web_lab_state_dir, args.web_lab_dvaa_image,
                  args.web_lab_fixture_image, args.web_lab_proxy_image,
                  args.web_lab_guard_base_image)):
            raise ValueError('Web Lab image and state options require explicit opt-in.')
        lab_preparer=None
        if args.enable_lab_preparation:
            if not args.admission_policy or policy is None or not args.lab_attempt_dir or len(secret)<32:
                raise ValueError('Lab preparation requires policy, output directory and operator secret.')
            images=ReviewedImages(args.lab_dvaa_image or '',args.lab_python_image or '',args.lab_proxy_image or '')
            lab_preparer=LabAttemptPreparer(catalog,policy,Path(args.lab_attempt_dir),reviewed_images=images)
        elif any((args.lab_attempt_dir,args.lab_dvaa_image,args.lab_python_image,args.lab_proxy_image)):
            raise ValueError('Lab preparation options require explicit opt-in.')
        evidence_policy = load_evidence_policy(Path(args.evidence_policy)) if args.evidence_policy else None
        mcp_action_service = None
        if args.mcp_action_catalog:
            if not args.enable_controlled_runs or dispatcher is None or not isinstance(catalog, ManagedTargetCatalog):
                raise ValueError('Structured MCP actions require managed controlled runs.')
            from targets.adapters.dvaa_action_evidence import DvaaActionObserverFactory
            mcp_action_service = McpActionWorkflow(catalog, dispatcher.output_root,
                Path(args.mcp_action_catalog), hybrid_config=hybrid_config,
                observer_factory=DvaaActionObserverFactory(
                    Path(args.dvaa_mcp_receipt_root) if args.dvaa_mcp_receipt_root else None),
                reviewed_catalog_sha256=args.reviewed_mcp_catalog_sha256)
        elif args.dvaa_mcp_receipt_root:
            raise ValueError('DVAA receipts require a structured MCP action catalog.')
        elif args.reviewed_mcp_catalog_sha256:
            raise ValueError('Reviewed catalog pin requires an MCP action catalog.')
        if evidence_policy and not isinstance(catalog, ManagedTargetCatalog):
            raise ValueError('Evidence sources require managed target storage.')
        app = create_app(catalog, port=args.port,admission_policy=policy,
                         dispatcher=dispatcher,lab_preparer=lab_preparer,operator_secret=secret,
                         local_single_user=local_single_user,batch_service=batch_service,
                         batch_services=batch_services,
                         evidence_policy=evidence_policy,
                         mcp_action_service=mcp_action_service,
                         response_policy_dir=ROOT / "configs" / "response_policies")
    except LiveJudgeConfigurationError as error:
        print(f'Judge preflight failed: {error}', file=sys.stderr)
        return 2
    except (CatalogError,ValueError,OSError,ValidationError,RuntimeError,subprocess.TimeoutExpired):
        print('Invalid operator catalog or admission policy.', file=sys.stderr)
        return 2
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
