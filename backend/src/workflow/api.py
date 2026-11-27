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

from workflow.catalog import CatalogError, ROOT, load_catalog, read_json, safe_file
from workflow.management import ManagedTargetCatalog
from workflow.application_context import ApplicationContextStore
from workflow.discovery import DiscoveryEngine
from targets.adapters.discovery_providers import evidence_discovery_providers
from workflow.evidence_sources import EvidenceSourceStore, load_evidence_policy
from workflow.admission import AdmissionPolicy
from workflow.dispatch import ControlledDispatcher
from workflow.generic_imported_batch import GenericImportedBatchWorkflow
from workflow.mcp_actions import McpActionWorkflow
from workflow.dataset_repository import DatasetRepository
from workflow.asi03_contracts import ASI03ContractStore, ASI03TargetPolicyStore
from workflow.asi05_policy import ASI05PolicyStore
from testing import RunnerEvaluationConfig
from testing.evaluation_config import LiveJudgeConfigurationError, validate_live_pi_config
from workflow.mcp_agent_runtime_binding import McpAgentRuntimeBindingStore
from workflow.mcp_tool_catalog import McpToolCatalogStore
from workflow.routes_agent_onboarding import register_agent_onboarding_routes
from workflow.routes_datasets_policies import register_dataset_policy_routes
from workflow.routes_execution import register_execution_routes
from workflow.response_policies import ResponsePolicyStore
from workflow.routes_generic_runner import GenericRunService, register_generic_runner_routes
from workflow.target_locks import TargetExecutionLockRegistry
from workflow.routes_targets import (DiscoveryProbeRequest, LocalProbeRequest,
    register_target_routes)
from generator.api_routes import (
    GENERATOR_EXACT_ROUTES,
    GENERATOR_REGEX_ROUTES,
    GeneratorApiContext,
    register_generator_routes,
)
from generator.orchestrator import GenerateAndRunOrchestrator
from generator.preview_store import GeneratorPreviewStore
from generator.provider_factory import create_server_generator_provider
from generator.service import GeneratorService


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
    services: dict[str, object]
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
    fail: object
    operator_authorized: object
    generic_run_service: object | None = None
    operator_identity: object | None = None


def create_app(catalog, *, port=8092, admission_policy=None,
               dispatcher=None, operator_secret=None,
               local_single_user=False, batch_service: GenericImportedBatchWorkflow | None = None,
               batch_services: dict[str, object] | None = None,
               discovery_transport=None, dataset_repository: DatasetRepository | None = None,
               evidence_policy=None, evidence_transport=None,
               mcp_action_service: McpActionWorkflow | None = None,
               response_policy_dir: Path | None = None,
               generic_runs_dir: Path | None = None,
               generic_run_service: GenericRunService | None = None,
               generator_provider=None,
               generator_service: GeneratorService | None = None):
    del admission_policy
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
        services['imported'] = batch_service
    if any(name != 'imported' or not isinstance(service, GenericImportedBatchWorkflow)
           or service.dispatcher is not dispatcher or dispatcher is None
           or not managed or not local_single_user for name, service in services.items()):
        raise ValueError('Batch must use the reviewed controlled dispatcher and catalog.')
    imported_service = next((s for s in services.values() if isinstance(s, GenericImportedBatchWorkflow)), None)
    if managed and dispatcher is None and (not isinstance(operator_secret, str) or len(operator_secret) < 32):
        raise ValueError('Target management requires a separate operator secret.')
    app = Flask(__name__, static_folder=None)
    app.config.update(MAX_CONTENT_LENGTH=5 * 1024 * 1024, DEBUG=False, PROPAGATE_EXCEPTIONS=False)
    nonce = secrets.token_urlsafe(32)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    if imported_service is not None:
        # Discovery and connection checks in this offline session also stay in-process.
        discovery_transport = imported_service.dispatcher.transport or imported_service.mock_live_transport
        catalog.probe_transport = imported_service.dispatcher.transport or imported_service.mock_live_transport
    discovery = (DiscoveryEngine(catalog.data_dir, transport=discovery_transport,
                 evidence_providers=evidence_discovery_providers())
                 if managed else None)
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
            "probe_authorization_required": "Explicit operator authorization and exact endpoint confirmation are required for each HTTP JSON connection probe.",
            "invalid_session_credential": "Session credential request is invalid. Check the authentication mode, header name, target endpoint, and token value.",
            "invalid_session_credential_header": "API key header name is invalid or disallowed.",
            "invalid_session_credential_value": "Session credential value is empty or contains invalid characters.",
            "invalid_session_credential_origin": "Session credential endpoint URL is invalid.",
            "unsafe_session_credential_origin": "Session credentials may only bind to authorized local or private IP endpoints.",
            "session_credential_origin_mismatch": "Session credential origin does not match the target endpoint.",
            "session_credential_scope_mismatch": "Session credential belongs to a different target or discovery draft.",
            "session_credential_header_mismatch": "Session credential type or header name does not match the target configuration.",
            "session_credential_too_large": "Session credential value exceeds the maximum allowed size.",
            "session_credential_capacity_exceeded": "Backend memory session credential capacity reached; clear unused credentials first.",
            "credential_unavailable": "Configured target credential is unavailable. Supply the session credential or verify the server environment variable.",
            "generic_session_credential_stale": "The session credential changed or was cleared after scan preview. Generate a fresh scan preview and reconfirm before starting.",
            "generic_session_credential_authorization_required": "Live scans on session-authenticated targets require preview confirmation bound to the current session credential generation.",
            "generic_target_revision_stale": "The target profile revision changed after scan preview. Generate a fresh scan preview and reconfirm before starting.",
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
            "generic_managed_target_override_forbidden": "Inline target profile overrides are forbidden for managed catalog targets in live mode.",
            "generic_unsafe_target_endpoint": "Inline live target profiles are restricted to literal loopback IP HTTP/HTTPS endpoints without embedded credentials.",
            "generic_inline_credential_ref_forbidden": "Inline target profiles and caller-supplied evidence sources must not reference server environment credentials.",
            "generic_unapproved_evidence_source_forbidden": "Live HTTP evidence sources must be configured through the server's approved Evidence Source store.",
            "generic_forged_evidence_provenance_rejected": "Caller-supplied evidence sources cannot claim independent verification provenance.",
            "generic_invalid_policy_binding": "Per-ASI policy binding mapping is malformed or contains unsupported ASI categories.",
            "generic_submission_conflict": "This submission ID was already used with different scan parameters. Generate a new preview before starting a different scan.",
            "generic_submission_in_progress": "A scan request with this submission ID is already initializing on the server. Verify its submission status without resending.",
            "generic_submission_init_failed": "The initial submission failed before creating a Run record; verify status and preview again before retrying.",
            "generic_submission_record_unavailable": "The submission mapping exists on disk, but the Run record is temporarily unavailable. Retry GET verification without starting a duplicate scan.",
            "judge_provider_unavailable": "Hybrid LLM Judge is unavailable or missing credentials. Configure Judge credentials on the server or switch to Deterministic Rules / Evidence Only.",
            "generic_resume_not_interrupted": "Only interrupted or cancelled scans can be resumed. Completed, running, or failed runs cannot be resumed.",
            "generic_run_not_found": "Generic scan run record was not found.",
            "generic_run_access_denied": "This scan run belongs to a different operator session and cannot be cancelled.",
            "cancellation_persistence_failed": "Cancellation was signaled to the active scan, but persisting the stop request to disk failed. Retry stop or reload scan status to verify final state.",
            "generic_resume_already_active": "Another continuation run for this scan lineage is already active. Wait for it to finish before resuming again.",
            "generic_resume_no_remaining_cases": "No remaining pending or uncertain testcases exist for this scan lineage.",
            "generic_resume_no_cases_selected": "No definitely pending testcases remain. Explicitly opt into uncertain in-flight testcase(s) and confirm re-execution to resume.",
            "generic_resume_invalid_uncertain_selection": "Only uncertain in-flight testcases from the interrupted run may be opted into for retry.",
            "generic_resume_uncertain_confirmation_required": "Confirm that prior target execution and state were checked before retrying uncertain in-flight testcase(s).",
            "generic_resume_stateful_acknowledgement_required": "Acknowledge the stateful target warning before starting a live resumed scan.",
            "generic_resume_digest_stale": "The resume preview is stale because run state, target revision, or credentials changed. Reload Resume Preview before starting.",
            "generic_resume_not_eligible": "This scan cannot be resumed until all listed resume blockers are resolved.",
            "resume_state_incomplete": "Persisted testcase progress for this interrupted run is incomplete; cannot safely determine remaining testcases.",
            "resume_dataset_not_found": "The original dataset for this scan is no longer available in the local dataset repository.",
            "resume_dataset_revision_missing": "The interrupted run is missing its recorded dataset revision SHA-256 and cannot verify dataset consistency.",
            "resume_dataset_mismatch": "The dataset revision or testcase set has changed since the original scan started.",
            "resume_target_not_found": "The original target profile is no longer registered in the target catalog.",
            "resume_target_revision_missing": "The interrupted run is missing its recorded target profile revision and cannot verify target consistency.",
            "resume_target_configuration_changed": "The target configuration or revision changed since the original scan started. Start a New Scan instead of resuming.",
            "resume_judge_configuration_missing": "The interrupted Hybrid scan is missing its recorded Judge provider or model identifier and cannot verify Judge consistency.",
            "resume_judge_configuration_changed": "The active LLM Judge provider or model differs from the original interrupted scan. Restore the original Judge configuration or start a New Scan.",
            "resume_configuration_incomplete": "Required historical configuration revisions are missing from the interrupted run record; cannot verify consistency for Resume.",
            "resume_policy_changed": "The reviewed response policy changed since the original scan started.",
            "resume_application_context_changed": "The target Application Context changed since the original scan started.",
            "unified_report_integrity_failed": "Unified lineage report export is blocked because persisted checkpoint state failed integrity validation. Individual session reports remain accessible.",
            "generic_target_execution_in_progress": "Another live security test is already active for this Target. Wait for it to finish or open the active progress view instead of launching a concurrent run.",
            "target_execution_in_progress": "Another live security test is already active for this Target. Open the active workflow/run progress instead of starting a duplicate.",
            "workflow_persistence_failed": "Failed to persist durable workflow state safely; operation aborted.",
            "worker_startup_failed": "Failed to start background workflow worker; live target lock was released safely.",
            "runner_worker_startup_failed": "Failed to start background scan worker; live target lock was released safely.",
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
                  "/api/testing/managed-targets/session-credentials": "POST",
                  "/api/testing/managed-targets/session-credentials/clear": "POST",
                  "/api/testing/discoveries": "POST",
                  "/api/testing/discovery-probes": "POST",
                  "/api/testing/application-contexts/save": "POST",
                  "/api/testing/batches/preview": "POST",
                  "/api/testing/batches": "POST",
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
        routes.update(GENERATOR_EXACT_ROUTES)
        for gen_pattern, gen_method in GENERATOR_REGEX_ROUTES:
            if re.fullmatch(gen_pattern, request.path):
                routes[request.path] = gen_method
                break
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
        if re.fullmatch(r"/api/testing/generic-runs/[a-f0-9]{32}(?:/(?:report|unified-report)\.json)?", request.path):
            routes[request.path] = "GET"
        if re.fullmatch(r"/api/testing/generic-runs/[a-f0-9]{32}/cancel", request.path):
            routes[request.path] = "POST"
        if re.fullmatch(r"/api/testing/generic-runs/[a-f0-9]{32}/resume/(?:preview|start)", request.path):
            routes[request.path] = "POST"
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
            else 256 * 1024 if request.path.startswith("/api/testing/generator")
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

    def _service_has_active_execution(svc) -> bool:
        if isinstance(svc, GenericRunService):
            with svc._lock:
                return bool(
                    svc._live_target_reservations
                    or svc._initializing_runs
                    or any(t.is_alive() for t in svc._in_progress_runs.values())
                )
        if isinstance(svc, GenericImportedBatchWorkflow):
            worker = getattr(svc, "_worker", None)
            svc_lock = getattr(svc, "_lock", None)
            return bool(
                (worker is not None and worker.is_alive())
                or (svc_lock is not None and svc_lock.locked())
            )
        if isinstance(svc, McpActionWorkflow):
            svc_lock = getattr(svc, "_lock", None)
            return bool(svc_lock is not None and svc_lock.locked())
        return False

    def _reconcile_shared_target_locks(exec_services: list[object]) -> TargetExecutionLockRegistry:
        """Enforce a single shared TargetExecutionLockRegistry across all app execution services.

        - Preserves any registry that already holds active reservations or belongs to an actively
          executing service (never replaces an active lock registry).
        - Fails closed if two distinct active registries exist, if an actively executing service
          lacks a valid registry, or if an invalid registry object was supplied.
        - Safely normalizes idle pre-initialized services to the single shared registry.
        """
        unique_regs: list[TargetExecutionLockRegistry] = []
        active_regs: list[TargetExecutionLockRegistry] = []
        for svc in exec_services:
            if not hasattr(svc, "target_locks"):
                continue
            reg = getattr(svc, "target_locks", None)
            if reg is not None and not isinstance(reg, TargetExecutionLockRegistry):
                raise ValueError("Execution services must use TargetExecutionLockRegistry for target_locks.")
            svc_active = _service_has_active_execution(svc)
            if svc_active and reg is None:
                raise ValueError("Cannot attach target lock registry to an actively executing service.")
            if reg is not None:
                if all(existing is not reg for existing in unique_regs):
                    unique_regs.append(reg)
                if (svc_active or reg.has_active_reservations()) and all(existing is not reg for existing in active_regs):
                    active_regs.append(reg)

        if len(active_regs) > 1:
            raise ValueError("Execution services have incompatible active target lock registries.")
        if len(active_regs) == 1:
            canonical_reg = active_regs[0]
        elif (
            generic_run_service is not None
            and isinstance(getattr(generic_run_service, "target_locks", None), TargetExecutionLockRegistry)
        ):
            canonical_reg = generic_run_service.target_locks
        elif unique_regs:
            canonical_reg = unique_regs[0]
        else:
            canonical_reg = TargetExecutionLockRegistry()

        # Rebind only idle services whose registry differs from canonical_reg, re-verifying under lock.
        for svc in exec_services:
            if not hasattr(svc, "target_locks"):
                continue
            current_reg = getattr(svc, "target_locks", None)
            if current_reg is canonical_reg:
                continue
            if isinstance(svc, GenericRunService):
                with svc._lock:
                    old_reg = svc.target_locks
                    if _service_has_active_execution(svc) or (
                        old_reg is not None and old_reg.has_active_reservations()
                    ):
                        raise ValueError("Execution services have incompatible active target lock registries.")
                    svc.target_locks = canonical_reg
            elif isinstance(svc, McpActionWorkflow):
                if not svc._lock.acquire(blocking=False):
                    raise ValueError("Execution services have incompatible active target lock registries.")
                try:
                    old_reg = svc.target_locks
                    if old_reg is not None and old_reg.has_active_reservations():
                        raise ValueError("Execution services have incompatible active target lock registries.")
                    svc.target_locks = canonical_reg
                finally:
                    svc._lock.release()
            else:
                svc_lock = getattr(svc, "_lock", None)
                if svc_lock is not None:
                    if not svc_lock.acquire(blocking=False):
                        raise ValueError("Execution services have incompatible active target lock registries.")
                    try:
                        old_reg = getattr(svc, "target_locks", None)
                        worker = getattr(svc, "_worker", None)
                        if (worker is not None and worker.is_alive()) or (
                            old_reg is not None and old_reg.has_active_reservations()
                        ):
                            raise ValueError("Execution services have incompatible active target lock registries.")
                        svc.target_locks = canonical_reg
                    finally:
                        svc_lock.release()
                else:
                    old_reg = getattr(svc, "target_locks", None)
                    if _service_has_active_execution(svc) or (
                        old_reg is not None and old_reg.has_active_reservations()
                    ):
                        raise ValueError("Execution services have incompatible active target lock registries.")
                    svc.target_locks = canonical_reg
        return canonical_reg

    pre_supplied_exec_services = [
        svc
        for svc in (generic_run_service, *services.values(), mcp_action_service)
        if svc is not None
    ]
    shared_target_locks = _reconcile_shared_target_locks(pre_supplied_exec_services)

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
            inventory=None,
            policy_store=ResponsePolicyStore(default_policy_dir),
            runs_root=default_runs_dir,
            controlled_runs_root=controlled_root,
            pi_config=pi_cfg,
            application_contexts=application_contexts,
            evidence_source_store=evidence_sources,
            target_lock_registry=shared_target_locks,
        )

    # Postcondition invariant: every active execution service in this app shares the exact same registry.
    for svc in (
        generic_run_service,
        *services.values(),
        *([mcp_action_service] if mcp_action_service is not None else []),
    ):
        if hasattr(svc, "target_locks") and getattr(svc, "target_locks", None) is not shared_target_locks:
            raise ValueError("Execution services failed to share a single target lock registry.")

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
                       target_network_access=controlled
                           and (not custom_imported or (imported_service.execution_mode != "offline_mock"
                               and imported_service.mock_live_transport is None)),
                       evaluation_modes=['rule_only','hybrid'] if hybrid_available else ['rule_only'],
                       judge_configuration='configured_unverified' if hybrid_available else 'unavailable',
                       judge_setup_reason=setup_reason,
                       judge_status=j_stat,
                       mcp_action_setup_reason='configured' if mcp_action_service else 'catalog_missing',
                       lab_preparation_enabled=False,
                       offline_batch_enabled=False,
                       asi01_batch_enabled=False,
                       asi01_text_targets=[],
                       web_lab_batch_enabled=False,
                       toolbot_lab_batch_enabled=False,
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

    from hashlib import sha256 as _sha256

    def operator_identity() -> str:
        if not operator_authorized():
            return ""
        if local_single_user:
            sess = request.headers.get("X-SecAgent-Session", "").strip()
            return _sha256(f"secagent-local:{sess or 'default'}".encode("utf-8")).hexdigest()
        supplied = request.headers.get("X-SecAgent-Operator", "")
        return _sha256(f"secagent-op:{supplied}".encode("utf-8")).hexdigest()

    ctx = WorkflowApiContext(
        catalog=catalog,
        managed=managed,
        local_single_user=local_single_user,
        nonce=nonce,
        admin_lock=admin_lock,
        dispatcher=dispatcher,
        discovery=discovery,
        services=services,
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
        fail=fail,
        operator_authorized=operator_authorized,
        generic_run_service=generic_run_service,
        operator_identity=operator_identity,
    )
    register_target_routes(app, ctx)
    register_dataset_policy_routes(app, ctx)
    register_execution_routes(app, ctx)
    register_agent_onboarding_routes(app, ctx)
    register_generic_runner_routes(app, ctx)

    gen_policy_store = getattr(generic_run_service, "policy_store", None)
    gen_dataset_repo = dataset_repo if dataset_repo is not None else getattr(generic_run_service, "dataset_repo", None)
    if generator_service is not None:
        resolved_gen_service = generator_service
    else:
        resolved_provider = (
            generator_provider if generator_provider is not None else create_server_generator_provider()
        )
        resolved_gen_service = GeneratorService(
            provider=resolved_provider,
            catalog=catalog,
            application_contexts=application_contexts,
            policy_store=gen_policy_store,
        )
    gen_preview_store = GeneratorPreviewStore()
    default_workflows_dir = (
        (generic_run_service.runs_root.parent / "generator-workflows")
        if generic_run_service is not None and getattr(generic_run_service, "runs_root", None) is not None
        else ((catalog.data_dir / "generator-workflows") if managed else None)
    )
    gen_orchestrator = (
        GenerateAndRunOrchestrator(
            generator_service=resolved_gen_service,
            dataset_repo=gen_dataset_repo,
            catalog=catalog,
            application_contexts=application_contexts,
            generic_run_service=generic_run_service,
            policy_store=gen_policy_store,
            workflows_root=default_workflows_dir,
        )
        if gen_dataset_repo is not None
        else None
    )

    gen_ctx = GeneratorApiContext(
        generator_service=resolved_gen_service,
        preview_store=gen_preview_store,
        dataset_repo=gen_dataset_repo,
        catalog=catalog,
        application_contexts=application_contexts,
        policy_store=gen_policy_store,
        orchestrator=gen_orchestrator,
        nonce=nonce,
        operator_authorized=operator_authorized,
        operator_identity=operator_identity,
    )
    register_generator_routes(app, gen_ctx)

    return app


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True)
    parser.add_argument('--target-data-dir', help='Operator-owned local directory for managed target profiles and reviews')
    parser.add_argument('--evidence-policy', help='Non-secret explicit HTTP evidence endpoint allowlist JSON; default denies collection')
    parser.add_argument("--port", type=int, default=8092)
    parser.add_argument('--admission-policy', help='Operator-owned execution grant JSON; default denies all')
    parser.add_argument('--enable-controlled-runs', action='store_true',
                        help='Explicitly enable controlled runtime services and run-output storage')
    parser.add_argument('--enable-custom-imported-batch', action='store_true',
                        help='Opt into Generic Custom Imported Testcase batch (Offline Mock by default)')
    parser.add_argument('--enable-unified-runtime', action='store_true',
                        help='Register unified Generic Scan and imported/MCP-agent workflows; per-run gates remain mandatory')
    parser.add_argument('--enable-imported-live-local', action='store_true',
                        help='Allow explicit Live Local execution of imported prompts against reviewed loopback chat targets')
    parser.add_argument('--mcp-action-catalog',
                        help='Opt in to structured MCP action cases from an operator-reviewed JSON file')
    parser.add_argument('--reviewed-mcp-catalog-sha256',
                        help='Exact operator-approved catalog hash required when a case claims reviewed action policy')
    parser.add_argument('--dvaa-mcp-receipt-root',
                        help='Optional instrumented DVAA lab receipt directory; never an independent effect')
    parser.add_argument('--run-output-dir', help='Fresh results directory for controlled runs')
    parser.add_argument('--enable-web-hybrid-judge', action='store_true',
                        help='Explicitly enable server-owned hybrid evaluation for controlled runs')
    parser.add_argument('--web-hybrid-config', help='Operator-owned RunnerEvaluationConfig JSON for Pi Judge')
    parser.add_argument('--sync-credential-aliases', action='store_true',
                        help='Explicitly merge newly added credential aliases from --catalog into an existing managed target catalog (strictly additive)')
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535.")
    try:
        policy=None
        if args.admission_policy:
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
                                         local_single_user=local_single_user,
                                         allow_additive_credential_aliases=args.sync_credential_aliases)
        hybrid_config=None
        if args.enable_web_hybrid_judge:
            if not args.enable_controlled_runs or not args.web_hybrid_config:
                raise ValueError('Web hybrid Judge requires controlled runs and explicit configuration.')
            path=Path(args.web_hybrid_config).absolute()
            safe_file(path,path.parent)
            hybrid_config=RunnerEvaluationConfig.model_validate(read_json(path.read_bytes()))
            validate_live_pi_config(hybrid_config)
        elif args.web_hybrid_config:
            raise ValueError('Web hybrid configuration requires explicit opt-in.')
        dispatcher=None
        if args.enable_unified_runtime and args.enable_custom_imported_batch:
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
            else:
                mock_transport = None
            dispatcher=ControlledDispatcher(catalog,policy,Path(args.run_output_dir),
                operator_secret=secret,hybrid_config=hybrid_config,transport=mock_transport)
        elif args.run_output_dir:
            raise ValueError('Output directory requires controlled-run opt-in.')
        batch_service=None
        batch_services=None
        if args.enable_unified_runtime:
            if (not args.enable_controlled_runs or dispatcher is None or not local_single_user
                    or not isinstance(catalog, ManagedTargetCatalog)):
                raise ValueError('Unified runtime requires local managed controlled-run startup.')
            dataset_repo = DatasetRepository(catalog.data_dir)
            batch_services = {
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
        app = create_app(catalog, port=args.port, admission_policy=policy,
                         dispatcher=dispatcher, operator_secret=secret,
                         local_single_user=local_single_user, batch_service=batch_service,
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
