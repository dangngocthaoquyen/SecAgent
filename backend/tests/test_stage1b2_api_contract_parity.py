"""Route parity and HTTP security-contract tests for Stage 1B.2 Workflow API modularization."""

import ast
import json
from pathlib import Path

from workflow.api import create_app
from workflow.catalog import CatalogConfig
from workflow.management import ManagedTargetCatalog


ROOT = Path(__file__).resolve().parents[2]
SECRET = "stage1b2-operator-secret-" + "x" * 32
BASE = "http://127.0.0.1:8092"

EXPECTED_URL_MAP = (
    ("/api/testing/agent-bindings", ("GET", "HEAD", "OPTIONS"), "agent_binding_list"),
    ("/api/testing/agent-bindings/<binding_id>", ("GET", "HEAD", "OPTIONS"), "agent_binding_read"),
    ("/api/testing/agent-bindings/<binding_id>/review", ("OPTIONS", "POST"), "agent_binding_review"),
    ("/api/testing/agent-bindings/drafts", ("OPTIONS", "POST"), "agent_binding_draft"),
    ("/api/testing/application-contexts/save", ("OPTIONS", "POST"), "save_application_context"),
    ("/api/testing/application-contexts/target/<target_id>", ("GET", "HEAD", "OPTIONS"), "read_application_context"),
    ("/api/testing/asi03-contracts/<contract_id>", ("GET", "HEAD", "OPTIONS"), "asi03_read"),
    ("/api/testing/asi03-contracts/<contract_id>/review", ("OPTIONS", "POST"), "asi03_review"),
    ("/api/testing/asi03-contracts/drafts", ("OPTIONS", "POST"), "asi03_draft"),
    ("/api/testing/asi03-contracts/lookup/<dataset_id>/<case_id>/<target_id>", ("GET", "HEAD", "OPTIONS"), "asi03_lookup"),
    ("/api/testing/asi03-policies/<policy_id>", ("GET", "HEAD", "OPTIONS"), "asi03_policy_read"),
    ("/api/testing/asi03-policies/<policy_id>/review", ("OPTIONS", "POST"), "asi03_policy_review"),
    ("/api/testing/asi03-policies/drafts", ("OPTIONS", "POST"), "asi03_policy_draft"),
    ("/api/testing/asi03-policies/target/<target_id>", ("GET", "HEAD", "OPTIONS"), "asi03_policy_lookup"),
    ("/api/testing/asi05-policies/<policy_id>", ("GET", "HEAD", "OPTIONS"), "asi05_policy_read"),
    ("/api/testing/asi05-policies/<policy_id>/review", ("OPTIONS", "POST"), "asi05_policy_review"),
    ("/api/testing/asi05-policies/drafts", ("OPTIONS", "POST"), "asi05_policy_draft"),
    ("/api/testing/asi05-policies/target/<target_id>", ("GET", "HEAD", "OPTIONS"), "asi05_policy_lookup"),
    ("/api/testing/batches", ("OPTIONS", "POST"), "batch_start"),
    ("/api/testing/batches/<batch_run_id>", ("GET", "HEAD", "OPTIONS"), "batch_status"),
    ("/api/testing/batches/<batch_run_id>/cancel", ("OPTIONS", "POST"), "batch_cancel"),
    ("/api/testing/batches/<batch_run_id>/events", ("GET", "HEAD", "OPTIONS"), "batch_events"),
    ("/api/testing/batches/<batch_run_id>/results", ("GET", "HEAD", "OPTIONS"), "batch_results"),
    ("/api/testing/batches/preview", ("OPTIONS", "POST"), "batch_preview"),
    ("/api/testing/connection-checks", ("OPTIONS", "POST"), "connection_check"),
    ("/api/testing/datasets", ("GET", "HEAD", "OPTIONS"), "list_datasets"),
    ("/api/testing/datasets/<dataset_id>", ("GET", "HEAD", "OPTIONS"), "get_dataset"),
    ("/api/testing/datasets/import", ("OPTIONS", "POST"), "import_dataset"),
    ("/api/testing/datasets/validate", ("OPTIONS", "POST"), "validate_dataset"),
    ("/api/testing/discoveries", ("OPTIONS", "POST"), "discover_target"),
    ("/api/testing/discoveries/<discovery_id>", ("GET", "HEAD", "OPTIONS"), "read_discovery"),
    ("/api/testing/discoveries/<discovery_id>/mcp-tools", ("GET", "HEAD", "OPTIONS"), "read_discovery_mcp_tools"),
    ("/api/testing/discovery-probes", ("OPTIONS", "POST"), "probe_discovery_candidate"),
    ("/api/testing/evidence-captures/<capture_id>", ("GET", "HEAD", "OPTIONS"), "evidence_capture"),
    ("/api/testing/evidence-sources/collect", ("OPTIONS", "POST"), "evidence_collect"),
    ("/api/testing/evidence-sources/save", ("OPTIONS", "POST"), "evidence_save"),
    ("/api/testing/evidence-sources/target/<target_id>", ("GET", "HEAD", "OPTIONS"), "evidence_list"),
    ("/api/testing/generic-runs", ("GET", "HEAD", "OPTIONS"), "generic_run_list"),
    ("/api/testing/generic-runs/<run_id>", ("GET", "HEAD", "OPTIONS"), "generic_run_read"),
    ("/api/testing/generic-runs/<run_id>/report.json", ("GET", "HEAD", "OPTIONS"), "generic_run_export"),
    ("/api/testing/generic-runs/<run_id>/resume/preview", ("OPTIONS", "POST"), "generic_run_resume_preview"),
    ("/api/testing/generic-runs/<run_id>/resume/start", ("OPTIONS", "POST"), "generic_run_resume_start"),
    ("/api/testing/generic-runs/<run_id>/unified-report.json", ("GET", "HEAD", "OPTIONS"), "generic_run_unified_export"),
    ("/api/testing/generic-runs/preview", ("OPTIONS", "POST"), "generic_run_preview"),
    ("/api/testing/generic-runs/start", ("OPTIONS", "POST"), "generic_run_start"),
    ("/api/testing/generic-runs/submission/<submission_id>", ("GET", "HEAD", "OPTIONS"), "generic_run_by_submission"),
    ("/api/testing/health", ("GET", "HEAD", "OPTIONS"), "health"),
    ("/api/testing/managed-targets", ("GET", "HEAD", "OPTIONS"), "managed_targets"),
    ("/api/testing/managed-targets/create", ("OPTIONS", "POST"), "managed_create"),
    ("/api/testing/managed-targets/delete", ("OPTIONS", "POST"), "managed_delete_target"),
    ("/api/testing/managed-targets/review", ("OPTIONS", "POST"), "managed_review"),
    ("/api/testing/managed-targets/session-credentials", ("OPTIONS", "POST"), "managed_set_session_credential"),
    ("/api/testing/managed-targets/session-credentials/clear", ("OPTIONS", "POST"), "managed_clear_session_credential"),
    ("/api/testing/managed-targets/update", ("OPTIONS", "POST"), "managed_update"),
    ("/api/testing/managed-targets/validate", ("OPTIONS", "POST"), "managed_validate"),
    ("/api/testing/mcp-actions", ("GET", "HEAD", "OPTIONS"), "mcp_actions"),
    ("/api/testing/mcp-actions/run", ("OPTIONS", "POST"), "run_mcp_action"),
    ("/api/testing/mcp-catalogs", ("GET", "HEAD", "OPTIONS"), "mcp_catalog_list"),
    ("/api/testing/mcp-catalogs/<catalog_id>", ("GET", "HEAD", "OPTIONS"), "mcp_catalog_read"),
    ("/api/testing/mcp-catalogs/<catalog_id>/review", ("OPTIONS", "POST"), "mcp_catalog_review"),
    ("/api/testing/mcp-catalogs/drafts", ("OPTIONS", "POST"), "mcp_catalog_draft"),
    ("/api/testing/mcp-catalogs/target/<target_id>", ("GET", "HEAD", "OPTIONS"), "mcp_catalog_for_target"),
    ("/api/testing/response-policies/<policy_id>/review", ("OPTIONS", "POST"), "generic_policy_review"),
    ("/api/testing/response-policies/drafts", ("OPTIONS", "POST"), "generic_policy_draft"),
    ("/api/testing/response-policies/target/<target_id>", ("GET", "HEAD", "OPTIONS"), "generic_policy_list"),
    ("/api/testing/target-drafts/validate", ("OPTIONS", "POST"), "validate"),
    ("/api/testing/targets", ("GET", "HEAD", "OPTIONS"), "targets"),
)


def _managed_app(tmp_path):
    catalog = ManagedTargetCatalog(
        CatalogConfig.model_validate({
            "catalog_schema_version": "1.0.0",
            "policy_ref": "stage1b2-policy",
            "targets": [],
        }),
        tmp_path / "operator-data",
        local_single_user=True,
    )
    app = create_app(catalog, operator_secret=SECRET, local_single_user=True)
    return app


def test_url_map_and_endpoints_match_frozen_contract(tmp_path):
    app = _managed_app(tmp_path)
    actual = tuple(sorted(
        (rule.rule, tuple(sorted(rule.methods)), rule.endpoint)
        for rule in app.url_map.iter_rules()
        if rule.endpoint != "static"
    ))
    assert actual == EXPECTED_URL_MAP
    assert len(actual) == 67
    assert len({ep for _, _, ep in actual}) == 67


def test_security_boundary_hooks_and_error_shapes_preserved(tmp_path):
    app = _managed_app(tmp_path)
    client = app.test_client()
    health = client.get("/api/testing/health", base_url=BASE)
    assert health.status_code == 200
    assert health.headers["Cache-Control"] == "no-store"
    assert health.headers["X-Content-Type-Options"] == "nosniff"
    assert health.headers["Content-Security-Policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert health.headers["Referrer-Policy"] == "no-referrer"
    nonce = health.get_json()["validation_nonce"]

    # Wrong host, Origin, Sec-Fetch-Site, query string, unknown route, wrong method
    bad_host = client.get("/api/testing/health", base_url="http://evil.example:8092")
    assert bad_host.status_code == 403 and bad_host.get_json()["error"]["code"] == "local_only"

    bad_origin = client.get("/api/testing/health", base_url=BASE, headers={"Origin": "http://evil.example"})
    assert bad_origin.status_code == 403 and bad_origin.get_json()["error"]["code"] == "origin_rejected"

    cross_site = client.get("/api/testing/health", base_url=BASE, headers={"Sec-Fetch-Site": "cross-site"})
    assert cross_site.status_code == 403 and cross_site.get_json()["error"]["code"] == "origin_rejected"

    with_query = client.get("/api/testing/health?x=1", base_url=BASE)
    assert with_query.status_code == 400 and with_query.get_json()["error"]["code"] == "invalid_request"

    missing = client.get("/api/testing/unknown-route", base_url=BASE)
    assert missing.status_code == 404 and missing.get_json()["error"]["code"] == "not_found"

    wrong_method = client.post("/api/testing/health", base_url=BASE)
    assert wrong_method.status_code == 405 and wrong_method.get_json()["error"]["code"] == "method_not_allowed"

    get_body = client.get("/api/testing/targets", base_url=BASE, data=b"x")
    assert get_body.status_code == 400 and get_body.get_json()["error"]["code"] == "body_not_allowed"

    too_large = client.post(
        "/api/testing/target-drafts/validate",
        base_url=BASE,
        headers={"Origin": BASE, "X-SecAgent-Validation": nonce, "Content-Type": "application/json"},
        data=b"{" + b" " * 9000 + b"}",
    )
    assert too_large.status_code == 413 and too_large.get_json()["error"]["code"] == "payload_too_large"

    no_origin_post = client.post("/api/testing/target-drafts/validate", base_url=BASE)
    assert no_origin_post.status_code == 403 and no_origin_post.get_json()["error"]["code"] == "origin_required"

    wrong_mime = client.post(
        "/api/testing/target-drafts/validate",
        base_url=BASE,
        headers={"Origin": BASE, "X-SecAgent-Validation": nonce},
        data=b"{}",
    )
    assert wrong_mime.status_code == 415 and wrong_mime.get_json()["error"]["code"] == "json_required"

    bad_nonce = client.post(
        "/api/testing/target-drafts/validate",
        base_url=BASE,
        headers={"Origin": BASE, "X-SecAgent-Validation": "bad", "Content-Type": "application/json"},
        data=b"{}",
    )
    assert bad_nonce.status_code == 403 and bad_nonce.get_json()["error"]["code"] == "validation_nonce_required"


def test_route_group_auth_and_error_contracts_preserved(tmp_path):
    app = _managed_app(tmp_path)
    client = app.test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).get_json()["validation_nonce"]
    unauth = {"Origin": BASE, "X-SecAgent-Validation": nonce, "Content-Type": "application/json"}
    auth = {**unauth, "X-SecAgent-Operator": SECRET}

    # Target, discovery, evidence routes
    assert client.get("/api/testing/targets", base_url=BASE).status_code == 200
    assert client.get("/api/testing/managed-targets", base_url=BASE).status_code == 403
    assert client.get("/api/testing/managed-targets", base_url=BASE, headers={"X-SecAgent-Operator": SECRET}).status_code == 200
    bad_draft = client.post("/api/testing/target-drafts/validate", base_url=BASE, headers=unauth, data=b"{not-json")
    assert bad_draft.status_code == 400 and bad_draft.get_json()["error"]["code"] == "invalid_draft"
    disc_miss = client.get(
        "/api/testing/discoveries/" + ("a" * 32),
        base_url=BASE,
        headers={"X-SecAgent-Operator": SECRET},
    )
    assert disc_miss.status_code == 404 and disc_miss.get_json()["error"]["code"] == "discovery_record_not_found"

    # Dataset & Policy routes
    assert client.get("/api/testing/datasets", base_url=BASE, headers=unauth).status_code == 403
    ds_ok = client.get("/api/testing/datasets", base_url=BASE, headers=auth)
    assert ds_ok.status_code == 200 and ds_ok.get_json()["datasets"] == []
    ds_miss = client.get("/api/testing/datasets/" + ("b" * 32), base_url=BASE, headers=auth)
    assert ds_miss.status_code == 404 and ds_miss.get_json()["error"]["code"] == "dataset_not_found"
    ds_bad = client.post("/api/testing/datasets/validate", base_url=BASE, headers=auth, data=b"{not-json")
    assert ds_bad.status_code == 400 and ds_bad.get_json()["error"]["code"] == "malformed_json"
    assert client.get("/api/testing/asi03-policies/" + ("c" * 32), base_url=BASE, headers=auth).status_code == 404
    assert client.get("/api/testing/asi05-policies/" + ("d" * 32), base_url=BASE, headers=auth).status_code == 404
    assert client.get("/api/testing/asi03-contracts/" + ("e" * 32), base_url=BASE, headers=auth).status_code == 404

    # Active execution/batch/mcp-actions routes & retired native-only routes return 404
    assert client.get("/api/testing/categories", base_url=BASE).status_code == 404
    assert client.get("/api/testing/testcases", base_url=BASE).status_code == 404
    assert client.post("/api/testing/batches/preview", base_url=BASE, headers=auth, data=json.dumps({})).get_json()["error"]["code"] == "offline_batch_disabled"
    assert client.post("/api/testing/runs", base_url=BASE, headers=auth, data=json.dumps({})).status_code == 404
    assert client.post("/api/testing/execution-grants", base_url=BASE, headers=auth, data=json.dumps({})).status_code == 404
    assert client.get("/api/testing/mcp-actions", base_url=BASE, headers={"X-SecAgent-Operator": SECRET}).get_json()["error"]["code"] == "mcp_action_workflow_disabled"
    assert client.post("/api/testing/lab-attempts/preview", base_url=BASE, headers=auth, data=json.dumps({})).status_code == 404

    # Error handler 500 parity
    def boom():
        raise RuntimeError("synthetic boom")

    app.view_functions["targets"] = boom
    internal = client.get("/api/testing/targets", base_url=BASE)
    assert internal.status_code == 500
    assert internal.get_json()["error"]["code"] == "internal_error"


def test_route_modules_do_not_import_workflow_api():
    workflow_dir = ROOT / "backend" / "src" / "workflow"
    for route_file in sorted(workflow_dir.glob("routes_*.py")):
        tree = ast.parse(route_file.read_text(encoding="utf-8"), filename=str(route_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(alias.name != "workflow.api" for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "workflow.api"
