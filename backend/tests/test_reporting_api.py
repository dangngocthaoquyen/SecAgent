"""Offline Flask test-client checks. No listening sockets, targets or providers."""
import hashlib
import json
from pathlib import Path
import socket
import subprocess

import httpx
import pytest

from reporting.api import create_app, main
from reporting.repository import DatasetError, load_dataset
from test_report_aggregation import native, norm, archived
from test_reporting_artifacts import archive as lab_archive


@pytest.fixture(autouse=True)
def no_outbound_or_execution(monkeypatch):
    def blocked(*a, **k): raise AssertionError("Reporting API must not execute or connect")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(httpx.Client, "request", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)


def manifest(tmp_path, rows=()):
    reports = []
    for i, row in enumerate(rows):
        p = tmp_path / f"source-{i}.json"
        p.write_text(json.dumps(row), encoding="utf-8")
        reports.append({"root": "local", "path": p.name,
                        "kind": "archived_assessment" if row.get("report_type") else "execution"})
    config = {"dataset_schema_version": "1.0.0", "allowed_roots": {"local": "."}, "reports": reports}
    p = tmp_path / "dataset.json"
    p.write_text(json.dumps(config), encoding="utf-8")
    return p


def change_manifest(path, transform):
    row = json.loads(path.read_text(encoding="utf-8"))
    transform(row)
    path.write_text(json.dumps(row), encoding="utf-8")


def client(tmp_path, rows=()):
    return create_app(load_dataset(manifest(tmp_path, rows))).test_client()


def test_health_empty_dataset_and_schema_compatibility(tmp_path):
    c = client(tmp_path)
    response = c.get("/api/reports/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok" and data["dataset"]["availability"] == "empty"
    assert data["report_schema_versions"] == ["2.0.0"]
    assert data["verification"]["prior_result_import_supported"] is False
    assert str(tmp_path) not in response.get_data(as_text=True)
    summary = c.get("/api/reports/overview").get_json()["summary"]
    assert summary["metrics"]["decision_coverage_over_all_records"]["value"] is None
    assert c.get("/api/reports/executions").get_json()["items"] == []


def test_golden_dataset_detail_and_archived_agreement(tmp_path):
    attack = native()
    control = native("INCONCLUSIVE", run="control", testcase="GH-WEB-C01")
    c = client(tmp_path, [control, attack, archived(norm(attack))])
    summary = c.get("/api/reports/overview").get_json()["summary"]
    assert summary["counts"]["recorded_execution_reports"] == 2
    assert summary["counts"]["security_verdicts"] == {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 1, "unknown": 0}
    assert summary["archived_assessments"] == 1
    assert summary["metrics"]["decisive_verdict_rate_among_classified"]["value"] == 0.5
    assert summary["metrics"]["decision_coverage_over_all_records"]["value"] == 0.5
    listing = c.get("/api/reports/executions?testcase_id=GH-WEB-001").get_json()
    record = listing["items"][0]
    assert record["linked_assessment_count"] == 1
    detail = c.get("/api/reports/executions/" + record["report_id"]).get_json()["execution"]
    assert detail["security"]["verdict"] == "FAIL"
    assert detail["deterministic"]["original"]["status"] == "FAIL"
    assert detail["observation"]["response_completeness"]["reported_value"] is None
    assert detail["linked_archived_assessments"][0]["target_execution_performed"] is False
    comparisons = c.get("/api/reports/comparisons").get_json()
    assert len(comparisons["production"]) == 2 and len(comparisons["archived"]) == 1
    assert comparisons["archived"][0]["state"] == "agreement"
    assert comparisons["archived"][0]["judge_invocation_state"] == "result_available"
    assert comparisons["archived"][0]["provider_diagnostics"]["reported_json_validation_status"] == "valid"


@pytest.mark.parametrize("verdict", ["PASS", "FAIL", "INCONCLUSIVE", "unknown"])
def test_security_filters_and_error_separation(tmp_path, verdict):
    c = client(tmp_path, [native(v, run=str(i), success=v != "ERROR") for i, v in enumerate(["PASS", "FAIL", "INCONCLUSIVE", "ERROR"])])
    rows = c.get("/api/reports/executions?verdict=" + verdict).get_json()["items"]
    assert len(rows) == 1
    assert rows[0]["historical_security_verdict"] == (None if verdict == "unknown" else verdict)
    if verdict == "unknown":
        assert rows[0]["execution_status"] == "failed" and rows[0]["historical_status"] == "ERROR"


def test_unknown_verdicts_make_metric_denominators_differ(tmp_path):
    c = client(tmp_path, [native("PASS", run="p"), native("INCONCLUSIVE", run="i"), native("ERROR", run="e")])
    metrics = c.get("/api/reports/overview").get_json()["summary"]["metrics"]
    assert metrics["decisive_verdict_rate_among_classified"]["value"] == 0.5
    assert metrics["decision_coverage_over_all_records"]["value"] == 1 / 3
    assert metrics["decision_coverage"]["value"] == 0.5
    assert "Deprecated" in metrics["decision_coverage"]["definition"]


@pytest.mark.parametrize("category,asi", [("goal_hijacking", "ASI01"), ("tool_misuse", "ASI02"),
    ("identity_privilege_abuse", "ASI03"), ("unexpected_code_execution", "ASI05")])
def test_asi_target_filters(tmp_path, category, asi):
    c = client(tmp_path, [native(category=category, target="chosen"), native(run="other", target="other")])
    result = c.get(f"/api/reports/executions?asi_category={asi}&target_id=chosen").get_json()
    assert result["total"] == 1 and result["items"][0]["target_id"] == "chosen"


def test_pagination_is_stable_and_does_not_change_overview(tmp_path):
    c = client(tmp_path, [native(run=str(i)) for i in range(4)])
    before = c.get("/api/reports/overview").data
    a = c.get("/api/reports/executions?page=1&page_size=2").get_json()
    b = c.get("/api/reports/executions?page=2&page_size=2").get_json()
    assert a["total"] == b["total"] == 4
    assert len({r["report_id"] for r in a["items"] + b["items"]}) == 4
    assert c.get("/api/reports/executions?page=99").get_json()["items"] == []
    assert c.get("/api/reports/overview").data == before


@pytest.mark.parametrize("query", ["page=0", "page=-1", "page=x", "page_size=101", "page=999999999",
    "page=1&page=2", "verdict=ERROR", "asi_category=ASI99", "target_id=../secret", "path=C:/private", "page_size="])
def test_invalid_query_rejected(tmp_path, query):
    c = client(tmp_path)
    response = c.get("/api/reports/executions?" + query)
    assert response.status_code == 400 and "error" in response.get_json()


def test_unknown_report_id_and_no_path_endpoint(tmp_path):
    c = client(tmp_path)
    assert c.get("/api/reports/executions/execution:" + "0" * 64).status_code == 404
    assert c.get("/api/reports/executions/not-an-id").status_code == 400
    assert c.get("/api/reports/executions/%2e%2e/%2e%2e/private").status_code in {400, 404}
    assert c.get("/api/reports/download").status_code == 404
    assert c.get("/api/reports/overview?file=private.json").status_code == 400


def test_selected_controlled_run_handoff_preserves_synthetic_report(tmp_path):
    run_id = "a" * 32
    run_dir = tmp_path / "runs" / run_id
    run_dir.mkdir(parents=True)
    row = native(run="synthetic-execution", testcase="SYN-001", target="synthetic-target")
    raw = json.dumps(row).encode("utf-8")
    report_file = "synthetic.secagent.json"
    (run_dir / report_file).write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    summary = {"run_id": run_id, "report_persisted": True, "report_file": report_file,
        "report_sha256": digest, "native_execution_id": "synthetic-execution",
        "testcase_id": "SYN-001", "target_id": "synthetic-target"}
    (run_dir / "run-summary.json").write_text(json.dumps(summary), encoding="utf-8")
    manifest_path = manifest(tmp_path)
    selected = json.loads(manifest_path.read_text(encoding="utf-8"))
    selected["allowed_roots"]["controlled"] = "runs"
    selected["controlled_runs_root"] = "controlled"
    manifest_path.write_text(json.dumps(selected), encoding="utf-8")
    index_path = tmp_path / 'history-index.json'
    api = create_app(load_dataset(manifest_path), history_index_path=index_path).test_client()
    assert api.get("/api/reports/executions").get_json()["total"] == 0
    response = api.get("/api/reports/runs/" + run_id)
    assert response.status_code == 200
    result = response.get_json()
    assert result["run_id"] == run_id
    assert result["execution"]["report_id"] == "execution:" + digest
    assert result["execution"]["security"]["verdict"] == row["evaluation"]["final_verdict"]
    assert len(result["execution"]["observation"]["evidence"]) == len(row["evaluation"]["observation"]["evidence"])
    history = api.get('/api/reports/saved-runs?target_id=synthetic-target').get_json()
    assert history['total'] == 1 and history['items'][0]['run_id'] == run_id
    assert history['items'][0]['verdict'] == row['evaluation']['final_verdict']
    assert history['items'][0]['started_at'] == row['timestamp']
    assert api.get('/api/reports/saved-runs?date_from=2026-11-06&date_to=2026-11-06').get_json()['total'] == 1
    assert history['index_persisted'] is True and index_path.is_file()
    restarted = create_app(load_dataset(manifest_path), history_index_path=index_path).test_client()
    assert restarted.get('/api/reports/saved-runs').get_json()['total'] == 1
    assert api.get('/api/reports/saved-runs?target_id=other').get_json()['total'] == 0
    assert api.get('/api/reports/saved-runs?target_id=../secret').status_code == 400
    assert api.get("/api/reports/runs/" + "b" * 32).status_code == 404
    assert api.get("/api/reports/runs/../../private").status_code in {400, 404}
    assert create_app(load_dataset(manifest(tmp_path))).test_client().get("/api/reports/runs/" + run_id).status_code == 404
    summary["report_file"] = "../synthetic.secagent.json"
    (run_dir / "run-summary.json").write_text(json.dumps(summary), encoding="utf-8")
    invalid = api.get("/api/reports/runs/" + run_id)
    assert invalid.status_code == 409
    assert invalid.get_json()["error"]["code"] == "run_invalid"


def test_controlled_runs_are_discovered_after_reporting_start_without_cross_run_confusion(tmp_path):
    (tmp_path / "runs").mkdir()
    manifest_path = manifest(tmp_path, [native(run="historical")])
    selected = json.loads(manifest_path.read_text(encoding="utf-8"))
    selected["allowed_roots"]["controlled"] = "runs"
    selected["controlled_runs_root"] = "controlled"
    manifest_path.write_text(json.dumps(selected), encoding="utf-8")
    api = create_app(load_dataset(manifest_path)).test_client()
    assert api.get("/api/reports/executions").get_json()["total"] == 1

    def save(run_id, verdict):
        folder = tmp_path / "runs" / run_id
        folder.mkdir(parents=True)
        row = native(verdict, run=f"execution-{run_id}", testcase="GH-WEB-001",
                     target="dvaa-researchbot-web-lab")
        row["source_provenance"] = "restricted_dvaa_lab"
        raw = json.dumps(row).encode("utf-8")
        filename = f"native-GH-WEB-001-{run_id}.secagent.json"
        (folder / filename).write_bytes(raw)
        summary = {"run_id": run_id, "report_persisted": True, "report_file": filename,
                   "report_sha256": hashlib.sha256(raw).hexdigest(),
                   "native_execution_id": f"execution-{run_id}",
                   "testcase_id": "GH-WEB-001", "target_id": "dvaa-researchbot-web-lab",
                   "target_request_count": 2}
        (folder / "run-summary.json").write_text(json.dumps(summary), encoding="utf-8")
        return folder, summary

    first_id, second_id = "a" * 32, "b" * 32
    assert api.get("/api/reports/runs/" + first_id).status_code == 404
    first_folder, first_summary = save(first_id, "FAIL")
    first = api.get("/api/reports/runs/" + first_id)
    assert first.status_code == 200
    assert first.get_json()["target_request_count"] == 2
    assert first.get_json()["execution"]["source"]["reported_provenance"] == "restricted_dvaa_lab"
    assert first.get_json()["execution"]["security"]["verdict"] == "FAIL"
    save(second_id, "INCONCLUSIVE")
    assert api.get("/api/reports/runs/" + first_id).get_json()["execution"]["security"]["verdict"] == "FAIL"
    assert api.get("/api/reports/runs/" + second_id).get_json()["execution"]["security"]["verdict"] == "INCONCLUSIVE"
    assert api.get("/api/reports/executions").get_json()["total"] == 1

    report_path = first_folder / first_summary["report_file"]
    report_path.write_bytes(report_path.read_bytes() + b" ")
    tampered = api.get("/api/reports/runs/" + first_id)
    assert tampered.status_code == 409
    assert tampered.get_json()["error"]["code"] == "run_invalid"
    assert api.get("/api/reports/runs/" + second_id).status_code == 200
    assert create_app(load_dataset(manifest(tmp_path))).test_client().get("/api/reports/runs/" + second_id).status_code == 404


@pytest.mark.parametrize("kind", ["disagreement", "missing_parent", "hash_mismatch", "timeout"])
def test_comparison_states_do_not_change_verdicts(tmp_path, kind):
    p = native()
    a = archived(norm(p), "PASS" if kind == "disagreement" else "FAIL")
    if kind == "hash_mismatch": a["original"]["report_file_byte_sha256"] = "d" * 64
    if kind == "timeout": a["judge"].update(provider_fault_code="timeout", json_validation_status="provider_fault")
    c = client(tmp_path, [a] if kind == "missing_parent" else [p, a])
    entry = c.get("/api/reports/comparisons").get_json()["archived"][0]
    if kind == "disagreement": assert entry["state"] == "disagreement"
    elif kind == "missing_parent": assert entry["linkage"] == "missing_parent_execution"
    elif kind == "hash_mismatch": assert entry["linkage"] == "parent_hash_mismatch"
    else: assert entry["state"] == "judge_unavailable_or_failed"
    if kind != "missing_parent":
        assert c.get("/api/reports/overview").get_json()["summary"]["counts"]["security_verdicts"]["FAIL"] == 1


def test_duplicates_dedup_and_conflicting_projections_rejected(tmp_path):
    p = manifest(tmp_path, [native()])
    change_manifest(p, lambda m: m["reports"].append(dict(m["reports"][0])))
    dataset = load_dataset(p)
    assert dataset.summary.duplicate_inputs_removed == 1
    assert dataset.summary.counts.recorded_execution_reports == 1


def test_current_lifecycle_verification_and_conflicting_plain_projection(lab_archive):
    p = manifest(lab_archive)
    job = {"root": "local", "inventory": "archive/evidence-sha256.csv", "execution": "archive/reports/native.json", "assessment": "assessment.json"}
    change_manifest(p, lambda m: m.update(verification_jobs=[job]))
    c = create_app(load_dataset(p)).test_client()
    assert c.get("/api/reports/health").get_json()["verification"]["current_api_lifecycle_records"] == 2
    row = c.get("/api/reports/executions").get_json()["items"][0]
    assert row["evidence_file_integrity_state"] == "verified"
    assert row["verification_origin"] == "current_api_lifecycle"
    d = c.get("/api/reports/executions/" + row["report_id"]).get_json()["execution"]
    assert d["artifact_verification"]["external_action_attestation"] == "not_performed"
    change_manifest(p, lambda m: m["reports"].append({"root": "local", "path": "archive/reports/native.json", "kind": "execution"}))
    with pytest.raises(DatasetError): load_dataset(p)


def test_mismatched_integrity_not_reported_as_unverified(lab_archive):
    p = manifest(lab_archive)
    change_manifest(p, lambda m: m.update(verification_jobs=[{"root": "local", "inventory": "archive/evidence-sha256.csv", "execution": "archive/reports/native.json"}]))
    events = lab_archive / "archive/fixture/events.jsonl"
    events.write_bytes(events.read_bytes() + b"\n")
    c = create_app(load_dataset(p)).test_client()
    row = c.get("/api/reports/executions").get_json()["items"][0]
    assert row["evidence_file_integrity_state"] == "mismatch"
    assert row["historical_security_verdict"] == "FAIL"


@pytest.mark.parametrize("path", ["../private.json", "C:/Windows/private.json", "https://example.com/private", "x:stream"])
def test_manifest_external_paths_rejected(tmp_path, path):
    p = manifest(tmp_path, [native()])
    change_manifest(p, lambda m: m["reports"][0].update(path=path))
    with pytest.raises(DatasetError) as error: load_dataset(p)
    assert path not in str(error.value)


def test_symlink_escape_rejected(tmp_path):
    p = manifest(tmp_path, [native()])
    link = tmp_path / "linked.json"
    try: link.symlink_to(tmp_path / "source-0.json")
    except OSError: pytest.skip("Symlink creation unavailable on this OS")
    change_manifest(p, lambda m: m["reports"][0].update(path="linked.json"))
    with pytest.raises(DatasetError): load_dataset(p)


@pytest.mark.parametrize("bad", [b'{"dataset_schema_version":"1.0.0","dataset_schema_version":"1.0.0"}', b'{', b'\xff'])
def test_malformed_manifest_rejected(tmp_path, bad):
    p = tmp_path / "manifest.json"
    p.write_bytes(bad)
    with pytest.raises(DatasetError): load_dataset(p)


def test_input_count_and_byte_limits(tmp_path, monkeypatch):
    import reporting.repository as repository
    p = manifest(tmp_path, [native()])
    change_manifest(p, lambda m: m.update(reports=m["reports"] * 129))
    with pytest.raises(DatasetError): load_dataset(p)
    p = manifest(tmp_path, [native()])
    monkeypatch.setattr(repository, "MAX_DATASET_BYTES", 10)
    with pytest.raises(DatasetError): load_dataset(p)


def test_unsupported_formats_and_fake_verification_are_not_imported(tmp_path):
    p = manifest(tmp_path, [native()])
    (tmp_path / "source-0.json").write_text('{"gradingResult":{"pass":true}}', encoding="utf-8")
    with pytest.raises(DatasetError): load_dataset(p)
    row = native()
    row["artifact_verification"] = {"file_integrity": "verified"}
    c = client(tmp_path, [row])
    assert c.get("/api/reports/executions").get_json()["items"][0]["evidence_file_integrity_state"] == "not_performed"


def test_redaction_json_html_and_declared_evidence(tmp_path):
    row = native()
    row["evaluation"]["observation"]["response_text"] = '<script>alert(1)</script> api_key=sk-sensitive123 D:\\private\\auth.json https://collector.invalid/canary-secret'
    row["evaluation"]["observation"]["evidence"].append({"kind": "declared_tool_call", "source": "http_response", "name": "http_post", "success": None,
        "reference": "collector.canary-abcdef0123456789abcdef0123456789", "data": {"arguments": {"token": "private-argument"}, "execution_verified": False}})
    c = client(tmp_path, [row])
    report_id = c.get("/api/reports/executions").get_json()["items"][0]["report_id"]
    response = c.get("/api/reports/executions/" + report_id)
    text = response.get_data(as_text=True)
    for secret in ["sk-sensitive123", "private-argument", "abcdef0123456789abcdef0123456789", "collector.invalid", "auth.json"]:
        assert secret not in text
    assert response.content_type == "application/json"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
    assert "Access-Control-Allow-Origin" not in response.headers
    detail = response.get_json()["execution"]
    assert detail["tool_evidence"]["declared_calls"][0]["verification"]["reported_execution_verified"] is False


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def test_only_get_methods(tmp_path, method):
    response = client(tmp_path).open("/api/reports/overview", method=method)
    assert response.status_code == 405


@pytest.mark.parametrize("overrides,headers", [({"REMOTE_ADDR": "192.168.1.2"}, {}), ({}, {"Host": "evil.invalid"}),
    ({}, {"Origin": "https://evil.invalid"}), ({}, {"Sec-Fetch-Site": "cross-site"})])
def test_loopback_host_origin_boundaries(tmp_path, overrides, headers):
    assert client(tmp_path).get("/api/reports/health", environ_overrides=overrides, headers=headers).status_code == 403


def test_requests_do_not_access_files_and_output_is_stable(tmp_path, monkeypatch):
    p = manifest(tmp_path, [native()])
    before = {f: hashlib.sha256(f.read_bytes()).hexdigest() for f in tmp_path.iterdir()}
    c = create_app(load_dataset(p)).test_client()
    report_id = c.get("/api/reports/executions").get_json()["items"][0]["report_id"]
    def blocked(*a, **k): raise AssertionError("No filesystem reads during HTTP request")
    with monkeypatch.context() as context:
        context.setattr(Path, "open", blocked)
        for route in ["health", "overview", "executions", "executions/" + report_id, "comparisons"]:
            assert c.get("/api/reports/" + route).data == c.get("/api/reports/" + route).data
    assert all(hashlib.sha256(f.read_bytes()).hexdigest() == h for f, h in before.items())


def test_startup_failures_are_structured_and_server_default_loopback(tmp_path, capsys, monkeypatch):
    assert main(["--manifest", str(tmp_path / "secret-missing.json")]) == 2
    assert "secret-missing" not in capsys.readouterr().err
    from flask import Flask
    seen = {}
    monkeypatch.setattr(Flask, "run", lambda self, **kwargs: seen.update(kwargs))
    assert main(["--manifest", str(manifest(tmp_path))]) == 0
    assert seen == {"host": "127.0.0.1", "port": 8091, "debug": False, "use_reloader": False}


def test_oversized_source_and_manifest_are_rejected(tmp_path):
    p = manifest(tmp_path, [native()])
    with (tmp_path / "source-0.json").open("wb") as stream:
        stream.truncate(10 * 1024 * 1024 + 1)
    with pytest.raises(DatasetError): load_dataset(p)
    p.write_bytes(b" " * (64 * 1024 + 1))
    with pytest.raises(DatasetError): load_dataset(p)


def test_network_root_rejected_without_access(tmp_path, monkeypatch):
    p = manifest(tmp_path)
    change_manifest(p, lambda m: m.update(allowed_roots={"remote": r"\\untrusted\share"}))
    with pytest.raises(DatasetError): load_dataset(p)


def test_unexpected_errors_are_generic_json(tmp_path):
    app = create_app(load_dataset(manifest(tmp_path)))
    def fail(): raise RuntimeError(r"D:\private\auth.json api_key=secret")
    app.view_functions["health"] = fail
    response = app.test_client().get("/api/reports/health")
    assert response.status_code == 500
    assert response.get_json()["error"]["code"] == "internal_error"
    assert "private" not in response.get_data(as_text=True)


def test_get_bodies_and_unconfigured_network_bind_are_rejected(tmp_path):
    c = client(tmp_path)
    assert c.get("/api/reports/overview", data="secret").status_code == 400
    with pytest.raises(SystemExit): main(["--manifest", "selected.json", "--host", "0.0.0.0"])


def test_dataset_is_a_snapshot_until_explicit_restart(tmp_path):
    p = manifest(tmp_path, [native()])
    c = create_app(load_dataset(p)).test_client()
    before = c.get("/api/reports/overview").data
    (tmp_path / "source-0.json").write_text("malformed", encoding="utf-8")
    assert c.get("/api/reports/overview").data == before
    with pytest.raises(DatasetError): load_dataset(p)


def test_saved_runs_date_filtering_unknown_asi_error_mcp_and_corruption(tmp_path):
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()

    def write_controlled(run_id, *, started_at, asi_category, verdict="PASS"):
        d = runs_dir / run_id
        d.mkdir()
        row = native(verdict, run=f"exec-{run_id}", testcase=f"TC-{run_id[:4]}",
                     target="target-1", category=asi_category)
        row["evaluation"]["execution"]["started_at"] = started_at
        raw = json.dumps(row).encode("utf-8")
        fname = f"native-{run_id}.secagent.json"
        (d / fname).write_bytes(raw)
        (d / "run-summary.json").write_text(json.dumps({
            "run_id": run_id, "report_persisted": True, "report_file": fname,
            "report_sha256": hashlib.sha256(raw).hexdigest(),
            "native_execution_id": f"exec-{run_id}",
            "testcase_id": f"TC-{run_id[:4]}", "target_id": "target-1",
            "target_request_count": 1,
        }), encoding="utf-8")

    def write_mcp_error(run_id, *, started_at, tamper=False):
        d = runs_dir / f"mcp-action-{run_id}"
        d.mkdir()
        report = {
            "run_id": f"exec-{run_id}",
            "testcase_id": "ASI05-MCP-ERR",
            "target_id": "dvaa-toolbot",
            "timestamp": started_at,
            "evaluation_scope": "execution_action",
            "final_verdict": "ERROR",
            "observation": {"response_text": None, "evidence": []},
            "execution_evaluation": {"evidence_level": "tool_invocation"},
        }
        raw = json.dumps(report).encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        (d / "native_report.json").write_bytes(raw + (b"x" if tamper else b""))
        (d / "run-summary.json").write_text(json.dumps({
            "run_id": run_id, "report_persisted": True, "report_kind": "mcp_action",
            "report_file": "native_report.json", "report_sha256": digest,
            "native_execution_id": f"exec-{run_id}",
            "testcase_id": "ASI05-MCP-ERR", "target_id": "dvaa-toolbot",
        }), encoding="utf-8")

    write_controlled("1" * 32, started_at="2026-11-18T10:00:00+00:00", asi_category="custom_unclassified", verdict="PASS")
    write_controlled("2" * 32, started_at="2026-11-19T12:00:00+00:00", asi_category="unexpected_code_execution", verdict="FAIL")
    write_mcp_error("3" * 32, started_at="2026-11-20T09:00:00+00:00")
    write_mcp_error("4" * 32, started_at="2026-11-20T10:00:00+00:00", tamper=True)

    manifest_path = manifest(tmp_path)
    change_manifest(manifest_path, lambda m: m.update(allowed_roots={"controlled": "runs"}, controlled_runs_root="controlled"))
    api = create_app(load_dataset(manifest_path)).test_client()

    all_rows = api.get("/api/reports/saved-runs").get_json()
    assert all_rows["total"] == 3
    assert all_rows["invalid_artifact_count"] == 1

    # Tampered MCP report stays rejected on detail and export.
    assert api.get("/api/reports/mcp-runs/" + "4" * 32).status_code == 409
    assert api.get("/api/reports/mcp-runs/" + "4" * 32 + "/download").status_code == 409

    # Valid ERROR MCP report renders, filters, opens detail and exports cleanly.
    err_filter = api.get("/api/reports/saved-runs?verdict=ERROR").get_json()
    assert err_filter["total"] == 1 and err_filter["items"][0]["run_id"] == "3" * 32
    detail = api.get("/api/reports/mcp-runs/" + "3" * 32)
    assert detail.status_code == 200 and detail.get_json()["native_report"]["final_verdict"] == "ERROR"
    export = api.get("/api/reports/mcp-runs/" + "3" * 32 + "/download")
    assert export.status_code == 200 and json.loads(export.data)["native_report"]["final_verdict"] == "ERROR"

    # asi_category=unknown matches unclassified runs only.
    unknown_asi = api.get("/api/reports/saved-runs?asi_category=unknown").get_json()
    assert unknown_asi["total"] == 1 and unknown_asi["items"][0]["run_id"] == "1" * 32

    # Valid date boundaries and pagination.
    bounded = api.get("/api/reports/saved-runs?date_from=2026-11-18&date_to=2026-11-19&page=1&page_size=1").get_json()
    assert bounded["total"] == 2 and len(bounded["items"]) == 1
    assert bounded["items"][0]["run_id"] == "2" * 32
    page2 = api.get("/api/reports/saved-runs?date_from=2026-11-18&date_to=2026-11-19&page=2&page_size=1").get_json()
    assert page2["items"][0]["run_id"] == "1" * 32

    # Invalid date format, non-existent calendar date, reversed range -> 400 invalid_filter.
    for bad in ("date_from=bad", "date_from=2026-11-1", "date_from=2026-02-30", "date_to=2026-04-31",
                "date_from=2026-11-20&date_to=2026-11-18"):
        res = api.get("/api/reports/saved-runs?" + bad)
        assert res.status_code == 400
        assert res.get_json()["error"]["code"] == "invalid_filter"

    # /api/reports/executions must continue rejecting date_from/date_to as before.
    assert api.get("/api/reports/executions?date_from=2026-11-18").status_code == 400
