"""Local, GET-only reporting API with an opt-in bounded controlled-run lookup."""
import argparse
import ipaddress
import json
import re
import sys

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from reporting.aggregation import _artifact_state
from reporting.models import ArchivedAssessmentReport, ExecutionReport
from reporting.repository import DatasetError, ReportDataset, load_controlled_run, load_dataset

API_VERSION = "1.0.0"


def _public(value):
    """Keep normalized redactions and hashes; additionally hide local paths in source text/errors."""
    if isinstance(value, dict):
        return {key: _public(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_public(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r"(?i)(?:[a-z]:[\\/]|\\\\)[^\s\"<>]+", "[LOCAL_PATH_REDACTED]", value)
        return re.sub(r"/(?:home|Users|tmp|mnt|etc|var)/[^\s\"<>]+", "[LOCAL_PATH_REDACTED]", value)
    return value


def create_app(dataset: ReportDataset):
    app = Flask(__name__, static_folder=None)
    app.config.update(DEBUG=False, TESTING=False, MAX_CONTENT_LENGTH=0, PROPAGATE_EXCEPTIONS=False)
    app.json.sort_keys = True
    app.json.ensure_ascii = True
    # Detached serialized views: incoming requests cannot mutate normalized records.
    executions = {r.report_id: r for r in dataset.records if isinstance(r, ExecutionReport)}
    assessments = {r.source.file_byte_sha256: r for r in dataset.records if isinstance(r, ArchivedAssessmentReport)}
    by_sha = {r.source.file_byte_sha256: r for r in dataset.records}
    summary = _public(dataset.summary.model_dump(mode="json"))
    verification_context = {"computed_at": "dataset_startup", "current_api_lifecycle_records": len(dataset.current_verification_sources),
                            "prior_result_records": 0, "prior_result_import_supported": False,
                            "external_action_attestation": "not_performed"}
    comparison_views = {"production": [], "archived": []}
    linked = {r.source.file_byte_sha256: [] for r in executions.values()}
    for comparison in dataset.summary.comparisons:
        source = by_sha[comparison.source_sha256]
        entry = comparison.model_dump(mode="json")
        entry.update(report_id=source.report_id, judge_invocation_state=source.judge.invocation_state,
                     verification_origin="current_api_lifecycle" if source.source.file_byte_sha256 in dataset.current_verification_sources else "not_requested",
                     provider_diagnostics=source.judge.model_dump(mode="json"))
        comparison_views[comparison.mode].append(_public(entry))
        if comparison.mode == "archived" and comparison.linkage == "matched_selected_source":
            linked[comparison.parent_source_sha256].append(assessments[comparison.source_sha256])

    def origin(record):
        return "current_api_lifecycle" if record.source.file_byte_sha256 in dataset.current_verification_sources else "not_requested"

    def detail_view(record, children):
        data = record.model_dump(mode="json")
        evidence = data["observation"]["evidence"]
        data["tool_evidence"] = {
            "declared_calls": [e for e in evidence if e["kind"] == "declared_tool_call"],
            "target_reported_actions": [e for e in evidence if e["reported_source"] == "http_response" and e["kind"] != "declared_tool_call"],
            "collector_records": [e for e in evidence if e["kind"] == "collector_receipt"],
            "other_observations": [e for e in evidence if e["kind"] not in {"declared_tool_call", "collector_receipt"} and e["reported_source"] != "http_response"],
        }
        data["verification_origin"] = origin(record)
        data["linked_archived_assessments"] = [dict(a.model_dump(mode="json"), verification_origin=origin(a)) for a in children]
        return _public(data)

    list_rows, details = [], {}
    for report_id, record in sorted(executions.items()):
        children = linked[record.source.file_byte_sha256]
        list_rows.append(_public(dict(report_id=report_id, execution_id=record.execution_id,
            testcase_id=record.identity.testcase_id, target_id=record.identity.target_id, asi_category=record.identity.asi_category,
            historical_security_verdict=record.security.verdict, historical_status=record.security.historical_status,
            execution_status=record.execution.status, record_status=record.record_status,
            response_completeness=record.observation.response_completeness.state,
            evidence_file_integrity_state=_artifact_state(record), verification_origin=origin(record),
            linked_assessment_count=len(children))))
        details[report_id] = detail_view(record, children)

    def fail(code, message, status):
        return jsonify(api_schema_version=API_VERSION, error={"code": code, "message": message}), status

    @app.before_request
    def boundary():
        try:
            local = ipaddress.ip_address(request.remote_addr or "").is_loopback
        except ValueError:
            local = False
        if not local or not re.fullmatch(r"(?:127\.0\.0\.1|localhost)(?::[0-9]{1,5})?", request.host):
            return fail("local_only", "This reporting service accepts loopback access only.", 403)
        if request.headers.get("Origin") not in {None, "http://" + request.host} or request.headers.get("Sec-Fetch-Site") == "cross-site":
            return fail("origin_rejected", "Cross-origin access is not enabled.", 403)
        if request.method != "GET":
            return fail("method_not_allowed", "Only GET is supported.", 405)
        if request.content_length or request.headers.get("Transfer-Encoding"):
            return fail("body_not_allowed", "GET request bodies are not supported.", 400)
        if len(request.query_string) > 2048 or "\\" in request.path or ".." in request.path.split("/"):
            return fail("invalid_request", "Invalid request path or query.", 400)
        allowed = {"asi_category", "target_id", "testcase_id", "verdict", "page", "page_size"} if request.path == "/api/reports/executions" else set()
        if any(key not in allowed or len(request.args.getlist(key)) != 1 for key in request.args):
            return fail("invalid_query", "Unsupported or repeated query parameter.", 400)

    @app.after_request
    def headers(response):
        if response.status_code == 405:
            response.headers["Allow"] = "GET"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.errorhandler(Exception)
    def errors(error):
        if isinstance(error, HTTPException):
            return fail("not_found" if error.code == 404 else "request_rejected", "Resource unavailable or request rejected.", error.code or 400)
        return fail("internal_error", "Reporting request could not be completed.", 500)

    @app.get("/api/reports/health")
    def health():
        return jsonify(api_schema_version=API_VERSION, status="ok", report_schema_versions=["2.0.0"],
            summary_schema_version=dataset.summary.summary_schema_version, metric_definition_version=dataset.summary.metric_definition_version,
            dataset={"availability": "available" if dataset.records else "empty", "snapshot_sha256": dataset.summary.snapshot_sha256,
                     "execution_records": len(executions), "archived_assessments": len(assessments)},
            verification=verification_context)

    @app.get("/api/reports/overview")
    def overview():
        return jsonify(api_schema_version=API_VERSION, summary=summary, verification=verification_context)

    @app.get("/api/reports/executions")
    def execution_list():
        args = request.args
        if args.get("asi_category") not in {None, "ASI01", "ASI02", "ASI03", "ASI05", "unknown"} or args.get("verdict") not in {None, "PASS", "FAIL", "INCONCLUSIVE", "unknown"}:
            return fail("invalid_filter", "Invalid ASI category or security verdict.", 400)
        for key in ("target_id", "testcase_id"):
            if key in args and not re.fullmatch(r"[A-Za-z0-9_.:\[\]-]{1,256}", args[key]):
                return fail("invalid_filter", "Invalid identifier filter.", 400)
        for key in ("page", "page_size"):
            if key in args and not re.fullmatch(r"[1-9][0-9]{0,5}", args[key]):
                return fail("invalid_pagination", "Pagination requires positive bounded integers.", 400)
        page, size = int(args.get("page", 1)), int(args.get("page_size", 25))
        if size > 100:
            return fail("invalid_pagination", "Page size exceeds 100.", 400)
        rows = list_rows
        for query, key in (("asi_category", "asi_category"), ("target_id", "target_id"), ("testcase_id", "testcase_id"), ("verdict", "historical_security_verdict")):
            if query in args:
                value = None if query in {"asi_category", "verdict"} and args[query] == "unknown" else args[query]
                rows = [r for r in rows if r[key] == value]
        return jsonify(api_schema_version=API_VERSION, snapshot_sha256=dataset.summary.snapshot_sha256,
            page=page, page_size=size, total=len(rows), items=rows[(page - 1) * size:page * size])

    @app.get("/api/reports/executions/<report_id>")
    def execution_detail(report_id):
        if not re.fullmatch(r"execution:[a-f0-9]{64}", report_id):
            return fail("invalid_report_id", "Invalid execution report identity.", 400)
        if report_id not in details:
            return fail("report_not_found", "Report is not in the selected dataset.", 404)
        return jsonify(api_schema_version=API_VERSION, snapshot_sha256=dataset.summary.snapshot_sha256, execution=details[report_id])

    @app.get("/api/reports/runs/<run_id>")
    def controlled_run_detail(run_id):
        if not re.fullmatch(r"[a-f0-9]{32}", run_id):
            return fail("invalid_run_id", "Invalid controlled run identity.", 400)
        try:
            record = load_controlled_run(dataset, run_id)
        except DatasetError:
            return fail("run_not_found", "Run is unavailable in the selected reporting dataset.", 404)
        return jsonify(api_schema_version=API_VERSION, snapshot_sha256=dataset.summary.snapshot_sha256,
            run_id=run_id, execution=detail_view(record, []))

    @app.get("/api/reports/comparisons")
    def comparisons():
        return jsonify(api_schema_version=API_VERSION, snapshot_sha256=dataset.summary.snapshot_sha256, **comparison_views)

    return app


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--port", type=int, default=8091)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535.")
    try:
        app = create_app(load_dataset(args.manifest))
    except DatasetError:
        print(json.dumps({"error": {"code": "invalid_dataset", "message": "Dataset selection could not be loaded."}}), file=sys.stderr)
        return 2
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
