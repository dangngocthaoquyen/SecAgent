"""Local, GET-only reporting API with an opt-in bounded controlled-run lookup."""
import argparse
from datetime import date
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import secrets
import sys
import threading

from flask import Flask, jsonify, request, Response
from werkzeug.exceptions import HTTPException

from reporting.aggregation import _artifact_state
from reporting.models import ArchivedAssessmentReport, ExecutionReport
from reporting.exports import batch_download, report_document, canonical, safe
from reporting.repository import (ControlledRunInvalid, ControlledRunMissing,
    DatasetError, ReportDataset, load_controlled_run_with_count, load_mcp_run,
    list_saved_runs, load_dataset)

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


def create_app(dataset: ReportDataset, *, history_index_path: Path | None = None):
    app = Flask(__name__, static_folder=None)
    app.config.update(DEBUG=False, TESTING=False, MAX_CONTENT_LENGTH=0, PROPAGATE_EXCEPTIONS=False)
    app.json.sort_keys = True
    app.json.ensure_ascii = True
    saved_index_lock = threading.Lock()
    saved_index = {"names": None, "rows": [], "invalid": 0, "persisted": False}
    index_root_hash = hashlib.sha256(str(dataset.controlled_runs_root).encode()).hexdigest()
    if history_index_path is not None and dataset.controlled_runs_root is not None:
        try:
            index_file = Path(history_index_path)
            if index_file.is_file() and not index_file.is_symlink() and index_file.stat().st_size <= 5_000_000:
                cached = json.loads(index_file.read_text(encoding='utf-8'))
                names = frozenset(p.name for p in dataset.controlled_runs_root.iterdir())
                if (cached.get('schema_version') == '1.0.1' and cached.get('root_sha256') == index_root_hash
                        and isinstance(cached.get('names'), list) and frozenset(cached['names']) == names
                        and isinstance(cached.get('rows'), list) and len(cached['rows']) <= 10000
                        and all(isinstance(row, dict) and re.fullmatch(r'[a-f0-9]{32}', str(row.get('run_id')))
                            and row.get('kind') in {'controlled','mcp_action'} for row in cached['rows'])
                        and type(cached.get('invalid')) is int and cached['invalid'] == 0):
                    saved_index.update(names=names, rows=cached['rows'], invalid=0, persisted=True)
        except (OSError, ValueError, TypeError, AttributeError):
            pass  # Cache failure never changes native report authority.
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
        allowed = ({"asi_category", "target_id", "testcase_id", "verdict", "page", "page_size", "date_from", "date_to"}
            if request.path == "/api/reports/saved-runs" else
            {"asi_category", "target_id", "testcase_id", "verdict", "page", "page_size"}
            if request.path == "/api/reports/executions" else set())
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
            record, request_count = load_controlled_run_with_count(dataset, run_id)
        except ControlledRunMissing:
            return fail("run_not_found", "Run is unavailable in the selected reporting dataset.", 404)
        except ControlledRunInvalid:
            return fail("run_invalid", "Saved run failed integrity or schema validation.", 409)
        return jsonify(api_schema_version=API_VERSION, snapshot_sha256=dataset.summary.snapshot_sha256,
            run_id=run_id, target_request_count=request_count,
            execution=detail_view(record, []))

    @app.get("/api/reports/saved-runs")
    def saved_runs():
        args = request.args
        if args.get("asi_category") not in {None, "ASI01", "ASI02", "ASI03", "ASI05", "unknown"} or args.get("verdict") not in {None, "PASS", "FAIL", "INCONCLUSIVE", "ERROR"}:
            return fail("invalid_filter", "Invalid ASI category or verdict.", 400)
        for key in ("target_id", "testcase_id"):
            if key in args and not re.fullmatch(r"[A-Za-z0-9_.:\[\]-]{1,256}", args[key]):
                return fail("invalid_filter", "Invalid identifier filter.", 400)
        for key in ("page", "page_size"):
            if key in args and not re.fullmatch(r"[1-9][0-9]{0,5}", args[key]):
                return fail("invalid_pagination", "Invalid pagination.", 400)
        page, size = int(args.get("page", 1)), int(args.get("page_size", 25))
        if size > 100:
            return fail("invalid_pagination", "Page size exceeds 100.", 400)
        parsed_dates = {}
        for key in ("date_from", "date_to"):
            if key in args:
                if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", args[key]):
                    return fail("invalid_filter", "Invalid date filter.", 400)
                try:
                    parsed_dates[key] = date.fromisoformat(args[key])
                except ValueError:
                    return fail("invalid_filter", "Invalid date filter.", 400)
        if "date_from" in parsed_dates and "date_to" in parsed_dates and parsed_dates["date_from"] > parsed_dates["date_to"]:
            return fail("invalid_filter", "Invalid date range.", 400)
        try:
            with saved_index_lock:
                names = frozenset(p.name for p in dataset.controlled_runs_root.iterdir()) if dataset.controlled_runs_root else frozenset()
                if names != saved_index["names"] or saved_index["invalid"]:
                    saved_index["rows"], saved_index["invalid"] = list_saved_runs(dataset)
                    saved_index["names"] = names
                    saved_index["persisted"] = False
                    if history_index_path is not None and not saved_index["invalid"]:
                        try:
                            index_file = Path(history_index_path)
                            payload = json.dumps({'schema_version':'1.0.1','root_sha256':index_root_hash,
                                'names':sorted(names),'rows':saved_index['rows'],'invalid':0},
                                sort_keys=True, separators=(',',':')).encode()
                            if len(payload) <= 5_000_000:
                                temporary = index_file.with_name('.history-' + secrets.token_hex(8) + '.tmp')
                                with temporary.open('xb') as stream:
                                    stream.write(payload);stream.flush();os.fsync(stream.fileno())
                                os.replace(temporary, index_file)
                                saved_index['persisted'] = True
                        except OSError:
                            pass  # History remains readable from native files.
                rows, invalid = saved_index["rows"], saved_index["invalid"]
        except (DatasetError, OSError, ValueError):
            return fail("history_unavailable", "Saved run inventory could not be safely read.", 409)
        for query in ("asi_category", "target_id", "testcase_id", "verdict"):
            if query in args:
                expected = None if query == "asi_category" and args[query] == "unknown" else args[query]
                rows = [row for row in rows if row[query] == expected]
        if 'date_from' in args:
            rows = [
                row for row in rows
                if isinstance(row.get('started_at'), str)
                and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", row['started_at'][:10])
                and row['started_at'][:10] >= args['date_from']
            ]
        if 'date_to' in args:
            rows = [
                row for row in rows
                if isinstance(row.get('started_at'), str)
                and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", row['started_at'][:10])
                and row['started_at'][:10] <= args['date_to']
            ]
        return jsonify(api_schema_version=API_VERSION, page=page, page_size=size,
            total=len(rows), invalid_artifact_count=invalid, index_persisted=saved_index['persisted'],
            items=_public(rows[(page - 1) * size:page * size]))

    @app.get("/api/reports/mcp-runs/<run_id>")
    def mcp_run_detail(run_id):
        if not re.fullmatch(r"[a-f0-9]{32}", run_id):
            return fail("invalid_run_id", "Invalid MCP run identity.", 400)
        try:
            record, digest = load_mcp_run(dataset, run_id)
        except ControlledRunMissing:
            return fail("run_not_found", "MCP run is unavailable.", 404)
        except ControlledRunInvalid:
            return fail("run_invalid", "MCP report failed schema validation.", 409)
        return jsonify(api_schema_version=API_VERSION, run_id=run_id,
            report_sha256=digest, native_report=_public(record),
            provenance_limit="Native MCP report is target and collector telemetry; independent effect verification requires its own evidence.")

    @app.get('/api/reports/mcp-runs/<run_id>/download')
    def mcp_run_export(run_id):
        if not re.fullmatch(r'[a-f0-9]{32}', run_id):
            return fail('invalid_run_id', 'Invalid MCP run identity.', 400)
        try:
            record, digest = load_mcp_run(dataset, run_id)
            document = {"api_schema_version":API_VERSION,"run_id":run_id,
                "source_report_sha256":digest,"native_report":_public(record)}
            return download_response(canonical(document), f'secagent-mcp-run-{run_id}.json', 'application/json')
        except ControlledRunMissing:
            return fail('run_not_found', 'MCP run is unavailable.', 404)
        except ControlledRunInvalid:
            return fail('run_invalid', 'MCP report failed schema validation.', 409)

    @app.get("/api/reports/comparisons")
    def comparisons():
        return jsonify(api_schema_version=API_VERSION, snapshot_sha256=dataset.summary.snapshot_sha256, **comparison_views)

    def download_response(raw, filename, mimetype):
        return Response(raw, mimetype=mimetype, headers={
            'Content-Disposition': f'attachment; filename="{filename}"',
            'X-SecAgent-Export-Schema': '1.0.0'})

    @app.get('/api/reports/batches/<batch_id>/download')
    def batch_export(batch_id):
        if not re.fullmatch(r'[a-f0-9]{32}', batch_id):
            return fail('invalid_batch_id', 'Invalid batch identity.', 400)
        try:
            raw, filename = batch_download(dataset, batch_id, _public, detail_view)
            return download_response(raw, filename, 'application/zip')
        except ControlledRunMissing:
            return fail('batch_not_found', 'Batch or linked report is unavailable in the selected reporting root.', 404)
        except ControlledRunInvalid:
            return fail('batch_export_rejected', 'Batch must be terminal with intact, correctly linked reports. No export was produced.', 409)

    @app.get('/api/reports/batches/<batch_id>/report.json')
    def batch_json_export(batch_id):
        if not re.fullmatch(r'[a-f0-9]{32}', batch_id):
            return fail('invalid_batch_id', 'Invalid batch identity.', 400)
        try:
            raw, zip_name = batch_download(dataset, batch_id, _public, detail_view)
            import io, zipfile
            with zipfile.ZipFile(io.BytesIO(raw), 'r') as zf:
                summary_obj = json.loads(zf.read('summary.json').decode('utf-8'))
                reports_list = [
                    json.loads(zf.read(name).decode('utf-8'))
                    for name in sorted(zf.namelist())
                    if name.startswith('reports/') and name.endswith('.json')
                ]
            document = safe(dict(
                api_schema_version=API_VERSION,
                batch_id=batch_id,
                summary=summary_obj,
                reports=reports_list,
            ), _public)
            json_name = zip_name[:-4] + '.json' if zip_name.endswith('.zip') else f'secagent-batch-{batch_id}.json'
            return download_response(canonical(document), json_name, 'application/json')
        except ControlledRunMissing:
            return fail('batch_not_found', 'Batch or linked report is unavailable in the selected reporting root.', 404)
        except ControlledRunInvalid:
            return fail('batch_export_rejected', 'Batch must be terminal with intact, correctly linked reports. No export was produced.', 409)

    @app.get('/api/reports/runs/<run_id>/download')
    def run_export(run_id):
        if not re.fullmatch(r'[a-f0-9]{32}', run_id):
            return fail('invalid_run_id', 'Invalid controlled run identity.', 400)
        try:
            record, count = load_controlled_run_with_count(dataset, run_id)
            document = report_document(record, count, _public, detail_view, run_id)
            return download_response(canonical(document), f'secagent-run-{run_id}.json', 'application/json')
        except ControlledRunMissing:
            return fail('run_not_found', 'Run is unavailable in the selected reporting dataset.', 404)
        except ControlledRunInvalid:
            return fail('run_invalid', 'Saved run failed integrity or schema validation.', 409)

    @app.get('/api/reports/executions/<report_id>/download')
    def execution_export(report_id):
        if not re.fullmatch(r'execution:[a-f0-9]{64}', report_id):
            return fail('invalid_report_id', 'Invalid execution report identity.', 400)
        record = executions.get(report_id)
        if record is None:
            return fail('report_not_found', 'Report is not in the selected dataset.', 404)
        document = report_document(record, None, _public, detail_view)
        return download_response(canonical(document), f'secagent-report-{report_id[10:]}.json', 'application/json')

    return app


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--port", type=int, default=8091)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535.")
    try:
        app = create_app(load_dataset(args.manifest), history_index_path=Path(args.manifest).resolve().parent / 'history-index.json')
    except DatasetError:
        print(json.dumps({"error": {"code": "invalid_dataset", "message": "Dataset selection could not be loaded."}}), file=sys.stderr)
        return 2
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
