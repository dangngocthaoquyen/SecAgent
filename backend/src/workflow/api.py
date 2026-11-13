"""Loopback workflow API; target dispatch requires explicit operator opt-in."""
import argparse
import ipaddress
import os
from pathlib import Path
import secrets
import re
import sys

from flask import Flask, jsonify, request
from pydantic import ValidationError
from werkzeug.exceptions import HTTPException

from workflow.catalog import CatalogError, load_catalog, read_json
from workflow.models import TargetDraft, ConnectionCheckRequest
from workflow.plans import TestcaseCatalog, PlanSelection, ASI
from workflow.admission import AdmissionService, AdmissionRequest, AdmissionPolicy
from workflow.dispatch import ControlledDispatcher, DispatchRejected
from testing import RunnerEvaluationConfig
from workflow.lab_attachment import (LabAttemptPreparer, LabAttemptReference,
    LabPreparationError, ReviewedImages)


def create_app(catalog, *, port=8092, testcase_catalog=None, admission_policy=None,
               dispatcher=None, lab_preparer=None, operator_secret=None):
    if lab_preparer is not None and dispatcher is None and (not isinstance(operator_secret,str) or len(operator_secret)<32):
        raise ValueError('Lab preparation requires a separate operator secret.')
    app = Flask(__name__, static_folder=None)
    app.config.update(MAX_CONTENT_LENGTH=8192, DEBUG=False, PROPAGATE_EXCEPTIONS=False)
    nonce = secrets.token_urlsafe(32)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    inventory = testcase_catalog if testcase_catalog is not None else TestcaseCatalog()
    admission = AdmissionService(catalog, admission_policy)

    def fail(code, status):
        message = ("Controlled run request rejected; inspect the local run record before retrying."
                   if request.path == "/api/testing/runs" else
                   "Offline configuration request rejected. No target request was made.")
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
                  "/api/testing/categories": "GET", "/api/testing/testcases": "GET",
                  "/api/testing/compatibility/preview": "POST", "/api/testing/plans/preview": "POST",
                  "/api/testing/readiness/preview": "POST", "/api/testing/admissions": "POST",
                  "/api/testing/runs": "POST",
                  "/api/testing/lab-attempts/preview": "POST",
                  "/api/testing/lab-attempts/prepare": "POST",
                  "/api/testing/lab-attempts/preflight": "POST"}
        if request.path not in routes:
            return fail("not_found", 404)
        if request.method != routes[request.path]:
            return fail("method_not_allowed", 405)
        if request.method == "GET" and request.content_length:
            return fail("body_not_allowed", 400)
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

    @app.get("/api/testing/health")
    def health():
        # Anti-CSRF capability only; NOT operator auth or an execution token.
        # Never persist in the browser or log it.
        return jsonify(workflow_schema_version="1.0.0", status="ok",
                       mode="controlled_execution_enabled" if dispatcher else "offline_configuration_only",
                       target_network_access=dispatcher is not None,
                       evaluation_modes=['rule_only','hybrid'] if dispatcher and dispatcher.hybrid_config else ['rule_only'],
                       judge_configuration='configured_unverified' if dispatcher and dispatcher.hybrid_config else 'unavailable',
                       lab_preparation_enabled=lab_preparer is not None,
                       validation_nonce=nonce)

    @app.get("/api/testing/targets")
    def targets():
        return jsonify(workflow_schema_version="1.0.0", targets=catalog.public_targets(), protocols=[
            {"id": "openai-chat", "state": "offline_configuration_supported"},
            {"id": "mcp-jsonrpc", "state": "limited_adapter_not_enabled_in_workflow"},
            {"id": "a2a", "state": "unsupported"}])

    @app.post("/api/testing/target-drafts/validate")
    def validate():
        try:
            draft = TargetDraft.model_validate(read_json(request.get_data()))
        except (ValueError, TypeError, ValidationError):
            return fail("invalid_draft", 400)
        errors = catalog.validate(draft)
        return jsonify(workflow_schema_version="1.0.0",
            configuration_status="invalid" if errors else "valid", errors=errors,
            target_id=draft.target_id, profile_revision=draft.profile_revision,
            connection_reachable=None, runtime_protocol_compatible=None,
            target_execution_performed=False, security_verdict=None)

    @app.post("/api/testing/connection-checks")
    def connection_check():
        try:
            selection = ConnectionCheckRequest.model_validate(read_json(request.get_data()))
        except (ValueError, TypeError, ValidationError):
            return fail("invalid_connection_selection", 400)
        result, status = catalog.connection_check(selection)
        return jsonify(result.model_dump()), status

    @app.get('/api/testing/categories')
    def categories():
        return jsonify(workflow_schema_version='1.0.0',items=[{'id':v[0],'name':v[1]} for v in ASI.values()])

    @app.get('/api/testing/testcases')
    def testcases():
        return jsonify(workflow_schema_version='1.0.0',items=inventory.items,invalid_records=inventory.invalid_records)

    @app.post('/api/testing/compatibility/preview')
    @app.post('/api/testing/plans/preview')
    def preview():
        try:
            selection=PlanSelection.model_validate(read_json(request.get_data()))
            result=inventory.preview(selection,catalog,plan=request.path.endswith('/plans/preview'))
        except (ValueError,TypeError):
            return fail('invalid_or_stale_plan_selection',400)
        return jsonify(result)

    @app.post('/api/testing/readiness/preview')
    @app.post('/api/testing/admissions')
    def readiness():
        try:
            selection=AdmissionRequest.model_validate(read_json(request.get_data()))
            result=(dispatcher.readiness(selection,admit=request.path.endswith('/admissions'))
                    if dispatcher else admission.assess(selection,admit=request.path.endswith('/admissions')))
            if lab_preparer is not None and selection.testcase_ids == ['GH-WEB-001']:
                result['lab_preflight_status']='not_checked'
                result['dispatch_available']=False
        except (ValueError,TypeError):
            return fail('invalid_admission_request',400)
        return jsonify(result)

    @app.post('/api/testing/runs')
    def run():
        if dispatcher is None:
            return fail('execution_disabled',403)
        if not dispatcher.authorized(request.headers.get('X-SecAgent-Operator', '')):
            return fail('operator_authentication_required',403)
        try:
            selection=AdmissionRequest.model_validate(read_json(request.get_data()))
            result=dispatcher.run(selection)
        except (ValueError,TypeError,DispatchRejected):
            return fail('run_rejected',409)
        return jsonify(result)

    def operator_authorized():
        supplied = request.headers.get('X-SecAgent-Operator', '')
        if dispatcher is not None:
            return dispatcher.authorized(supplied)
        return bool(operator_secret and supplied and secrets.compare_digest(supplied, operator_secret))

    @app.post('/api/testing/lab-attempts/preview')
    def lab_preview():
        if lab_preparer is None:
            return fail('lab_preparation_disabled',403)
        try:
            selection=AdmissionRequest.model_validate(read_json(request.get_data()))
            return jsonify(lab_preparer.preview(selection))
        except (ValueError,TypeError,LabPreparationError):
            return fail('lab_preparation_rejected',400)

    @app.post('/api/testing/lab-attempts/prepare')
    def lab_prepare():
        if lab_preparer is None:
            return fail('lab_preparation_disabled',403)
        if not operator_authorized():
            return fail('operator_authentication_required',403)
        try:
            selection=AdmissionRequest.model_validate(read_json(request.get_data()))
            return jsonify(lab_preparer.prepare(selection))
        except (ValueError,TypeError,LabPreparationError,OSError):
            return fail('lab_preparation_rejected',409)

    @app.post('/api/testing/lab-attempts/preflight')
    def lab_preflight():
        if lab_preparer is None:
            return fail('lab_preparation_disabled',403)
        if not operator_authorized():
            return fail('operator_authentication_required',403)
        try:
            reference=LabAttemptReference.model_validate(read_json(request.get_data()))
            return jsonify(lab_preparer.preflight(reference.attempt_id))
        except (ValueError,TypeError,LabPreparationError,OSError):
            return fail('lab_preflight_rejected',409)

    return app


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True)
    parser.add_argument("--port", type=int, default=8092)
    parser.add_argument('--admission-policy', help='Operator-owned execution grant JSON; default denies all')
    parser.add_argument('--enable-controlled-runs', action='store_true',
                        help='Explicitly enable the bounded GH-C01 Runner slice')
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
            from pathlib import Path
            from workflow.plans import safe_file
            path=Path(args.admission_policy).absolute()
            safe_file(path,path.parent)
            policy=AdmissionPolicy.model_validate(read_json(path.read_bytes()))
        catalog=load_catalog(args.catalog)
        secret=os.environ.get('SECAGENT_WORKFLOW_OPERATOR_TOKEN','')
        hybrid_config=None
        if args.enable_web_hybrid_judge:
            if not args.enable_controlled_runs or not args.web_hybrid_config:
                raise ValueError('Web hybrid Judge requires controlled runs and explicit configuration.')
            path=Path(args.web_hybrid_config).absolute()
            from workflow.plans import safe_file
            safe_file(path,path.parent)
            hybrid_config=RunnerEvaluationConfig.model_validate(read_json(path.read_bytes()))
            if (hybrid_config.mode!='hybrid' or not hybrid_config.judge_enabled
                    or not hybrid_config.allow_live_judge or hybrid_config.pi is None
                    or hybrid_config.max_judge_calls!=1):
                raise ValueError('Invalid web hybrid Judge configuration.')
        elif args.web_hybrid_config:
            raise ValueError('Web hybrid configuration requires explicit opt-in.')
        dispatcher=None
        if args.enable_controlled_runs:
            if policy is None or not args.run_output_dir:
                raise ValueError('Controlled runs require policy and output directory.')
            dispatcher=ControlledDispatcher(catalog,policy,Path(args.run_output_dir),
                operator_secret=secret,hybrid_config=hybrid_config)
        elif args.run_output_dir:
            raise ValueError('Output directory requires controlled-run opt-in.')
        lab_preparer=None
        if args.enable_lab_preparation:
            if policy is None or not args.lab_attempt_dir or len(secret)<32:
                raise ValueError('Lab preparation requires policy, output directory and operator secret.')
            images=ReviewedImages(args.lab_dvaa_image or '',args.lab_python_image or '',args.lab_proxy_image or '')
            lab_preparer=LabAttemptPreparer(catalog,policy,Path(args.lab_attempt_dir),reviewed_images=images)
        elif any((args.lab_attempt_dir,args.lab_dvaa_image,args.lab_python_image,args.lab_proxy_image)):
            raise ValueError('Lab preparation options require explicit opt-in.')
        app = create_app(catalog, port=args.port,admission_policy=policy,
                         dispatcher=dispatcher,lab_preparer=lab_preparer,operator_secret=secret)
    except (CatalogError,ValueError,OSError,ValidationError):
        print('Invalid operator catalog or admission policy.', file=sys.stderr)
        return 2
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
