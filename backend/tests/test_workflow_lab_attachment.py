"""Offline lab attachment preparation; no Docker, target or Judge invocation."""

from datetime import datetime, timezone, timedelta
from hashlib import sha256
import json
from pathlib import Path
import shutil
from uuid import uuid4

import pytest
import yaml

from test_workflow_targets import config
from workflow.admission import AdmissionPolicy, AdmissionRequest, AdmissionService, ExecutionGrant
from workflow.api import create_app
from workflow.catalog import TargetCatalog
from workflow.lab_attachment import (FIXTURE_ORIGIN, EXPECTED_PEER, LabAttemptPreparer,
    LabPreparationError, ReviewedImages, RuntimeInspection,
    runtime_inspection_errors, static_topology_errors)
from workflow.models import CatalogConfig
from workflow.plans import ROOT

SECRET = "local-operator-secret-for-offline-tests-123"
IMAGES = ReviewedImages("sha256:"+"a"*64,"python:3.13-slim@sha256:"+"b"*64,
                        "nginx:stable-alpine@sha256:"+"c"*64)


@pytest.fixture(autouse=True)
def no_live_operations(monkeypatch):
    import subprocess
    from testing.executor import Executor
    from integrations.external_evaluator.pi import PiEvaluatorProvider
    def forbidden(*_args, **_kwargs):
        raise AssertionError("No Docker, target, Pi or process invocation is allowed")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(Executor, "execute", forbidden)
    monkeypatch.setattr(PiEvaluatorProvider, "evaluate", forbidden)


def repository_copy(tmp_path):
    root = tmp_path / "repository"
    for relative in ("deploy/asi01-lab/compose.yaml", "deploy/asi01-lab/nginx.conf",
                     "testcases/goal_hijacking/GH-WEB-001.yaml", "payload/goal_hijacking.yaml"):
        dst = root / relative
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, dst)
    (root / "results").mkdir()
    return root


def environment(tmp_path, *, root=None, expires=None, authorization_id=None):
    root = root or ROOT
    raw = config()
    raw["targets"][0].update(id="dvaa-researchbot-lab", name="DVAA ResearchBot Lab",
        endpoint="http://127.0.0.1:17015/v1/chat/completions")
    catalog = TargetCatalog(CatalogConfig.model_validate(raw))
    preset = catalog.public_targets()[0]
    draft = {key:preset[key] for key in ("profile_revision","policy_ref","endpoint","protocol","method",
        "request_mapping","response_parser","credential_alias")}
    draft.update(target_id=preset["id"],model=preset["default_model"],timeout_seconds=preset["timeout_default"])
    request = AdmissionRequest(target=draft, asi_categories=["ASI01"], testcase_ids=["GH-WEB-001"])
    asset = AdmissionService(catalog, root=root).assess(request)["asset_sha256"]["GH-WEB-001"]
    grant = ExecutionGrant(authorization_id=authorization_id or uuid4().hex,
        target_id=draft["target_id"],profile_revision=draft["profile_revision"],
        policy_ref=draft["policy_ref"],testcase_id="GH-WEB-001",asset_sha256=asset,
        scope="security_test_execution",expires_at=expires or datetime.now(timezone.utc)+timedelta(minutes=20))
    policy = AdmissionPolicy(grants=[grant])
    boundary = tmp_path / "selected-results"
    boundary.mkdir(exist_ok=True)
    preparer = LabAttemptPreparer(catalog,policy,boundary / "lab-attempts",root=root,
        output_boundary=boundary,reviewed_images=IMAGES)
    return catalog,policy,request,preparer


def test_static_compose_is_consistent_but_not_runtime_proof(tmp_path):
    assert static_topology_errors() == []
    root = repository_copy(tmp_path)
    assert static_topology_errors(root) == []
    path = root / "deploy/asi01-lab/compose.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    value["services"]["fixture"]["volumes"][-1]["source"] = "../../old-fixture"
    path.write_text(yaml.safe_dump(value),encoding="utf-8")
    assert "fixture_mount_or_route_mismatch" in static_topology_errors(root)


@pytest.mark.parametrize("mutation,reason",[
    (lambda x:x["services"]["dvaa"]["networks"]["lab"].update(ipv4_address="172.30.77.9"),"dvaa_service_mismatch"),
    (lambda x:x["services"]["fixture"].update(ports=["8787:8787"]),"fixture_mount_or_route_mismatch"),
    (lambda x:x["services"]["proxy"]["ports"][0].update(host_ip="0.0.0.0"),"proxy_publication_mismatch"),
    (lambda x:x["networks"]["lab"].update(internal=False),"private_network_mismatch"),
    (lambda x:x["networks"]["access"]["ipam"]["config"][0].update(subnet="172.30.99.0/24"),"access_network_mismatch"),
    (lambda x:x["services"]["proxy"]["networks"].update(extra={}),"proxy_publication_mismatch"),
    (lambda x:x["services"]["dvaa"].update(extra_hosts=["example.test:172.30.77.3"]),"unexpected_lab_service_settings"),
    (lambda x:x["services"]["fixture"]["build"].update(dockerfile="other.Dockerfile"),"fixture_mount_or_route_mismatch"),
])
def test_static_topology_rejects_unsafe_changes(tmp_path, mutation, reason):
    root = repository_copy(tmp_path)
    path = root / "deploy/asi01-lab/compose.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutation(value)
    path.write_text(yaml.safe_dump(value),encoding="utf-8")
    assert reason in static_topology_errors(root)


def test_prepare_fresh_fixture_and_preflight_remains_unchecked(tmp_path):
    catalog,policy,request,preparer = environment(tmp_path)
    preview = preparer.preview(request)
    assert preview["preparation_status"] == "eligible" and not preview["dispatch_available"]
    request = request.model_copy(update={"expected_plan_id":preview["plan_id"]})
    response = preparer.prepare(request)
    assert response["preparation_status"] == "requires_lab_setup"
    assert response["runtime_preflight"] == "not_checked" and response["target_request_count"] == 0
    attempt = preparer.output_root / response["attempt_id"]
    manifest = json.loads((attempt/"fixture/manifest.json").read_text(encoding="utf-8"))
    assert manifest["origin"] == FIXTURE_ORIGIN and manifest["expected_peer"] == EXPECTED_PEER
    assert manifest["condition"] == "attack" and not (attempt/"fixture/events.jsonl").exists()
    record = json.loads((attempt/"attempt.json").read_text(encoding="utf-8"))
    assert record["asset_sha256"] == policy.grants[0].asset_sha256
    assert record["fixture_manifest_sha256"] == sha256((attempt/"fixture/manifest.json").read_bytes()).hexdigest()
    assert "FIXTURE_STATE_DIR" in (attempt/"compose.env").read_text(encoding="utf-8")
    assert manifest["canary"] not in json.dumps(response)
    state = preparer.preflight(response["attempt_id"])
    assert state["runtime_preflight"] == "not_checked" and not state["dispatch_available"]
    assert "runtime_inspection_not_available" in state["blockers"]
    with pytest.raises(LabPreparationError,match="already reserved"):
        preparer.prepare(request)


@pytest.mark.parametrize("artifact", ["fixture/manifest.json", "compose.env", "reservation", "missing_fixture"])
def test_preflight_rejects_tampered_attempt_state(tmp_path, artifact):
    _,policy,request,preparer = environment(tmp_path)
    request = request.model_copy(update={"expected_plan_id":preparer.preview(request)["plan_id"]})
    prepared = preparer.prepare(request)
    directory = preparer.output_root / prepared["attempt_id"]
    path = (preparer.output_root / ("reserved-auth-" + policy.grants[0].authorization_id)
            if artifact == "reservation" else directory / artifact)
    if artifact == "missing_fixture":
        (directory / "fixture/manifest.json").unlink()
    else:
        path.write_text('{"attempt_id":"wrong"}' if artifact == "reservation"
                        else path.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(LabPreparationError):
        preparer.preflight(prepared["attempt_id"])


def test_missing_reviewed_images_blocks_preparation(tmp_path):
    _,_,request,preparer = environment(tmp_path)
    preparer.reviewed_images = None
    assert "reviewed_images_missing" in preparer.preview(request)["blockers"]
    request = request.model_copy(update={"expected_plan_id":preparer.preview(request)["plan_id"]})
    with pytest.raises(LabPreparationError):
        preparer.prepare(request)


def test_malformed_compose_is_blocked(tmp_path):
    root = repository_copy(tmp_path)
    path = root / "deploy/asi01-lab/compose.yaml"
    path.write_text("services: []\nnetworks: null\n", encoding="utf-8")
    assert static_topology_errors(root) == ["lab_source_unavailable_or_invalid"]


def test_repeat_same_stable_plan_requires_new_single_use_authorization(tmp_path):
    catalog,policy,request,preparer = environment(tmp_path)
    plan = preparer.preview(request)["plan_id"]
    request = request.model_copy(update={"expected_plan_id":plan})
    first = preparer.prepare(request)
    second_grant = policy.grants[0].model_copy(update={"authorization_id":uuid4().hex})
    preparer.policy = policy.model_copy(update={"grants":[policy.grants[0],second_grant]})
    assert preparer.preview(request)["plan_id"] == plan
    second = preparer.prepare(request)
    assert second["plan_id"] == plan and second["attempt_id"] != first["attempt_id"]
    first_manifest = json.loads((preparer.output_root/first["attempt_id"]/"fixture/manifest.json").read_text(encoding="utf-8"))
    second_manifest = json.loads((preparer.output_root/second["attempt_id"]/"fixture/manifest.json").read_text(encoding="utf-8"))
    assert first_manifest["run_id"] != second_manifest["run_id"]
    assert first_manifest["canary"] != second_manifest["canary"]


def test_expired_wrong_target_stale_plan_and_asset_are_rejected(tmp_path):
    root = repository_copy(tmp_path)
    catalog,policy,request,preparer = environment(tmp_path,root=root)
    plan = preparer.preview(request)["plan_id"]
    request = request.model_copy(update={"expected_plan_id":plan})
    with pytest.raises(LabPreparationError):
        preparer.prepare(request.model_copy(update={"expected_plan_id":"a"*64}))
    with pytest.raises(LabPreparationError):
        preparer.prepare(request.model_copy(update={"target":request.target.model_copy(update={"endpoint":"http://127.0.0.1:7015/v1/chat/completions"})}))
    preparer.policy = policy.model_copy(update={"grants":[policy.grants[0].model_copy(update={"expires_at":datetime.now(timezone.utc)-timedelta(seconds=1)})]})
    with pytest.raises(LabPreparationError):
        preparer.prepare(request)
    preparer.policy = policy
    response = preparer.prepare(request)
    (root/"testcases/goal_hijacking/GH-WEB-001.yaml").write_text(
        (root/"testcases/goal_hijacking/GH-WEB-001.yaml").read_text(encoding="utf-8")+"\n# synthetic change\n",encoding="utf-8")
    with pytest.raises(LabPreparationError,match="stale"):
        preparer.preflight(response["attempt_id"])


def test_runtime_inspection_comparison_does_not_authorize_dispatch(tmp_path):
    _,_,request,preparer = environment(tmp_path)
    request = request.model_copy(update={"expected_plan_id":preparer.preview(request)["plan_id"]})
    response = preparer.prepare(request)
    fixture_dir = preparer.output_root/response["attempt_id"]/"fixture"
    manifest = json.loads((fixture_dir/"manifest.json").read_text(encoding="utf-8"))
    page_url = f"{FIXTURE_ORIGIN}/page/attack/{manifest['run_id']}"
    valid = RuntimeInspection(fixture_mount_source=fixture_dir,fixture_mount_target="/state",
        fixture_mount_type="bind",fixture_mount_readonly=False,dvaa_image_id=IMAGES.dvaa_image,
        dvaa_mount_count=0,dvaa_port_publications=0,fixture_port_publications=0,
        dvaa_private_ip=EXPECTED_PEER,fixture_private_ip="172.30.77.3",
        proxy_host_bind="127.0.0.1:17015",container_visible_url=page_url,
        observed_collector_peer=EXPECTED_PEER,fixture_reachable=True,
        isolated_network=True,cleanup_scope_verified=True)
    assert runtime_inspection_errors(valid,fixture_dir,page_url,IMAGES.dvaa_image) == []
    wrong = RuntimeInspection(**{**valid.__dict__,"fixture_mount_source":tmp_path/"old-fixture",
        "container_visible_url":page_url.replace("172.30.77.3","127.0.0.1"),
        "observed_collector_peer":"172.30.77.9","fixture_reachable":False,
        "dvaa_image_id":"sha256:"+"d"*64,"fixture_port_publications":1})
    errors = runtime_inspection_errors(wrong,fixture_dir,page_url,IMAGES.dvaa_image)
    assert {"fixture_mount_mismatch","container_visible_fixture_url_mismatch",
        "collector_peer_not_verified","fixture_reachability_not_verified",
        "container_image_or_exposure_mismatch"} <= set(errors)
    assert preparer.preflight(response["attempt_id"])["dispatch_available"] is False


def test_api_prepare_requires_operator_secret_and_never_enables_run(tmp_path):
    catalog,policy,request,preparer = environment(tmp_path)
    client=create_app(catalog,admission_policy=policy,lab_preparer=preparer,operator_secret=SECRET).test_client()
    base="http://127.0.0.1:8092"
    nonce=client.get("/api/testing/health",base_url=base).json["validation_nonce"]
    headers={"Origin":base,"X-SecAgent-Validation":nonce}
    body=request.model_dump(mode="json")
    preview=client.post("/api/testing/lab-attempts/preview",base_url=base,json=body,headers=headers)
    assert preview.status_code==200 and preview.json["preparation_status"]=="eligible"
    body["expected_plan_id"]=preview.json["plan_id"]
    assert client.post("/api/testing/lab-attempts/prepare",base_url=base,json=body,headers=headers).status_code==403
    approved={**headers,"X-SecAgent-Operator":SECRET}
    prepared=client.post("/api/testing/lab-attempts/prepare",base_url=base,json=body,headers=approved)
    assert prepared.status_code==200 and not prepared.json["dispatch_available"]
    check=client.post("/api/testing/lab-attempts/preflight",base_url=base,
        json={"attempt_id":prepared.json["attempt_id"]},headers=approved)
    assert check.status_code==200 and check.json["runtime_preflight"]=="not_checked"
    assert client.post("/api/testing/runs",base_url=base,json=body,headers=approved).status_code==403
    assert client.post("/api/testing/lab-attempts/preflight",base_url=base,
        json={"attempt_id":"../secret"},headers=approved).status_code==409


def test_lab_readiness_cannot_advertise_dispatch_from_another_backend(tmp_path):
    catalog,policy,request,preparer = environment(tmp_path)
    class AdvertisedDispatcher:
        def readiness(self, _selection, *, admit=False):
            return {"dispatch_available": True, "admitted": True}
    client = create_app(catalog,admission_policy=policy,lab_preparer=preparer,
                        dispatcher=AdvertisedDispatcher()).test_client()
    base = "http://127.0.0.1:8092"
    nonce = client.get("/api/testing/health",base_url=base).json["validation_nonce"]
    result = client.post("/api/testing/readiness/preview",base_url=base,
        json=request.model_dump(mode="json"),headers={"Origin":base,"X-SecAgent-Validation":nonce})
    assert result.status_code == 200
    assert result.json["lab_preflight_status"] == "not_checked"
    assert result.json["dispatch_available"] is False
