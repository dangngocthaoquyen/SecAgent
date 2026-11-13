"""Offline catalog/API tests: any target, DNS or Judge operation fails the test."""
import json
import socket
from pathlib import Path
import pytest

from workflow.api import create_app
from workflow.catalog import load_catalog, CatalogError, TargetCatalog
from workflow.models import CatalogConfig

EXAMPLE = Path(__file__).resolve().parents[2] / "configs/workflow/authorized-targets.example.json"


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Network/target/Judge activity forbidden in offline validation")
    from tools.http import HttpClient
    from testing.executor import Executor
    from integrations.external_evaluator.pi import PiEvaluatorProvider
    monkeypatch.setattr(HttpClient, "request", forbidden)
    monkeypatch.setattr(Executor, "execute", forbidden)
    monkeypatch.setattr(PiEvaluatorProvider, "evaluate", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def config():
    raw = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    raw["targets"][0]["reviewed"] = True
    return raw


def setup(raw=None):
    catalog = TargetCatalog(CatalogConfig.model_validate(raw or config()))
    client = create_app(catalog).test_client()
    base = "http://127.0.0.1:8092"
    nonce = client.get("/api/testing/health", base_url=base).json["validation_nonce"]
    p = client.get("/api/testing/targets", base_url=base).json["targets"][0] if catalog.public_targets() else None
    draft = None if p is None else {k:p[k] for k in ("profile_revision", "policy_ref", "endpoint", "protocol", "method", "request_mapping", "response_parser", "credential_alias")}
    if draft is not None:
        draft.update(target_id=p["id"], model=p["default_model"], timeout_seconds=p["timeout_default"])
    return client, draft, {"Origin": base, "X-SecAgent-Validation": nonce}


def post(client, draft, headers):
    return client.post("/api/testing/target-drafts/validate", base_url="http://127.0.0.1:8092", json=draft, headers=headers)


def test_example_requires_operator_review():
    catalog = load_catalog(EXAMPLE)
    assert catalog.public_targets()[0]["authorization_status"] == "review_required"
    assert catalog.public_targets()[0]["platform_id"] == "dvaa"
    assert catalog.public_targets()[0]["platform_name"] == "DVAA"
    c,d,h=setup(json.loads(EXAMPLE.read_text(encoding="utf-8")))
    assert post(c,d,h).json["errors"] == ["operator_review_required"]


def test_reviewed_valid_configuration_is_not_a_connection_or_verdict():
    c,d,h=setup()
    r=post(c,d,h)
    assert r.status_code == 200
    assert r.json["configuration_status"] == "valid"
    assert r.json["connection_reachable"] is None
    assert r.json["runtime_protocol_compatible"] is None
    assert r.json["target_execution_performed"] is False
    assert r.json["security_verdict"] is None


@pytest.mark.parametrize("field,value,code", [
    ("endpoint","http://127.0.0.1:9000/","unauthorized_endpoint"),
    ("endpoint","http://169.254.169.254/latest/meta-data","unauthorized_endpoint"),
    ("endpoint","file:///private","unauthorized_endpoint"),
    ("target_id","unknown","unknown_target"),
    ("profile_revision","a"*64,"stale_profile_revision"),
    ("policy_ref","another-policy","policy_mismatch"),
    ("model","unapproved-model","model_not_approved"),
    ("timeout_seconds",61,"timeout_outside_policy"),
    ("credential_alias","other-alias","credential_alias_mismatch"),
])
def test_policy_rejections(field,value,code):
    c,d,h=setup();d[field]=value
    r=post(c,d,h)
    assert r.status_code==200 and r.json["configuration_status"]=="invalid"
    assert code in r.json["errors"]


@pytest.mark.parametrize("field,value", [
    ("protocol","a2a"),("protocol","mcp-jsonrpc"),("method","GET"),
    ("model",""),("model","$(shell-command)"),("request_mapping",{"script":"evil"}),
    ("response_parser","eval(response)"),("timeout_seconds",0),("timeout_seconds",121),
    ("timeout_seconds",True),("timeout_seconds",1.5),("timeout_seconds","30"),
    ("authorized_origin","http://arbitrary"),("headers",{"Authorization":"raw-secret"}),
    ("adapter","arbitrary-import"),("executable","cmd.exe"),
])
def test_closed_draft_schema(field,value):
    c,d,h=setup();d[field]=value
    r=post(c,d,h)
    assert r.status_code==400 and r.json["error"]["code"]=="invalid_draft"
    assert "raw-secret" not in r.get_data(as_text=True)


def test_missing_model_and_timeout_boundaries():
    c,d,h=setup()
    for timeout in (1,60):
        d["timeout_seconds"]=timeout
        assert post(c,d,h).json["configuration_status"]=="valid"
    del d["model"]
    assert post(c,d,h).status_code==400


def test_credential_presence_without_secret_disclosure(monkeypatch):
    raw=config();raw["credential_aliases"]={"lab-auth":"TEST_WORKFLOW_AUTH"};raw["targets"][0]["credential_alias"]="lab-auth"
    monkeypatch.delenv("TEST_WORKFLOW_AUTH",raising=False)
    c,d,h=setup(raw)
    assert post(c,d,h).json["errors"]==["credential_unavailable"]
    monkeypatch.setenv("TEST_WORKFLOW_AUTH","Bearer very-private-credential")
    assert post(c,d,h).json["configuration_status"]=="valid"
    output=c.get("/api/testing/targets",base_url="http://127.0.0.1:8092").get_data(as_text=True)
    assert "very-private" not in output and "TEST_WORKFLOW_AUTH" not in output


@pytest.mark.parametrize("url",["http://example.org/chat","http://127.0.0.1:7015/a/../b","http://127.0.0.1:7015/%2e%2e/x","http://user:secret@127.0.0.1/chat","http://127.0.0.1/chat?key=secret","ftp://127.0.0.1/chat","http://169.254.169.254/chat"])
def test_invalid_operator_endpoint_fails_closed(tmp_path,url):
    raw=config();raw['targets'][0]['endpoint']=url
    p=tmp_path/'catalog.json';p.write_text(json.dumps(raw),encoding='utf-8')
    with pytest.raises(CatalogError,match='Invalid operator'):
        load_catalog(p)


def test_invalid_catalogs_and_revision(tmp_path):
    p=tmp_path/'catalog.json'
    for raw in ['{"targets":[],"targets":[]}', '{bad', '{"catalog_schema_version":"9"}']:
        p.write_text(raw,encoding='utf-8')
        with pytest.raises(CatalogError):load_catalog(p)
    first=TargetCatalog(CatalogConfig.model_validate(config())).public_targets()[0]['profile_revision']
    assert first==TargetCatalog(CatalogConfig.model_validate(config())).public_targets()[0]['profile_revision']
    changed=config();changed['policy_ref']='new-policy'
    assert first!=TargetCatalog(CatalogConfig.model_validate(changed)).public_targets()[0]['profile_revision']


def test_platform_labels_are_display_only_and_legacy_revision_is_stable():
    raw=config()
    revision=TargetCatalog(CatalogConfig.model_validate(raw)).public_targets()[0]['profile_revision']
    assert revision=='c0efd197c1a90925959f5aab689e657f6db12872e4eaa52a2d034da47796db4b'
    assert load_catalog(EXAMPLE).public_targets()[0]['profile_revision']=='68a5add73e3dc62fcce61c959b0fbd246c455f22b066403e59361eb565d0c937'
    legacy=config();legacy['targets'][0].pop('platform_id');legacy['targets'][0].pop('platform_name')
    assert TargetCatalog(CatalogConfig.model_validate(legacy)).public_targets()[0]['profile_revision']==revision
    relabeled=config();relabeled['targets'][0].update(platform_id='research-lab',platform_name='Research Lab')
    assert TargetCatalog(CatalogConfig.model_validate(relabeled)).public_targets()[0]['profile_revision']==revision
    changed=config();changed['targets'][0]['endpoint']='http://127.0.0.1:7999/v1/chat/completions'
    assert TargetCatalog(CatalogConfig.model_validate(changed)).public_targets()[0]['profile_revision']!=revision


def test_multiple_synthetic_profiles_are_grouped_without_authorization():
    raw=json.loads(EXAMPLE.read_text(encoding='utf-8'))
    raw['targets'].append({**raw['targets'][0], 'id':'synthetic-second',
        'name':'Synthetic Second', 'endpoint':'http://127.0.0.1:7999/v1/chat/completions',
        'models':['synthetic-model'], 'default_model':'synthetic-model',
        'timeout_default':15})
    raw['targets'].append({**raw['targets'][0], 'id':'synthetic-other',
        'name':'Synthetic Other', 'platform_id':'other-lab', 'platform_name':'Other Lab'})
    catalog=TargetCatalog(CatalogConfig.model_validate(raw))
    targets=catalog.public_targets()
    assert len(targets)==3
    assert [t['platform_id'] for t in targets]==['dvaa','dvaa','other-lab']
    assert len({t['profile_revision'] for t in targets})==3
    assert all(t['authorization_status']=='review_required' for t in targets)
    assert targets[1]['models']==['synthetic-model'] and targets[1]['timeout_default']==15
    raw['targets'][2]['id']='synthetic-second'
    with pytest.raises(ValueError,match='Duplicate target identity'):
        CatalogConfig.model_validate(raw)


@pytest.mark.parametrize('change',[
    {'platform_id':None,'platform_name':'DVAA'},
    {'platform_id':'dvaa','platform_name':None},
    {'platform_id':'bad space','platform_name':'DVAA'},
    {'platform_id':'dvaa','platform_name':'<script>'},
])
def test_invalid_platform_presentation_is_rejected(change):
    raw=config();raw['targets'][0].update(change)
    with pytest.raises(ValueError):CatalogConfig.model_validate(raw)


def test_same_platform_id_cannot_have_conflicting_names():
    raw=config();raw['targets'].append({**raw['targets'][0], 'id':'synthetic-second',
        'platform_name':'Different Name'})
    with pytest.raises(ValueError,match='Conflicting platform display names'):
        CatalogConfig.model_validate(raw)


@pytest.mark.parametrize('headers,remote',[
    ({'Host':'evil.example:8092'},'127.0.0.1'),
    ({'Host':'127.0.0.1:7015'},'127.0.0.1'),
    ({'Origin':'https://evil.example'},'127.0.0.1'),
    ({'Sec-Fetch-Site':'cross-site'},'127.0.0.1'),
    ({},'192.168.1.2'),
])
def test_host_origin_peer_boundary(headers,remote):
    c,_,_=setup();r=c.get('/api/testing/health',base_url='http://127.0.0.1:8092',headers=headers,environ_overrides={'REMOTE_ADDR':remote})
    assert r.status_code==403 and 'validation_nonce' not in r.json


def test_post_nonce_origin_json_and_unsupported_routes():
    c,d,h=setup()
    assert post(c,d,{}).status_code==403
    assert post(c,d,{'Origin':h['Origin']}).status_code==403
    assert post(c,d,{**h,'X-SecAgent-Validation':'x'*43}).status_code==403
    assert c.post('/api/testing/target-drafts/validate',base_url=h['Origin'],data='{}',headers=h).status_code==415
    assert c.post('/api/testing/runs',base_url=h['Origin'],json={},headers=h).status_code==403
    assert c.post('/api/testing/private',base_url=h['Origin'],json={},headers=h).status_code==404
    r=c.get('/api/testing/targets',base_url=h['Origin'])
    assert 'Access-Control-Allow-Origin' not in r.headers
    assert r.headers['Cache-Control']=='no-store'


def test_empty_catalog_and_json_limits():
    raw=config();raw['targets']=[];c,_,h=setup(raw)
    assert c.get('/api/testing/targets',base_url=h['Origin']).json['targets']==[]
    for body in ('{"model":"a","model":"b"}', '{bad', '{"timeout_seconds":NaN}'):
        assert c.post('/api/testing/target-drafts/validate',base_url=h['Origin'],data=body,headers={**h,'Content-Type':'application/json'}).status_code==400
    assert c.post('/api/testing/target-drafts/validate',base_url=h['Origin'],data=' '*9000,headers={**h,'Content-Type':'application/json'}).status_code==413
    assert c.get('/api/testing/targets?path=private',base_url=h['Origin']).status_code==400
