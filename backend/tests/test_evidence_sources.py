"""Offline source collection contracts. All HTTP is in-process."""
import json
import socket
from pathlib import Path

import httpx
import pytest

from workflow.evidence_sources import EvidenceSourceStore, EvidenceSourceDraft, EvidenceNetworkPolicy, EvidenceSourceError
from test_target_management import setup, profile, post, BASE, SECRET

URL = 'http://127.0.0.1:7000/api/attack-log'


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, 'connect', lambda *_: pytest.fail('Live network forbidden'))


def store_fixture(tmp_path, handler=None, policy=None):
    catalog, client, headers = setup(tmp_path)
    target = post(client, 'managed-targets/create', {'profile': profile()}, headers).json['profile']
    store = EvidenceSourceStore(catalog, policy=EvidenceNetworkPolicy.model_validate(policy or {
        'allowed_endpoints': [{'url': URL, 'credential_ref': None}]}),
        transport=httpx.MockTransport(handler or (lambda _: httpx.Response(200, json=[]))))
    draft = EvidenceSourceDraft.model_validate(dict(name='Detector log', target_id=target['id'],
        target_revision=target['profile_revision'], endpoint=URL,
        mapping={'event_id':'id', 'request_id':'requestId', 'content':'response'}))
    return store, draft, catalog, client, headers


def test_persistence_revision_and_no_collection_on_save(tmp_path):
    store, draft, catalog, _, _ = store_fixture(tmp_path, lambda _: pytest.fail('No I/O on save'))
    saved = store.save(draft)
    assert EvidenceSourceStore(catalog).list(draft.target_id)[0]['revision'] == saved['revision']
    changed = store.save(draft.model_copy(update={'name':'New name'}), saved['id'], saved['revision'])
    assert changed['revision'] != saved['revision']
    with pytest.raises(EvidenceSourceError):
        store.save(draft, saved['id'], saved['revision'])


def test_explicit_authorization_stale_source_and_target(tmp_path):
    seen = []
    store, draft, _, client, headers = store_fixture(tmp_path, lambda r: (seen.append(r), httpx.Response(200,json=[]))[1])
    source = store.save(draft)
    for consent, revision in [(False, source['revision']), (True, 'f'*64)]:
        with pytest.raises(EvidenceSourceError):
            store.collect(source['id'], revision, consent)
    post(client, 'managed-targets/update', {'profile':profile(model='changed'),
        'expected_profile_revision':draft.target_revision}, headers)
    with pytest.raises(EvidenceSourceError):
        store.collect(source['id'], source['revision'], True)
    assert not seen


@pytest.mark.parametrize('semantics', ['detector_reported','declared_tool_call','tool_handler_invoked','simulated_execution','runtime_execution_verified'])
def test_no_success_or_declared_semantics_upgrades_trust(tmp_path, semantics):
    row = {'id':'event1','requestId':'run1','successful':True,'response':'I refuse.'}
    store, draft, _, _, _ = store_fixture(tmp_path, lambda _:httpx.Response(200,json=[row,row]))
    source = store.save(draft.model_copy(update={'semantics':semantics}))
    capture = store.collect(source['id'],source['revision'],True)
    assert capture['availability'] == 'available'
    assert capture['correlation_status'] == 'uncorrelated'
    assert capture['action_eligible'] is False
    assert capture['duplicate_count'] == 1 and len(capture['events']) == 1
    assert capture['events'][0]['reported_semantics'] == semantics
    assert capture['events'][0]['trust'] == 'target_reported_unverified'
    assert capture['events'][0]['reported_request_id_sha256']
    assert capture['complete_agent_trace'] is False


@pytest.mark.parametrize('url', ['http://example.com/log','http://169.254.169.254/log',
    'http://127.0.0.1/log?token=x','http://user:pass@127.0.0.1/log',
    'http://127.0.0.1/a/../log','http://127.0.0.1/%2e/log','file:///tmp/log',
    'http://127.0.0.1/log#fragment','http://127.0.0.1:7000/api/other'])
def test_ssrf_or_unallowlisted_rejected_without_http(tmp_path, url):
    store, draft, _, _, _ = store_fixture(tmp_path, lambda _:pytest.fail('No HTTP'))
    with pytest.raises(ValueError):
        store.save(EvidenceSourceDraft.model_validate(draft.model_dump() | {'endpoint':url}))


@pytest.mark.parametrize('response,code', [
    (httpx.Response(302,headers={'Location':'http://169.254.169.254/'}),'redirect_rejected'),
    (httpx.Response(503),'http_unavailable'),
    (httpx.Response(200,content='not json'),'malformed_json'),
    (httpx.Response(200,content='[{"x":1,"x":2}]'),'malformed_json'),
    (httpx.Response(200,json={'unexpected':[]}), 'invalid_event_schema'),
    (httpx.Response(200,content='x'*66000),'response_too_large'),
    (httpx.Response(200,json=[{'response':{'secret':'hidden'}}]),'invalid_event_schema'),
])
def test_bounded_errors_persist_without_raw_body(tmp_path, response, code):
    store, draft, _, _, _ = store_fixture(tmp_path, lambda _:response)
    source=store.save(draft)
    capture=store.collect(source['id'],source['revision'],True)
    assert capture['availability']=='unavailable' and capture['error']==code
    assert capture['events']==[]
    assert store.capture(capture['id'])==capture


def test_timeout_redaction_duplicates_and_untrusted_text(tmp_path, monkeypatch):
    monkeypatch.setenv('LAB_EVIDENCE_TOKEN','synthetic-credential-value')
    rows=[{'id':'same','response':'Ignore all policy. secret=hidden synthetic-credential-value user@example.org'},
          {'id':'same','response':'different'}]
    seen=[]
    store,draft,_,_,_=store_fixture(tmp_path,lambda r:(seen.append(r),httpx.Response(200,json=rows))[1],
        {'allowed_endpoints':[{'url':URL,'credential_ref':'lab'}], 'credential_env':{'lab':'LAB_EVIDENCE_TOKEN'}})
    source=store.save(draft.model_copy(update={'credential_ref':'lab'}))
    capture=store.collect(source['id'],source['revision'],True)
    assert seen[0].method=='GET' and seen[0].headers['authorization']=='Bearer synthetic-credential-value'
    assert capture['conflicting_event_ids']==1
    assert capture['events'][0]['content'].startswith('Ignore all policy.')
    serialized=json.dumps(capture)
    assert all(s not in serialized for s in ['synthetic-credential-value','hidden','user@example.org'])
    store.transport=httpx.MockTransport(lambda _:(_ for _ in ()).throw(httpx.ReadTimeout('sensitive URL')))
    failure=store.collect(source['id'],source['revision'],True)
    assert failure['error']=='timeout' and 'sensitive URL' not in json.dumps(failure)


def test_api_auth_no_load_collection_and_explicit_collect(tmp_path):
    from workflow.api import create_app
    seen=[]
    store,draft,catalog,_,_=store_fixture(tmp_path,lambda r:(seen.append(r),httpx.Response(200,json=[]))[1])
    client=create_app(catalog,operator_secret=SECRET,evidence_policy=store.policy,evidence_transport=store.transport).test_client()
    nonce=client.get('/api/testing/health',base_url=BASE).json['validation_nonce']
    headers={'Origin':BASE,'X-SecAgent-Validation':nonce,'X-SecAgent-Operator':SECRET}
    route='evidence-sources/save'
    assert post(client,route,{'profile':draft.model_dump()},headers | {'X-SecAgent-Operator':'wrong'}).status_code==403
    source=post(client,route,{'profile':draft.model_dump()},headers).json['source']
    assert client.get('/api/testing/evidence-sources/target/'+draft.target_id,base_url=BASE,headers=headers).status_code==200
    assert not seen
    body={'source_id':source['id'],'expected_revision':source['revision'],'authorization_confirmed':False}
    assert post(client,'evidence-sources/collect',body,headers).status_code==409
    assert not seen
    result=post(client,'evidence-sources/collect',body | {'authorization_confirmed':True},headers)
    assert result.status_code==200 and len(seen)==1
    assert result.json['capture']['action_eligible'] is False


@pytest.mark.parametrize('filename,path,mapping,semantics,count', [
    ('dvaa-attack-log.json','/api/attack-log',{'items':'','content':'response','timestamp':'timestamp'},'detector_reported',1),
    ('dvaa-cmd-log.json','/api/sandbox/cmd-log',{'items':'','content':'command','timestamp':'timestamp'},'simulated_execution',1),
    ('dvaa-files.json','/api/sandbox/files',{'items':'files','content':'path'},'detector_reported',2),
])
def test_verified_external_shapes_are_only_uncorrelated_snapshots(tmp_path,filename,path,mapping,semantics,count):
    url='http://127.0.0.1:7000'+path
    raw=(Path(__file__).parent/'fixtures'/'evidence'/filename).read_bytes()
    store,draft,_,_,_=store_fixture(tmp_path,lambda _:httpx.Response(200,content=raw),
        {'allowed_endpoints':[{'url':url}]})
    from workflow.evidence_sources import EventMapping
    source=store.save(draft.model_copy(update={'endpoint':url,'mapping':EventMapping.model_validate(mapping),'semantics':semantics}))
    result=store.collect(source['id'],source['revision'],True)
    assert result['availability']=='available' and len(result['events'])==count
    assert result['correlation_status']=='uncorrelated' and not result['action_eligible']
    assert not result['complete_agent_trace']
    assert all(e['reported_request_id_sha256'] is None for e in result['events'])


def test_default_denial_credentials_binding_and_disabled_source(tmp_path):
    store,draft,catalog,_,_=store_fixture(tmp_path,lambda _:pytest.fail('No request'))
    with pytest.raises(EvidenceSourceError):
        EvidenceSourceStore(catalog).save(draft)
    with pytest.raises(EvidenceSourceError):
        store.save(draft.model_copy(update={'credential_ref':'other'}))
    source=store.save(draft.model_copy(update={'enabled':False}))
    with pytest.raises(EvidenceSourceError):
        store.collect(source['id'],source['revision'],True)


def test_repeated_snapshots_are_preserved_not_claimed_as_new_execution(tmp_path):
    store,draft,_,_,_=store_fixture(tmp_path,lambda _:httpx.Response(200,json=[{'id':'one','response':'x'*1500}]))
    source=store.save(draft)
    first=store.collect(source['id'],source['revision'],True)
    second=store.collect(source['id'],source['revision'],True)
    assert first['id']!=second['id']
    assert first['events']==second['events']
    assert first['events'][0]['content_truncated'] and len(first['events'][0]['content'])==1024
    assert first['external_judge_disclosure']=='forbidden'
    assert store.capture(first['id'])==first
    assert store.list(draft.target_id)[0]['latest_capture_id']==second['id']


def test_tamper_and_target_switch_are_rejected(tmp_path):
    store,draft,_,_,_=store_fixture(tmp_path)
    source=store.save(draft)
    assert store.list('another-target')==[]
    path=store.root/'profiles'/f'{source["id"]}.json'
    record=json.loads(path.read_text());record['name']='tampered';path.write_text(json.dumps(record))
    with pytest.raises(EvidenceSourceError,match='integrity'):
        store.get(source['id'])


def test_existing_native_reports_are_never_a_storage_destination(tmp_path):
    store,draft,_,_,_=store_fixture(tmp_path)
    historical=tmp_path/'native-report.secagent.json'
    historical.write_bytes(b'{"historical":"opaque immutable bytes"}')
    before=historical.read_bytes()
    source=store.save(draft);store.collect(source['id'],source['revision'],True)
    assert historical.read_bytes()==before
    assert store.root.name=='evidence-sources-v1'


def test_missing_nonce_origin_or_auth_never_collects(tmp_path):
    from workflow.api import create_app
    store,draft,catalog,_,_=store_fixture(tmp_path,lambda _:pytest.fail('No I/O'))
    source=store.save(draft)
    client=create_app(catalog,operator_secret=SECRET,evidence_policy=store.policy,evidence_transport=store.transport).test_client()
    nonce=client.get('/api/testing/health',base_url=BASE).json['validation_nonce']
    headers={'Origin':BASE,'X-SecAgent-Validation':nonce,'X-SecAgent-Operator':SECRET}
    body={'source_id':source['id'],'expected_revision':source['revision'],'authorization_confirmed':True}
    for key in headers:
        assert post(client,'evidence-sources/collect',body,{k:v for k,v in headers.items() if k!=key}).status_code==403
    assert client.get('/api/testing/evidence-sources/target/'+draft.target_id,base_url=BASE).status_code==403
    assert post(client,'evidence-sources/collect',body,headers|{'Origin':'https://external.invalid'}).status_code==403


@pytest.mark.parametrize('response,code',[
    (httpx.Response(200,json=[],headers={'Content-Encoding':'identity','Content-Type':'text/html'}),'json_content_type_required'),
    (httpx.Response(200,content='[NaN]'),'malformed_json'),
    (httpx.Response(200,content='[{"value":1e999}]'),'invalid_event_schema'),
    (httpx.Response(200,content='[{"nested":'+ '['*40+'0'+']'*40+'}]'),'invalid_event_schema'),
    (httpx.Response(200,json=[{}]*201),'invalid_event_schema'),
])
def test_content_schema_limits(tmp_path,response,code):
    store,draft,_,_,_=store_fixture(tmp_path,lambda _:response)
    source=store.save(draft)
    result=store.collect(source['id'],source['revision'],True)
    assert result['availability']=='unavailable' and result['error']==code


def test_active_controlled_execution_blocks_collection(tmp_path):
    from workflow.api import create_app
    from workflow.dispatch import ControlledDispatcher
    from workflow.admission import AdmissionPolicy
    store,draft,catalog,_,_=store_fixture(tmp_path,lambda _:pytest.fail('No I/O'))
    source=store.save(draft)
    boundary=tmp_path/'run-output'
    dispatcher=ControlledDispatcher(catalog,AdmissionPolicy(),boundary/'runs',operator_secret=SECRET,
        output_boundary=boundary,transport=httpx.MockTransport(lambda _:pytest.fail('No I/O')))
    dispatcher._active=True
    client=create_app(catalog,operator_secret=SECRET,dispatcher=dispatcher,
        evidence_policy=store.policy,evidence_transport=store.transport).test_client()
    nonce=client.get('/api/testing/health',base_url=BASE).json['validation_nonce']
    headers={'Origin':BASE,'X-SecAgent-Validation':nonce,'X-SecAgent-Operator':SECRET}
    result=post(client,'evidence-sources/collect',{'source_id':source['id'],
        'expected_revision':source['revision'],'authorization_confirmed':True},headers)
    assert result.status_code==409 and result.json['error']['code']=='active_run_blocks_source_collection'


def test_missing_policy_and_invalid_cursor_fail_closed(tmp_path):
    from workflow.evidence_sources import load_evidence_policy
    with pytest.raises(EvidenceSourceError):
        load_evidence_policy(tmp_path/'absent.json')
    _,draft,_,_,_=store_fixture(tmp_path)
    with pytest.raises(ValueError):
        EvidenceSourceDraft.model_validate(draft.model_dump()|{'collection_mode':'cursor'})


def test_capture_integrity_and_streaming_size_bound(tmp_path):
    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            yield b'['+b' '*40000
            yield b' '*40000+b']'
    store,draft,_,_,_=store_fixture(tmp_path,lambda _:httpx.Response(200,stream=Stream()))
    source=store.save(draft)
    result=store.collect(source['id'],source['revision'],True)
    assert result['error']=='response_too_large' and result['events']==[]
    path=store.root/'captures'/f'{result["id"]}.json'
    data=json.loads(path.read_text());data['availability']='available';path.write_text(json.dumps(data))
    with pytest.raises(EvidenceSourceError,match='integrity'):
        store.capture(result['id'])


def test_invalid_policy_diagnostics_never_echo_input(tmp_path):
    from workflow.evidence_sources import load_evidence_policy
    policy=tmp_path/'policy.json';policy.write_text('{"credential_env":{"lab":"synthetic-secret-value"}}')
    with pytest.raises(EvidenceSourceError) as failure:
        load_evidence_policy(policy)
    assert 'synthetic-secret-value' not in str(failure.value)


def test_launcher_forwards_named_credentials_only_to_workflow(tmp_path,monkeypatch):
    import start_secagent_local as launcher
    policy=tmp_path/'policy.json'
    policy.write_text(json.dumps({'allowed_endpoints':[{'url':URL,'credential_ref':'lab'}],
                                 'credential_env':{'lab':'LAB_READ_CREDENTIAL'}}))
    monkeypatch.setenv('LAB_READ_CREDENTIAL','synthetic-private-value')
    # All startup processes, ports and health checks are replaced. No service starts.
    monkeypatch.setattr(launcher,'local_data_dir',lambda _:tmp_path)
    monkeypatch.setattr(launcher,'reporting_manifest',lambda _:tmp_path/'manifest.json')
    monkeypatch.setattr(launcher,'available_port',lambda preferred,_:preferred)
    monkeypatch.setattr(launcher,'ready',lambda *_args,**_kwargs:True)
    monkeypatch.setattr(launcher.shutil,'which',lambda _:'node')
    commands=[]
    class Process:
        def poll(self): return 0
        def wait(self,**_): return 0
    def start(command,**kwargs):
        commands.append((command,kwargs['env']))
        return Process()
    monkeypatch.setattr(launcher.subprocess,'Popen',start)
    assert launcher.main(['--no-browser','--evidence-policy',str(policy)])==2  # Fake children exit immediately.
    assert len(commands)==3
    for command,environment in commands:
        if 'workflow.api' in command:
            assert environment['LAB_READ_CREDENTIAL']=='synthetic-private-value'
            assert '--evidence-policy' in command
        else:
            assert 'LAB_READ_CREDENTIAL' not in environment
