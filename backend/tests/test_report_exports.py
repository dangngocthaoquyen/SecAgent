"""Read-only research downloads, synthetic artifacts and no live services."""
import csv
import hashlib
import io
import json
import socket
import zipfile

import pytest

from reporting.api import create_app
from reporting.repository import load_dataset
from test_report_aggregation import native
from test_reporting_api import manifest, change_manifest

BATCH='a'*32

@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setattr(socket.socket,'connect',lambda *_:pytest.fail('No network'))

def sha(raw): return hashlib.sha256(raw).hexdigest()

def setup_batch(tmp_path,count=30):
    root=tmp_path/'runs';root.mkdir()
    cases=[];results=[]
    for index in range(count):
        case=f'TC{index+1:04d}';run=f'{index+1:032x}';execution=f'execution-{index}'
        row=native('PASS',run=execution,testcase=case,target='synthetic-legacybot',category='identity_privilege_abuse')
        row['evaluation']['evaluation_mode']='hybrid'
        row['evaluation']['judge'].update(semantic_invoked=True,provider_invoked=True,
            classification='ORIGINAL_GOAL',recommendation='PASS',json_validation_status='valid',
            judge_reason='The agent refused the claim.',judge_evidence=[{'type':'response_span','value':'I cannot claim that identity.'}],
            provider='fixture-provider',model='fixture-model')
        row['evaluation']['observation']['response_text']='I cannot claim that identity. Bearer synthetic-sensitive-token C:\\private\\operator.json'
        folder=root/run;folder.mkdir();raw=json.dumps(row).encode();(folder/'native.secagent.json').write_bytes(raw)
        summary={'run_id':run,'report_file':'native.secagent.json','report_persisted':True,
            'report_sha256':sha(raw),'native_execution_id':execution,'testcase_id':case,
            'target_id':'synthetic-legacybot','target_request_count':1}
        (folder/'run-summary.json').write_text(json.dumps(summary))
        cases.append({'testcase_id':case,'asi_category':'ASI03','input_sha256':'1'*64,'asset_sha256':'2'*64})
        results.append({'testcase_id':case,'execution_id':execution,'report_run_id':run,'report_sha256':sha(raw),
            'verdict':'PASS','status':'completed','request_count':1})
    snapshot={'cases':cases,'target_id':'synthetic-legacybot','profile_revision':'3'*64,'evaluation_mode':'hybrid'}
    state={'schema_version':'1.0.0','batch_run_id':BATCH,'snapshot':snapshot,
        'snapshot_sha256':sha(json.dumps(snapshot,sort_keys=True,separators=(',',':')).encode()),
        'status':'completed','total':count,'processed':count,'target_request_count':count,
        'request_count_unknown':False,'results':results,'created_at':'2026-01-01T00:00:00Z',
        'events':[{'stage':'terminal','at':'2026-01-01T00:01:00Z'}]}
    folder=root/'batch-runs'/BATCH;folder.mkdir(parents=True)
    (folder/'state.json').write_text(json.dumps(state))
    config=manifest(tmp_path)
    change_manifest(config,lambda d:d.update(allowed_roots={'controlled':'runs'},controlled_runs_root='controlled'))
    return create_app(load_dataset(config)).test_client(),root,state

def unpack(response):
    assert response.status_code==200,response.get_data(as_text=True) if response.status_code!=200 else ''
    return zipfile.ZipFile(io.BytesIO(response.data))

def test_batch_contains_exact_30_reports_hashes_judge_and_counts(tmp_path):
    client,root,_=setup_batch(tmp_path)
    before={str(p):sha(p.read_bytes()) for p in root.rglob('*.json')}
    response=client.get(f'/api/reports/batches/{BATCH}/download')
    archive=unpack(response)
    reports=[p for p in archive.namelist() if p.startswith('reports/')]
    assert len(reports)==30 and 'reports/TC0001.json' in reports and 'reports/TC0030.json' in reports
    manifest=json.loads(archive.read('manifest.json'));summary=json.loads(archive.read('summary.json'))
    assert manifest['batch_id']==BATCH and manifest['total_cases']==30
    for item in manifest['artifacts']:
        assert sha(archive.read(item['path']))==item['sha256']
    assert set(x['path'] for x in manifest['artifacts'])==set(archive.namelist())-{'manifest.json'}
    assert summary['verdict_counts']['PASS']==30 and summary['target_request_count']==30
    assert summary['judge']['reported_semantic_invoked_true']==30
    report=json.loads(archive.read(reports[0]))
    assert report['execution']['judge']['classification']=='ORIGINAL_GOAL'
    assert report['execution']['judge']['citations'][0]['value_preview']=='I cannot claim that identity.'
    assert report['execution']['security']['verdict']=='PASS'
    assert len(list(csv.DictReader(io.StringIO(archive.read('results.csv').decode('utf-8-sig')))))==30
    text=''.join(archive.read(p).decode('utf-8-sig') for p in archive.namelist())
    assert 'synthetic-sensitive-token' not in text and 'C:\\private' not in text and str(tmp_path) not in text
    assert before=={str(p):sha(p.read_bytes()) for p in root.rglob('*.json')}

def test_single_run_and_selected_execution_download(tmp_path):
    client,_,state=setup_batch(tmp_path,1)
    run=state['results'][0]['report_run_id']
    response=client.get(f'/api/reports/runs/{run}/download')
    assert response.status_code==200
    assert response.json['execution']['identity']['testcase_id']=='TC0001'
    assert response.json['export_schema_version']=='1.0.0'
    assert 'attachment;' in response.headers['Content-Disposition']
    other=tmp_path/'selection';other.mkdir()
    selected=create_app(load_dataset(manifest(other,[native()]))).test_client()
    id=selected.get('/api/reports/executions').json['items'][0]['report_id']
    assert selected.get(f'/api/reports/executions/{id}/download').status_code==200
    assert client.get(f'/api/reports/executions/{id}/download').status_code==404

@pytest.mark.parametrize('headers,remote', [({'Origin':'https://external.invalid'},'127.0.0.1'),
    ({'Sec-Fetch-Site':'cross-site'},'127.0.0.1'),({},'192.0.2.1'),({'Host':'evil.invalid'},'127.0.0.1')])
def test_existing_reporting_authorization_applies(tmp_path,headers,remote):
    client,_,_=setup_batch(tmp_path,1)
    assert client.get(f'/api/reports/batches/{BATCH}/download',headers=headers,
        environ_base={'REMOTE_ADDR':remote}).status_code==403

@pytest.mark.parametrize('change',[ 'wrong_batch','wrong_report_hash','wrong_case','duplicate_run','active','snapshot_hash'])
def test_export_fails_closed_for_inconsistent_batch(tmp_path,change):
    client,root,state=setup_batch(tmp_path,2)
    if change=='wrong_batch':state['batch_run_id']='f'*32
    if change=='wrong_report_hash':state['results'][0]['report_sha256']='f'*64
    if change=='wrong_case':state['results'][0]['testcase_id']='other-case'
    if change=='duplicate_run':state['results'][1]['report_run_id']=state['results'][0]['report_run_id']
    if change=='active':state['status']='running'
    if change=='snapshot_hash':state['snapshot']['target_id']='different-target'
    (root/'batch-runs'/BATCH/'state.json').write_text(json.dumps(state))
    assert client.get(f'/api/reports/batches/{BATCH}/download').status_code==409

def test_unknown_batch_and_unselected_root(tmp_path):
    client,_,_=setup_batch(tmp_path,1)
    assert client.get('/api/reports/batches/'+'f'*32+'/download').status_code==404
    other=tmp_path/'empty';other.mkdir()
    client=create_app(load_dataset(manifest(other))).test_client()
    assert client.get(f'/api/reports/batches/{BATCH}/download').status_code==404


def make_imported(root,state):
    """Synthetic imported provenance; no external dataset or reference labels."""
    snapshot=state['snapshot']
    imported=dict(dataset_id='d'*32,dataset_revision_sha256='d'*64,submission_id='e'*32,
        plan_id='e'*64,asi03_policy_id='f'*32,asi03_policy_revision_sha256='f'*64,
        asi05_policy_id=None,asi05_policy_revision_sha256=None,cases=[])
    for index,(case,result) in enumerate(zip(snapshot['cases'],state['results'])):
        original=case['testcase_id'];internal='import-'+f'{index+1:024x}'
        case['testcase_id']=result['testcase_id']=internal
        imported['cases'].append(dict(internal_id=internal,source_testcase_id=original,prompt_sha256=case['input_sha256']))
        folder=root/result['report_run_id'];report_path=folder/'native.secagent.json'
        source=json.loads(report_path.read_bytes());source['testcase_id']=internal
        source['evaluation']['testcase_id']=internal
        provenance=dict(dataset_id=imported['dataset_id'],dataset_revision_sha256=imported['dataset_revision_sha256'],
            content_sha256='c'*64,source_testcase_id=original,internal_testcase_id=internal,
            prompt_sha256=case['input_sha256'],source_case_sha256=case['asset_sha256'],
            source_taxonomy_basis='untrusted_source_claim',target_profile_id=snapshot['target_id'],
            target_profile_revision_sha256=snapshot['profile_revision'],binding_id='GENERIC-DIRECT-CHAT',
            adapter='generic_http',delivery_surface='direct_chat',evaluation_readiness='reviewed_asi03_response_semantic',
            evaluation_mode='hybrid',evidence_contract='complete_response_text',submission_id=imported['submission_id'],
            plan_id=imported['plan_id'],batch_run_id=BATCH,batch_execution_id=result['execution_id'].encode().hex().ljust(32,'0')[:32],
            authorization_id='9'*32,target_request_count=1,evidence_provenance='synthetic_mock',
            execution_mode='offline_mock',evaluation_scope='identity_claim_response',
            asi03_policy_id=imported['asi03_policy_id'],asi03_policy_revision_sha256=imported['asi03_policy_revision_sha256'])
        result['execution_id']=provenance['batch_execution_id']
        source['imported_provenance']=provenance
        source['runtime_snapshot']={'report_contract':'imported-v1','target_request_count':1}
        raw=json.dumps(source).encode();report_path.write_bytes(raw);result['report_sha256']=sha(raw)
        path=folder/'run-summary.json';summary=json.loads(path.read_bytes())
        summary.update(testcase_id=internal,report_sha256=sha(raw),dataset_id=imported['dataset_id'],
            input_sha256=case['input_sha256'],batch_execution_id=result['execution_id'])
        path.write_text(json.dumps(summary))
    snapshot['imported_provenance']=imported
    state['snapshot_sha256']=sha(json.dumps(snapshot,sort_keys=True,separators=(',',':')).encode())
    (root/'batch-runs'/BATCH/'state.json').write_text(json.dumps(state))


def test_imported_export_preserves_source_case_policy_and_correlated_batch(tmp_path):
    client,root,state=setup_batch(tmp_path,30);make_imported(root,state)
    archive=unpack(client.get(f'/api/reports/batches/{BATCH}/download'))
    assert len([n for n in archive.namelist() if n.startswith('reports/')])==30
    report=json.loads(archive.read('reports/TC0004.json'))
    assert report['execution']['imported_provenance']['source_testcase_id']=='TC0004'
    assert report['execution']['imported_provenance']['internal_testcase_id'].startswith('import-')
    manifest=json.loads(archive.read('manifest.json'))
    assert manifest['dataset_id']=='d'*32
    assert manifest['policies'][0]['policy_id']=='f'*32
    assert manifest['evaluation_scopes']==['identity_claim_response']
    # A renamed batch cannot reuse these imported runs, even with an intact snapshot hash.
    other=root/'batch-runs'/('b'*32);other.mkdir()
    state['batch_run_id']='b'*32;(other/'state.json').write_text(json.dumps(state))
    assert client.get('/api/reports/batches/'+'b'*32+'/download').status_code==409


def test_csv_formula_neutralization_and_unsafe_member_names(tmp_path):
    client,root,state=setup_batch(tmp_path,1);make_imported(root,state)
    folder=root/state['results'][0]['report_run_id'];path=folder/'native.secagent.json'
    source=json.loads(path.read_bytes());source['imported_provenance']['source_testcase_id']='=HYPERLINK("x")'
    source['evaluation']['final_result']['reason']='=untrusted_formula()'
    raw=json.dumps(source).encode();path.write_bytes(raw)
    summary_path=folder/'run-summary.json';summary=json.loads(summary_path.read_bytes());summary['report_sha256']=sha(raw);summary_path.write_text(json.dumps(summary))
    state['results'][0]['report_sha256']=sha(raw)
    state['snapshot']['imported_provenance']['cases'][0]['source_testcase_id']='=HYPERLINK("x")'
    state['snapshot_sha256']=sha(json.dumps(state['snapshot'],sort_keys=True,separators=(',',':')).encode())
    (root/'batch-runs'/BATCH/'state.json').write_text(json.dumps(state))
    archive=unpack(client.get(f'/api/reports/batches/{BATCH}/download'))
    assert 'reports/case-0001.json' in archive.namelist()
    row=list(csv.DictReader(io.StringIO(archive.read('results.csv').decode('utf-8-sig'))))[0]
    assert row['case_id'].startswith("'=") and row['reason'].startswith("'=")


def test_unreported_case_is_explicitly_unavailable_not_fabricated_verdict(tmp_path):
    client,root,state=setup_batch(tmp_path,2)
    state.update(status='cancelled',target_request_count=1)
    state['results'][1].update(status='cancelled',report_run_id=None,report_sha256=None,verdict=None,request_count=0)
    (root/'batch-runs'/BATCH/'state.json').write_text(json.dumps(state))
    archive=unpack(client.get(f'/api/reports/batches/{BATCH}/download'))
    report=json.loads(archive.read('reports/TC0002.json'))
    assert report['report_available'] is False and 'execution' not in report
    assert json.loads(archive.read('summary.json'))['verdict_counts']['unknown']==1
