from datetime import datetime,timezone,timedelta
import pytest
from test_workflow_targets import setup,config
from test_workflow_preflight import forbidden_operations
from workflow.catalog import TargetCatalog
from workflow.models import CatalogConfig
from workflow.admission import AdmissionService,AdmissionPolicy,ExecutionGrant,AdmissionRequest


def fixture(case='GH-C01'):
    catalog=TargetCatalog(CatalogConfig.model_validate(config()))
    _,draft,_=setup()
    asi='ASI03' if case.startswith('IPA') else 'ASI05' if case.startswith('UCE') else 'ASI01'
    req=AdmissionRequest(target=draft,asi_categories=[asi],testcase_ids=[case])
    return AdmissionService(catalog),req


def test_inventory_reconciliation_and_web_blockers():
    service,req=fixture('GH-WEB-001');r=service.assess(req)
    assert r['items'][0]['stages']['schema_valid']
    assert r['blocked_count']==1 and not r['admitted']
    assert {'fresh_collector_binding_missing','collector_recording_executor_not_wired','required_inputs_or_preflight_unresolved','response_observer_missing'}<=set(r['items'][0]['blockers'])
    assert service.assess(req)['plan_id']==r['plan_id']
    assert service.assess(req.model_copy(update={'expected_plan_id':r['plan_id']}),admit=True)['decision']=='blocked'


def authorized():
    service,req=fixture();asset=service.assess(req)['asset_sha256']['GH-C01']
    grant=ExecutionGrant(target_id=req.target.target_id,profile_revision=req.target.profile_revision,policy_ref=req.target.policy_ref,testcase_id='GH-C01',asset_sha256=asset,scope='security_test_execution',expires_at=datetime.now(timezone.utc)+timedelta(hours=1))
    service.policy=AdmissionPolicy(revision='synthetic-offline-policy',grants=[grant])
    service.bindings[(req.target.target_id,req.target.profile_revision,'GH-C01',asset)]={'protocol':'openai-chat','response_observer':True,'report_sink':True,'variables':{},'environment':{}}
    return service,req


def test_valid_synthetic_admission_no_execution():
    service,req=authorized();r=service.assess(req)
    assert r['ready_count']==1 and not r['admitted']
    result=service.assess(req.model_copy(update={'expected_plan_id':r['plan_id']}),admit=True)
    assert result['admitted'] and result['execution_status']=='not_started' and not result['dispatch_available']
    assert result['max_judge_calls']==0
    stale=service.assess(req.model_copy(update={'expected_plan_id':'b'*64}),admit=True)
    assert stale['ready_count']==0 and not stale['items'][0]['ready']


def test_stale_expired_and_changed_bindings():
    service,req=authorized();identity=service.assess(req)['plan_id']
    assert not service.assess(req.model_copy(update={'expected_plan_id':'a'*64}),admit=True)['admitted']
    service.bindings.clear()
    assert not service.assess(req.model_copy(update={'expected_plan_id':identity}),admit=True)['admitted']
    service,req=authorized();service.policy=service.policy.model_copy(update={'grants':[service.policy.grants[0].model_copy(update={'expires_at':datetime.now(timezone.utc)-timedelta(seconds=1)})]})
    assert service.assess(req)['blocked_count']==1


@pytest.mark.parametrize('case,reason',[('IPA-001','authorization_baseline_missing'),('UCE-001','sandbox_configuration_missing'),('missing','invalid_testcase_or_assets')])
def test_guard_blockers(case,reason):
    service,req=fixture(case);assert reason in service.assess(req)['items'][0]['blockers']


def test_budgets_and_unauthorized_revision():
    service,req=authorized()
    assert 'request_budget_exceeded' in service.assess(req.model_copy(update={'target_request_budget':2}))['blockers']
    assert 'testcase_budget_exceeded' in service.assess(req.model_copy(update={'testcase_ids':['GH-C01','GH-001']}))['blockers']
    assert 'stale_profile_revision' in service.assess(req.model_copy(update={'target':req.target.model_copy(update={'profile_revision':'b'*64})}))['blockers']
    assert 'unknown_target' in service.assess(req.model_copy(update={'target':req.target.model_copy(update={'target_id':'unknown'})}))['blockers']


def test_api_no_client_asserted_permission_or_archives():
    client,draft,headers=setup();body=dict(target=draft,asi_categories=['ASI01'],testcase_ids=['GH-WEB-001'])
    for field in ('runtime_bindings','collector_receipts','archive_path','execution_authorized'):
        r=client.post('/api/testing/admissions',base_url=headers['Origin'],headers=headers,json={**body,field:True})
        assert r.status_code==400
    r=client.post('/api/testing/readiness/preview',base_url=headers['Origin'],headers=headers,json=body)
    assert r.status_code==200 and not r.json['admitted']
    assert 'REQUIRES_FIXTURE_RUN' not in str(r.json)
