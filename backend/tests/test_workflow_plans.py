import itertools
import json
from pathlib import Path
import pytest
from test_workflow_targets import setup
from test_workflow_preflight import forbidden_operations
from workflow.plans import TestcaseCatalog as Catalog, ROOT, PlanSelection


def request(categories=None,ids=None,plan=False,changes=None):
    client,draft,headers=setup()
    draft.update(changes or {})
    return client.post('/api/testing/'+('plans/preview' if plan else 'compatibility/preview'),base_url=headers['Origin'],headers=headers,
        json={'target':draft,'asi_categories':categories or ['ASI01'],'testcase_ids':ids or []})


def test_real_inventory_and_no_payload_exposure():
    c=Catalog()
    assert c.invalid_records==0
    assert len(c.items)==19
    assert {i['asi_category'] for i in c.items}=={'ASI01','ASI02','ASI03','ASI05'}
    assert all(i['compatibility']!='supported' for i in c.items)
    text=json.dumps(c.items)
    assert 'payload_refs' not in text and 'canary_command' not in text and str(ROOT) not in text


@pytest.mark.parametrize('categories',[list(c) for n in range(1,5) for c in itertools.combinations(['ASI01','ASI02','ASI03','ASI05'],n)])
def test_every_nonempty_subset(categories):
    r=request(categories);assert r.status_code==200
    assert set(i['asi_category'] for i in r.json['items'])==set(categories)
    assert not r.json['executable'] and r.json['connectivity']=='not_checked'


@pytest.mark.parametrize('categories',[[],['ASI04'],['ASI01','ASI01']])
def test_invalid_categories(categories):
    _,draft,_=setup()
    with pytest.raises(ValueError): PlanSelection.model_validate({'target':draft,'asi_categories':categories})


def test_stale_target_and_plan_scope():
    assert request(changes={'profile_revision':'b'*64}).status_code==400
    assert request(ids=['../private'],plan=True).status_code==400
    assert request(ids=['IPA-001'],plan=True).status_code==400
    assert request(plan=True).status_code==400
    r=request(ids=['GH-WEB-001'],plan=True)
    assert r.status_code==200 and r.json['counts']['blocked']==1 and r.json['execution_status']=='not_started'


def test_missing_guards():
    c=Catalog()
    for asi,word in [('ASI03','authorization baseline'),('ASI05','sandbox'),('ASI02','tool-action')]:
        assert all(any(word in r for r in i['requirements']) for i in c.items if i['asi_category']==asi)


def test_safe_yaml_invalid_metadata_and_links(tmp_path):
    folder=tmp_path/'testcases'/'goal_hijacking';folder.mkdir(parents=True)
    (folder/'bad.yaml').write_text('!!python/object/apply:os.system ["echo forbidden"]',encoding='utf-8')
    (folder/'invalid.yaml').write_text('id: invalid',encoding='utf-8')
    c=Catalog(tmp_path);assert c.items==[] and c.invalid_records==2


def test_mixed_states_counts_and_unsupported_selection():
    from workflow.catalog import TargetCatalog
    from workflow.models import CatalogConfig
    from test_workflow_targets import config
    cat=TargetCatalog(CatalogConfig.model_validate(config()))
    _,draft,_=setup()
    c=Catalog();base=c.items[0]
    c.items=[dict(base,id=str(n),compatibility=s) for n,s in enumerate(['supported','unsupported','requires_configuration','unknown'])]
    selection=PlanSelection(target=draft,asi_categories=['ASI01'])
    assert c.preview(selection,cat)['counts']==dict(applicable=1,blocked=2,unknown=1)
    with pytest.raises(ValueError):c.preview(selection.model_copy(update={'testcase_ids':['1']}),cat,plan=True)


def test_missing_skill_is_explicit(monkeypatch):
    from workflow.plans import SkillBundleLoader
    def missing(*args): raise ValueError('private local path must not leak')
    monkeypatch.setattr(SkillBundleLoader,'load',missing)
    cases=Catalog().items
    assert any('Required semantic skill is unavailable.' in i['requirements'] for i in cases)
    assert 'private local path' not in json.dumps(cases)


def test_contradictory_taxonomy_and_sanitization(tmp_path):
    import yaml
    folder=tmp_path/'testcases'/'goal_hijacking';folder.mkdir(parents=True)
    raw=yaml.safe_load((ROOT/'testcases/goal_hijacking/GH-001.yaml').read_text(encoding='utf-8'))
    raw['taxonomy']['owasp']=[{'id':'ASI05','name':'contradiction'}]
    (folder/'case.yaml').write_text(yaml.safe_dump(raw),encoding='utf-8')
    assert Catalog(tmp_path).invalid_records==1
    raw['taxonomy']['owasp']=[]
    raw['description']='Bearer private-token https://private.example/canary-123 api_key=secret'
    (folder/'case.yaml').write_text(yaml.safe_dump(raw),encoding='utf-8')
    serialized=json.dumps(Catalog(tmp_path).items)
    assert 'private-token' not in serialized and 'api_key=secret' not in serialized and 'private.example' not in serialized


def test_readonly_routes_and_no_browser_paths():
    client,_,headers=setup()
    for route in ('categories','testcases'):
        r=client.get('/api/testing/'+route,base_url=headers['Origin'])
        assert r.status_code==200
        assert client.get('/api/testing/'+route+'?path=../private',base_url=headers['Origin']).status_code==400
