"""Independent B4.7 negative and acceptance tests: real APIs/Runner, offline transport."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import socket
from threading import Event
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest

from test_generic_imported_batch import setup_imported_workflow, post, get, terminal, BASE, SECRET, CODEBOT_JSON, REDTEAM_YAML
from workflow.generic_imported_batch import GenericImportedBatchWorkflow
from workflow.dataset_repository import DatasetRepository
from workflow.admission import ExecutionGrant
from reporting.repository import _load_controlled_run, ControlledRunInvalid


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Real network forbidden in B4.7 acceptance")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


def response(text="Claim: I executed the requested action."):
    return httpx.Response(200, json={"choices": [{"message": {"content": text}, "finish_reason": "stop"}]})


def imported(ctx, cases=None, raw=None):
    client, headers = ctx[:2]
    raw = raw if raw is not None else json.dumps(cases, ensure_ascii=False).encode("utf-8")
    result = client.post('/api/testing/datasets/import', base_url=BASE, data=raw,
        content_type='application/json', headers=headers | {'X-Dataset-Filename': 'acceptance.json'})
    assert result.status_code in (200, 201), result.json
    return result.json['dataset']


def selection(ctx, ds=None, count=1):
    ds = ds or ctx[6].model_dump(mode='json')
    return {'target': ctx[5], 'dataset_id': ds['dataset_id'],
        'testcase_ids': [c.get('internal_id', c['testcase_id']) for c in ds['testcases'][:count]],
        'total_request_budget': count, 'evaluation_mode': 'rule_only'}


def launch(ctx, selected, *, submission=None):
    preview = post(ctx[0], 'batches/preview', selected, ctx[1])
    assert preview.status_code == 200, preview.json
    body = selected | {'expected_plan_id': preview.json['plan_id'],
        'submission_id': submission or uuid4().hex, 'authorization_confirmed': True}
    started = post(ctx[0], 'batches', body, ctx[1])
    assert started.status_code == 202, started.json
    return started.json['batch_run_id'], body


def finish(ctx, identity):
    status = terminal(ctx[0], identity, ctx[1])
    ctx[2]._worker.join(10)
    assert not ctx[2]._worker.is_alive()
    return status, get(ctx[0], f'batches/{identity}/results', ctx[1]).json


@pytest.mark.parametrize('answer', ['SECAGENT_UNMATCHABLE_CANARY_EVIDENCE_999', 'Done. I deleted production.', 'I refuse.'])
def test_response_claims_and_old_marker_are_not_security_verdicts(tmp_path, answer):
    ctx = setup_imported_workflow(tmp_path, lambda req: response(answer))
    identity, _ = launch(ctx, selection(ctx))
    status, results = finish(ctx, identity)
    assert status['target_request_count'] == 1
    row = results['results'][0]
    assert row['verdict'] == 'INCONCLUSIVE'
    assert 'No reviewed security evaluation contract' in row['evaluation_reason']
    record, count = _load_controlled_run(SimpleNamespace(controlled_runs_root=ctx[3].output_root), row['report_run_id'])
    assert count == 1 and record.security.verdict == 'INCONCLUSIVE'


def test_dataset_scope_and_missing_selection_fail_closed(tmp_path):
    sent = []
    ctx = setup_imported_workflow(tmp_path, lambda req: (sent.append(json.loads(req.content)) or response()))
    a = imported(ctx, [{'id': 'same', 'prompt': 'A'}])
    b = imported(ctx, [{'id': 'same', 'prompt': 'B'}, {'id': 'absent', 'prompt': 'B-only'}])
    identity, _ = launch(ctx, selection(ctx, a))
    finish(ctx, identity)
    assert [r['messages'][0]['content'] for r in sent] == ['A']
    wrong = selection(ctx, a) | {'testcase_ids': [b['testcases'][1].get('internal_id', 'absent')]}
    preview = post(ctx[0], 'batches/preview', wrong, ctx[1])
    assert preview.status_code != 200 or preview.json['ready_count'] == 0
    missing = selection(ctx, a); missing.pop('dataset_id')
    assert post(ctx[0], 'batches/preview', missing, ctx[1]).status_code >= 400


def test_offline_transport_cannot_be_missing_or_replaced(tmp_path):
    ctx = setup_imported_workflow(tmp_path, lambda req: response())
    ctx[3].transport = None
    with pytest.raises(ValueError):
        GenericImportedBatchWorkflow(ctx[3], ctx[4])
    preview = post(ctx[0], 'batches/preview', selection(ctx), ctx[1])
    assert preview.json['ready_count'] == 0


def test_timeout_policy_blocks_before_transport(tmp_path):
    sent = []
    ctx = setup_imported_workflow(tmp_path, lambda req: sent.append(req) or response())
    selected = selection(ctx)
    selected['target'] = selected['target'] | {'timeout_seconds': 60}
    preview = post(ctx[0], 'batches/preview', selected, ctx[1])
    assert preview.status_code == 200
    assert preview.json['ready_count'] == 0
    assert preview.json['items'][0]['reason'] == 'timeout_budget_exceeded'
    started = post(ctx[0], 'batches', selected | {'expected_plan_id': preview.json['plan_id'],
        'submission_id': uuid4().hex, 'authorization_confirmed': True}, ctx[1])
    assert started.status_code == 409 and sent == []


def test_long_metadata_and_start_failure_do_not_leak_active_state(tmp_path, monkeypatch):
    ctx = setup_imported_workflow(tmp_path, lambda req: response())
    ds = imported(ctx, [{'id': 'x' * 128, 'plugin_id': 'p' * 64, 'prompt': 'long metadata'}])
    identity, _ = launch(ctx, selection(ctx, ds))
    assert finish(ctx, identity)[0]['status'] == 'completed'
    from threading import Thread
    original = Thread.start
    monkeypatch.setattr(Thread, 'start', lambda self: (_ for _ in ()).throw(RuntimeError('startup failure')))
    sel = selection(ctx); preview = post(ctx[0], 'batches/preview', sel, ctx[1]).json
    assert post(ctx[0], 'batches', sel | {'expected_plan_id': preview['plan_id'],
        'submission_id': uuid4().hex, 'authorization_confirmed': True}, ctx[1]).status_code == 500
    assert ctx[3]._active is False
    monkeypatch.setattr(Thread, 'start', original)
    identity, _ = launch(ctx, selection(ctx))
    assert finish(ctx, identity)[0]['status'] == 'completed'


def corrupt_prompt(repo, dataset_id):
    path = repo.root / f'{dataset_id}.json'
    data = json.loads(path.read_bytes())
    envelope = data.get('envelope', data)
    envelope['testcases'][0]['prompt'] = 'TAMPERED'
    path.write_text(json.dumps(data), encoding='utf-8')


def test_stored_dataset_tampering_blocks_preview(tmp_path):
    ctx = setup_imported_workflow(tmp_path, lambda req: pytest.fail('dispatch after tamper'))
    corrupt_prompt(ctx[4], ctx[6].dataset_id)
    assert ctx[4].get_dataset(ctx[6].dataset_id) is None
    assert post(ctx[0], 'batches/preview', selection(ctx), ctx[1]).status_code >= 400


def test_dataset_drift_after_authorization_blocks_dispatch(tmp_path, monkeypatch):
    ctx = setup_imported_workflow(tmp_path, lambda req: pytest.fail('dispatch after drift'))
    original = ctx[2]._run_case
    def mutate(*args):
        corrupt_prompt(ctx[4], ctx[6].dataset_id)
        return original(*args)
    monkeypatch.setattr(ctx[2], '_run_case', mutate)
    identity, _ = launch(ctx, selection(ctx))
    status, _ = finish(ctx, identity)
    assert status['target_request_count'] == 0
    assert status['status'] != 'completed'
    assert ctx[3].policy.grants == []


def test_request_count_tampering_rejected(tmp_path):
    ctx = setup_imported_workflow(tmp_path, lambda req: response())
    identity, _ = launch(ctx, selection(ctx))
    _, results = finish(ctx, identity)
    run = results['results'][0]['report_run_id']
    path = ctx[3].output_root / run / 'run-summary.json'
    value = json.loads(path.read_bytes()); value['target_request_count'] = 0
    path.write_text(json.dumps(value), encoding='utf-8')
    with pytest.raises(ControlledRunInvalid):
        _load_controlled_run(SimpleNamespace(controlled_runs_root=ctx[3].output_root), run)


def test_cli_custom_mode_uses_actual_managed_storage_and_mock(tmp_path, monkeypatch):
    from workflow import api
    from flask import Flask
    from workflow.dispatch import ControlledDispatcher
    seed = tmp_path / 'catalog.json'
    seed.write_text(json.dumps({'catalog_schema_version': '1.0.0', 'policy_ref': 'cli-test', 'targets': []}))
    # Keep real constructor behavior; only relocate the existing results boundary to test storage.
    class IsolatedDispatcher(ControlledDispatcher):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs, output_boundary=tmp_path / 'results')
    monkeypatch.setattr(api, 'ControlledDispatcher', IsolatedDispatcher)
    monkeypatch.setenv('SECAGENT_WORKFLOW_OPERATOR_TOKEN', SECRET)
    monkeypatch.setenv('SECAGENT_LOCAL_SINGLE_USER', '1')
    seen = []
    monkeypatch.setattr(Flask, 'run', lambda app, **kw: seen.append(app.test_client().get('/api/testing/health', base_url=BASE).json))
    assert api.main(['--catalog', str(seed), '--target-data-dir', str(tmp_path / 'operator'),
        '--enable-controlled-runs', '--enable-custom-imported-batch',
        '--run-output-dir', str(tmp_path / 'results' / 'runs')]) == 0
    assert seen[0]['custom_imported_batch_enabled'] and seen[0]['target_network_access'] is False
    assert (tmp_path / 'operator' / 'datasets').is_dir()


def test_original_bytes_deduplicate_and_survive_restart(tmp_path):
    ctx = setup_imported_workflow(tmp_path, lambda req: response())
    raw = '[ {"id":" case/α ","prompt":"雪\\n  \\\"quoted\\\" ","description":null,"strategy_id":null,"n":9007199254740993} ]\r\n'.encode()
    first = imported(ctx, raw=raw)
    same = imported(ctx, raw=raw)
    other = imported(ctx, raw=json.dumps(json.loads(raw), ensure_ascii=False).encode())
    assert first['dataset_id'] == same['dataset_id'] != other['dataset_id']
    assert first['file_sha256'] == sha256(raw).hexdigest()
    restarted = DatasetRepository(tmp_path / 'operator-data')
    saved = restarted.get_dataset(first['dataset_id'])
    assert saved._source_bytes == raw
    assert saved.testcases[0].source_case == json.loads(raw)[0]
    assert saved.testcases[0].testcase_id == ' case/α '
    assert saved.testcases[0].description is None and saved.testcases[0].strategy_id is None
    assert saved.testcases[0].prompt_sha256 == sha256(json.loads(raw)[0]['prompt'].encode()).hexdigest()


def test_unusual_source_identity_metadata_and_generic_taxonomy(tmp_path):
    sent = []
    ctx = setup_imported_workflow(tmp_path, lambda req: sent.append(json.loads(req.content)) or response())
    source = {'id': ' /α\\.. 空白 ', 'vars': {'prompt': '  ```\n雪\n```\n', 'extra_var': 123},
        'description': 'd' * 4000, 'plugin_id': 'excessive-agency', 'extension': {'transform': 'process.exit(1)'},
        'assert': [{'type': 'javascript', 'value': 'throw Error("must remain inert")'}]}
    ds = imported(ctx, [source])
    assert ds['testcases'][0]['source_case'] == source
    assert ds['testcases'][0]['description'] == source['description']
    identity, _ = launch(ctx, selection(ctx, ds))
    status, results = finish(ctx, identity)
    assert status['status'] == 'completed'
    assert sent[0]['messages'][0]['content'] == source['vars']['prompt']
    record, _ = _load_controlled_run(SimpleNamespace(controlled_runs_root=ctx[3].output_root), results['results'][0]['report_run_id'])
    assert record.identity.category == 'unclassified' and record.identity.asi_category is None
    assert record.security.verdict == 'INCONCLUSIVE'


def test_credentialed_target_is_explicitly_unsupported(tmp_path):
    ctx = setup_imported_workflow(tmp_path, lambda req: pytest.fail('credentialed request'))
    preset = ctx[2].catalog._targets[ctx[5]['target_id']]
    ctx[2].catalog._targets[preset.id] = preset.model_copy(update={'credential_alias': 'server-owned'})
    preview = post(ctx[0], 'batches/preview', selection(ctx), ctx[1]).json
    assert preview['ready_count'] == 0
    assert preview['items'][0]['reason'] == 'imported_credentialed_target_unsupported'


def test_missing_trusted_binding_prevents_dispatch(tmp_path):
    ctx = setup_imported_workflow(tmp_path, lambda req: pytest.fail('unbound dispatch'))
    ctx[2].registry._bindings.clear()
    assert post(ctx[0], 'batches/preview', selection(ctx), ctx[1]).json['ready_count'] == 0


def test_api_import_one_two_thirty_and_repeated_batches_with_restart(tmp_path):
    sent, grant_sizes = [], []
    def answer(req):
        sent.append(json.loads(req.content)['messages'][0]['content'])
        grant_sizes.append(len(ctx[3].policy.grants))
        return response()
    ctx = setup_imported_workflow(tmp_path, answer)
    one = imported(ctx, [{'id': 'single/雪', 'prompt': 'independent single import'}])
    all_cases = imported(ctx, raw=CODEBOT_JSON.read_bytes())
    unrelated = ExecutionGrant(authorization_id='unrelated', target_id=ctx[5]['target_id'],
        profile_revision=ctx[5]['profile_revision'], policy_ref=ctx[5]['policy_ref'], testcase_id='GH-C01',
        asset_sha256='a'*64, scope='security_test_execution', expires_at=datetime.now(timezone.utc)+timedelta(hours=1))
    ctx[3].policy = ctx[3].policy.model_copy(update={'grants': [unrelated]})
    run_ids, batches = [], []
    for ds, count in [(one, 1), (all_cases, 1), (all_cases, 2), (all_cases, 30), (all_cases, 30), (all_cases, 30)]:
        before = len(sent)
        identity, body = launch(ctx, selection(ctx, ds, count))
        status, results = finish(ctx, identity)
        batches.append(identity)
        assert status['status'] == 'completed'
        assert status['target_request_count'] == status['request_budget_consumed'] == count
        assert sent[before:] == [c['prompt'] for c in ds['testcases'][:count]]
        assert ctx[3].policy.grants == [unrelated]
        assert post(ctx[0], 'batches', body, ctx[1]).status_code == 409
        for row in results['results']:
            assert row['verdict'] == 'INCONCLUSIVE' and row['request_count'] == 1
            record, requests = _load_controlled_run(SimpleNamespace(controlled_runs_root=ctx[3].output_root), row['report_run_id'])
            assert requests == 1 and record.imported_provenance.dataset_id == ds['dataset_id']
            assert record.imported_provenance.dataset_revision_sha256 == ds['file_sha256']
            assert record.imported_provenance.submission_id == body['submission_id']
            run_ids.append(row['report_run_id'])
    assert len(sent) == 94 and set(grant_sizes) == {2}
    assert len(list(ctx[2].root.glob('grant-*'))) == 94
    assert len(set(run_ids)) == 94
    restarted = GenericImportedBatchWorkflow(ctx[3], DatasetRepository(tmp_path / 'operator-data'))
    assert ctx[3].policy.grants == [unrelated]
    for identity in batches:
        assert restarted.orchestrator.state(identity)['status'] == 'completed'
    for run in run_ids:
        assert _load_controlled_run(SimpleNamespace(controlled_runs_root=ctx[3].output_root), run)[1] == 1


@pytest.mark.parametrize('mode', ['cancel', 'expiry', 'tamper'])
def test_final_transport_gate_and_concurrent_submission(tmp_path, monkeypatch, mode):
    sent = []
    ctx = setup_imported_workflow(tmp_path, lambda req: sent.append(req) or response())
    from workflow.dispatch import OneRequestHttpClient
    entered, release = Event(), Event()
    original = OneRequestHttpClient.request
    def gated(self, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(self, **kwargs)
    monkeypatch.setattr(OneRequestHttpClient, 'request', gated)
    identity, body = launch(ctx, selection(ctx, count=2))
    assert entered.wait(5)
    assert post(ctx[0], 'batches', body | {'submission_id': uuid4().hex}, ctx[1]).status_code == 409
    if mode == 'cancel':
        assert post(ctx[0], f'batches/{identity}/cancel', {}, ctx[1]).status_code == 200
    elif mode == 'expiry':
        # The final gate checks the exact grant object already selected for this request.
        grant = ctx[3].policy.grants[0]
        object.__setattr__(grant, 'expires_at', datetime.now(timezone.utc)-timedelta(seconds=1))
        ctx[2]._authorization_expires_at = grant.expires_at
    else:
        corrupt_prompt(ctx[4], ctx[6].dataset_id)
    release.set()
    status, results = finish(ctx, identity)
    assert sent == [] and status['target_request_count'] == 0
    assert ctx[3].policy.grants == [] and ctx[3]._active is False
    if mode == 'cancel':
        assert status['status'] == 'cancelled'
        assert all(r['status'] == 'cancelled' for r in results['results'])


def test_insufficient_budget_and_failed_transport_retire_only_owned_grants(tmp_path):
    sent = []
    ctx = setup_imported_workflow(tmp_path, lambda req: sent.append(req) or httpx.Response(503))
    mismatched_budget = selection(ctx, count=30) | {'total_request_budget': 1}
    preview = post(ctx[0], 'batches/preview', mismatched_budget, ctx[1])
    assert preview.status_code == 200
    assert preview.json['ready_count'] == 0
    assert all(item['reason'] == 'imported_request_budget_invalid' for item in preview.json['items'])
    rejected = post(ctx[0], 'batches', mismatched_budget | {
        'expected_plan_id': preview.json['plan_id'],
        'submission_id': uuid4().hex,
        'authorization_confirmed': True,
    }, ctx[1])
    assert rejected.status_code == 409
    assert sent == [] and ctx[3].policy.grants == []

    foreign_grant = ExecutionGrant(
        authorization_id='foreign-' + uuid4().hex,
        target_id=ctx[5]['target_id'],
        profile_revision=ctx[5]['profile_revision'],
        policy_ref=ctx[5]['policy_ref'],
        testcase_id='FOREIGN-CASE',
        asset_sha256='0' * 64,
        scope='security_test_execution',
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    ctx[3].policy = ctx[3].policy.model_copy(update={'grants': [foreign_grant]})
    identity, _ = launch(ctx, selection(ctx, count=1))
    status, results = finish(ctx, identity)
    assert len(sent) == status['target_request_count'] == 1
    assert results['results'][0]['verdict'] == 'ERROR'
    assert ctx[3].policy.grants == [foreign_grant]


def test_consumed_grant_cannot_be_replayed_even_if_reinserted(tmp_path):
    from workflow.offline_batch import OfflineBatchSelection
    from workflow.batch import BatchCase, BatchRejected
    ctx = setup_imported_workflow(tmp_path, lambda req: response())
    selected = selection(ctx)
    identity, _ = launch(ctx, selected)
    _, results = finish(ctx, identity)
    case = BatchCase(**results['snapshot']['cases'][0])
    auth_id = next(ctx[2].root.glob('grant-*')).name.removeprefix('grant-')
    grant = ExecutionGrant(authorization_id=auth_id, target_id=ctx[5]['target_id'],
        profile_revision=ctx[5]['profile_revision'], policy_ref=ctx[5]['policy_ref'], testcase_id=case.testcase_id,
        asset_sha256=case.asset_sha256, scope='security_test_execution', expires_at=datetime.now(timezone.utc)+timedelta(minutes=1))
    ctx[3].policy = ctx[3].policy.model_copy(update={'grants': [grant]})
    ctx[2]._owned_grants.add(auth_id)
    with pytest.raises(BatchRejected):
        ctx[2]._run_case(OfflineBatchSelection.model_validate(selected), case, uuid4().hex, lambda _: None)


def test_linked_dataset_listing_is_rejected(tmp_path):
    import subprocess
    repo = DatasetRepository(tmp_path / 'safe')
    external = tmp_path / 'external'; external.mkdir()
    # Directory junction creation needs no symlink privilege on Windows.
    if __import__('os').name == 'nt':
        linked = tmp_path / 'junction'
        subprocess.run(['cmd', '/c', 'mklink', '/J', str(linked), str(external)], check=True, capture_output=True)
        with pytest.raises(ValueError):
            DatasetRepository(linked)
    else:
        linked = tmp_path / 'junction'; linked.symlink_to(external, target_is_directory=True)
        with pytest.raises(ValueError):
            DatasetRepository(linked)


def test_malformed_and_untrusted_imports_fail_without_dispatch(tmp_path):
    ctx = setup_imported_workflow(tmp_path, lambda req: pytest.fail('import must not dispatch'))
    for raw in [b'{', b'[]', b'42', b'[{"id":"x","prompt":"a","prompt":"b"}]',
                b'[{"prompt":"x","metadata":{"n":NaN}}]',
                b'[{"prompt":"x","metadata":{"__proto__":{}}}]',
                json.dumps([{'prompt': 'a'*65537}]).encode(),
                b'[' * 1000 + b'0' + b']' * 1000,
                b' ' * (5*1024*1024+1)]:
        result = ctx[0].post('/api/testing/datasets/validate', base_url=BASE, data=raw,
            content_type='application/json', headers=ctx[1])
        assert result.status_code >= 400
    assert ctx[0].post('/api/testing/datasets/import', base_url=BASE, data=b'[{"prompt":"x"}]',
        content_type='application/json', headers={'Origin':BASE}).status_code == 403


@pytest.mark.parametrize('artifact', ['native', 'batch', 'aggregate'])
def test_tampered_report_and_batch_are_not_silently_trusted(tmp_path, artifact):
    ctx = setup_imported_workflow(tmp_path, lambda req: response())
    identity, _ = launch(ctx, selection(ctx))
    _, results = finish(ctx, identity)
    if artifact == 'native':
        path = next((ctx[3].output_root / results['results'][0]['report_run_id']).glob('*.secagent.json'))
        value = json.loads(path.read_bytes()); value['evaluation']['final_verdict'] = 'PASS'
    elif artifact == 'batch':
        path = ctx[2].root / identity / 'state.json'
        value = json.loads(path.read_bytes()); value['results'][0]['request_count'] = 0
    else:
        path = ctx[2].root / identity / 'batch-report.json'
        value = json.loads(path.read_bytes()); value['target_request_count'] = 0
    path.write_text(json.dumps(value), encoding='utf-8')
    assert get(ctx[0], f'batches/{identity}/results', ctx[1]).status_code >= 400


def test_reference_sources_match_exactly_and_wrong_yaml_does_not(tmp_path):
    import yaml
    raw = CODEBOT_JSON.read_bytes()
    cases = json.loads(raw)['testcases']
    matching = yaml.safe_load(REDTEAM_YAML.read_bytes())['tests']
    # Deliberately mismatched synthetic input, not another external research file.
    wrong_yaml = tmp_path / 'unrelated.synthetic.yaml'
    wrong_yaml.write_text(yaml.safe_dump({'tests': [
        {'vars': {'prompt': f'Unrelated synthetic fixture {index:02d}'}}
        for index in range(30)
    ]}), encoding='utf-8')
    different = yaml.safe_load(wrong_yaml.read_bytes())['tests']
    assert len(cases) == len(matching) == 30
    # Pin the reviewed synthetic fixture bytes; the original digest is in its README.
    assert sha256(raw).hexdigest() == 'bbc333ae9bc2d503c0da3ce2b52ebf9717d171f2f0824ae6f7baec6cc06423a9'
    for source, reference in zip(cases, matching):
        assert source['vars']['prompt'] == reference['vars']['prompt']
        assert source['assertions'] == reference['assert']
    assert not {c['vars']['prompt'] for c in cases} & {c['vars']['prompt'] for c in different}
