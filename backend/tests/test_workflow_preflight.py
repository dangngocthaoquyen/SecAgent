"""No verified safe probe: every decision must leave the network untouched."""
import socket
import pytest
from pydantic import ValidationError
from test_workflow_targets import setup, config
from workflow.models import CatalogConfig, ConnectionCheckResult


@pytest.fixture(autouse=True)
def forbidden_operations(monkeypatch):
    import httpx
    from testing.executor import Executor
    from integrations.external_evaluator.pi import PiEvaluatorProvider
    def forbidden(*args, **kwargs):
        raise AssertionError("Preflight must not execute or access network")
    for cls, method in [(httpx.Client, "request"), (httpx.Client, "send"),
                        (Executor, "execute"), (PiEvaluatorProvider, "evaluate"),
                        (socket, "create_connection"), (socket, "getaddrinfo")]:
        monkeypatch.setattr(cls, method, forbidden)


def check(raw=None, changes=None):
    client, draft, headers = setup(raw)
    selection = {k: draft[k] for k in ("target_id", "profile_revision", "policy_ref")}
    selection.update(changes or {})
    return client.post('/api/testing/connection-checks', base_url=headers['Origin'],
                       json=selection, headers=headers)


def test_review_required_and_offline_review_are_not_probe_authorization():
    raw = config(); raw['targets'][0]['reviewed'] = False
    response = check(raw)
    assert response.status_code == 403
    assert response.json['connection_status'] == 'requires_approval'
    response = check()
    assert response.status_code == 200
    result = ConnectionCheckResult.model_validate(response.json)
    assert result.connection_status == 'unsupported'
    assert result.target_request_count == 0
    assert result.connection_reachable is None and result.runtime_protocol_compatible is None
    assert result.security_verdict is None and not result.security_test_executed


@pytest.mark.parametrize('changes,status', [({'target_id':'unknown'},404),
    ({'profile_revision':'b'*64},409), ({'policy_ref':'other'},409)])
def test_selection_integrity(changes,status):
    assert check(changes=changes).status_code == status


@pytest.mark.parametrize('field,value', [
    ('url','http://169.254.169.254/latest'), ('url','http://[::1]/health'),
    ('url','http://127.0.0.1:7015/v1/chat/completions'), ('path','/../admin'),
    ('method','POST'), ('headers',{'Authorization':'secret'}), ('body',{'messages':[]}),
    ('follow_redirects',True), ('proxy','http://localhost:8888'), ('host','untrusted.example'),
    ('active_probe_authorized',True), ('security_execution_authorized',True),
    ('protocol','mcp-jsonrpc'), ('protocol','a2a'), ('timeout_seconds',999),
    ('max_requests',999), ('response_size',999999)])
def test_browser_cannot_define_probe(field,value):
    response=check(changes={field:value})
    assert response.status_code == 400
    assert 'secret' not in response.get_data(as_text=True)


@pytest.mark.parametrize('field', ['active_probe_authorized','security_execution_authorized','probe'])
def test_unimplemented_operator_permissions_cannot_be_enabled(field):
    raw=config(); raw['targets'][0][field]=True
    with pytest.raises(ValidationError): CatalogConfig.model_validate(raw)


def test_repeated_requests_never_allocate_network_budget():
    for _ in range(12): assert check().json['target_request_count'] == 0


def test_preflight_requires_same_csrf_boundary():
    client,draft,headers=setup()
    data={k:draft[k] for k in ('target_id','profile_revision','policy_ref')}
    for h in ({}, {'Origin':'https://untrusted.example'}, {'Origin':headers['Origin']}):
        assert client.post('/api/testing/connection-checks',base_url=headers['Origin'],json=data,headers=h).status_code==403
    public=client.get('/api/testing/targets',base_url=headers['Origin']).json['targets'][0]
    assert public['connection_probe']==dict(status='unsupported',reason='safe_probe_not_verified',active_probe_authorized=False,security_execution_authorized=False)
