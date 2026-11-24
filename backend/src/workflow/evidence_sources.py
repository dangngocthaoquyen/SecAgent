"""Operator-configured HTTP snapshots, isolated from evaluation and native reports.

An HTTP receipt authenticates neither a tool invocation nor agent-run completeness.
All source event content is untrusted, local-only, and action-ineligible in v1.
"""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
from threading import RLock
from time import monotonic
from typing import Literal
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from pydantic import Field, field_validator, model_validator

from reporting.artifacts import ArchiveReader, _json, _no_links
from reporting.redaction import Redactor
from workflow.batch import _write_atomic
from workflow.models import ClosedModel

ID = r'^[a-f0-9]{32}$'
HASH = r'^[a-f0-9]{64}$'
NAME = r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$'
Semantics = Literal['detector_reported', 'declared_tool_call', 'tool_handler_invoked',
                    'simulated_execution', 'runtime_execution_verified']


class EvidenceSourceError(ValueError):
    """Fixed public error codes only; never embed response data or credentials."""


def validate_endpoint(value: str) -> str:
    try:
        parts = urlsplit(value)
        host = ipaddress.ip_address(parts.hostname or '')
        if (parts.scheme not in {'http', 'https'} or not host.is_loopback
                or parts.username or parts.password or parts.query or parts.fragment
                or not parts.path.startswith('/') or any(c in value for c in '%\\?#')
                or any(c.isspace() or ord(c) < 32 for c in value)
                or any(p in {'.', '..'} for p in parts.path.split('/'))
                or parts.port == 0 or host.is_unspecified
                or value != value.strip()):
            raise ValueError()
    except ValueError:
        raise EvidenceSourceError('unsafe_evidence_endpoint') from None
    return value


class AllowedEndpoint(ClosedModel):
    url: str = Field(max_length=512)
    credential_ref: str | None = Field(default=None, pattern=NAME)
    _endpoint = field_validator('url')(validate_endpoint)


class EvidenceNetworkPolicy(ClosedModel):
    schema_version: Literal['1.0.0'] = '1.0.0'
    allowed_endpoints: list[AllowedEndpoint] = Field(default_factory=list, max_length=100)
    credential_env: dict[str, str] = Field(default_factory=dict, max_length=20)

    @model_validator(mode='after')
    def references(self):
        if len({p.url for p in self.allowed_endpoints}) != len(self.allowed_endpoints):
            raise ValueError('Duplicate endpoint')
        for key, name in self.credential_env.items():
            if not re.fullmatch(NAME, key) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', name):
                raise ValueError('Invalid credential reference')
        if any(p.credential_ref and p.credential_ref not in self.credential_env for p in self.allowed_endpoints):
            raise ValueError('Unknown credential reference')
        return self


class EventMapping(ClosedModel):
    items: str = ''  # Empty means the response itself must be an array.
    event_id: str | None = None
    request_id: str | None = None
    correlation_id: str | None = None
    invocation_id: str | None = None
    timestamp: str | None = None
    tool: str | None = None
    content: str | None = None

    @field_validator('*')
    @classmethod
    def safe_path(cls, value):
        if value is not None and value != '' and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}(?:\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}', value):
            raise ValueError('Use bounded dotted object keys')
        return value


class EvidenceSourceDraft(ClosedModel):
    name: str = Field(min_length=1, max_length=80)
    target_id: str = Field(pattern=NAME)
    target_revision: str = Field(pattern=HASH)
    source_type: Literal['http_json'] = 'http_json'
    endpoint: str = Field(max_length=512)
    credential_ref: str | None = Field(default=None, pattern=NAME)
    collection_mode: Literal['snapshot'] = 'snapshot'
    mapping: EventMapping = Field(default_factory=EventMapping)
    semantics: Semantics = 'detector_reported'
    timeout_seconds: int = Field(default=5, ge=1, le=10)
    max_response_bytes: int = Field(default=65536, ge=256, le=262144)
    max_events: int = Field(default=200, ge=1, le=500)
    enabled: bool = True
    _endpoint = field_validator('endpoint')(validate_endpoint)


class EvidenceSourceProfile(EvidenceSourceDraft):
    schema_version: Literal['1.0.0'] = '1.0.0'
    id: str = Field(pattern=ID)
    revision: str = Field(pattern=HASH)


class SaveEvidenceSource(ClosedModel):
    profile: EvidenceSourceDraft
    source_id: str | None = Field(default=None, pattern=ID)
    expected_revision: str | None = Field(default=None, pattern=HASH)


class CollectEvidenceSource(ClosedModel):
    source_id: str = Field(pattern=ID)
    expected_revision: str = Field(pattern=HASH)
    authorization_confirmed: bool = False


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def _revision_payload(row: dict) -> dict:
    """Canonical revision material preserving legacy pre-G08 hashes when optional mapping.correlation_id is None."""
    payload = {k: v for k, v in row.items() if k != 'revision'}
    mapping = payload.get('mapping')
    if isinstance(mapping, dict) and mapping.get('correlation_id') is None:
        payload['mapping'] = {k: v for k, v in mapping.items() if k != 'correlation_id'}
    return payload


def pick(row, path):
    if not path:
        return None
    for key in path.split('.'):
        if not isinstance(row, dict) or key not in row:
            return None
        row = row[key]
    return row


def validate_document(document):
    """Bound JSON nesting and reject overflowed numeric literals as well as NaN."""
    pending = [(document, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > 32 or isinstance(value, float) and not math.isfinite(value):
            raise EvidenceSourceError('invalid_event_schema')
        if isinstance(value, dict):
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)


class EvidenceSourceStore:
    def __init__(self, catalog, *, policy=None, transport=None):
        self.catalog = catalog
        self.policy = policy or EvidenceNetworkPolicy()
        self.transport = transport
        self.lock = RLock()
        self.root = catalog.data_dir / 'evidence-sources-v1'
        _no_links(self.root)
        for directory in (self.root, self.root / 'profiles', self.root / 'revisions', self.root / 'captures'):
            _no_links(directory)
            directory.mkdir(exist_ok=True, mode=0o700)
        self.reader = ArchiveReader(self.root)

    def _write(self, relative, record):
        _write_atomic(self.reader.path(relative), record)

    def _read(self, relative):
        raw = self.reader.read(self.reader.path(relative), limit=4*1024*1024)
        if raw is None:
            raise EvidenceSourceError('evidence_record_unavailable')
        return _json(raw)

    def _target(self, draft):
        row = next((t for t in self.catalog.public_targets() if t['id'] == draft.target_id), None)
        if row is None or row['profile_revision'] != draft.target_revision:
            raise EvidenceSourceError('evidence_target_stale')

    def _allowed(self, draft):
        if not any(p.url == draft.endpoint and p.credential_ref == draft.credential_ref for p in self.policy.allowed_endpoints):
            raise EvidenceSourceError('evidence_endpoint_not_allowed')

    def get(self, source_id):
        if not re.fullmatch(ID, source_id):
            raise EvidenceSourceError('invalid_source_id')
        row = EvidenceSourceProfile.model_validate(self._read(f'profiles/{source_id}.json'))
        if digest(_revision_payload(row.model_dump(exclude={'revision'}))) != row.revision:
            raise EvidenceSourceError('source_integrity_failed')
        return row

    def list(self, target_id):
        with self.lock:
            result = []
            for path in sorted(self.reader.path('profiles').glob('*.json')):
                row = self.get(path.stem)
                if row.target_id != target_id:
                    continue
                summary = row.model_dump() | {'availability':'not_checked', 'correlation_status':'uncorrelated',
                    'action_eligible':False, 'latest_capture_id':None, 'last_checked_at':None}
                status_path = f'{row.id}-{row.revision}-status.json'
                if self.reader.path(status_path).exists():
                    capture = self.capture(self._read(status_path)['capture_id'])
                    if capture['source_revision'] != row.revision or capture['source_id'] != row.id:
                        raise EvidenceSourceError('capture_integrity_failed')
                    summary.update(availability=capture['availability'], latest_capture_id=capture['id'],
                                   last_checked_at=capture['collected_at'], collection_error=capture['error'])
                try:
                    self._target(row)
                    self._allowed(row)
                    summary['configuration_status'] = 'configured' if row.enabled else 'disabled'
                except EvidenceSourceError as exc:
                    summary['configuration_status'] = str(exc)
                    summary['availability'] = 'not_checked'
                result.append(summary)
            return result

    def save(self, draft, source_id=None, expected_revision=None):
        with self.catalog._lock, self.lock:
            self._target(draft)
            self._allowed(draft)
            if source_id:
                previous = self.get(source_id)
                if previous.revision != expected_revision or previous.target_id != draft.target_id:
                    raise EvidenceSourceError('evidence_source_stale')
            elif expected_revision is not None:
                raise EvidenceSourceError('evidence_source_stale')
            elif len(list(self.reader.path('profiles').glob('*.json'))) >= 200:
                raise EvidenceSourceError('source_quota_exceeded')
            source_id = source_id or uuid4().hex
            row = draft.model_dump() | {'schema_version':'1.0.0', 'id':source_id}
            row['revision'] = digest(_revision_payload(row))
            record = EvidenceSourceProfile.model_validate(row).model_dump()
            self._write(f'revisions/{source_id}-{row["revision"]}.json', record)
            self._write(f'profiles/{source_id}.json', record)
            return record

    def capture(self, capture_id):
        if not re.fullmatch(ID, capture_id):
            raise EvidenceSourceError('invalid_capture_id')
        record = self._read(f'captures/{capture_id}.json')
        if record.get('capture_sha256') != digest({k:v for k,v in record.items() if k != 'capture_sha256'}):
            raise EvidenceSourceError('capture_integrity_failed')
        return record

    def collect(self, source_id, revision, authorization_confirmed):
        with self.catalog._lock, self.lock:
            if authorization_confirmed is not True:
                raise EvidenceSourceError('evidence_authorization_required')
            source = self.get(source_id)
            if source.revision != revision or not source.enabled:
                raise EvidenceSourceError('evidence_source_stale')
            self._target(source)
            self._allowed(source)
            if len(list(self.reader.path('captures').glob('*.json'))) >= 1000:
                raise EvidenceSourceError('capture_quota_exceeded')
            credential = os.environ.get(self.policy.credential_env[source.credential_ref], '') if source.credential_ref else ''
            if source.credential_ref and (not credential or not credential.isascii() or any(c.isspace() for c in credential)):
                raise EvidenceSourceError('evidence_credential_unavailable')
            capture = dict(schema_version='1.0.0', id=uuid4().hex, source_id=source.id,
                source_revision=source.revision, target_id=source.target_id, target_revision=source.target_revision,
                network_policy_sha256=digest(self.policy.model_dump()),
                collected_at=datetime.now(timezone.utc).isoformat(), collection_mode='snapshot',
                execution_scope='operator_source_snapshot', provenance='http_json_collector_v1',
                trust='target_reported_unverified', correlation_status='uncorrelated',
                correlation_reason='no_trusted_agent_run_binding', complete_agent_trace=False,
                action_eligible=False, external_judge_disclosure='forbidden', availability='unavailable',
                error=None, events=[], duplicate_count=0, conflicting_event_ids=0,
                request_count=0, response_bytes=0)
            try:
                headers = {'Accept':'application/json', 'Accept-Encoding':'identity'}
                if credential:
                    headers['Authorization'] = 'Bearer ' + credential
                started = monotonic()
                with httpx.Client(transport=self.transport, trust_env=False, follow_redirects=False,
                                  timeout=source.timeout_seconds) as client:
                    capture['request_count'] = 1
                    with client.stream('GET', source.endpoint, headers=headers) as response:
                        if 300 <= response.status_code < 400:
                            raise EvidenceSourceError('redirect_rejected')
                        if response.status_code != 200:
                            raise EvidenceSourceError('http_unavailable')
                        if response.headers.get('content-encoding', 'identity') != 'identity':
                            raise EvidenceSourceError('encoded_response_rejected')
                        if response.headers.get('content-type', '').split(';')[0].strip() not in {'application/json', ''}:
                            raise EvidenceSourceError('json_content_type_required')
                        body = bytearray()
                        for chunk in response.iter_bytes():
                            if monotonic() - started > source.timeout_seconds:
                                raise EvidenceSourceError('timeout')
                            if len(body) + len(chunk) > source.max_response_bytes:
                                raise EvidenceSourceError('response_too_large')
                            body.extend(chunk)
                        capture['response_bytes'] = len(body)
                try:
                    document = _json(bytes(body))
                except (ValueError, UnicodeError, RecursionError):
                    raise EvidenceSourceError('malformed_json') from None
                validate_document(document)
                rows = pick(document, source.mapping.items) if source.mapping.items else document
                if not isinstance(rows, list) or len(rows) > source.max_events or any(not isinstance(r, dict) for r in rows):
                    raise EvidenceSourceError('invalid_event_schema')
                # Exact registered secrets and common credential formats are removed.
                # No raw response body, arbitrary nested payload, or headers are persisted.
                redactor = Redactor(values=[os.environ.get(n,'') for n in self.policy.credential_env.values()])
                events, seen, event_ids = [], set(), {}
                for row in rows:
                    event_hash = digest(row)
                    if event_hash in seen:
                        capture['duplicate_count'] += 1
                        continue
                    seen.add(event_hash)
                    event = dict(record_sha256=event_hash, reported_semantics=source.semantics,
                        source_id=source.id, source_revision=source.revision,
                        target_id=source.target_id, target_revision=source.target_revision,
                        provenance='http_json_collector_v1', execution_scope='operator_source_snapshot',
                        trust='target_reported_unverified', correlation_status='uncorrelated', action_eligible=False)
                    for field in ('event_id', 'request_id', 'invocation_id', 'timestamp', 'tool', 'content'):
                        value = pick(row, getattr(source.mapping, field))
                        if value is not None and not isinstance(value, (str, int, float, bool)):
                            raise EvidenceSourceError('invalid_event_schema')
                        if field.endswith('_id'):
                            event['reported_'+field+'_sha256'] = digest(str(value)) if value is not None else None
                        else:
                            text = redactor.clean(str(value), limit=source.max_response_bytes) if value is not None else None
                            if text is not None:
                                text = re.sub(r'\b[^\s@]+@[^\s@]+\.[^\s@]+', '[EMAIL_REDACTED]', text)
                            event[field] = text[:1024] if text is not None else None
                            event[field+'_truncated'] = text is not None and len(text)>1024
                    reported_id = event['reported_event_id_sha256']
                    if reported_id and reported_id in event_ids and event_ids[reported_id] != event_hash:
                        capture['conflicting_event_ids'] += 1
                    if reported_id:
                        event_ids[reported_id] = event_hash
                    events.append(event)
                capture.update(availability='available', events=events)
            except EvidenceSourceError as exc:
                capture['error'] = str(exc)
            except httpx.TimeoutException:
                capture['error'] = 'timeout'
            except (httpx.HTTPError, OSError):
                capture['error'] = 'source_unavailable'
            capture['capture_sha256'] = digest(capture)
            self._write(f'captures/{capture["id"]}.json', capture)
            self._write(f'{source.id}-{source.revision}-status.json', {'capture_id':capture['id']})
            return capture


def load_evidence_policy(path: Path):
    try:
        reader = ArchiveReader(path.absolute().parent)
        raw = reader.read(reader.path(path.absolute(), absolute=True), limit=65536)
        if raw is None:
            raise EvidenceSourceError('evidence_policy_unavailable')
        return EvidenceNetworkPolicy.model_validate(_json(raw))
    except (ValueError, OSError, TypeError, RecursionError):
        # Startup handlers print exception messages. Never expose Pydantic's
        # input-value diagnostics if an operator mistakenly pasted a secret.
        raise EvidenceSourceError('invalid_or_unavailable_evidence_policy') from None
