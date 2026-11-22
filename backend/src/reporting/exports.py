"""Read-only downloads from the existing normalized reporting boundary."""
from collections import Counter
import csv
import hashlib
import io
import json
import re
import zipfile

from reporting.artifacts import _json
from reporting.redaction import Redactor
from reporting.repository import (ControlledRunInvalid, ControlledRunMissing,
    MAX_DATASET_BYTES, _local_root, load_controlled_run_with_count)

VERSION = '1.0.0'
LIMITATIONS = [
    'Sanitized reporting projection only; not a byte-for-byte raw report archive.',
    'Original prompts are not exposed by this reporting contract and are not exported.',
    'Response previews and citations retain reporting redaction and length limits; citations are not revalidated.',
    'Recorded verdicts and Judge recommendations are preserved, not recomputed or human ground truth.',
    'No independent runtime verification or external evidence captures are added.',
    'Export artifact hashes cover exported bytes; source report hashes refer to original stored bytes.',
]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def safe(value, public):
    """Apply existing path filtering and credential redaction, preserving digests."""
    if isinstance(value, dict):
        return {key: safe(item, public) for key, item in value.items()
                if key.lower() not in {'authorization', 'headers', 'api_key', 'password', 'secret',
                                       'access_token', 'refresh_token', 'credentials', 'credential_env'}}
    if isinstance(value, list):
        return [safe(item, public) for item in value]
    if isinstance(value, str):
        return public(Redactor().clean(value, opaque=False, limit=max(4096, len(value)*8)))
    return value


def report_document(record, request_count, public, detail, run_id=None):
    execution = detail(record, [])
    execution.pop('linked_archived_assessments', None)
    return safe(dict(export_schema_version=VERSION, representation='sanitized_reporting_projection',
        run_id=run_id, target_request_count=request_count,
        original_prompt=None, original_prompt_export_status='not_exposed_by_reporting_contract',
        execution=execution, export_limitations=LIMITATIONS), public)


def filename_part(value, fallback='report'):
    if (isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', value)
            and not re.fullmatch(r'(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])', value)):
        return value
    return fallback


def csv_cell(value):
    text = '' if value is None else str(value)
    # Spreadsheet programs must not execute formulas from adversarial content.
    return "'"+text if text.lstrip().startswith(('=', '+', '-', '@')) or text.startswith(('\t','\r','\n')) else text


def batch_download(dataset, batch_id, public, detail):
    if dataset.controlled_runs_root is None or not re.fullmatch(r'[a-f0-9]{32}', batch_id):
        raise ControlledRunMissing('Batch unavailable.')
    try:
        reader = _local_root(dataset.controlled_runs_root)
        path = reader.path(f'batch-runs/{batch_id}/state.json')
        raw_state = reader.read(path)
        if raw_state is None:
            raise ControlledRunMissing('Batch unavailable.')
        state = _json(raw_state)
        snapshot = state['snapshot']
        if (state['batch_run_id'] != batch_id or state.get('schema_version') != '1.0.0'
                or sha(canonical(snapshot)) != state['snapshot_sha256']
                or state['status'] not in {'completed', 'partially_completed', 'cancelled', 'failed', 'interrupted'}):
            raise ValueError()
        cases, results = snapshot['cases'], state['results']
        if (not isinstance(cases, list) or not 1 <= len(cases) <= 128
                or type(state['total']) is not int or state['total'] != len(cases)
                or not isinstance(results, list) or len(results) > len(cases)):
            raise ValueError()
        case_ids = [c['testcase_id'] for c in cases]
        result_ids = [r['testcase_id'] for r in results]
        if (len(set(case_ids)) != len(case_ids) or len(set(result_ids)) != len(result_ids)
                or not set(result_ids).issubset(case_ids)
                or state['status'] == 'completed' and len(results) != len(cases)):
            raise ValueError()
        by_case = {r['testcase_id']:r for r in results}
        imported = snapshot.get('imported_provenance') or {}
        mapped_cases = {c['internal_id']:c for c in imported.get('cases', [])}
        if imported and (len(mapped_cases) != len(cases) or set(mapped_cases) != set(case_ids)):
            raise ValueError()
        documents, csv_rows, artifact_meta, seen_runs, seen_paths = {}, [], [], set(), set()
        verdicts = Counter({v:0 for v in ('PASS','FAIL','INCONCLUSIVE','ERROR','unknown')})
        statuses, completeness, invocations = Counter(), Counter(), Counter()
        scopes, policies, modes = set(), set(), set()
        semantic_true = provider_true = semantic_unknown = provider_unknown = 0
        known_requests = 0
        unknown_requests = 0
        for index, case in enumerate(cases):
            internal_id = case['testcase_id']
            row = by_case.get(internal_id, {})
            run_id = row.get('report_run_id')
            record = None
            count = row.get('request_count')
            if count is not None and (type(count) is not int or count < 0):
                raise ValueError()
            if run_id is not None:
                if run_id in seen_runs:
                    raise ValueError()
                seen_runs.add(run_id)
                record, report_count = load_controlled_run_with_count(dataset, run_id)
                p = record.imported_provenance
                if (record.source.file_byte_sha256 != row.get('report_sha256')
                        or (p.internal_testcase_id if p else record.identity.testcase_id) != internal_id
                        or record.identity.target_id != snapshot['target_id']
                        or report_count != count
                        or record.security.historical_status != row.get('verdict')):
                    raise ValueError()
                if imported:
                    if (p is None or p.batch_run_id != batch_id or p.batch_execution_id != row.get('execution_id')
                            or p.dataset_id != imported.get('dataset_id')
                            or p.dataset_revision_sha256 != imported.get('dataset_revision_sha256')
                            or p.target_profile_revision_sha256 != snapshot.get('profile_revision')
                            or p.target_profile_id != snapshot['target_id']
                            or p.source_testcase_id != mapped_cases[internal_id]['source_testcase_id']
                            or p.prompt_sha256 != case.get('input_sha256')
                            or p.prompt_sha256 != mapped_cases[internal_id]['prompt_sha256']
                            or p.evaluation_mode != snapshot.get('evaluation_mode')):
                        raise ValueError()
                    for prefix in ('asi03', 'asi05'):
                        for suffix in ('policy_id', 'policy_revision_sha256'):
                            key = prefix+'_'+suffix
                            if getattr(p,key) != imported.get(key):
                                raise ValueError()
                elif p is not None:
                    raise ValueError()
                elif record.execution_id != Redactor().identifier(row.get('execution_id'), limit=256):
                    raise ValueError()
                document = report_document(record, count, public, detail, run_id)
                judge = record.judge
                invocations[judge.invocation_state] += 1
                semantic_true += judge.reported_semantic_invoked is True
                provider_true += judge.reported_provider_invoked is True
                semantic_unknown += judge.reported_semantic_invoked is None
                provider_unknown += judge.reported_provider_invoked is None
                completeness[record.observation.response_completeness.state] += 1
                scope = p.evaluation_scope if p else None
                if scope: scopes.add(scope)
                if p:
                    modes.add(p.evaluation_mode)
                    for prefix in ('asi03','asi05'):
                        identity, revision = getattr(p,prefix+'_policy_id'), getattr(p,prefix+'_policy_revision_sha256')
                        if identity: policies.add((prefix,identity,revision))
                final = record.security.historical_status
                deterministic = record.deterministic.effective or record.deterministic.original
                csv_row = dict(deterministic_verdict=deterministic.status if deterministic else None,
                    judge_classification=judge.classification, judge_recommendation=judge.recommendation,
                    final_verdict=final, evaluation_scope=scope,
                    evidence_completeness=record.observation.response_completeness.state,
                    citation_status='recorded_not_revalidated' if judge.citations else 'none_recorded',
                    reason=record.security.reason)
            else:
                if row.get('report_sha256') is not None or row.get('verdict') is not None:
                    raise ValueError()
                if row.get('status') == 'completed':
                    raise ValueError()
                final = None
                document = dict(export_schema_version=VERSION, report_available=False,
                    internal_testcase_id=internal_id, execution_status=row.get('status'),
                    reason=row.get('reason'), export_limitations=LIMITATIONS)
                csv_row = dict(deterministic_verdict=None, judge_classification=None, judge_recommendation=None,
                    final_verdict=None, evaluation_scope=None, evidence_completeness='unknown',
                    citation_status='report_unavailable', reason=row.get('reason'))
            if count is None: unknown_requests += 1
            else: known_requests += count
            verdicts[final or 'unknown'] += 1
            statuses[row.get('status') or 'not_recorded'] += 1
            source_case = mapped_cases.get(internal_id, {}).get('source_testcase_id', internal_id)
            label = safe(source_case, public)
            stem = filename_part(label, f'case-{index+1:04d}')
            member = 'reports/'+stem+'.json'
            if member.lower() in seen_paths:
                member = f'reports/case-{index+1:04d}-{sha(internal_id.encode())[:12]}.json'
            if member.lower() in seen_paths: raise ValueError()
            seen_paths.add(member.lower())
            documents[member] = canonical(safe(document, public))
            artifact_meta.append(dict(path=member, case_id=label, internal_testcase_id=safe(internal_id,public),
                source_report_sha256=record.source.file_byte_sha256 if record else None))
            csv_rows.append(safe(dict(case_id=label, asi=case.get('asi_category'),
                execution_status=row.get('status'), **csv_row), public))
            if sum(map(len, documents.values())) > MAX_DATASET_BYTES:
                raise ValueError()
        recorded_count = state.get('target_request_count')
        if type(recorded_count) is not int or recorded_count < 0 or recorded_count != known_requests:
            raise ValueError()
        summary = dict(export_schema_version=VERSION, batch_id=batch_id, batch_status=state['status'],
            total_cases=len(cases), reports_available=len(seen_runs), verdict_counts=dict(verdicts),
            execution_status_counts=dict(statuses), target_request_count=recorded_count,
            request_count_unknown=state.get('request_count_unknown'), cases_with_unknown_request_count=unknown_requests,
            evaluation_mode=snapshot.get('evaluation_mode'), recorded_case_evaluation_modes=sorted(modes),
            evaluation_scopes=sorted(scopes), evidence_completeness_counts=dict(completeness),
            evidence_availability=dict(reports_with_response_preview=sum(
                bool(_json(raw).get('execution',{}).get('observation',{}).get('response_preview'))
                for raw in documents.values()), external_captures_included=0),
            judge=dict(reported_semantic_invoked_true=semantic_true,reported_provider_invoked_true=provider_true,
                semantic_invocation_unknown=semantic_unknown,provider_invocation_unknown=provider_unknown,
                invocation_states=dict(invocations),independent_provider_verification=False),
            limitations=LIMITATIONS)
        documents['summary.json'] = canonical(safe(summary, public))
        csv_buffer = io.StringIO(newline='')
        writer = csv.DictWriter(csv_buffer,fieldnames=['case_id','asi','execution_status','deterministic_verdict',
            'judge_classification','judge_recommendation','final_verdict','evaluation_scope','evidence_completeness','citation_status','reason'])
        writer.writeheader()
        writer.writerows({k:csv_cell(v) for k,v in row.items()} for row in csv_rows)
        documents['results.csv'] = csv_buffer.getvalue().encode('utf-8-sig')
        extra = {a['path']:a for a in artifact_meta}
        terminal_times = [e.get('at') for e in state.get('events',[]) if e.get('stage')=='terminal']
        manifest = safe(dict(export_schema_version=VERSION,batch_id=batch_id,
            dataset_id=imported.get('dataset_id'),dataset_revision_sha256=imported.get('dataset_revision_sha256'),
            target_id=snapshot.get('target_id'),target_profile_revision=snapshot.get('profile_revision'),
            evaluation_mode=snapshot.get('evaluation_mode'),evaluation_scopes=sorted(scopes),
            policies=[dict(category=p[0],policy_id=p[1],revision_sha256=p[2]) for p in sorted(policies)],
            total_cases=len(cases),created_at=state.get('created_at'),completed_at=terminal_times[-1] if terminal_times else None,
            batch_state_file_sha256=sha(raw_state),batch_snapshot_sha256=state['snapshot_sha256'],
            representation='sanitized_reporting_projection',limitations=LIMITATIONS), public)
        manifest['artifacts'] = [dict(**extra.get(name,{'path':name}),sha256=sha(raw),size_bytes=len(raw))
                                 for name,raw in sorted(documents.items())]
        manifest['manifest_self_hash'] = 'excluded_to_avoid_circular_hash'
        documents['manifest.json'] = canonical(manifest)
        if reader.read(path) != raw_state or sum(map(len,documents.values())) > MAX_DATASET_BYTES:
            raise ValueError()
        output = io.BytesIO()
        with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED) as archive:
            for name,raw in sorted(documents.items()):
                archive.writestr(name,raw)
        categories = sorted({c.get('asi_category') for c in cases if c.get('asi_category')})
        category = categories[0].lower() if len(categories)==1 else 'batch'
        target = filename_part(safe(snapshot.get('target_id'),public),'target')
        return output.getvalue(), f'secagent-{filename_part(category)}-{target}-{batch_id}.zip'
    except ControlledRunMissing:
        raise
    except (ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError):
        raise ControlledRunInvalid('Batch export failed integrity or schema validation.') from None
