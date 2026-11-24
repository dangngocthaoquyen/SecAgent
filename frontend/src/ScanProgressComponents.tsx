import { useEffect, useState } from 'react';
import { safeLabel } from './api';
import {
  computeVerdictCounts,
  deriveRunAsiSummary,
  formatCaseAsiCategory,
  formatDateTime,
  formatDurationBetween,
  formatEvidenceLevel,
  normalizeVerdict,
  verdictBadgeClass,
} from './scanFormatters';
import type { GenericCaseStatus, GenericRunEvent, GenericRunRecord } from './testingApi';

const readableStage = (stage: string | null | undefined) => {
  if (!stage) return 'Queued';
  const map: Record<string, string> = {
    preparing: 'Preparing',
    queued: 'Queued',
    run_started: 'Run initialized',
    sending_request_to_target: 'Sending request to target',
    awaiting_target_response: 'Awaiting target response',
    collecting_evidence: 'Collecting evidence',
    evaluating: 'Evaluating response',
    running_rule_evaluator: 'Evaluating rules',
    persisting_result: 'Persisting result',
    case_completed: 'Case completed',
    completed: 'Completed',
    interrupted: 'Interrupted',
    failed: 'Failed',
    cancelled: 'Cancelled',
    skipped: 'Skipped',
  };
  return map[stage] ?? stage.replaceAll('_', ' ');
};

export function ExecutionStatusIndicator({ status, stage }: { status: string; stage?: string | null }) {
  const active = status === 'preparing' || status === 'running';
  return (
    <span className={`batch-status-pill ${active ? 'is-running' : status}`}>
      {active && <span className="running-indicator" aria-hidden="true" />}
      {readableStage(active ? (stage || status) : status)}
    </span>
  );
}

export function ProgressMetadata({ record }: { record: GenericRunRecord }) {
  const asiSummary = deriveRunAsiSummary(record);
  return (
    <div className="card live-meta-card" aria-label="Scan Progress Metadata">
      <div className="live-meta-row">
        <span>
          <strong>Target:</strong> {safeLabel(record.target_name)} (<code className="mono">{safeLabel(record.target_id)}</code>)
        </span>
        <span>
          · <strong>Dataset:</strong> {safeLabel(record.dataset_name || record.dataset_id || 'Direct Testcases')}
        </span>
        <span>
          · <strong>ASI:</strong> <code className="mono">{safeLabel(asiSummary.label)}</code>
        </span>
      </div>
      <div className="live-meta-row">
        <span>
          <strong>Run ID:</strong> <code className="mono">{record.generic_run_id}</code>
        </span>
        <span>
          · <strong>Mode:</strong> <code className="mono">{record.mode.toUpperCase()}</code>
        </span>
        <span>
          · <strong>Engine:</strong> {record.use_judge ? 'Hybrid LLM Judge + Rules' : 'Deterministic Rules / Evidence Only'}
        </span>
        {record.started_at && (
          <span>
            · <strong>Started:</strong>{' '}
            <time dateTime={record.started_at}>{formatDateTime(record.started_at)}</time>
          </span>
        )}
      </div>
    </div>
  );
}

export function ScanProgressBar({ record }: { record: GenericRunRecord }) {
  const executed = record.executed_cases ?? record.cases.length;
  const skipped = record.skipped_count ?? (record.skipped_cases?.length ?? 0);
  const selected = record.selected_cases ?? executed + skipped;
  const ready = record.ready_count ?? Math.max(executed, selected - skipped);
  const status = record.status ?? 'completed';
  const active = status === 'preparing' || status === 'running';
  const rawPercent = record.progress_percent ?? (ready > 0 ? Math.floor((executed / ready) * 100) : 0);
  const percent =
    status === 'completed' && ready > 0 && executed >= ready
      ? 100
      : Math.min(rawPercent, executed < ready ? 99 : 100);

  return (
    <section className="card live-hero" aria-label="Live Scan Progress Bar">
      <div className="live-hero-top">
        <div>
          <ExecutionStatusIndicator status={status} stage={record.current_stage} />
          <h2>Scan {status.replaceAll('_', ' ')}</h2>
          <p className="caption">
            {active
              ? 'Results persist to disk incrementally as each testcase finishes. Re-opening this Run ID never replays payloads.'
              : 'Scan execution finished and results are persisted.'}
          </p>
        </div>
        <div className="live-hero-pct">
          <strong>{percent}%</strong>
          <span>{executed} / {ready} ready cases</span>
        </div>
      </div>

      <div className="progress-track-wrap">
        <progress value={executed} max={ready || 1} aria-label="Executed testcase progress" className="sec-progress" />
      </div>

      <div className="live-hero-foot">
        <strong>Executed: {executed}/{ready}</strong>
        <span>
          Selected: {selected} · Ready: {ready} · Executed: {executed}/{ready} · Skipped: {skipped}
        </span>
      </div>

      {status === 'interrupted' && (
        <p className="notice warn" role="alert">
          The scan process stopped before all testcases finished ({record.interrupted_reason || 'process_interrupted'}). Completed testcase records remain safely persisted; re-opening this Run ID does not resend payloads.
        </p>
      )}
      {status === 'failed' && (
        <p className="notice error" role="alert">
          The scan terminated with an execution or persistence failure ({record.error_code || 'scan_failed'}). Partial testcase records remain safely persisted without replaying payloads.
        </p>
      )}
    </section>
  );
}

export function ExecutionCounters({ record }: { record: GenericRunRecord }) {
  const counts = computeVerdictCounts(record);
  const executed = record.executed_cases ?? record.cases.length;
  const skipped = record.skipped_count ?? (record.skipped_cases?.length ?? 0);
  const selected = record.selected_cases ?? executed + skipped;
  const ready = record.ready_count ?? Math.max(executed, selected - skipped);
  const remaining = Math.max(0, ready - executed);

  const cards = [
    { label: 'PASS', value: counts.PASS, cls: 'ok' },
    { label: 'FAIL', value: counts.FAIL, cls: 'fail' },
    { label: 'INCONCLUSIVE', value: counts.INCONCLUSIVE, cls: 'warn' },
    { label: 'ERROR', value: counts.ERROR, cls: 'err' },
    { label: 'SKIPPED', value: skipped, cls: '' },
    { label: 'REMAINING', value: remaining, cls: '' },
  ] as const;

  return (
    <div className="cards live-counters" aria-label="Live verdict counters">
      {cards.map(item => (
        <article className={`metric ${item.cls}`} key={item.label}>
          <div className="k">{item.label}</div>
          <div className="v">{item.value}</div>
        </article>
      ))}
    </div>
  );
}

export function CurrentTestcase({ record }: { record: GenericRunRecord }) {
  const status = record.status ?? 'completed';
  const active = status === 'preparing' || status === 'running';

  return (
    <section className="card" aria-label="Current testcase execution stage">
      {active ? (
        <>
          <span className="eyebrow">CURRENTLY EXECUTING</span>
          <h3>
            Current case:{' '}
            {record.current_case_id ? (
              <code className="mono">{safeLabel(record.current_case_id)}</code>
            ) : (
              'Preparing next case'
            )}
          </h3>
          <div className="batch-stage" style={{ marginTop: '0.6rem' }}>
            <span className="running-indicator" aria-hidden="true" />
            <span>
              Stage: <strong>{readableStage(record.current_stage)}</strong>
            </span>
          </div>
        </>
      ) : (
        <>
          <span className="eyebrow">EXECUTION STATUS</span>
          <h3>{status === 'completed' ? 'All ready testcases completed' : `Scan ${status}`}</h3>
          <p className="caption">
            Executed {record.executed_cases ?? record.cases.length} of {record.ready_count ?? record.total_cases} ready testcases ({record.skipped_count ?? 0} skipped).
          </p>
        </>
      )}
    </section>
  );
}

export function BudgetUsage({ record, events }: { record: GenericRunRecord; events?: GenericRunEvent[] }) {
  const active = record.status === 'preparing' || record.status === 'running';
  const [nowIso, setNowIso] = useState<string>(() => new Date().toISOString());

  useEffect(() => {
    if (!active || !record.started_at) return undefined;
    setNowIso(new Date().toISOString());
    const id = window.setInterval(() => {
      setNowIso(new Date().toISOString());
    }, 1000);
    return () => window.clearInterval(id);
  }, [active, record.started_at]);

  const targetUsed =
    record.target_requests_used !== undefined && record.target_requests_used !== null
      ? String(record.target_requests_used)
      : record.mode === 'offline'
        ? '0'
        : 'Unknown';
  const targetBudget =
    record.target_request_budget ?? (record.mode === 'offline' ? 0 : record.ready_count ?? record.total_cases);
  const judgeUsed = record.judge_requests_used ?? (record.judge_metadata?.request_count ?? 0);
  const judgeBudget =
    record.judge_request_budget ?? (record.use_judge ? record.ready_count ?? record.total_cases : 0);
  const activity = events ?? record.events ?? [];
  const elapsed = formatDurationBetween(record.started_at, record.completed_at || (active ? nowIso : null));

  return (
    <section className="card" aria-label="Budget usage and activity">
      <div className="card-head-row">
        <h3>Budget Usage &amp; Activity</h3>
        <span className="pill">{activity.length} events</span>
      </div>
      <div className="detail-grid compact" style={{ marginBottom: '0.65rem' }}>
        <div className="detail-pair">
          <span>Target Requests</span>
          <strong>{targetUsed} / {targetBudget}</strong>
        </div>
        <div className="detail-pair">
          <span>Judge Calls</span>
          <strong>{judgeUsed} / {judgeBudget}</strong>
        </div>
        {elapsed !== 'Not recorded' && (
          <div className="detail-pair">
            <span>{active ? 'Elapsed' : 'Duration'}</span>
            <strong>{elapsed}</strong>
          </div>
        )}
      </div>

      {activity.length > 0 && (
        <ol className="activity-feed" aria-label="Scan execution events">
          {activity
            .slice(-6)
            .reverse()
            .map((ev, idx) => (
              <li key={`${ev.at}-${idx}`}>
                <time dateTime={ev.at}>{new Date(ev.at).toLocaleTimeString()}</time>{' '}
                <span>
                  {readableStage(ev.stage)}
                  {ev.case_id ? ` · ${safeLabel(ev.case_id)}` : ''}
                  {ev.verdict ? ` (${ev.verdict})` : ''}
                </span>
              </li>
            ))}
        </ol>
      )}
    </section>
  );
}

export function TestcaseStatusList({ cases }: { cases: GenericCaseStatus[] }) {
  return (
    <section className="card" aria-label="Testcase execution status list">
      <div className="card-head-row">
        <div>
          <span className="eyebrow">CASE-BY-CASE PROGRESS</span>
          <h3>Testcase Status List ({cases.length})</h3>
        </div>
      </div>
      <div className="tablewrap">
        <table className="case-table">
          <thead>
            <tr>
              <th>Case ID</th>
              <th>ASI</th>
              <th>Status</th>
              <th>Verdict</th>
              <th>Execution Stage</th>
              <th>Evidence Level</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {cases.map(row => (
              <tr key={row.case_id}>
                <td>
                  <strong>
                    <code className="mono">{safeLabel(row.case_id)}</code>
                  </strong>
                </td>
                <td>
                  <span className="pill">{safeLabel(formatCaseAsiCategory(row.asi_code || row.category))}</span>
                </td>
                <td>
                  <span
                    className={`batch-cell-pill ${row.status === 'completed' ? 'ready' : row.status === 'running' ? 'is-running' : 'blocked'}`}
                  >
                    {row.status}
                  </span>
                </td>
                <td>
                  {row.verdict ? (
                    <span className={verdictBadgeClass(row.verdict)}>{normalizeVerdict(row.verdict)}</span>
                  ) : (
                    '—'
                  )}
                </td>
                <td>
                  <code className="mono">{readableStage(row.stage)}</code>
                  {row.reason && row.status !== 'completed' && (
                    <small> ({safeLabel(row.reason)})</small>
                  )}
                </td>
                <td>
                  <span className="pill">{row.evidence_level ? formatEvidenceLevel(row.evidence_level) : '—'}</span>
                </td>
                <td>{row.run_id ? <a href={`#run/${row.run_id}`}>Inspect Detail</a> : 'Pending'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
