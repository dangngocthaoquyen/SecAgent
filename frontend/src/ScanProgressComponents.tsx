import { useEffect, useState } from 'react';
import { safeLabel } from './api';
import {
  deriveRunAsiSummary,
  formatCaseAsiCategory,
  formatDateTime,
  formatDurationBetween,
  formatEvidenceLevel,
  normalizeVerdict,
  verdictBadgeClass,
} from './scanFormatters';
import { resolveUnifiedDisplay } from './scanLineage';
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
  const unified = resolveUnifiedDisplay(record);
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
          <strong>{unified.isUnified ? 'Scan ID:' : 'Run ID:'}</strong>{' '}
          <code className="mono">{unified.logicalScanId}</code>
        </span>
        {record.workflow_id && (
          <span>
            · <strong>Workflow ID:</strong>{' '}
            <code className="mono">{safeLabel(record.workflow_id)}</code>
          </span>
        )}
        {unified.isUnified && unified.activeSessionId !== unified.logicalScanId && (
          <span>
            · <strong>Resume Session #{unified.resumeCount}:</strong>{' '}
            <code className="mono">{unified.activeSessionId}</code>
          </span>
        )}
        <span>
          · <strong>Mode:</strong> <code className="mono">{record.mode.toUpperCase()}</code>
        </span>
        <span>
          · <strong>Engine:</strong> {record.use_judge ? 'Hybrid LLM Judge + Rules' : 'Deterministic Rules / Evidence Only'}
        </span>
        {unified.startedAt && (
          <span>
            · <strong>Started:</strong>{' '}
            <time dateTime={unified.startedAt}>{formatDateTime(unified.startedAt)}</time>
          </span>
        )}
      </div>
    </div>
  );
}

export function ScanProgressBar({ record }: { record: GenericRunRecord }) {
  const unified = resolveUnifiedDisplay(record);
  const executed = unified.executedCount;
  const skipped = unified.skippedCount;
  const selected = unified.selectedCount;
  const ready = unified.readyCount;
  const status = unified.logicalStatus;
  const active = status === 'preparing' || status === 'running';
  const rawPercent = unified.progressPercent;
  const percent =
    (status === 'completed' || status === 'completed_with_errors') && ready > 0 && executed >= ready
      ? 100
      : Math.min(rawPercent, executed < ready ? 99 : 100);

  return (
    <section className="card live-hero" aria-label="Live Scan Progress Bar">
      <div className="live-hero-top">
        <div>
          <ExecutionStatusIndicator status={status} stage={record.current_stage} />
          <h2>
            Scan {status.replaceAll('_', ' ')}
            {unified.isUnified && unified.resumeCount > 0 ? ` · Session ${unified.sessionCount}` : ''}
          </h2>
          <p className="caption">
            {active
              ? unified.isUnified
                ? `Continuing logical scan ${unified.logicalScanId.slice(0, 12)} (preserving previously completed results without re-running them).`
                : 'Results persist to disk incrementally as each testcase finishes. Re-opening this Run ID never replays payloads.'
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
          {unified.isUnified ? ` · Sessions: ${unified.sessionCount}` : ''}
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
  const unified = resolveUnifiedDisplay(record);
  const vc = unified.verdictCounts;
  const executed = unified.executedCount;
  const skipped = unified.skippedCount;
  const ready = unified.readyCount;
  const remaining = Math.max(0, ready - executed);
  const techFailureCount = Number(
    record.unified_lineage?.evaluation_summary?.technical_failure_count ??
      record.evaluation_summary?.technical_failure_count ??
      vc.ERROR ??
      0,
  );
  const isBinaryV2 = Boolean(
    (record.unified_lineage?.verdict_schema_version ??
      record.verdict_schema_version ??
      '').startsWith('2.'),
  );
  const legacyInconclusive = Number(vc.INCONCLUSIVE ?? 0);

  const cards =
    isBinaryV2 && legacyInconclusive === 0
      ? ([
          { label: 'PASS', value: Number(vc.PASS ?? 0), cls: 'ok' },
          { label: 'FAIL', value: Number(vc.FAIL ?? 0), cls: 'fail' },
          { label: 'TECH ERRORS', value: techFailureCount, cls: techFailureCount > 0 ? 'err' : '' },
          { label: 'SKIPPED', value: skipped, cls: '' },
          { label: 'REMAINING', value: remaining, cls: '' },
        ] as const)
      : ([
          { label: 'PASS', value: Number(vc.PASS ?? 0), cls: 'ok' },
          { label: 'FAIL', value: Number(vc.FAIL ?? 0), cls: 'fail' },
          { label: 'INCONCLUSIVE', value: legacyInconclusive, cls: 'warn' },
          { label: 'ERROR', value: Number(vc.ERROR ?? 0), cls: 'err' },
          { label: 'SKIPPED', value: skipped, cls: '' },
          { label: 'REMAINING', value: remaining, cls: '' },
        ] as const);

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

export function TechnicalDiagnosticsNotice({ record }: { record: GenericRunRecord }) {
  const unified = resolveUnifiedDisplay(record);
  const errored = unified.cases.filter(
    c =>
      c.evaluation_status === 'EXECUTION_ERROR' ||
      c.verdict === 'ERROR' ||
      (typeof c.http_status_code === 'number' && c.http_status_code >= 400),
  );
  const erroredStatuses = unified.caseStatuses.filter(
    s =>
      s.status === 'error' ||
      s.verdict === 'ERROR' ||
      (typeof s.http_status_code === 'number' && s.http_status_code >= 400),
  );
  const count = Math.max(errored.length, erroredStatuses.length);
  if (count === 0) return null;

  const codes = new Map<number, number>();
  const durations: number[] = [];
  for (const item of errored.length > 0 ? errored : erroredStatuses) {
    if (typeof item.http_status_code === 'number') {
      codes.set(item.http_status_code, (codes.get(item.http_status_code) ?? 0) + 1);
    }
    if (typeof item.duration_ms === 'number' && Number.isFinite(item.duration_ms)) {
      durations.push(item.duration_ms);
    }
  }
  const codeSummary = Array.from(codes.entries())
    .sort((a, b) => a[0] - b[0])
    .map(([code, n]) => `HTTP ${code} (×${n})`)
    .join(', ');
  const avgSec =
    durations.length > 0
      ? `${(durations.reduce((sum, v) => sum + v, 0) / durations.length / 1000).toFixed(1)}s avg`
      : null;

  return (
    <div className="notice warn" role="status" data-testid="technical-diagnostics-banner">
      <strong>Technical Execution Failures Detected ({count}):</strong>{' '}
      {codeSummary ? <code className="mono">{codeSummary}</code> : <span>Target request error</span>}
      {avgSec ? <span> · {avgSec}</span> : null}
      <span>
        {' '}
        — Technical failures are excluded from binary PASS/FAIL security counts and Judge is not invoked for failed target responses.
      </span>
    </div>
  );
}

export function CurrentTestcase({ record }: { record: GenericRunRecord }) {
  const unified = resolveUnifiedDisplay(record);
  const status = unified.logicalStatus;
  const active = status === 'preparing' || status === 'running';

  return (
    <section className="card" aria-label="Current testcase execution stage">
      {active ? (
        <>
          <span className="eyebrow">
            CURRENTLY EXECUTING{unified.isUnified && unified.resumeCount > 0 ? ` · RESUME SESSION #${unified.resumeCount}` : ''}
          </span>
          <h3>
            Current case:{' '}
            {unified.currentCaseId ? (
              <code className="mono">{safeLabel(unified.currentCaseId)}</code>
            ) : (
              'Preparing next case'
            )}
          </h3>
          <div className="batch-stage" style={{ marginTop: '0.6rem' }}>
            <span className="running-indicator" aria-hidden="true" />
            <span>
              Stage: <strong>{readableStage(unified.currentStage)}</strong>
            </span>
          </div>
        </>
      ) : (
        <>
          <span className="eyebrow">EXECUTION STATUS</span>
          <h3>{status === 'completed' ? 'All ready testcases completed' : `Scan ${status.replaceAll('_', ' ')}`}</h3>
          <p className="caption">
            Executed {unified.executedCount} of {unified.readyCount} ready testcases ({unified.skippedCount} skipped).
          </p>
        </>
      )}
    </section>
  );
}

export function BudgetUsage({ record, events }: { record: GenericRunRecord; events?: GenericRunEvent[] }) {
  const unified = resolveUnifiedDisplay(record);
  const active = unified.logicalStatus === 'preparing' || unified.logicalStatus === 'running';
  const [nowIso, setNowIso] = useState<string>(() => new Date().toISOString());

  useEffect(() => {
    if (!active || !unified.startedAt) return undefined;
    setNowIso(new Date().toISOString());
    const id = window.setInterval(() => {
      setNowIso(new Date().toISOString());
    }, 1000);
    return () => window.clearInterval(id);
  }, [active, unified.startedAt]);

  const activity = events ?? unified.activeSessionEvents;
  const elapsed = formatDurationBetween(unified.startedAt, unified.completedAt || (active ? nowIso : null));

  const formatMetric = (value: number | null | undefined, offlineDefaultZero = false): string => {
    if (typeof value === 'number') return String(value);
    return offlineDefaultZero ? '0' : 'Not recorded';
  };

  const singleTargetUsed =
    record.target_requests_used !== undefined && record.target_requests_used !== null
      ? String(record.target_requests_used)
      : record.mode === 'offline'
        ? '0'
        : 'Unknown';
  const singleTargetBudget =
    record.target_request_budget ?? (record.mode === 'offline' ? 0 : record.ready_count ?? record.total_cases);
  const singleJudgeUsed = record.judge_requests_used ?? (record.judge_metadata?.request_count ?? 0);
  const singleJudgeBudget =
    record.judge_request_budget ?? (record.use_judge ? record.ready_count ?? record.total_cases : 0);

  return (
    <section className="card" aria-label="Budget usage and activity">
      <div className="card-head-row">
        <h3>Budget Usage &amp; Activity</h3>
        <span className="pill">{activity.length} events</span>
      </div>
      <div className="detail-grid compact" style={{ marginBottom: '0.65rem' }}>
        {unified.isUnified ? (
          <>
            <div className="detail-pair">
              <span>Cumulative Target Requests</span>
              <strong>{formatMetric(unified.targetRequestsUsed, record.mode === 'offline')}</strong>
            </div>
            <div className="detail-pair">
              <span>Current Session Target Budget</span>
              <strong>
                {formatMetric(unified.activeSessionTargetUsed, record.mode === 'offline')} /{' '}
                {formatMetric(unified.activeSessionTargetBudget, record.mode === 'offline')}
              </strong>
            </div>
            <div className="detail-pair">
              <span>Cumulative Judge Calls</span>
              <strong>{formatMetric(unified.judgeRequestsUsed, !record.use_judge)}</strong>
            </div>
            <div className="detail-pair">
              <span>Current Session Judge Budget</span>
              <strong>
                {formatMetric(unified.activeSessionJudgeUsed, !record.use_judge)} /{' '}
                {formatMetric(unified.activeSessionJudgeBudget, !record.use_judge)}
              </strong>
            </div>
          </>
        ) : (
          <>
            <div className="detail-pair">
              <span>Target Requests</span>
              <strong>{singleTargetUsed} / {singleTargetBudget}</strong>
            </div>
            <div className="detail-pair">
              <span>Judge Calls</span>
              <strong>{singleJudgeUsed} / {singleJudgeBudget}</strong>
            </div>
          </>
        )}
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
                  {typeof row.http_status_code === 'number' && row.http_status_code >= 400 && (
                    <small className="mono">
                      {' '}
                      (HTTP {row.http_status_code}
                      {typeof row.duration_ms === 'number' ? ` · ${(row.duration_ms / 1000).toFixed(1)}s` : ''})
                    </small>
                  )}
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
