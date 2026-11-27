import { useEffect, useMemo, useRef, useState } from 'react';
import { TechnicalDiagnosticsNotice } from './ScanProgressComponents';
import TestcaseDetailDrawer from './TestcaseDetailDrawer';
import {
  classifyJudgeFault,
  computeEvaluationMetrics,
  copyTextToClipboard,
  deriveRunAsiSummary,
  formatCaseAsiCategory,
  formatDateTime,
  formatDurationBetween,
  formatEvaluationReasonCode,
  formatEvaluationStatus,
  formatEvidenceLevel,
  formatInvocationStatus,
  formatProviderModel,
  formatRunStatus,
  normalizeVerdict,
  runStatusBadgeClass,
  safePercent,
  summarizeRunEvidenceVerification,
  verdictBadgeClass,
} from './scanFormatters';
import { resolveUnifiedDisplay } from './scanLineage';
import {
  testingApi,
  type GenericRunCaseResult,
  type GenericRunRecord,
} from './testingApi';

export interface ScanResultsViewProps {
  runRecord: GenericRunRecord;
  localSingleUser: boolean;
  secret: string;
  onNewScan: () => void;
  onExportError?: (message: string) => void;
  onResumeScan?: () => void;
  onOpenRun?: (runId: string) => void;
  workflowId?: string | null;
  onRerunSavedDataset?: () => void;
  rerunBusy?: boolean;
  resumeBusy?: boolean;
  resumePanelOpen?: boolean;
}

export default function ScanResultsView({
  runRecord,
  localSingleUser,
  secret,
  onNewScan,
  onExportError,
  onResumeScan,
  onOpenRun,
  workflowId = null,
  onRerunSavedDataset,
  rerunBusy = false,
  resumeBusy = false,
  resumePanelOpen = false,
}: ScanResultsViewProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL');
  const [asiFilter, setAsiFilter] = useState<string>('ALL');
  const [evidenceFilter, setEvidenceFilter] = useState<string>('ALL');
  const [pageSize, setPageSize] = useState<number>(10);
  const [page, setPage] = useState<number>(1);
  const [selectedCase, setSelectedCase] = useState<GenericRunCaseResult | null>(null);
  const [copiedRunId, setCopiedRunId] = useState(false);

  const lastTriggerRef = useRef<HTMLElement | null>(null);

  // Reset filters and drawer when navigating to a different scan run
  useEffect(() => {
    setSearchQuery('');
    setVerdictFilter('ALL');
    setAsiFilter('ALL');
    setEvidenceFilter('ALL');
    setPage(1);
    setSelectedCase(null);
  }, [runRecord.generic_run_id]);

  const unified = useMemo(() => resolveUnifiedDisplay(runRecord), [runRecord]);
  const cases = unified.cases;
  const skippedCases = runRecord.unified_lineage?.skipped_cases ?? runRecord.skipped_cases ?? [];
  const verdictCounts = {
    PASS: Number(unified.verdictCounts.PASS ?? 0),
    FAIL: Number(unified.verdictCounts.FAIL ?? 0),
    INCONCLUSIVE: Number(unified.verdictCounts.INCONCLUSIVE ?? 0),
    ERROR: Number(unified.verdictCounts.ERROR ?? 0),
  };
  const evalMetrics = useMemo(
    () =>
      computeEvaluationMetrics({
        summary: runRecord.unified_lineage?.evaluation_summary ?? runRecord.evaluation_summary ?? null,
        verdictCounts: unified.verdictCounts,
        cases,
        totalCases: runRecord.total_cases,
        schemaVersion: runRecord.unified_lineage?.verdict_schema_version ?? runRecord.verdict_schema_version ?? null,
        policyVersion: runRecord.unified_lineage?.verdict_policy_version ?? runRecord.verdict_policy_version ?? null,
      }),
    [runRecord, unified.verdictCounts, cases],
  );
  const notEvaluatedReasonEntries = Object.entries(evalMetrics.notEvaluatedReasons);
  const status = unified.logicalStatus.toLowerCase();
  const isCompleted = status === 'completed';
  const isCompletedWithErrors = status === 'completed_with_errors';

  const selectedCount = unified.selectedCount;
  const readyCount = unified.readyCount;
  const executedCount = unified.executedCount;
  const skippedCount = unified.skippedCount;

  const progressPct = unified.progressPercent;

  const barTotal = Math.max(
    1,
    evalMetrics.isBinarySchema
      ? evalMetrics.passCount + evalMetrics.failCount + evalMetrics.notEvaluatedCount
      : verdictCounts.PASS + verdictCounts.FAIL + verdictCounts.INCONCLUSIVE + verdictCounts.ERROR,
  );

  const judgeMeta = unified.judgeMetadata;
  const hasIntegrityError = unified.integrityStatus === 'invalid_checkpoint';
  const judgeOptions = useMemo(
    () => ({ useJudge: runRecord.use_judge, judgeMode: judgeMeta?.mode ?? null }),
    [runRecord.use_judge, judgeMeta?.mode],
  );
  const asiSummary = useMemo(
    () => deriveRunAsiSummary({ ...runRecord, cases, skipped_cases: skippedCases }),
    [runRecord, cases, skippedCases],
  );
  const evidenceEntries = Object.entries(unified.evidenceSummary);
  const execVerification = useMemo(() => summarizeRunEvidenceVerification(cases), [cases]);

  const availableAsis = useMemo(
    () => Array.from(new Set(cases.map(c => formatCaseAsiCategory(c.category)).filter(Boolean))).sort(),
    [cases],
  );
  const availableEvidenceLevels = useMemo(
    () => Array.from(new Set(cases.map(c => c.evidence_level || 'unknown'))).sort(),
    [cases],
  );

  const filteredCases = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return cases.filter(c => {
      const normAsi = formatCaseAsiCategory(c.category);
      if (
        q &&
        !c.case_id.toLowerCase().includes(q) &&
        !(c.category || '').toLowerCase().includes(q) &&
        !normAsi.toLowerCase().includes(q)
      ) {
        return false;
      }
      if (verdictFilter !== 'ALL' && normalizeVerdict(c.verdict, c.evaluation_status) !== verdictFilter) {
        return false;
      }
      if (asiFilter !== 'ALL' && normAsi !== asiFilter) {
        return false;
      }
      const evKey = c.evidence_level || 'unknown';
      if (evidenceFilter !== 'ALL' && evKey !== evidenceFilter) {
        return false;
      }
      return true;
    });
  }, [cases, searchQuery, verdictFilter, asiFilter, evidenceFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredCases.length / pageSize));
  const safePage = Math.min(page, totalPages);

  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages);
    }
  }, [page, totalPages]);

  const startIdx = (safePage - 1) * pageSize;
  const endIdx = Math.min(filteredCases.length, startIdx + pageSize);
  const pagedCases = filteredCases.slice(startIdx, endIdx);

  function resetFilters() {
    setSearchQuery('');
    setVerdictFilter('ALL');
    setAsiFilter('ALL');
    setEvidenceFilter('ALL');
    setPage(1);
  }

  async function handleCopyRunId() {
    const ok = await copyTextToClipboard(unified.logicalScanId);
    if (ok) {
      setCopiedRunId(true);
      window.setTimeout(() => setCopiedRunId(false), 1600);
    }
  }

  const showResumeAction = Boolean(onResumeScan && unified.hasResumableWork && !hasIntegrityError);
  const canExportUnified = unified.isUnified && !hasIntegrityError;
  const primaryExportHref = canExportUnified
    ? testingApi.genericRunUnifiedExportUrl(unified.logicalScanId)
    : testingApi.genericRunExportUrl(runRecord.generic_run_id);
  const primaryExportFilename = canExportUnified
    ? `secagent-unified-scan-${unified.logicalScanId}.json`
    : `secagent-generic-run-${runRecord.generic_run_id}.json`;

  return (
    <section className="scan-results-shell" aria-label="Step 3: Scan Results">
      {/* Header card */}
      <header className="results-header card">
        <div className="results-header-main">
          <div className="results-eyebrow-row">
            <span className="eyebrow">
              STEP 3 OF 3 · SCAN {formatRunStatus(status).toUpperCase()}
              {unified.sessionCount > 1 ? ` · ${unified.sessionCount} EXECUTION SESSIONS` : ''}
            </span>
            <span className={runStatusBadgeClass(status)}>{formatRunStatus(status)}</span>
          </div>
          <h2>3 · Scan Results: {runRecord.target_name}</h2>
          <div className="results-meta-row">
            <span>
              Target:{' '}
              <a href="#targets" className="mono">
                {runRecord.target_id}
              </a>
            </span>
            <span>
              · Dataset:{' '}
              {runRecord.dataset_id ? (
                <a href="#datasets">
                  <strong>{runRecord.dataset_name || runRecord.dataset_id}</strong>
                </a>
              ) : (
                <strong>{runRecord.dataset_name || 'Not recorded'}</strong>
              )}
            </span>
            {(runRecord.workflow_id || workflowId) && (
              <span>
                · Workflow: <code className="mono">{runRecord.workflow_id || workflowId}</code>
              </span>
            )}
            <span>· ASI: <strong>{asiSummary.label}</strong></span>
            <span>· Mode: <strong>{runRecord.mode === 'offline' ? 'Offline' : 'Live'}</strong></span>
            <span>· Engine: <strong>{runRecord.use_judge ? 'Hybrid LLM Judge' : 'Rule-Only'}</strong></span>
            <span className="run-id-chip">
              {unified.isUnified ? 'Scan ID:' : 'Run ID:'} <code className="mono">{unified.logicalScanId}</code>
              <button
                type="button"
                className="btn ghost xs"
                onClick={() => void handleCopyRunId()}
                aria-label="Copy Run ID"
              >
                {copiedRunId ? 'Copied' : 'Copy'}
              </button>
            </span>
          </div>
        </div>

        <div className="results-header-actions">
          {showResumeAction && (
            <button
              type="button"
              className="btn primary"
              disabled={resumeBusy}
              onClick={onResumeScan}
            >
              {resumePanelOpen ? 'Resume Preview Open' : resumeBusy ? 'Loading Resume…' : 'Resume Scan'}
            </button>
          )}
          {onRerunSavedDataset && (
            <button
              type="button"
              className="btn ghost"
              data-testid="results-rerun-dataset-btn"
              disabled={rerunBusy}
              onClick={onRerunSavedDataset}
            >
              {rerunBusy ? 'Starting Rerun…' : 'Rerun Saved Dataset'}
            </button>
          )}
          <a
            className={showResumeAction ? 'btn ghost' : 'btn primary'}
            href={primaryExportHref}
            download={primaryExportFilename}
            onClick={e => {
              if (!localSingleUser && secret) {
                e.preventDefault();
                const dl = canExportUnified
                  ? testingApi.downloadGenericRunUnifiedReport(unified.logicalScanId, secret)
                  : testingApi.downloadGenericRunReport(runRecord.generic_run_id, secret);
                void dl.catch(err =>
                  onExportError?.(err instanceof Error ? err.message : 'Unable to export scan report.'),
                );
              }
            }}
          >
            {canExportUnified
              ? 'Export Unified Report JSON'
              : hasIntegrityError
                ? 'Export Session Report JSON'
                : 'Export Report JSON'}
          </a>
          <a className="btn ghost" href="#executions">
            View in Results History →
          </a>
          <button type="button" className="btn ghost" onClick={onNewScan}>
            New Scan
          </button>
        </div>
      </header>

      {(unified.isUnified ||
        runRecord.continuation_of_run_id ||
        (runRecord.child_run_ids && runRecord.child_run_ids.length > 0)) && (
        <div className="notice" role="region" aria-label="Continuation lineage summary">
          <strong>
            Unified Logical Scan ({unified.sessionCount} execution session{unified.sessionCount === 1 ? '' : 's'}
            {unified.resumeCount > 0 ? ` · ${unified.resumeCount} resume${unified.resumeCount === 1 ? '' : 's'}` : ''}):
          </strong>{' '}
          <span>
            Logical Scan <code className="mono">{unified.logicalScanId}</code> · Selected:{' '}
            <strong>{selectedCount}</strong> · Recorded outcomes: <strong>{executedCount}</strong> (deduplicated across
            sessions, no double-counting).
          </span>
          {runRecord.continuation_of_run_id && (
            <span style={{ marginLeft: '0.5rem' }}>
              {onOpenRun && (
                <button
                  type="button"
                  className="btn ghost xs"
                  onClick={() => onOpenRun(runRecord.continuation_of_run_id!)}
                >
                  Open Parent Run
                </button>
              )}
            </span>
          )}
          {runRecord.child_run_ids && runRecord.child_run_ids.length > 0 && (
            <span style={{ marginLeft: '0.5rem' }}>
              {runRecord.child_run_ids.map(cid => (
                <span key={cid} style={{ marginRight: '0.4rem' }}>
                  {onOpenRun && (
                    <button
                      type="button"
                      className="btn ghost xs"
                      onClick={() => onOpenRun(cid)}
                    >
                      Open Continuation Run
                    </button>
                  )}
                </span>
              ))}
            </span>
          )}
          {unified.sessions.length > 1 && (
            <details style={{ marginTop: '0.55rem' }}>
              <summary style={{ cursor: 'pointer', fontWeight: 600 }}>
                Execution History ({unified.sessions.length} sessions)
              </summary>
              <div className="tablewrap" style={{ marginTop: '0.5rem' }}>
                <table className="case-table">
                  <thead>
                    <tr>
                      <th>Session</th>
                      <th>Session Run ID</th>
                      <th>Started</th>
                      <th>Recorded</th>
                      <th>Verdicts</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {unified.sessions.map(sess => {
                      const p = Number(sess.verdict_counts?.PASS ?? 0);
                      const f = Number(sess.verdict_counts?.FAIL ?? 0);
                      const i = Number(sess.verdict_counts?.INCONCLUSIVE ?? 0);
                      const err = Number(sess.verdict_counts?.ERROR ?? 0);
                      return (
                        <tr key={sess.generic_run_id}>
                          <td>
                            <strong>{sess.session_index === 1 ? 'Original' : `Resume #${sess.session_index - 1}`}</strong>
                          </td>
                          <td>
                            <code className="mono">{sess.generic_run_id.slice(0, 12)}</code>
                          </td>
                          <td>{formatDateTime(sess.started_at)}</td>
                          <td>{sess.executed_cases}</td>
                          <td>
                            {p}P · {f}F · {i}I{err > 0 ? ` · ${err}E` : ''}
                          </td>
                          <td>
                            <span className={runStatusBadgeClass(sess.status)}>{formatRunStatus(sess.status)}</span>
                          </td>
                          <td>
                            <div className="history-actions">
                              {onOpenRun && sess.generic_run_id !== runRecord.generic_run_id && (
                                <button
                                  type="button"
                                  className="btn ghost xs"
                                  onClick={() => onOpenRun(sess.generic_run_id)}
                                >
                                  Inspect Session
                                </button>
                              )}
                              <a
                                className="btn ghost xs"
                                href={testingApi.genericRunExportUrl(sess.generic_run_id)}
                                download={`secagent-generic-run-${sess.generic_run_id}.json`}
                                onClick={e => {
                                  if (!localSingleUser && secret) {
                                    e.preventDefault();
                                    void testingApi
                                      .downloadGenericRunReport(sess.generic_run_id, secret)
                                      .catch(err2 =>
                                        onExportError?.(
                                          err2 instanceof Error ? err2.message : 'Unable to export session report.',
                                        ),
                                      );
                                  }
                                }}
                              >
                                Export Session JSON
                              </a>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </details>
          )}
        </div>
      )}

      {hasIntegrityError && (
        <div className="notice error" role="alert">
          <strong>Lineage Checkpoint Integrity Warning:</strong>{' '}
          <span>
            {unified.integrityWarning ||
              'Persisted checkpoint state failed integrity validation. Unified completion and unified report export are blocked; individual session reports remain accessible.'}
          </span>
        </div>
      )}

      {isCompletedWithErrors && (
        <div className="notice warn" role="status">
          <strong>
            Completed with errors ({executedCount} of {readyCount} ready testcases recorded · {verdictCounts.ERROR}{' '}
            ERROR):
          </strong>{' '}
          <span>
            All selected testcases reached a recorded outcome, but {verdictCounts.ERROR} testcase(s) encountered
            operational or runtime errors and were not evaluated as PASS or FAIL.
          </span>
        </div>
      )}

      {!isCompleted && !isCompletedWithErrors && (
        <div className="notice error" role="alert">
          <strong>
            Scan {status.toUpperCase()} ({progressPct}% · {executedCount} of {readyCount} ready cases executed):
          </strong>{' '}
          <span>
            {runRecord.error_code || runRecord.interrupted_reason || 'Execution did not reach clean completion.'}
          </span>
          {executedCount > 0 && (
            <p>Partial testcase results recorded before interruption are shown accurately below.</p>
          )}
        </div>
      )}

      <TechnicalDiagnosticsNotice record={runRecord} />

      {evalMetrics.technicalFailureCount > 0 && (
        <div
          className="notice warn"
          role="alert"
          data-testid="degraded-evaluation-alert"
        >
          <strong>
            Evaluation Degraded by Technical Failures ({evalMetrics.technicalFailureCount} case
            {evalMetrics.technicalFailureCount === 1 ? '' : 's'}):
          </strong>{' '}
          <span>
            {evalMetrics.cleanlyEvaluatedCases !== null && evalMetrics.cleanEvaluationCoveragePercent !== null ? (
              <>
                Clean evaluation coverage (without technical failures):{' '}
                <strong>
                  {evalMetrics.cleanlyEvaluatedCases} / {evalMetrics.coverageDenominator} (
                  {evalMetrics.cleanEvaluationCoveragePercent.toFixed(1)}%)
                </strong>
                {' · '}Binary verdict coverage: {evalMetrics.evaluatedCases} / {evalMetrics.coverageDenominator} (
                {evalMetrics.evaluationCoveragePercent.toFixed(1)}%).
              </>
            ) : (
              <>
                Clean evaluation coverage: <strong>Unavailable</strong> (historical report lacks sufficient per-case
                evaluation status breakdown; binary verdict coverage is{' '}
                {evalMetrics.evaluationCoveragePercent.toFixed(1)}%).
              </>
            )}
          </span>{' '}
          <span>
            {evalMetrics.degradedPassCount !== null && evalMetrics.degradedFailCount !== null ? (
              evalMetrics.degradedPassCount > 0 || evalMetrics.degradedFailCount > 0 ? (
                <>
                  Verdicts affected by technical failures:{' '}
                  <strong>
                    {evalMetrics.degradedPassCount} PASS
                    {evalMetrics.degradedFailCount > 0 ? `, ${evalMetrics.degradedFailCount} FAIL` : ''}
                  </strong>
                  .
                </>
              ) : (
                <>
                  {evalMetrics.technicalFailureCount} case{evalMetrics.technicalFailureCount === 1 ? '' : 's'}{' '}
                  recorded technical failures without a binary PASS/FAIL verdict.
                </>
              )
            ) : evalMetrics.degradedBinaryVerdictCount !== null && evalMetrics.degradedBinaryVerdictCount > 0 ? (
              <>
                Binary verdicts affected by technical failures:{' '}
                <strong>{evalMetrics.degradedBinaryVerdictCount}</strong> (exact PASS/FAIL split unavailable from
                summary-only historical data).
              </>
            ) : null}
          </span>{' '}
          {Object.entries(evalMetrics.technicalFailureReasons).length > 0 && (
            <span>
              Reasons:{' '}
              {Object.entries(evalMetrics.technicalFailureReasons)
                .map(([r, cnt]) => `${formatEvaluationReasonCode(r)}: ${cnt}`)
                .join(' · ')}
              .{' '}
            </span>
          )}
          <span>
            Technical-error-degraded PASS verdicts indicate no violation was established under observation-binary policy
            and do not demonstrate target security.
          </span>
        </div>
      )}

      {/* Distinct Binary PASS/FAIL & Technical Failure KPI Cards */}
      {evalMetrics.isBinarySchema && evalMetrics.legacyInconclusiveCount === 0 ? (
        <div className="cards verdict-kpis" role="region" aria-label="Verdict summary metrics">
          <article className="metric ok">
            <div className="k">PASS</div>
            <div className="v">{evalMetrics.passCount}</div>
            <div className="s">{evalMetrics.passRatePercent.toFixed(1)}% PASS rate · No observed violation</div>
          </article>
          <article className="metric fail">
            <div className="k">FAIL</div>
            <div className="v">{evalMetrics.failCount}</div>
            <div className="s">{evalMetrics.failRatePercent.toFixed(1)}% FAIL rate · Finding requires review</div>
          </article>
          <article className={`metric ${evalMetrics.technicalFailureCount > 0 ? 'err' : ''}`}>
            <div className="k">TECHNICAL FAILURES</div>
            <div className="v">{evalMetrics.technicalFailureCount}</div>
            <div className="s">
              {Object.entries(evalMetrics.technicalFailureReasons).length > 0
                ? Object.entries(evalMetrics.technicalFailureReasons)
                    .map(([r, cnt]) => `${formatEvaluationReasonCode(r)}: ${cnt}`)
                    .join(' · ')
                : '0 technical errors · Separate from PASS/FAIL'}
            </div>
          </article>
          <article className="metric">
            <div className="k">EVALUATED CASES</div>
            <div className="v">
              {evalMetrics.evaluatedCases} / {evalMetrics.totalCases}
            </div>
            <div className="s">
              {evalMetrics.evaluationCoveragePercent.toFixed(1)}% binary
              {evalMetrics.technicalFailureCount > 0 && (
                <>
                  {' · '}
                  {evalMetrics.cleanlyEvaluatedCases !== null && evalMetrics.cleanEvaluationCoveragePercent !== null
                    ? `${evalMetrics.cleanlyEvaluatedCases}/${evalMetrics.coverageDenominator} (${evalMetrics.cleanEvaluationCoveragePercent.toFixed(1)}%) clean`
                    : 'Clean coverage unavailable'}
                </>
              )}
              {' · '}Policy {evalMetrics.policyVersion}
            </div>
          </article>
        </div>
      ) : (
        <div className="cards verdict-kpis" role="region" aria-label="Verdict summary metrics">
          <article className="metric ok">
            <div className="k">PASS</div>
            <div className="v">{verdictCounts.PASS}</div>
            <div className="s">{safePercent(verdictCounts.PASS, executedCount)}% of executed cases</div>
          </article>
          <article className="metric fail">
            <div className="k">FAIL</div>
            <div className="v">{verdictCounts.FAIL}</div>
            <div className="s">{safePercent(verdictCounts.FAIL, executedCount)}% · Finding requires review</div>
          </article>
          <article className="metric warn">
            <div className="k">INCONCLUSIVE</div>
            <div className="v">{verdictCounts.INCONCLUSIVE}</div>
            <div className="s">{safePercent(verdictCounts.INCONCLUSIVE, executedCount)}% · Legacy report outcome</div>
          </article>
          <article className="metric err">
            <div className="k">ERROR</div>
            <div className="v">{verdictCounts.ERROR}</div>
            <div className="s">{safePercent(verdictCounts.ERROR, executedCount)}% · Operational / tool failure</div>
          </article>
        </div>
      )}

      {/* Verdict Distribution & Timing Card */}
      <section className="card dist-card" aria-label="Verdict distribution and execution coverage">
        <div className="dist-head">
          <div>
            <h3>Verdict Distribution &amp; Coverage</h3>
            <p className="caption">
              {unified.sessionCount > 1 ? (
                <>
                  Selected Cases: {selectedCount} · Recorded Outcomes: {executedCount} · Evaluated Cases:{' '}
                  {evalMetrics.evaluatedCases} · Not Evaluated: {evalMetrics.notEvaluatedCount} · Coverage:{' '}
                  {evalMetrics.evaluationCoveragePercent.toFixed(1)}% · Skipped Cases: {skippedCount} · Execution Sessions:{' '}
                  {unified.sessionCount}
                </>
              ) : evalMetrics.isBinarySchema && evalMetrics.legacyInconclusiveCount === 0 ? (
                <>
                  Selected Cases: {selectedCount} · Executed Cases: {executedCount} · Skipped Cases: {skippedCount} ·
                  Total Cases: {evalMetrics.totalCases} · PASS: {evalMetrics.passCount} ({evalMetrics.passRatePercent.toFixed(1)}%) ·
                  FAIL: {evalMetrics.failCount} ({evalMetrics.failRatePercent.toFixed(1)}%) ·
                  Technical Failures: {evalMetrics.technicalFailureCount} · Policy: {evalMetrics.policyVersion}
                </>
              ) : (
                <>
                  Selected Cases: {selectedCount} · Executed Cases: {executedCount} · Skipped Cases: {skippedCount} ·
                  Total Cases: {evalMetrics.totalCases}
                </>
              )}
            </p>
          </div>
          <div className="dist-times">
            <span>Started: <strong>{formatDateTime(unified.startedAt)}</strong></span>
            <span>Completed: <strong>{formatDateTime(unified.completedAt)}</strong></span>
            <span>Duration: <strong>{formatDurationBetween(unified.startedAt, unified.completedAt)}</strong></span>
          </div>
        </div>

        <div
          className="bar"
          role="img"
          aria-label={
            evalMetrics.isBinarySchema && evalMetrics.legacyInconclusiveCount === 0
              ? `Verdict bar: ${evalMetrics.passCount} PASS, ${evalMetrics.failCount} FAIL, ${evalMetrics.notEvaluatedCount} NOT_EVALUATED`
              : `Verdict bar: ${verdictCounts.PASS} PASS, ${verdictCounts.FAIL} FAIL, ${verdictCounts.INCONCLUSIVE} INCONCLUSIVE, ${verdictCounts.ERROR} ERROR`
          }
        >
          {evalMetrics.passCount > 0 && (
            <span className="b-pass" style={{ width: `${safePercent(evalMetrics.passCount, barTotal)}%` }} />
          )}
          {evalMetrics.failCount > 0 && (
            <span className="b-fail" style={{ width: `${safePercent(evalMetrics.failCount, barTotal)}%` }} />
          )}
          {evalMetrics.isBinarySchema && evalMetrics.legacyInconclusiveCount === 0 ? (
            evalMetrics.notEvaluatedCount > 0 && (
              <span className="b-inc" style={{ width: `${safePercent(evalMetrics.notEvaluatedCount, barTotal)}%` }} />
            )
          ) : (
            <>
              {verdictCounts.INCONCLUSIVE > 0 && (
                <span className="b-inc" style={{ width: `${safePercent(verdictCounts.INCONCLUSIVE, barTotal)}%` }} />
              )}
              {verdictCounts.ERROR > 0 && (
                <span className="b-err" style={{ width: `${safePercent(verdictCounts.ERROR, barTotal)}%` }} />
              )}
            </>
          )}
        </div>

        <div className="bar-legend">
          <span><i className="dot pass" /> PASS {evalMetrics.passCount} ({evalMetrics.isBinarySchema ? evalMetrics.passRatePercent.toFixed(1) : safePercent(evalMetrics.passCount, executedCount)}%)</span>
          <span><i className="dot fail" /> FAIL {evalMetrics.failCount} ({evalMetrics.isBinarySchema ? evalMetrics.failRatePercent.toFixed(1) : safePercent(evalMetrics.failCount, executedCount)}%)</span>
          {evalMetrics.isBinarySchema && evalMetrics.legacyInconclusiveCount === 0 ? (
            evalMetrics.technicalFailureCount > 0 && (
              <span><i className="dot err" /> TECHNICAL FAILURES {evalMetrics.technicalFailureCount}</span>
            )
          ) : (
            <>
              <span><i className="dot inc" /> INCONCLUSIVE {verdictCounts.INCONCLUSIVE} ({safePercent(verdictCounts.INCONCLUSIVE, executedCount)}%)</span>
              <span><i className="dot err" /> ERROR {verdictCounts.ERROR} ({safePercent(verdictCounts.ERROR, executedCount)}%)</span>
            </>
          )}
        </div>
        {evalMetrics.isBinarySchema && evalMetrics.legacyInconclusiveCount === 0 && (
          <p className="caption" style={{ marginTop: '0.5rem' }}>
            {evalMetrics.policyStatement}
            {Object.keys(evalMetrics.evidenceLimitationCounts).length > 0 && (
              <>
                {' '}· Evidence limitations:{' '}
                {Object.entries(evalMetrics.evidenceLimitationCounts)
                  .map(([k, v]) => `${k}: ${v}`)
                  .join(' · ')}
              </>
            )}
          </p>
        )}
      </section>

      {/* Judge Evaluation & Evidence Verification 2-Column Panel */}
      <div className="split" role="region" aria-label="Evaluation and evidence summary">
        <section className="card">
          <div className="card-head-row">
            <h3>Judge Evaluation</h3>
            <span className="pill">{formatInvocationStatus(judgeMeta?.invocation_status)}</span>
          </div>
          <div className="detail-grid compact">
            <div className="detail-pair">
              <span>Evaluation Engine</span>
              <strong>{runRecord.use_judge ? 'Hybrid LLM Judge + Rules' : 'Deterministic Rules Only'}</strong>
            </div>
            <div className="detail-pair">
              <span>Judge Calls (Succeeded / Requested)</span>
              <strong>
                {judgeMeta
                  ? `${judgeMeta.success_count} / ${judgeMeta.request_count}`
                  : 'Not recorded'}
              </strong>
            </div>
            <div className="detail-pair">
              <span>Provider / Model</span>
              <strong>
                {judgeMeta && (judgeMeta.provider || judgeMeta.model) ? (
                  <>
                    {judgeMeta.provider && <code className="mono">{judgeMeta.provider}</code>}
                    {judgeMeta.provider && judgeMeta.model && ' / '}
                    {judgeMeta.model && <code className="mono">{judgeMeta.model}</code>}
                  </>
                ) : (
                  formatProviderModel(judgeMeta)
                )}
              </strong>
            </div>
            <div className="detail-pair">
              <span>Judge Faults / Errors</span>
              <strong>
                {judgeMeta
                  ? judgeMeta.failure_count > 0
                    ? `${judgeMeta.failure_count} (${(judgeMeta.error_categories ?? []).join(', ') || 'fault'})`
                    : '0'
                  : 'Not recorded'}
              </strong>
            </div>
          </div>
        </section>

        <section className="card">
          <div className="card-head-row">
            <h3>Evidence Verification</h3>
            <span className={`pill ${execVerification.verifiedCaseCount > 0 ? 'ok' : ''}`}>
              {execVerification.verifiedCaseCount} / {cases.length} testcases with verified execution
            </span>
          </div>
          <div className="evidence-summary-block">
            <p className="caption" style={{ margin: 0 }}>
              <strong>Explicit execution verification:</strong>{' '}
              {execVerification.verifiedItemCount} / {execVerification.totalItems} evidence items execution-verified
              {execVerification.unknownItemCount > 0 && (
                <span> · {execVerification.unknownItemCount} without verification metadata</span>
              )}
            </p>
            <p className="evidence-breakdown-line">
              {evidenceEntries.length > 0
                ? evidenceEntries.map(([level, count]) => `${level}: ${count}`).join(' · ')
                : 'No evidence breakdown recorded.'}
            </p>
            <div className="badge-wrap">
              {evidenceEntries.map(([level, count]) => (
                <span key={level} className="pill">
                  {formatEvidenceLevel(level)}: {count}
                </span>
              ))}
            </div>
          </div>
        </section>
      </div>

      {/* Honest Evidence Limitation Notice */}
      <div className="notice info" role="note">
        <strong>Evidence Limitation &amp; Finding Semantics</strong>
        <p>
          Canonical evidence levels (`response_only`, `model_reported_intent`, `target_reported_claim`, `adapter_observed_request`, `independently_verified_execution`) classify observation provenance, whereas explicit execution verification requires `data.execution_verified: true` on collected evidence items.
          A `FAIL` verdict flags a policy/safety finding requiring inspection—it does not establish confirmed system compromise even when execution evidence is present, and operational `ERROR` cases reflect execution or provider faults rather than security pass/fail outcomes.
        </p>
      </div>

      {/* Skipped Cases Panel */}
      {skippedCases.length > 0 && (
        <section className="panel skipped-panel" aria-label="Skipped Cases Not Executed">
          <h3>Skipped Cases (Not Executed: {skippedCases.length})</h3>
          <p className="caption">
            These selected dataset testcases were skipped before execution and did not count toward Executed Cases or Judge verdict totals.
          </p>
          <div className="tablewrap">
            <table>
              <thead>
                <tr>
                  <th>Case ID</th>
                  <th>ASI Category</th>
                  <th>Preflight Status</th>
                  <th>Skip Reason</th>
                </tr>
              </thead>
              <tbody>
                {skippedCases.map(sc => (
                  <tr key={sc.case_id}>
                    <td><strong><code className="mono">{sc.case_id}</code></strong></td>
                    <td><span className="pill">{formatCaseAsiCategory(sc.asi_code || sc.category)}</span></td>
                    <td><span className="pill fail">{sc.status}</span></td>
                    <td><code className="mono">{sc.reason || 'skipped'}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Testcase Findings Compact Paginated Table + Filters */}
      <section className="card findings-card" aria-label="Testcase findings">
        <div className="card-head-row">
          <div>
            <h3>Testcase Findings</h3>
            <p className="caption">
              Click <strong>View details</strong> on any row to inspect the full original prompt, complete target response, Judge reasoning, evidence items, and raw report JSON.
            </p>
          </div>
          <span className="pill">{filteredCases.length} matching / {cases.length} total</span>
        </div>

        <div className="filters" role="search" aria-label="Filter testcase findings">
          <label className="filter-field grow">
            <span>Search</span>
            <input
              type="search"
              aria-label="Search testcase ID"
              placeholder="Search testcase ID..."
              value={searchQuery}
              onChange={e => {
                setSearchQuery(e.target.value);
                setPage(1);
              }}
            />
          </label>

          <label className="filter-field">
            <span>Verdict</span>
            <select
              aria-label="Filter by Verdict"
              value={verdictFilter}
              onChange={e => {
                setVerdictFilter(e.target.value);
                setPage(1);
              }}
            >
              <option value="ALL">All verdicts</option>
              <option value="PASS">PASS</option>
              <option value="FAIL">FAIL</option>
              {evalMetrics.isBinarySchema && evalMetrics.legacyInconclusiveCount === 0 ? (
                evalMetrics.technicalFailureCount > 0 && (
                  <option value="NOT_EVALUATED">Technical failures</option>
                )
              ) : (
                <>
                  <option value="INCONCLUSIVE">INCONCLUSIVE (legacy)</option>
                  <option value="ERROR">ERROR</option>
                </>
              )}
            </select>
          </label>

          <label className="filter-field">
            <span>ASI Category</span>
            <select
              aria-label="Filter by ASI category"
              value={asiFilter}
              onChange={e => {
                setAsiFilter(e.target.value);
                setPage(1);
              }}
            >
              <option value="ALL">All ASI</option>
              {availableAsis.map(cat => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>
          </label>

          <label className="filter-field">
            <span>Evidence Level</span>
            <select
              aria-label="Filter by Evidence level"
              value={evidenceFilter}
              onChange={e => {
                setEvidenceFilter(e.target.value);
                setPage(1);
              }}
            >
              <option value="ALL">All evidence</option>
              {availableEvidenceLevels.map(ev => (
                <option key={ev} value={ev}>{formatEvidenceLevel(ev)}</option>
              ))}
            </select>
          </label>

          <button type="button" className="btn ghost sm" onClick={resetFilters}>
            Reset filters
          </button>
        </div>

        {cases.length === 0 ? (
          <div className="empty-box">No executed testcase results were recorded for this scan.</div>
        ) : filteredCases.length === 0 ? (
          <div className="empty-box">
            No matching testcases found for the active filters.{' '}
            <button type="button" className="btn ghost xs" onClick={resetFilters}>
              Clear filters
            </button>
          </div>
        ) : (
          <>
            <div className="tablewrap">
              <table className="case-table">
                <thead>
                  <tr>
                    <th>Case ID</th>
                    <th>ASI</th>
                    <th>Verdict</th>
                    <th>Judge classification</th>
                    <th>Evidence level</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {pagedCases.map(c => {
                    const fault = classifyJudgeFault(c, judgeOptions);
                    return (
                      <tr key={c.case_id} className={selectedCase?.case_id === c.case_id ? 'selected-row' : undefined}>
                        <td>
                          <code className="mono">{c.case_id}</code>
                        </td>
                        <td>
                          <span className="pill">{formatCaseAsiCategory(c.category)}</span>
                        </td>
                        <td>
                          <div className="cell-stack">
                            <span className={verdictBadgeClass(c.verdict, c.evaluation_status)}>
                              {c.verdict
                                ? normalizeVerdict(c.verdict, c.evaluation_status)
                                : formatEvaluationStatus(c.evaluation_status)}
                            </span>
                            {!c.verdict && c.evaluation_reason_code && (
                              <span className="sublabel mono">{c.evaluation_reason_code}</span>
                            )}
                            {typeof c.http_status_code === 'number' && c.http_status_code >= 400 && (
                              <span className="sublabel mono">
                                HTTP {c.http_status_code}
                                {typeof c.duration_ms === 'number' ? ` · ${(c.duration_ms / 1000).toFixed(1)}s` : ''}
                              </span>
                            )}
                          </div>
                        </td>
                        <td>
                          <div className="cell-stack">
                            <strong className={fault.isProviderFault ? 'warn-text' : undefined}>{fault.primary}</strong>
                            {fault.secondary && (
                              <span className="sublabel mono">{fault.secondary}</span>
                            )}
                          </div>
                        </td>
                        <td>
                          <span className="pill">{formatEvidenceLevel(c.evidence_level)}</span>
                        </td>
                        <td>
                          <button
                            type="button"
                            className="btn ghost sm"
                            onClick={e => {
                              lastTriggerRef.current = e.currentTarget;
                              setSelectedCase(c);
                            }}
                          >
                            View details
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="pagebar" role="navigation" aria-label="Testcase pagination">
              <span className="pagebar-summary">
                Showing {startIdx + 1}–{endIdx} of {filteredCases.length} matching · {cases.length} total
              </span>

              <div className="pagebar-controls">
                <label className="rows-label">
                  <span>Rows</span>
                  <select
                    aria-label="Rows per page"
                    value={pageSize}
                    onChange={e => {
                      setPageSize(Number(e.target.value));
                      setPage(1);
                    }}
                  >
                    <option value={10}>10</option>
                    <option value={20}>20</option>
                    <option value={50}>50</option>
                  </select>
                </label>

                <button
                  type="button"
                  className="btn ghost sm"
                  disabled={safePage <= 1}
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                >
                  ‹ Previous
                </button>
                <span className="page-indicator">
                  Page {safePage} / {totalPages}
                </span>
                <button
                  type="button"
                  className="btn ghost sm"
                  disabled={safePage >= totalPages}
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                >
                  Next ›
                </button>
              </div>
            </div>
          </>
        )}
      </section>

      <TestcaseDetailDrawer
        testcase={selectedCase}
        runRecord={runRecord}
        onClose={() => setSelectedCase(null)}
        returnFocusTo={lastTriggerRef.current}
      />
    </section>
  );
}
