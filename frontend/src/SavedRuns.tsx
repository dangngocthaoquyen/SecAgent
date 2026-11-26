import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { api, emptySavedRunFilters, safeLabel, type SavedRunFilters, type SavedRunsPage } from './api';
import { Badge } from './components';
import DownloadReport from './DownloadReport';
import {
  classifyJudgeFault,
  computeVerdictCounts,
  deriveRunAsiSummary,
  formatCaseAsiCategory,
  formatDateTime,
  formatEvidenceLevel,
  formatRunStatus,
  normalizeVerdict,
  runStatusBadgeClass,
  safePercent,
  verdictBadgeClass,
} from './scanFormatters';
import { groupLogicalScans, resolveRootRunId, type LogicalScanGroup } from './scanLineage';
import {
  getEphemeralOperatorSecret,
  setEphemeralOperatorSecret,
  testingApi,
  type GenericRunRecord,
  type GenericRunSummary,
} from './testingApi';

export type HistoryTab = 'runs' | 'native' | 'dataset';

export interface SavedRunsProps {
  secret?: string;
  includeSelectedDataset?: boolean;
  selectedDatasetCount?: number | null;
  selectedDatasetAvailable?: boolean;
  renderSelectedDataset?: () => ReactNode;
}

export default function SavedRuns({
  secret: propSecret,
  includeSelectedDataset = false,
  selectedDatasetCount = null,
  selectedDatasetAvailable = false,
  renderSelectedDataset,
}: SavedRunsProps = {}) {
  const [draft, setDraft] = useState<SavedRunFilters>({ ...emptySavedRunFilters });
  const [filters, setFilters] = useState<SavedRunFilters>({ ...emptySavedRunFilters });
  const [page, setPage] = useState(1);
  const [retry, setRetry] = useState(0);
  const [data, setData] = useState<SavedRunsPage | null>(null);
  const [error, setError] = useState('');

  const [operatorSecret, setOperatorSecret] = useState<string>(() => propSecret ?? getEphemeralOperatorSecret());
  const [secretInput, setSecretInput] = useState<string>('');
  const [genericAuthRequired, setGenericAuthRequired] = useState(false);
  const [genericAuthError, setGenericAuthError] = useState('');
  const [genericError, setGenericError] = useState('');
  const [genericRuns, setGenericRuns] = useState<GenericRunSummary[]>([]);
  const [genericLoaded, setGenericLoaded] = useState(false);

  const [expandedRunId, setExpandedRunId] = useState<string>('');
  const [expandedRunDetail, setExpandedRunDetail] = useState<GenericRunRecord | null>(null);
  const [expandedRunError, setExpandedRunError] = useState<string>('');
  const [loadingRunDetail, setLoadingRunDetail] = useState(false);
  const [nativeScope, setNativeScope] = useState<'all' | 'ungrouped'>('all');
  const [selectedTab, setSelectedTab] = useState<HistoryTab | null>(null);

  const detailRequestSeqRef = useRef(0);

  useEffect(() => {
    if (propSecret && propSecret !== operatorSecret) {
      setOperatorSecret(propSecret);
      setEphemeralOperatorSecret(propSecret);
    }
  }, [propSecret, operatorSecret]);

  useEffect(() => {
    const controller = new AbortController();
    setGenericError('');
    testingApi
      .listGenericRuns(operatorSecret, '')
      .then(runs => {
        if (!controller.signal.aborted && Array.isArray(runs)) {
          setGenericAuthRequired(false);
          setGenericAuthError('');
          setGenericRuns(runs);
          setGenericLoaded(true);
        }
      })
      .catch(e => {
        if (controller.signal.aborted) return;
        const msg = e instanceof Error ? e.message : '';
        if (msg.includes('operator_authentication_required') || msg.includes('HTTP 403')) {
          setGenericAuthRequired(true);
          setGenericLoaded(false);
          if (operatorSecret) {
            setGenericAuthError('Operator authentication rejected.');
          }
        } else if (msg) {
          setGenericError(msg);
          setGenericLoaded(false);
        }
      });
    return () => controller.abort();
  }, [retry, operatorSecret]);

  useEffect(() => {
    const controller = new AbortController();
    setError('');
    api
      .savedRuns(filters, page, 25, controller.signal)
      .then(setData)
      .catch(e => {
        if (!controller.signal.aborted) {
          setError(e instanceof Error ? e.message : 'Saved history unavailable.');
        }
      });
    return () => controller.abort();
  }, [filters, page, retry]);

  const logicalScans = useMemo(() => groupLogicalScans(genericRuns), [genericRuns]);

  const caseRunToGenericRunMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const gr of genericRuns) {
      const logicalId = resolveRootRunId(gr);
      for (const cid of gr.case_run_ids ?? []) {
        if (cid) map.set(cid, logicalId);
      }
    }
    return map;
  }, [genericRuns]);

  const filteredLogicalScans = useMemo(() => {
    return logicalScans.filter(lg => {
      if (filters.target_id && lg.target_id !== filters.target_id) return false;
      if (filters.asi_category) {
        const asiSummary = deriveRunAsiSummary(lg);
        if (filters.asi_category === 'unknown') {
          if (!asiSummary.hasUnknown && asiSummary.codes.length > 0) return false;
        } else if (!asiSummary.codes.includes(filters.asi_category)) {
          return false;
        }
      }
      if (filters.testcase_id) {
        if (!Array.isArray(lg.testcase_ids) || !lg.testcase_ids.includes(filters.testcase_id)) {
          return false;
        }
      }
      if (filters.verdict && !(Number(lg.verdict_counts?.[filters.verdict] ?? 0) > 0)) return false;
      const runDate = (lg.started_at || lg.completed_at || '').slice(0, 10);
      if (filters.date_from && (!runDate || runDate < filters.date_from)) return false;
      if (filters.date_to && (!runDate || runDate > filters.date_to)) return false;
      return true;
    });
  }, [logicalScans, filters]);

  async function toggleExpandRun(runId: string) {
    const reqSeq = ++detailRequestSeqRef.current;
    if (expandedRunId === runId) {
      setExpandedRunId('');
      setExpandedRunDetail(null);
      setExpandedRunError('');
      setLoadingRunDetail(false);
      return;
    }
    setExpandedRunId(runId);
    setExpandedRunDetail(null);
    setExpandedRunError('');
    setLoadingRunDetail(true);
    try {
      const detail = await testingApi.getGenericRun(runId, operatorSecret, '');
      if (detailRequestSeqRef.current !== reqSeq) return;
      if (detail.generic_run_id !== runId) {
        setExpandedRunDetail(null);
        setExpandedRunError('Returned scan run record did not match requested Run ID.');
        return;
      }
      setExpandedRunDetail(detail);
    } catch (e) {
      if (detailRequestSeqRef.current !== reqSeq) return;
      const msg = e instanceof Error ? e.message : '';
      if (msg.includes('operator_authentication_required') || msg.includes('HTTP 403')) {
        setGenericAuthRequired(true);
        setExpandedRunError('Operator authentication is required to inspect testcase details for this Scan Run.');
      } else {
        setExpandedRunError(msg || 'Unable to load testcase breakdown for this Scan Run.');
      }
      setExpandedRunDetail(null);
    } finally {
      if (detailRequestSeqRef.current === reqSeq) {
        setLoadingRunDetail(false);
      }
    }
  }

  const edit = (key: keyof SavedRunFilters, value: string) =>
    setDraft(current => ({ ...current, [key]: value }));

  const displayedItems = useMemo(() => {
    if (!data) return [];
    if (nativeScope === 'ungrouped') {
      return data.items.filter(row => !caseRunToGenericRunMap.has(row.run_id));
    }
    return data.items;
  }, [data, nativeScope, caseRunToGenericRunMap]);

  const liveRunsCount = logicalScans.filter(r => r.mode === 'live').length;
  const activeExpandedDetail =
    expandedRunDetail &&
    (expandedRunDetail.generic_run_id === expandedRunId ||
      expandedRunDetail.unified_lineage?.root_run_id === expandedRunId)
      ? expandedRunDetail
      : null;
  const expandedGroup: LogicalScanGroup | null =
    expandedRunId ? (logicalScans.find(lg => lg.logicalScanId === expandedRunId) ?? null) : null;
  const activeExpandedCases = activeExpandedDetail?.unified_lineage?.cases ?? activeExpandedDetail?.cases ?? [];
  const activeExpandedSessions = activeExpandedDetail?.unified_lineage?.sessions ?? [];

  const activeTab: HistoryTab =
    selectedTab ??
    (genericRuns.length > 0 || genericAuthRequired
      ? 'runs'
      : includeSelectedDataset && selectedDatasetAvailable
        ? 'dataset'
        : (data?.items.length ?? 0) > 0
          ? 'native'
          : 'runs');

  return (
    <section className="panel history-shell" aria-label="Saved run history">
      <div className="page-title">
        <div>
          <span className="eyebrow">PERSISTENT HISTORY · LIVE DISCOVERY</span>
          <h2>Saved Native Reports</h2>
          <p>
            Generic Scan Runs are discovered from disk on each request. Native Reporting snapshots reflect files discovered when the Reporting service started; click Refresh or reload the snapshot to inspect newly persisted artifacts.
          </p>
        </div>
        <button type="button" className="btn ghost sm" onClick={() => setRetry(n => n + 1)}>
          Refresh History
        </button>
      </div>

      {/* 3 Honest Summary KPI Cards */}
      <div className="cards history-kpis" role="region" aria-label="Execution history metrics">
        <article className="metric">
          <div className="k">Scan Runs</div>
          <div className="v">
            {genericAuthRequired ? 'Locked' : genericError ? 'Unavailable' : filteredLogicalScans.length}
          </div>
          <div className="s">
            {genericAuthRequired
              ? 'Unlock operator secret to list scan runs'
              : genericError
                ? 'Workflow API unavailable'
                : genericRuns.length > logicalScans.length
                  ? `${logicalScans.length} logical scan(s) · ${genericRuns.length} sessions on disk`
                  : `${logicalScans.length} total recorded on disk`}
          </div>
        </article>
        <article className="metric">
          <div className="k">Native Reports</div>
          <div className="v">{data ? data.total : error ? 'Unavailable' : '...'}</div>
          <div className="s">
            {data
              ? `${data.invalid_artifact_count > 0 ? `${data.invalid_artifact_count} invalid excluded` : 'Reporting API index'}`
              : 'Persisted native artifacts'}
          </div>
        </article>
        <article className="metric">
          <div className="k">Live Runs</div>
          <div className="v">
            {genericAuthRequired ? 'Locked' : genericError || !genericLoaded ? 'Unavailable' : liveRunsCount}
          </div>
          <div className="s">
            {genericAuthRequired
              ? 'Unlock required'
              : genericError || !genericLoaded
                ? 'Mode counts not loaded'
                : `${logicalScans.length - liveRunsCount} offline stored-response runs`}
          </div>
        </article>
      </div>

      {genericAuthRequired && (
        <div className="card auth-unlock-card" aria-label="Operator Authentication for Grouped Scan Runs">
          <p role="status">
            <strong>Operator Authentication Required:</strong> Enter the Operator Secret to load, inspect, and export Grouped Generic Scan Runs in authenticated operator mode.
          </p>
          {genericAuthError && (
            <p className="notice error" role="alert">
              {genericAuthError}
            </p>
          )}
          <div className="inline-row">
            <label htmlFor="saved-runs-operator-secret">
              Operator Secret
              <input
                id="saved-runs-operator-secret"
                type="password"
                value={secretInput}
                onChange={e => setSecretInput(e.target.value)}
              />
            </label>
            <button
              type="button"
              className="btn primary"
              disabled={!secretInput.trim()}
              onClick={() => {
                const trimmed = secretInput.trim();
                setEphemeralOperatorSecret(trimmed);
                setOperatorSecret(trimmed);
                setRetry(n => n + 1);
              }}
            >
              Unlock Scan Runs
            </button>
          </div>
        </div>
      )}

      {/* Shared Filters Toolbar for Scan Runs and Native Reports */}
      {activeTab !== 'dataset' && (
        <form
          className="filters history-filters"
          onSubmit={e => {
            e.preventDefault();
            if (draft.date_from && draft.date_to && draft.date_from > draft.date_to) {
              setError('Date from must not be after Date to.');
              return;
            }
            setError('');
            setPage(1);
            setFilters({
              ...draft,
              testcase_id: draft.testcase_id.trim(),
              target_id: draft.target_id.trim(),
            });
          }}
        >
          <label>
            ASI
            <select value={draft.asi_category} onChange={e => edit('asi_category', e.target.value)}>
              <option value="">All</option>
              {['ASI01', 'ASI02', 'ASI03', 'ASI05'].map(v => (
                <option key={v}>{v}</option>
              ))}
              <option value="unknown">Unknown</option>
            </select>
          </label>
          <label>
            Target ID
            <input value={draft.target_id} onChange={e => edit('target_id', e.target.value)} maxLength={256} />
          </label>
          <label>
            Testcase ID
            <input value={draft.testcase_id} onChange={e => edit('testcase_id', e.target.value)} maxLength={256} />
          </label>
          <label>
            Verdict / Outcome
            <select value={draft.verdict} onChange={e => edit('verdict', e.target.value)}>
              <option value="">All</option>
              {['PASS', 'FAIL', 'INCONCLUSIVE', 'ERROR'].map(v => (
                <option key={v} value={v}>
                  {v === 'ERROR' ? 'ERROR (execution error)' : v}
                </option>
              ))}
            </select>
          </label>
          <label>
            Date from
            <input type="date" value={draft.date_from} onChange={e => edit('date_from', e.target.value)} />
          </label>
          <label>
            Date to
            <input type="date" value={draft.date_to} onChange={e => edit('date_to', e.target.value)} />
          </label>
          <div className="filter-actions">
            <button type="submit" className="btn primary sm">Filter</button>
            <button
              type="button"
              className="btn ghost sm"
              onClick={() => {
                setError('');
                setDraft({ ...emptySavedRunFilters });
                setFilters({ ...emptySavedRunFilters });
                setPage(1);
              }}
            >
              Reset
            </button>
            <button type="button" className="btn ghost sm" onClick={() => setRetry(n => n + 1)}>
              Refresh
            </button>
          </div>
        </form>
      )}

      {/* Consolidated Tab Navigation: Scan Runs vs Native Reports vs Selected Dataset */}
      <div className="tabs" role="tablist" aria-label="History report views">
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'runs'}
          className={`tab${activeTab === 'runs' ? ' active' : ''}`}
          onClick={() => setSelectedTab('runs')}
        >
          Scan Runs ({filteredLogicalScans.length})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'native'}
          className={`tab${activeTab === 'native' ? ' active' : ''}`}
          onClick={() => setSelectedTab('native')}
        >
          Native Reports ({data?.total ?? 0})
        </button>
        {includeSelectedDataset && (
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'dataset'}
            className={`tab${activeTab === 'dataset' ? ' active' : ''}`}
            onClick={() => setSelectedTab('dataset')}
          >
            Selected Dataset ({selectedDatasetCount ?? 0})
          </button>
        )}
      </div>

      {/* TAB 1: GROUPED SCAN RUNS */}
      {activeTab === 'runs' && (
        <div className="history-tab-pane" aria-label="Grouped Generic Scan Runs" role="tabpanel">
          {filteredLogicalScans.length > 0 ? (
            <>
              <div className="section-title">
                <div>
                  <span className="eyebrow">VIEW A · SCAN RUNS</span>
                  <h3>Grouped Scan Runs ({filteredLogicalScans.length})</h3>
                  <p>
                    Each row represents one logical scan (grouping resumed continuation sessions under the original scan). Expand a scan to inspect deduplicated testcases or execution session history.
                  </p>
                </div>
              </div>

              <div className="tablewrap">
                <table className="history-table">
                  <thead>
                    <tr>
                      <th>Date / Scan ID</th>
                      <th>Target / Dataset</th>
                      <th>ASI / Mode</th>
                      <th>Cases</th>
                      <th>Verdicts</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredLogicalScans.map(lg => {
                      const vc = computeVerdictCounts({ verdict_counts: lg.verdict_counts } as GenericRunSummary);
                      const barTotal = Math.max(1, vc.PASS + vc.FAIL + vc.INCONCLUSIVE + vc.ERROR);
                      const isExpanded = expandedRunId === lg.logicalScanId;
                      const asiSummary = deriveRunAsiSummary(lg);
                      const canExportUnified = lg.has_continuations && lg.integrity_status !== 'invalid_checkpoint';
                      const exportHref = canExportUnified
                        ? testingApi.genericRunUnifiedExportUrl(lg.rootRunId)
                        : testingApi.genericRunExportUrl(lg.rootRunId);
                      const exportFilename = canExportUnified
                        ? `secagent-unified-scan-${lg.rootRunId}.json`
                        : `secagent-generic-run-${lg.rootRunId}.json`;
                      return (
                        <tr key={lg.logicalScanId} className={isExpanded ? 'selected-row' : undefined}>
                          <td>
                            <div className="cell-stack">
                              <span>{safeLabel(formatDateTime(lg.started_at || lg.completed_at))}</span>
                              <code className="mono sublabel">{lg.rootRunId.slice(0, 12)}</code>
                              {lg.resume_count > 0 && (
                                <span className="sublabel">
                                  {lg.resume_count} resume{lg.resume_count > 1 ? 's' : ''} · {lg.session_count} sessions
                                </span>
                              )}
                            </div>
                          </td>
                          <td>
                            <div className="cell-stack">
                              <strong>{safeLabel(lg.target_name || lg.target_id)}</strong>
                              <span className="sublabel">
                                {safeLabel(lg.dataset_name || lg.dataset_id || 'Direct cases')} ·{' '}
                                <code className="mono">{safeLabel(lg.target_id)}</code>
                              </span>
                            </div>
                          </td>
                          <td>
                            <div className="cell-stack">
                              <span className="pill">{safeLabel(asiSummary.label)}</span>
                              <span className="sublabel">
                                {lg.mode.toUpperCase()} · {lg.use_judge ? 'Hybrid' : 'Rule'}
                              </span>
                            </div>
                          </td>
                          <td>
                            <strong>{lg.executed_cases}</strong>
                            <span className="sublabel"> / {lg.selected_cases}</span>
                            {lg.skipped_count > 0 && (
                              <span className="sublabel"> (+{lg.skipped_count} skipped)</span>
                            )}
                          </td>
                          <td>
                            <div className="mini-verdict-cell">
                              <div className="bar mini" aria-hidden="true">
                                {vc.PASS > 0 && <span className="b-pass" style={{ width: `${safePercent(vc.PASS, barTotal)}%` }} />}
                                {vc.FAIL > 0 && <span className="b-fail" style={{ width: `${safePercent(vc.FAIL, barTotal)}%` }} />}
                                {vc.INCONCLUSIVE > 0 && <span className="b-inc" style={{ width: `${safePercent(vc.INCONCLUSIVE, barTotal)}%` }} />}
                                {vc.ERROR > 0 && <span className="b-err" style={{ width: `${safePercent(vc.ERROR, barTotal)}%` }} />}
                              </div>
                              <div className="mini-counts">
                                <span className="ok-text">{vc.PASS}P</span> ·{' '}
                                <span className="fail-text">{vc.FAIL}F</span> ·{' '}
                                <span className="warn-text">{vc.INCONCLUSIVE}I</span>
                                {vc.ERROR > 0 && <> · <span className="err-text">{vc.ERROR}E</span></>}
                              </div>
                            </div>
                          </td>
                          <td>
                            <span className={runStatusBadgeClass(lg.logical_status)}>
                              {formatRunStatus(lg.logical_status)}
                            </span>
                          </td>
                          <td>
                            <div className="history-actions">
                              <button
                                type="button"
                                className="btn ghost sm"
                                onClick={() => void toggleExpandRun(lg.rootRunId)}
                              >
                                {isExpanded ? 'Hide Cases' : 'View Cases'}
                              </button>
                              <a className="btn ghost sm" href={`#scan/${lg.rootRunId}`}>
                                Open Run Results →
                              </a>
                              <a
                                className="btn ghost sm"
                                href={exportHref}
                                download={exportFilename}
                                onClick={e => {
                                  if (operatorSecret) {
                                    e.preventDefault();
                                    const dl = canExportUnified
                                      ? testingApi.downloadGenericRunUnifiedReport(lg.rootRunId, operatorSecret)
                                      : testingApi.downloadGenericRunReport(lg.rootRunId, operatorSecret);
                                    void dl.catch(err => {
                                      setError(err instanceof Error ? err.message : 'Failed to export summary JSON.');
                                    });
                                  }
                                }}
                              >
                                {canExportUnified ? 'Export Unified Report JSON' : 'Export Summary JSON'}
                              </a>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {expandedRunId && (
                <div className="card expanded-run-panel" aria-label={`Cases in Run ${expandedRunId}`}>
                  <div className="section-title">
                    <div>
                      <span className="eyebrow">VIEW B · CASES IN SCAN</span>
                      <h4>
                        {expandedGroup && expandedGroup.session_count > 1 ? (
                          <>
                            Scan <code>{expandedRunId}</code> Case Breakdown ({activeExpandedCases.length} recorded
                            outcomes across {expandedGroup.session_count} execution sessions)
                          </>
                        ) : (
                          <>
                            Run <code>{expandedRunId}</code> Case Breakdown ({activeExpandedCases.length} executed cases)
                          </>
                        )}
                      </h4>
                    </div>
                    <a className="btn primary sm" href={`#scan/${expandedRunId}`}>
                      Open Full Scan Results →
                    </a>
                  </div>

                  {loadingRunDetail && (
                    <p role="status">
                      Loading cases for Run <code>{expandedRunId}</code>...
                    </p>
                  )}

                  {expandedRunError && (
                    <p className="notice error" role="alert">
                      {expandedRunError}
                    </p>
                  )}

                  {activeExpandedDetail && (
                    <>
                      {(activeExpandedSessions.length > 1 || (expandedGroup && expandedGroup.sessions.length > 1)) && (
                        <details style={{ marginBottom: '0.85rem' }}>
                          <summary style={{ cursor: 'pointer', fontWeight: 600 }}>
                            Execution History ({activeExpandedSessions.length || expandedGroup?.sessions.length || 0} sessions)
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
                                {(activeExpandedSessions.length > 0
                                  ? activeExpandedSessions
                                  : (expandedGroup?.sessions ?? []).map((s, idx) => ({
                                      session_index: idx + 1,
                                      generic_run_id: s.generic_run_id,
                                      status: s.status,
                                      started_at: s.started_at,
                                      executed_cases: s.executed_cases,
                                      verdict_counts: s.verdict_counts,
                                    }))
                                ).map(sess => {
                                  const svc = computeVerdictCounts({ verdict_counts: sess.verdict_counts } as GenericRunSummary);
                                  return (
                                    <tr key={sess.generic_run_id}>
                                      <td>
                                        <strong>
                                          {sess.session_index === 1 ? 'Original' : `Resume #${sess.session_index - 1}`}
                                        </strong>
                                      </td>
                                      <td>
                                        <code className="mono">{sess.generic_run_id.slice(0, 12)}</code>
                                      </td>
                                      <td>{safeLabel(formatDateTime(sess.started_at))}</td>
                                      <td>{sess.executed_cases}</td>
                                      <td>
                                        {svc.PASS}P · {svc.FAIL}F · {svc.INCONCLUSIVE}I
                                        {svc.ERROR > 0 ? ` · ${svc.ERROR}E` : ''}
                                      </td>
                                      <td>
                                        <span className={runStatusBadgeClass(sess.status)}>
                                          {formatRunStatus(sess.status)}
                                        </span>
                                      </td>
                                      <td>
                                        <div className="history-actions">
                                          <a className="btn ghost sm" href={`#scan/${sess.generic_run_id}`}>
                                            Open Session
                                          </a>
                                          <a
                                            className="btn ghost sm"
                                            href={testingApi.genericRunExportUrl(sess.generic_run_id)}
                                            download={`secagent-generic-run-${sess.generic_run_id}.json`}
                                            onClick={e => {
                                              if (operatorSecret) {
                                                e.preventDefault();
                                                void testingApi
                                                  .downloadGenericRunReport(sess.generic_run_id, operatorSecret)
                                                  .catch(err => {
                                                    setError(err instanceof Error ? err.message : 'Failed to export session JSON.');
                                                  });
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

                      <div className="tablewrap">
                        <table className="case-table">
                          <thead>
                            <tr>
                              <th>Case ID</th>
                              <th>ASI Category</th>
                              <th>Verdict</th>
                              <th>Judge Classification</th>
                              <th>Evidence Level</th>
                              <th>Case Detail</th>
                              <th>Export Case Report</th>
                            </tr>
                          </thead>
                          <tbody>
                            {activeExpandedCases.map(c => {
                              const fault = classifyJudgeFault(c, {
                                useJudge: activeExpandedDetail.use_judge,
                                judgeMode: activeExpandedDetail.judge_metadata?.mode ?? null,
                              });
                              return (
                                <tr key={c.case_id}>
                                  <th scope="row">
                                    <code className="mono">{safeLabel(c.case_id)}</code>
                                  </th>
                                  <td>
                                    <span className="pill">{safeLabel(formatCaseAsiCategory(c.category))}</span>
                                  </td>
                                  <td>
                                    <span className={verdictBadgeClass(c.verdict)}>{normalizeVerdict(c.verdict)}</span>
                                  </td>
                                  <td>
                                    <div className="cell-stack">
                                      <strong>{fault.primary}</strong>
                                      {fault.secondary && <span className="sublabel mono">{fault.secondary}</span>}
                                    </div>
                                  </td>
                                  <td>
                                    <span className="pill">{formatEvidenceLevel(c.evidence_level)}</span>
                                  </td>
                                  <td>
                                    <a href={`#run/${c.run_id}`}>Inspect Case Detail</a>
                                  </td>
                                  <td>
                                    <DownloadReport kind="runs" id={c.run_id} />
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </>
                  )}
                </div>
              )}
            </>
          ) : (
            <div className="empty-box">
              {genericAuthRequired
                ? 'Operator unlock is required to display Grouped Scan Runs.'
                : genericError
                  ? `Unable to load Generic Scan Runs: ${genericError}`
                  : genericRuns.length === 0
                    ? 'No Generic Scan Runs found yet. Start a scan in New Scan to create one.'
                    : 'No Scan Runs match the current filter criteria.'}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: NATIVE REPORTS */}
      {activeTab === 'native' && (
        <div className="history-tab-pane" aria-label="Native SecAgent Reports" role="tabpanel">
          {genericRuns.length > 0 && (
            <div className="inline-row scope-toggle" style={{ marginBottom: '0.75rem' }}>
              <span>Native report grouping:</span>
              <button
                type="button"
                className={`btn ghost sm${nativeScope === 'all' ? ' active-pill' : ''}`}
                aria-pressed={nativeScope === 'all'}
                onClick={() => setNativeScope('all')}
              >
                All Native Reports ({data?.total ?? 0})
              </button>
              <button
                type="button"
                className={`btn ghost sm${nativeScope === 'ungrouped' ? ' active-pill' : ''}`}
                aria-pressed={nativeScope === 'ungrouped'}
                onClick={() => setNativeScope('ungrouped')}
              >
                Legacy / Ungrouped Reports
              </button>
            </div>
          )}

          {error && <p className="notice error" role="alert">{error}</p>}

          {data && (
            <>
              <p role="status" className="caption" style={{ marginBottom: '0.5rem' }}>
                {data.total} saved reports
                {data.invalid_artifact_count > 0 ? `; ${data.invalid_artifact_count} invalid artifacts excluded` : ''}.
              </p>

              <div className="tablewrap">
                <table className="history-table">
                  <thead>
                    <tr>
                      <th>Date</th>
                      <th>Testcase</th>
                      <th>ASI</th>
                      <th>Target</th>
                      <th>Outcome / Verdict</th>
                      <th>Source / Run Group</th>
                      <th>Export</th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayedItems.map(row => {
                      const parentLogicalId = caseRunToGenericRunMap.get(row.run_id);
                      return (
                        <tr key={`${row.kind}-${row.run_id}`}>
                          <td>{safeLabel(row.started_at)}</td>
                          <th scope="row">
                            <a href={`#${row.kind === 'mcp_action' ? 'mcp-run' : 'run'}/${row.run_id}`}>
                              {safeLabel(row.testcase_id)}
                            </a>
                          </th>
                          <td>
                            <span className="pill">{safeLabel(formatCaseAsiCategory(row.asi_category))}</span>
                          </td>
                          <td>
                            <code className="mono">{safeLabel(row.target_id)}</code>
                          </td>
                          <td>
                            <Badge value={row.verdict} />
                          </td>
                          <td>
                            {parentLogicalId ? (
                              <a href={`#scan/${parentLogicalId}`}>
                                Scan Run <code>{parentLogicalId.slice(0, 8)}</code>
                              </a>
                            ) : (
                              <span>
                                {row.kind === 'mcp_action' ? 'MCP action' : 'Controlled run'}{' '}
                                <small>(Legacy / Ungrouped)</small>
                              </span>
                            )}
                          </td>
                          <td>
                            <DownloadReport kind={row.kind === 'mcp_action' ? 'mcp-runs' : 'runs'} id={row.run_id} />
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <div className="pagebar" role="navigation" aria-label="Native reports pagination">
                <span>
                  Page {page} of {Math.max(1, Math.ceil(data.total / 25))}
                </span>
                <div className="pagebar-controls">
                  <button
                    type="button"
                    className="btn ghost sm"
                    disabled={page <= 1}
                    onClick={() => setPage(n => n - 1)}
                  >
                    Previous
                  </button>
                  <button
                    type="button"
                    className="btn ghost sm"
                    disabled={page * 25 >= data.total}
                    onClick={() => setPage(n => n + 1)}
                  >
                    Next
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* TAB 3: SELECTED DATASET (REPORTING SNAPSHOT EXECUTIONS) */}
      {includeSelectedDataset && activeTab === 'dataset' && (
        <div className="history-tab-pane" aria-label="Selected Dataset Execution Results" role="tabpanel">
          {renderSelectedDataset?.()}
        </div>
      )}
    </section>
  );
}
