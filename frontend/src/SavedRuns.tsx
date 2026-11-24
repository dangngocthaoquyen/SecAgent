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

  const caseRunToGenericRunMap = useMemo(() => {
    const map = new Map<string, GenericRunSummary>();
    for (const gr of genericRuns) {
      for (const cid of gr.case_run_ids ?? []) {
        if (cid) map.set(cid, gr);
      }
    }
    return map;
  }, [genericRuns]);

  const filteredGenericRuns = useMemo(() => {
    return genericRuns.filter(gr => {
      if (filters.target_id && gr.target_id !== filters.target_id) return false;
      if (filters.asi_category) {
        const asiSummary = deriveRunAsiSummary(gr);
        if (filters.asi_category === 'unknown') {
          if (!asiSummary.hasUnknown && asiSummary.codes.length > 0) return false;
        } else if (!asiSummary.codes.includes(filters.asi_category)) {
          return false;
        }
      }
      if (filters.testcase_id) {
        if (!Array.isArray(gr.testcase_ids) || !gr.testcase_ids.includes(filters.testcase_id)) {
          return false;
        }
      }
      if (filters.verdict && !(Number(gr.verdict_counts?.[filters.verdict] ?? 0) > 0)) return false;
      const runDate = (gr.started_at || gr.completed_at || '').slice(0, 10);
      if (filters.date_from && (!runDate || runDate < filters.date_from)) return false;
      if (filters.date_to && (!runDate || runDate > filters.date_to)) return false;
      return true;
    });
  }, [genericRuns, filters]);

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

  const liveRunsCount = genericRuns.filter(r => r.mode === 'live').length;
  const activeExpandedDetail =
    expandedRunDetail && expandedRunDetail.generic_run_id === expandedRunId ? expandedRunDetail : null;

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
    <section className="panel results-panel history-shell" aria-label="Saved run history">
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
            {genericAuthRequired ? 'Locked' : genericError ? 'Unavailable' : filteredGenericRuns.length}
          </div>
          <div className="s">
            {genericAuthRequired
              ? 'Unlock operator secret to list scan runs'
              : genericError
                ? 'Workflow API unavailable'
                : `${genericRuns.length} total recorded on disk`}
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
                : `${genericRuns.length - liveRunsCount} offline stored-response runs`}
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
          Scan Runs ({filteredGenericRuns.length})
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
          {filteredGenericRuns.length > 0 ? (
            <>
              <div className="section-title">
                <div>
                  <span className="eyebrow">VIEW A · SCAN RUNS</span>
                  <h3>Grouped Scan Runs ({filteredGenericRuns.length})</h3>
                  <p>
                    Each row represents one Scan execution. Expand a run to preview individual testcases or open its full Scan Results page.
                  </p>
                </div>
              </div>

              <div className="tablewrap">
                <table className="history-table">
                  <thead>
                    <tr>
                      <th>Date / Run ID</th>
                      <th>Target / Dataset</th>
                      <th>ASI / Mode</th>
                      <th>Cases</th>
                      <th>Verdicts</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredGenericRuns.map(gr => {
                      const vc = computeVerdictCounts(gr);
                      const barTotal = Math.max(1, vc.PASS + vc.FAIL + vc.INCONCLUSIVE + vc.ERROR);
                      const isExpanded = expandedRunId === gr.generic_run_id;
                      const asiSummary = deriveRunAsiSummary(gr);
                      return (
                        <tr key={gr.generic_run_id} className={isExpanded ? 'selected-row' : undefined}>
                          <td>
                            <div className="cell-stack">
                              <span>{safeLabel(formatDateTime(gr.started_at || gr.completed_at))}</span>
                              <code className="mono sublabel">{gr.generic_run_id.slice(0, 12)}</code>
                            </div>
                          </td>
                          <td>
                            <div className="cell-stack">
                              <strong>{safeLabel(gr.target_name || gr.target_id)}</strong>
                              <span className="sublabel">
                                {safeLabel(gr.dataset_name || gr.dataset_id || 'Direct cases')} ·{' '}
                                <code className="mono">{safeLabel(gr.target_id)}</code>
                              </span>
                            </div>
                          </td>
                          <td>
                            <div className="cell-stack">
                              <span className="pill">{safeLabel(asiSummary.label)}</span>
                              <span className="sublabel">
                                {gr.mode.toUpperCase()} · {gr.use_judge ? 'Hybrid' : 'Rule'}
                              </span>
                            </div>
                          </td>
                          <td>
                            <strong>{gr.executed_cases}</strong>
                            {gr.skipped_count > 0 && (
                              <span className="sublabel"> (+{gr.skipped_count} skipped)</span>
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
                            <span className={runStatusBadgeClass(gr.status)}>
                              {formatRunStatus(gr.status)}
                            </span>
                          </td>
                          <td>
                            <div className="history-actions">
                              <button
                                type="button"
                                className="btn ghost sm"
                                onClick={() => void toggleExpandRun(gr.generic_run_id)}
                              >
                                {isExpanded ? 'Hide Cases' : 'View Cases'}
                              </button>
                              <a className="btn ghost sm" href={`#scan/${gr.generic_run_id}`}>
                                Open Run Results →
                              </a>
                              <a
                                className="btn ghost sm"
                                href={testingApi.genericRunExportUrl(gr.generic_run_id)}
                                download={`secagent-generic-run-${gr.generic_run_id}.json`}
                                onClick={e => {
                                  if (operatorSecret) {
                                    e.preventDefault();
                                    void testingApi
                                      .downloadGenericRunReport(gr.generic_run_id, operatorSecret)
                                      .catch(err => {
                                        setError(err instanceof Error ? err.message : 'Failed to export summary JSON.');
                                      });
                                  }
                                }}
                              >
                                Export Summary JSON
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
                      <span className="eyebrow">VIEW B · CASES IN RUN</span>
                      <h4>
                        Run <code>{expandedRunId}</code> Case Breakdown (
                        {activeExpandedDetail?.cases.length ?? 0} executed cases)
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
                          {activeExpandedDetail.cases.map(c => {
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
                      const parentRun = caseRunToGenericRunMap.get(row.run_id);
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
                            {parentRun ? (
                              <a href={`#scan/${parentRun.generic_run_id}`}>
                                Scan Run <code>{parentRun.generic_run_id.slice(0, 8)}</code>
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
