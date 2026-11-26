import { useEffect, useId, useRef, useState } from 'react';
import {
  classifyJudgeFault,
  copyTextToClipboard,
  downloadJsonFile,
  formatCaseAsiCategory,
  formatEvaluationReasonCode,
  formatEvaluationStatus,
  formatEvidenceLevel,
  formatInvocationStatus,
  formatProviderModel,
  formatResponseCompleteness,
  normalizeVerdict,
  summarizeCaseEvidenceVerification,
  verdictBadgeClass,
} from './scanFormatters';
import type { GenericRunCaseResult, GenericRunRecord } from './testingApi';

export type DrawerTab = 'overview' | 'prompt' | 'response' | 'judge' | 'evidence' | 'raw';

const TABS: { id: DrawerTab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'prompt', label: 'Prompt' },
  { id: 'response', label: 'Target Response' },
  { id: 'judge', label: 'Judge Evaluation' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'raw', label: 'Raw Report' },
];

export interface TestcaseDetailDrawerProps {
  testcase: GenericRunCaseResult | null;
  runRecord: GenericRunRecord;
  onClose: () => void;
  returnFocusTo?: HTMLElement | null;
}

export default function TestcaseDetailDrawer({
  testcase,
  runRecord,
  onClose,
  returnFocusTo,
}: TestcaseDetailDrawerProps) {
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const closeBtnRef = useRef<HTMLButtonElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const titleId = useId();

  const [activeTab, setActiveTab] = useState<DrawerTab>('overview');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [nativeReportState, setNativeReportState] = useState<{
    caseRunId: string;
    loading: boolean;
    payload: unknown | null;
    error: string | null;
  } | null>(null);

  useEffect(() => {
    if (!testcase) return;
    setActiveTab('overview');
    setCopiedKey(null);
    setNativeReportState(null);
  }, [testcase?.case_id, testcase?.run_id]);

  useEffect(() => {
    const el = dialogRef.current;
    if (!el) return;

    if (testcase) {
      previousFocusRef.current = returnFocusTo ?? (document.activeElement instanceof HTMLElement ? document.activeElement : null);
      if (!el.hasAttribute('open')) {
        if (typeof el.showModal === 'function') {
          try {
            el.showModal();
          } catch {
            el.setAttribute('open', '');
          }
        } else {
          el.setAttribute('open', '');
        }
      }
      queueMicrotask(() => {
        closeBtnRef.current?.focus();
      });

      const onKeyDown = (e: KeyboardEvent) => {
        if (e.key === 'Escape') {
          e.preventDefault();
          handleClose();
        }
      };
      document.addEventListener('keydown', onKeyDown);
      return () => {
        document.removeEventListener('keydown', onKeyDown);
      };
    }

    if (el.hasAttribute('open')) {
      if (typeof el.close === 'function') {
        try {
          el.close();
        } catch {
          el.removeAttribute('open');
        }
      } else {
        el.removeAttribute('open');
      }
    }
    return undefined;
  }, [testcase]);

  function handleClose() {
    const el = dialogRef.current;
    if (el?.hasAttribute('open')) {
      if (typeof el.close === 'function') {
        try {
          el.close();
        } catch {
          el.removeAttribute('open');
        }
      } else {
        el.removeAttribute('open');
      }
    }
    const targetToFocus = returnFocusTo ?? previousFocusRef.current;
    onClose();
    if (targetToFocus && targetToFocus.isConnected) {
      queueMicrotask(() => {
        targetToFocus.focus();
      });
    }
  }

  async function handleCopy(key: string, text: string) {
    const ok = await copyTextToClipboard(text);
    setCopiedKey(ok ? key : `${key}-unavailable`);
    window.setTimeout(() => {
      setCopiedKey(prev => (prev === key || prev === `${key}-unavailable` ? null : prev));
    }, 1800);
  }

  async function handleFetchNativeReport() {
    if (!testcase?.run_id) return;
    setNativeReportState({ caseRunId: testcase.run_id, loading: true, payload: null, error: null });
    try {
      const resp = await fetch(`/api/reports/runs/${encodeURIComponent(testcase.run_id)}`, {
        method: 'GET',
        credentials: 'omit',
        cache: 'no-store',
      });
      if (!resp.ok) {
        throw new Error(`Native report request returned HTTP ${resp.status}.`);
      }
      const json = (await resp.json()) as unknown;
      setNativeReportState({ caseRunId: testcase.run_id, loading: false, payload: json, error: null });
    } catch (err) {
      setNativeReportState({
        caseRunId: testcase.run_id,
        loading: false,
        payload: null,
        error: err instanceof Error ? err.message : 'Unable to fetch native SecAgent report.',
      });
    }
  }

  if (!testcase) {
    return <dialog ref={dialogRef} className="detail-drawer" aria-hidden="true" />;
  }

  const judgeOptions = {
    useJudge: runRecord.use_judge,
    judgeMode: runRecord.judge_metadata?.mode ?? null,
  };
  const faultInfo = classifyJudgeFault(testcase, judgeOptions);
  const verdict = normalizeVerdict(testcase.verdict, testcase.evaluation_status);
  const verdictDisplay = testcase.verdict ? verdict : formatEvaluationStatus(testcase.evaluation_status);
  const caseEvidence = summarizeCaseEvidenceVerification(testcase);
  const responseText = testcase.response_text ?? '';
  const hasResponse = testcase.response_text !== null && testcase.response_text !== '';
  const completenessLabel = formatResponseCompleteness(testcase.response_complete);
  const showingNativePayload = nativeReportState && nativeReportState.caseRunId === testcase.run_id && nativeReportState.payload !== null;

  const executionVerifiedSummary =
    caseEvidence.hasVerifiedExecution
      ? 'Yes'
      : caseEvidence.totalItems > 0 && caseEvidence.unknownItemCount === caseEvidence.totalItems
        ? 'Not recorded'
        : 'No';

  return (
    <dialog
      ref={dialogRef}
      className="detail-drawer"
      aria-labelledby={titleId}
      aria-modal="true"
      onCancel={e => {
        e.preventDefault();
        handleClose();
      }}
      onClick={e => {
        if (e.target === dialogRef.current) {
          handleClose();
        }
      }}
    >
      <div className="drawer-surface" onClick={e => e.stopPropagation()}>
        <header className="drawer-head">
          <div className="drawer-title-group">
            <div className="drawer-badges">
              <span className="pill">{formatCaseAsiCategory(testcase.category)}</span>
              <span className={verdictBadgeClass(testcase.verdict, testcase.evaluation_status)}>{verdictDisplay}</span>
              {!testcase.verdict && testcase.evaluation_reason_code && (
                <span className="pill">{formatEvaluationReasonCode(testcase.evaluation_reason_code)}</span>
              )}
              {faultInfo.isProviderFault && (
                <span className="pill warn">{faultInfo.primary}</span>
              )}
              {testcase.execution_status && (
                <span className="pill">Execution: {testcase.execution_status}</span>
              )}
            </div>
            <h3 id={titleId} className="mono">{testcase.case_id}</h3>
            <p className="drawer-sub">
              Target: <strong>{runRecord.target_name}</strong> · Run <code className="mono">{runRecord.generic_run_id}</code>
            </p>
          </div>
          <button
            ref={closeBtnRef}
            type="button"
            className="btn ghost sm"
            onClick={handleClose}
            aria-label="Close testcase detail drawer"
          >
            Close ×
          </button>
        </header>

        <nav className="drawer-tabs" role="tablist" aria-label="Testcase inspection sections">
          {TABS.map(tab => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={activeTab === tab.id}
              className={`tab${activeTab === tab.id ? ' active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </nav>

        <div className="drawer-body" role="tabpanel">
          {activeTab === 'overview' && (
            <div className="drawer-stack">
              {faultInfo.isProviderFault && (
                <div className="notice warn" role="status">
                  <strong>Judge Provider Fault Recorded ({faultInfo.rawCode ?? 'provider_fault'})</strong>
                  <p>
                    The semantic Judge encountered an operational fault ({faultInfo.primary}). This outcome is tracked separately from semantic <code>UNCLEAR</code> decisions and does not imply confirmed target exploitation.
                  </p>
                </div>
              )}

              <div className="detail-grid">
                <div className="detail-pair">
                  <span>Case ID</span>
                  <strong className="mono">{testcase.case_id}</strong>
                </div>
                <div className="detail-pair">
                  <span>ASI Category</span>
                  <strong>{formatCaseAsiCategory(testcase.category, true)}</strong>
                </div>
                <div className="detail-pair">
                  <span>Verdict</span>
                  <strong><span className={verdictBadgeClass(verdict)}>{verdict}</span></strong>
                </div>
                <div className="detail-pair">
                  <span>Judge Classification</span>
                  <strong>
                    {faultInfo.primary}
                    {faultInfo.secondary && <span className="muted-inline"> · {faultInfo.secondary}</span>}
                  </strong>
                </div>
                <div className="detail-pair">
                  <span>Canonical Evidence Level</span>
                  <strong>{formatEvidenceLevel(testcase.evidence_level, true)}</strong>
                </div>
                <div className="detail-pair">
                  <span>Execution Verification</span>
                  <strong>
                    {caseEvidence.verifiedItemCount} of {caseEvidence.totalItems} items (Execution verified: {executionVerifiedSummary})
                  </strong>
                </div>
                <div className="detail-pair">
                  <span>Execution Status</span>
                  <strong>{testcase.execution_status || 'Not recorded'}</strong>
                </div>
                <div className="detail-pair">
                  <span>Response Completeness</span>
                  <strong>{completenessLabel}</strong>
                </div>
                <div className="detail-pair">
                  <span>Provenance Tiers</span>
                  <strong>{(testcase.provenance_tiers ?? []).length > 0 ? testcase.provenance_tiers.join(', ') : 'Not recorded'}</strong>
                </div>
                <div className="detail-pair">
                  <span>Case Run ID</span>
                  <strong>
                    {testcase.run_id ? (
                      <a href={`#run/${encodeURIComponent(testcase.run_id)}`} className="mono">
                        {testcase.run_id}
                      </a>
                    ) : 'Not recorded'}
                  </strong>
                </div>
                <div className="detail-pair">
                  <span>Report Path</span>
                  <strong className="mono wrap-anywhere">{testcase.report_path || 'Not recorded'}</strong>
                </div>
              </div>

              <section className="drawer-section">
                <div className="drawer-section-head">
                  <h4>Evaluation Reason</h4>
                </div>
                <pre className="raw" tabIndex={0}>{testcase.reason || 'No evaluation reason recorded.'}</pre>
              </section>

              {testcase.judge_reason && (
                <section className="drawer-section">
                  <div className="drawer-section-head">
                    <h4>Judge Reasoning Summary</h4>
                    <button type="button" className="btn ghost sm" onClick={() => setActiveTab('judge')}>
                      Open Judge Tab →
                    </button>
                  </div>
                  <pre className="raw" tabIndex={0}>{testcase.judge_reason}</pre>
                </section>
              )}
            </div>
          )}

          {activeTab === 'prompt' && (
            <div className="drawer-stack">
              <div className="drawer-section-head">
                <div>
                  <h4>Original Testcase Prompt</h4>
                  <span className="caption">
                    {testcase.prompt ? `${testcase.prompt.length} characters` : '0 characters'}
                  </span>
                </div>
                <button
                  type="button"
                  className="btn ghost sm"
                  onClick={() => void handleCopy('prompt', testcase.prompt || '')}
                >
                  {copiedKey === 'prompt' ? 'Copied Prompt' : copiedKey === 'prompt-unavailable' ? 'Copy Unavailable' : 'Copy Prompt'}
                </button>
              </div>
              <pre className="raw" tabIndex={0}>{testcase.prompt || 'No prompt recorded.'}</pre>
            </div>
          )}

          {activeTab === 'response' && (
            <div className="drawer-stack">
              {testcase.response_complete === false && (
                <div className="notice warn" role="status">
                  <strong>Incomplete Target Response</strong>
                  <p>This response was flagged as incomplete by the runner or transport layer.</p>
                </div>
              )}
              <div className="drawer-section-head">
                <div>
                  <h4>Full Target Response</h4>
                  <span className="caption">
                    {hasResponse ? `${responseText.length} characters` : 'No response captured'} · {completenessLabel}
                  </span>
                </div>
                {hasResponse && (
                  <button
                    type="button"
                    className="btn ghost sm"
                    onClick={() => void handleCopy('response', responseText)}
                  >
                    {copiedKey === 'response' ? 'Copied Response' : copiedKey === 'response-unavailable' ? 'Copy Unavailable' : 'Copy Response'}
                  </button>
                )}
              </div>
              <pre className="raw" tabIndex={0}>
                {hasResponse ? responseText : 'No response text recorded.'}
              </pre>
            </div>
          )}

          {activeTab === 'judge' && (
            <div className="drawer-stack">
              {faultInfo.isProviderFault && (
                <div className="notice warn" role="status">
                  <strong>Operational Judge Fault: {faultInfo.primary}</strong>
                  <p>
                    Provider fault code: <code>{faultInfo.rawCode ?? 'provider_fault'}</code>.
                    JSON validation: <code>{testcase.json_validation_status ?? 'Not recorded'}</code>.
                    Do not confuse a provider timeout or transport failure with semantic <code>UNCLEAR</code>.
                  </p>
                </div>
              )}

              <div className="detail-grid">
                <div className="detail-pair">
                  <span>Judge Classification</span>
                  <strong>
                    {faultInfo.primary}
                    {faultInfo.rawCode && <span className="muted-inline"> ({faultInfo.rawCode})</span>}
                  </strong>
                </div>
                <div className="detail-pair">
                  <span>Run Evaluation Mode</span>
                  <strong>{runRecord.use_judge ? 'Hybrid LLM Judge + Rules' : 'Deterministic Rules Only'}</strong>
                </div>
                <div className="detail-pair">
                  <span>Semantic Invoked</span>
                  <strong>
                    {testcase.semantic_invoked === undefined
                      ? 'Not recorded'
                      : testcase.semantic_invoked
                        ? 'Yes'
                        : runRecord.use_judge
                          ? 'No (Judge not invoked)'
                          : 'No (Judge not requested)'}
                  </strong>
                </div>
                <div className="detail-pair">
                  <span>Provider Fault Code</span>
                  <strong className="mono">{testcase.provider_fault_code || 'None'}</strong>
                </div>
                <div className="detail-pair">
                  <span>JSON Validation Status</span>
                  <strong className="mono">{testcase.json_validation_status || 'Not recorded'}</strong>
                </div>
                <div className="detail-pair">
                  <span>Provider Duration</span>
                  <strong>{typeof testcase.provider_duration_ms === 'number' ? `${testcase.provider_duration_ms} ms` : 'Not recorded'}</strong>
                </div>
                <div className="detail-pair">
                  <span>Recorded Judge Provider / Model</span>
                  <strong>{formatProviderModel(runRecord.judge_metadata)}</strong>
                </div>
                <div className="detail-pair">
                  <span>Run Judge Invocation Status</span>
                  <strong>{formatInvocationStatus(runRecord.judge_metadata?.invocation_status)}</strong>
                </div>
              </div>

              <section className="drawer-section">
                <div className="drawer-section-head">
                  <h4>Full Judge Reason</h4>
                  {testcase.judge_reason && (
                    <button
                      type="button"
                      className="btn ghost sm"
                      onClick={() => void handleCopy('judge', testcase.judge_reason || '')}
                    >
                      {copiedKey === 'judge' ? 'Copied Judge Reason' : 'Copy Judge Reason'}
                    </button>
                  )}
                </div>
                <pre className="raw" tabIndex={0}>
                  {testcase.judge_reason || 'No Judge reasoning recorded for this testcase.'}
                </pre>
              </section>
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="drawer-stack">
              <div className="notice info" role="note">
                <strong>Evidence Boundary &amp; Verification Semantics</strong>
                <p>
                  Model responses (`response_only`), model-reported tool claims (`model_reported_intent`), target-reported claims (`target_reported_claim`), and adapter-observed requests (`adapter_observed_request`) do not independently prove runtime tool, filesystem, or host execution. Explicit execution verification requires `data.execution_verified: true` from an independent observer/collector and does not by itself establish confirmed system compromise.
                </p>
              </div>

              <div className="detail-grid">
                <div className="detail-pair">
                  <span>Canonical Evidence Level</span>
                  <strong>{formatEvidenceLevel(testcase.evidence_level, true)}</strong>
                </div>
                <div className="detail-pair">
                  <span>Provenance Tiers</span>
                  <strong>{(testcase.provenance_tiers ?? []).length > 0 ? testcase.provenance_tiers.join(', ') : 'Not recorded'}</strong>
                </div>
                <div className="detail-pair">
                  <span>Verified Execution Items</span>
                  <strong>
                    {caseEvidence.verifiedItemCount} of {caseEvidence.totalItems} items (Execution verified: {executionVerifiedSummary})
                  </strong>
                </div>
                <div className="detail-pair">
                  <span>Collector Diagnostics</span>
                  <strong>{testcase.collector_diagnostics?.length ?? 0}</strong>
                </div>
              </div>

              <section className="drawer-section">
                <h4>Recorded Evidence Items</h4>
                {caseEvidence.items.length === 0 ? (
                  <div className="empty-box">No structured evidence items were recorded for this testcase.</div>
                ) : (
                  <div className="drawer-list">
                    {caseEvidence.items.map((item, idx) => (
                      <article key={`${item.ev.source || 'ev'}-${idx}`} className="evidence-card">
                        <div className="evidence-card-head">
                          <strong>{item.ev.name || item.ev.source || `Evidence #${idx + 1}`}</strong>
                          <div className="drawer-badges">
                            <span className="pill">{item.ev.kind}</span>
                            {item.ev.source && <span className="pill">{item.ev.source}</span>}
                            <span className="pill">
                              {item.provenance ? `Provenance: ${item.provenance}` : 'Provenance not recorded'}
                            </span>
                            <span
                              className={`pill ${
                                item.isExecutionVerified
                                  ? 'ok'
                                  : item.verificationLabel === 'Verification not recorded'
                                    ? 'warn'
                                    : ''
                              }`}
                            >
                              {item.verificationLabel}
                            </span>
                            {item.verificationStatus && (
                              <span className="pill mono">{item.verificationStatus}</span>
                            )}
                          </div>
                        </div>
                        {item.ev.data !== undefined && (
                          <pre className="raw compact">{JSON.stringify(item.ev.data, null, 2)}</pre>
                        )}
                      </article>
                    ))}
                  </div>
                )}
              </section>

              <section className="drawer-section">
                <h4>Collector Diagnostics</h4>
                {(testcase.collector_diagnostics?.length ?? 0) === 0 ? (
                  <div className="empty-box">No collector diagnostics were recorded for this testcase.</div>
                ) : (
                  <div className="drawer-list">
                    {testcase.collector_diagnostics.map((diag, idx) => (
                      <article key={`${diag.collector_id || 'diag'}-${idx}`} className="evidence-card">
                        <div className="evidence-card-head">
                          <strong>{diag.collector_id || `Collector #${idx + 1}`}</strong>
                          <div className="drawer-badges">
                            <span className="pill">{diag.collector_kind}</span>
                            <span className="pill">{diag.status}</span>
                            <span className="pill">matched={diag.matched_count}</span>
                            {diag.uncorrelated_count > 0 && (
                              <span className="pill warn">uncorrelated={diag.uncorrelated_count}</span>
                            )}
                          </div>
                        </div>
                        {diag.reason && <p className="caption">{diag.reason}</p>}
                      </article>
                    ))}
                  </div>
                )}
              </section>
            </div>
          )}

          {activeTab === 'raw' && (
            <div className="drawer-stack">
              <div className="notice info" role="note">
                <strong>
                  {showingNativePayload
                    ? `Native SecAgent Run Report JSON (${testcase.run_id})`
                    : 'Stored Generic Run Case JSON — not a native SecAgent report'}
                </strong>
                <p>
                  {showingNativePayload
                    ? 'Fetched read-only from the Reporting API for this testcase run ID.'
                    : 'Displaying the persisted Generic Scan case record stored inside this Scan Run. Use the Native Run links below to inspect or download the full native SecAgent report when present.'}
                </p>
              </div>

              <div className="drawer-actions">
                <button
                  type="button"
                  className="btn ghost sm"
                  onClick={() =>
                    void handleCopy(
                      'raw',
                      JSON.stringify(showingNativePayload ? nativeReportState.payload : testcase, null, 2),
                    )
                  }
                >
                  {copiedKey === 'raw' ? 'Copied JSON' : 'Copy JSON'}
                </button>
                <button
                  type="button"
                  className="btn ghost sm"
                  onClick={() =>
                    downloadJsonFile(
                      `${runRecord.generic_run_id}-${testcase.case_id}${showingNativePayload ? '-native-report' : '-case'}.json`,
                      showingNativePayload ? nativeReportState.payload : testcase,
                    )
                  }
                >
                  Download JSON
                </button>
                {testcase.run_id && (
                  <>
                    <button
                      type="button"
                      className="btn ghost sm"
                      disabled={nativeReportState?.loading}
                      onClick={() => void handleFetchNativeReport()}
                    >
                      {nativeReportState?.loading
                        ? 'Fetching Native Report...'
                        : showingNativePayload
                          ? 'Reload Native Report JSON'
                          : 'Fetch Native Report JSON'}
                    </button>
                    <a
                      className="btn ghost sm"
                      href={`#run/${encodeURIComponent(testcase.run_id)}`}
                    >
                      Open Native Run Detail →
                    </a>
                    <a
                      className="btn ghost sm"
                      href={`/api/reports/runs/${encodeURIComponent(testcase.run_id)}/download`}
                    >
                      Download Native Archive
                    </a>
                  </>
                )}
              </div>

              {nativeReportState?.error && (
                <div className="notice warn" role="alert">
                  <strong>Native Report Unavailable</strong>
                  <p>{nativeReportState.error} Continuing to show the Stored Generic Run Case JSON below.</p>
                </div>
              )}

              <pre className="raw" tabIndex={0}>
                {JSON.stringify(showingNativePayload ? nativeReportState.payload : testcase, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </dialog>
  );
}
