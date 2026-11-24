import { formatCaseAsiCategory } from './scanFormatters';
import { type DatasetEnvelope, type GenericRunPreview } from './testingApi';

export interface ScanPreviewPanelProps {
  preview: GenericRunPreview;
  datasetDetail: DatasetEnvelope | null;
  scanMode: 'live' | 'offline';
  useJudge: boolean;
  datasetHasStoredResponses: boolean;
  judgeSetupReason: string;
  selectedCaseIds: string[];
  authorized: boolean;
  busy: boolean;
  submissionLocked?: boolean;
  onBackToStep1: () => void;
  onChangeMode: (nextMode: 'live' | 'offline') => void;
  onChangeEngine: (nextJudge: boolean) => void;
  onSelectCases: (nextIds: string[]) => void;
  onToggleAuthorized: (checked: boolean) => void;
  onStartScan: () => void;
}

export default function ScanPreviewPanel({
  preview,
  datasetDetail,
  scanMode,
  useJudge,
  datasetHasStoredResponses,
  judgeSetupReason,
  selectedCaseIds,
  authorized,
  busy,
  submissionLocked = false,
  onBackToStep1,
  onChangeMode,
  onChangeEngine,
  onSelectCases,
  onToggleAuthorized,
  onStartScan,
}: ScanPreviewPanelProps) {
  const judgeReadyFromPreview = preview.judge_status
    ? preview.judge_status.judge_ready
    : preview.pi_judge_ready;
  const credentialMissing =
    preview.judge_status?.reason === 'credential_missing' ||
    judgeSetupReason === 'credential_missing';
  const judgeReady = judgeReadyFromPreview === true && !credentialMissing;
  const hybridStatusLabel = judgeReady
    ? 'Ready'
    : credentialMissing
      ? 'Credential Missing'
      : 'Judge Not Configured';

  const totalSelected = preview.total_cases ?? preview.items.length;
  const targetBudget = preview.target_request_budget ?? (scanMode === 'offline' ? 0 : preview.ready_count);
  const judgeBudget = preview.judge_request_budget ?? (useJudge ? preview.ready_count : 0);
  const selectedSet = new Set(selectedCaseIds);
  const isLocked = busy || Boolean(submissionLocked);
  const canStart = authorized && !preview.blocker && preview.ready_count > 0 && !isLocked;

  return (
    <section className="panel preview-shell" aria-label="Step 2: Scan Preview">
      <div className="section-title">
        <div>
          <span className="eyebrow">STEP 2 OF 3</span>
          <h2>2 · Scan Preview</h2>
          <p>
            Review preflight checks, ASI distribution, execution mode, and request budgets before authorizing execution.
          </p>
        </div>
        <button
          type="button"
          className="btn ghost"
          disabled={isLocked}
          onClick={() => {
            if (isLocked) return;
            onBackToStep1();
          }}
        >
          ← Change Target or Dataset
        </button>
      </div>

      <div className="cards" role="region" aria-label="Scan preview metrics">
        <article className="metric">
          <div className="k">Target Agent</div>
          <div className="v sm-v">{preview.target_name}</div>
          <div className="s"><code className="mono">{preview.target_id}</code></div>
        </article>
        <article className="metric">
          <div className="k">Dataset Scope</div>
          <div className="v sm-v">{preview.dataset_name || datasetDetail?.name || preview.dataset_id}</div>
          <div className="s">{totalSelected} selected testcases</div>
        </article>
        <article className="metric ok">
          <div className="k">Readiness Breakdown</div>
          <div className="v sm-v">{preview.ready_count} Ready</div>
          <div className="s">{preview.blocked_count} Blocked · {preview.unsupported_count} Unsupported</div>
        </article>
        <article className="metric">
          <div className="k">Safety Request Budgets</div>
          <div className="v sm-v">{targetBudget} Target Requests</div>
          <div className="s">{judgeBudget} Max Judge Calls</div>
        </article>
      </div>

      <div className="split preflight-grid">
        <section className="card">
          <div className="card-head-row">
            <h3>Execution Configuration</h3>
            <span className={`pill ${scanMode === 'offline' ? 'ok' : ''}`}>
              {scanMode === 'offline' ? 'Offline Evaluation' : 'Live Target Scan'}
            </span>
          </div>

          <div className="scan-form-grid vertical">
            <label htmlFor="scan-mode-select">
              Execution Mode
              <select
                id="scan-mode-select"
                value={scanMode}
                disabled={isLocked}
                onChange={e => {
                  if (isLocked) return;
                  onChangeMode(e.target.value as 'live' | 'offline');
                }}
              >
                <option value="live">Live Test · Send prompts to Target</option>
                {(datasetHasStoredResponses || preview.has_stored_responses) && (
                  <option value="offline">
                    Offline Evaluation · Stored responses (0 Target requests)
                  </option>
                )}
              </select>
            </label>

            <label htmlFor="scan-evaluation-select">
              Evaluation Engine
              <select
                id="scan-evaluation-select"
                value={useJudge ? 'hybrid' : 'rule_only'}
                disabled={isLocked}
                onChange={e => {
                  if (isLocked) return;
                  onChangeEngine(e.target.value === 'hybrid');
                }}
              >
                <option value="hybrid">
                  Hybrid LLM Judge + Rules ({hybridStatusLabel})
                </option>
                <option value="rule_only">
                  Deterministic Rules / Evidence Only (0 Judge Calls)
                </option>
              </select>
            </label>
          </div>

          <div className="config-note">
            <span>Judge readiness: </span>
            <strong className={judgeReady ? 'ok-text' : 'warn-text'}>{hybridStatusLabel}</strong>
            {preview.judge_status?.provider && (
              <span> · Provider: <code className="mono">{preview.judge_status.provider}</code></span>
            )}
            {preview.judge_status?.model && (
              <span> · Model: <code className="mono">{preview.judge_status.model}</code></span>
            )}
          </div>
        </section>

        <section className="card">
          <div className="card-head-row">
            <h3>Preflight Checks &amp; ASI Distribution</h3>
            <span className={`pill ${preview.blocker ? 'fail' : 'ok'}`}>
              {preview.blocker ? 'Action Required' : 'Preflight Clear'}
            </span>
          </div>

          <ul className="preflight-checklist">
            <li>
              <span className={`dot ${preview.ready_count > 0 ? 'pass' : 'fail'}`} />
              <span>
                <strong>Ready testcases:</strong> {preview.ready_count} of {totalSelected} eligible to execute
              </span>
            </li>
            <li>
              <span className={`dot ${preview.unsupported_count === 0 ? 'pass' : 'inc'}`} />
              <span>
                <strong>Unsupported / skipped on target:</strong> {preview.unsupported_count}
              </span>
            </li>
            <li>
              <span className={`dot ${preview.blocked_count === 0 ? 'pass' : 'fail'}`} />
              <span>
                <strong>Blocked testcases:</strong> {preview.blocked_count}
              </span>
            </li>
            <li>
              <span className={`dot ${!useJudge || judgeReady ? 'pass' : 'fail'}`} />
              <span>
                <strong>Evaluation engine:</strong>{' '}
                {useJudge
                  ? `Hybrid LLM Judge (${hybridStatusLabel})`
                  : 'Deterministic Rules Only (no external Judge call)'}
              </span>
            </li>
          </ul>

          {preview.asi_breakdown && Object.keys(preview.asi_breakdown).length > 0 && (
            <div className="scan-summary-card" aria-label="ASI Category Breakdown">
              <strong>ASI Category Breakdown:</strong>
              <div className="badge-wrap" style={{ marginTop: '0.45rem' }}>
                {Object.entries(preview.asi_breakdown).map(([cat, cnt]) => (
                  <span
                    key={cat}
                    className={`batch-cell-pill ${cat === 'unmapped' ? 'blocked' : 'ready'}`}
                  >
                    {cat}: {cnt}
                  </span>
                ))}
              </div>
            </div>
          )}
        </section>
      </div>

      {preview.blocker && (
        <div className="notice error" role="alert">
          <strong>
            Preflight Blocker: <code>{preview.blocker}</code>
          </strong>
          <p>
            {preview.blocker === 'policy_review_required'
              ? 'Save operator-confirmed Application Details for this Target in the Targets tab (or approve a ResponsePolicyStore policy) before running Hybrid Judge evaluation.'
              : preview.blocker === 'unmapped_asi_category'
                ? 'One or more testcases do not have a determinable ASI category (ASI01/ASI02/ASI03/ASI05). Assign metadata.asi_category in the dataset.'
                : preview.blocker === 'judge_provider_unavailable'
                  ? 'Hybrid LLM Judge is not ready (missing or unverified Judge credential). Configure the DeepSeek Judge credential on the server or switch Evaluation Engine to Deterministic Rules / Evidence Only.'
                  : `Resolve blocker "${preview.blocker}" before starting the scan.`}
          </p>
        </div>
      )}

      <details className="target-advanced" aria-label="Testcase subset selection">
        <summary>
          Testcase Subset &amp; Preflight Status ({selectedCaseIds.length} of{' '}
          {datasetDetail?.total_testcases ?? preview.items.length} selected)
        </summary>
        {datasetDetail && (
          <div className="batch-selection-actions">
            <button
              type="button"
              className="btn ghost sm"
              disabled={isLocked}
              onClick={() => {
                if (isLocked) return;
                onSelectCases(datasetDetail.testcases.map(tc => tc.testcase_id));
              }}
            >
              Select All ({datasetDetail.total_testcases})
            </button>
            <button
              type="button"
              className="btn ghost sm"
              disabled={isLocked}
              onClick={() => {
                if (isLocked) return;
                const readyIds = preview.items.filter(i => i.status === 'ready').map(i => i.case_id);
                if (readyIds.length > 0) {
                  onSelectCases(readyIds);
                }
              }}
            >
              Select Ready Only ({preview.ready_count})
            </button>
          </div>
        )}
        <div className="tablewrap">
          <table>
            <thead>
              <tr>
                <th>Include</th>
                <th>Case ID</th>
                <th>ASI Category</th>
                <th>Preflight Status</th>
                <th>Reason</th>
                <th>Prompt Preview</th>
              </tr>
            </thead>
            <tbody>
              {preview.items.map(item => {
                const checked = selectedSet.has(item.case_id);
                return (
                  <tr key={item.case_id}>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`Include testcase ${item.case_id}`}
                        checked={checked}
                        disabled={isLocked}
                        onChange={e => {
                          if (isLocked) return;
                          const next = e.target.checked
                            ? Array.from(new Set([...selectedCaseIds, item.case_id]))
                            : selectedCaseIds.filter(id => id !== item.case_id);
                          onSelectCases(next);
                        }}
                      />
                    </td>
                    <td><code className="mono">{item.case_id}</code></td>
                    <td><span className="pill">{formatCaseAsiCategory(item.asi_code || item.category)}</span></td>
                    <td>
                      <span className={`pill ${item.status === 'ready' ? 'ok' : item.status === 'blocked' ? 'fail' : 'warn'}`}>
                        {item.status}
                      </span>
                    </td>
                    <td className="caption">{item.reason || 'Ready'}</td>
                    <td className="caption wrap-anywhere">
                      {item.prompt_preview ? item.prompt_preview.slice(0, 120) : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </details>

      <div className="card auth-card">
        <label className="auth-check-label">
          <input
            type="checkbox"
            checked={authorized}
            disabled={isLocked}
            onChange={e => {
              if (isLocked) return;
              onToggleAuthorized(e.target.checked);
            }}
          />
          <span>
            I authorize SecAgent to run this{' '}
            {scanMode === 'offline'
              ? 'offline evaluation on stored dataset responses (0 Target requests)'
              : `live security scan (${targetBudget} Target requests)`}{' '}
            for <strong>{preview.target_name}</strong> ({preview.ready_count} ready testcases).
          </span>
        </label>

        <div className="auth-actions">
          <button
            type="button"
            className="btn primary"
            disabled={!canStart}
            onClick={() => {
              if (isLocked) return;
              onStartScan();
            }}
          >
            {busy ? 'Starting Scan...' : 'Start Scan'}
          </button>
        </div>
      </div>
    </section>
  );
}
