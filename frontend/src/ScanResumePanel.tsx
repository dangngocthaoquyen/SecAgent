import { type GenericResumePreview } from './testingApi';

const RESUME_BLOCKER_LABELS: Record<string, string> = {
  generic_resume_not_interrupted: 'Only interrupted or cancelled scans can be resumed.',
  generic_resume_already_active: 'A continuation run for this scan lineage is already active.',
  generic_resume_no_remaining_cases: 'All originally selected testcases in this lineage already have completed results.',
  generic_resume_no_cases_selected: 'No testcases are selected for continuation. Re-enable at least one uncertain testcase in Advanced Resume Options to resume.',
  resume_state_incomplete: 'Persisted testcase status for this interrupted run is incomplete; remaining cases cannot be determined safely.',
  resume_dataset_not_found: 'The original dataset is no longer available in the local dataset repository.',
  resume_dataset_revision_missing: 'The interrupted run is missing its recorded dataset revision SHA-256.',
  resume_dataset_mismatch: 'The dataset contents or revision changed since the original scan started.',
  resume_target_not_found: 'The original target profile is no longer registered in the target catalog.',
  resume_target_revision_missing: 'The interrupted run is missing its recorded target profile revision.',
  resume_target_configuration_changed: 'The target profile configuration changed since the original scan started. Start a New Scan instead.',
  resume_judge_configuration_missing: 'The interrupted Hybrid scan is missing its recorded Judge provider or model identifier.',
  resume_judge_configuration_changed: 'The current LLM Judge provider or model differs from the original scan. Restore the original Judge configuration or start a New Scan.',
  resume_configuration_incomplete: 'Required historical configuration metadata is missing from the interrupted run.',
  resume_policy_changed: 'The reviewed response policy changed since the original scan started.',
  resume_application_context_changed: 'The target Application Context changed since the original scan started.',
  credential_unavailable: 'Target authentication credential is not currently available in backend session memory or environment.',
  judge_provider_unavailable: 'Hybrid LLM Judge is currently unavailable or missing credentials.',
};

function formatBlocker(code: string): string {
  return RESUME_BLOCKER_LABELS[code] || code;
}

export default function ScanResumePanel({
  preview,
  previewStale = false,
  loading,
  starting,
  error,
  selectedUncertainIds,
  onToggleUncertain,
  onRecheck,
  onConfirmAndResume,
  onCancel,
}: {
  preview: GenericResumePreview | null;
  previewStale?: boolean;
  loading: boolean;
  starting: boolean;
  error: string;
  selectedUncertainIds: string[];
  onToggleUncertain: (caseId: string, checked: boolean) => void;
  onRecheck: () => void;
  onConfirmAndResume: () => void;
  onCancel: () => void;
}) {
  if (loading && !preview) {
    return (
      <section className="panel" aria-label="Resume Scan Preview">
        <div className="section-title">
          <div>
            <span className="eyebrow">INTERRUPTED SCAN RECOVERY</span>
            <h3>Loading Resume Preview…</h3>
          </div>
          <button type="button" className="btn ghost" onClick={onCancel}>
            Cancel
          </button>
        </div>
        <p className="muted">Inspecting persisted run state (read-only · 0 target or judge requests).</p>
      </section>
    );
  }

  if (!preview) {
    return (
      <section className="panel" aria-label="Resume Scan Preview">
        <div className="section-title">
          <div>
            <span className="eyebrow">INTERRUPTED SCAN RECOVERY</span>
            <h3>Resume Scan Preview</h3>
          </div>
          <div className="actions">
            <button type="button" className="btn ghost" onClick={onRecheck} disabled={loading || starting}>
              {loading ? 'Checking…' : 'Re-check Readiness'}
            </button>
            <button type="button" className="btn ghost" onClick={onCancel}>
              Close
            </button>
          </div>
        </div>
        {error && (
          <div className="notice error" role="alert">
            {error}
          </div>
        )}
        <p className="muted">
          The previous preview was invalidated after refresh failed. Click <strong>Re-check Readiness</strong> to load a
          fresh preview before confirming.
        </p>
        <div className="actions" style={{ marginTop: '0.8rem' }}>
          <button type="button" className="btn primary" disabled>
            Confirm &amp; Resume
          </button>
        </div>
      </section>
    );
  }

  const includedUncertain = preview.included_uncertain_case_ids;
  const selectionSynced =
    includedUncertain.length === selectedUncertainIds.length &&
    selectedUncertainIds.every(id => includedUncertain.includes(id));
  const startingCaseId = preview.selected_resume_case_ids[0] ?? null;
  const startingIsUncertain = Boolean(startingCaseId && includedUncertain.includes(startingCaseId));
  const remainingCount = preview.selected_resume_case_ids.length;
  const authMissing =
    preview.credential_availability === 'unavailable' || preview.blockers.includes('credential_unavailable');
  const canConfirm = preview.eligible && !previewStale && selectionSynced && remainingCount > 0 && !loading && !starting;

  const preservedVerdictSummary = preview.completed_cases_summary.reduce<Record<string, number>>((acc, item) => {
    const v = item.verdict || 'UNKNOWN';
    acc[v] = (acc[v] || 0) + 1;
    return acc;
  }, {});

  return (
    <section className="panel" aria-label="Resume Scan Preview">
      <div className="section-title">
        <div>
          <span className="eyebrow">
            {preview.parent_status === 'cancelled'
              ? 'CANCELLED SCAN CONTINUATION · LINKED CONTINUATION RUN'
              : 'INTERRUPTED SCAN RECOVERY · LINKED CONTINUATION RUN'}
          </span>
          <h3>{preview.parent_status === 'cancelled' ? 'Resume Cancelled Scan' : 'Resume Interrupted Scan'}</h3>
          <p className="muted">
            Parent run <code className="mono">{preview.parent_run_id}</code> · Target{' '}
            <strong>{preview.target_name}</strong> (<code className="mono">{preview.target_id}</code>) · Dataset{' '}
            <strong>{preview.dataset_name || preview.dataset_id || 'Unknown'}</strong> · Mode{' '}
            <strong>{preview.mode === 'live' ? 'Live' : 'Offline'}</strong> · Engine{' '}
            <strong>{preview.use_judge ? 'Hybrid LLM Judge + Rules' : 'Deterministic Rules Only'}</strong>
          </p>
        </div>
        <div className="actions">
          <button type="button" className="btn ghost" onClick={onRecheck} disabled={loading || starting}>
            {loading ? 'Checking…' : 'Re-check Readiness'}
          </button>
          <button type="button" className="btn ghost" onClick={onCancel} disabled={starting}>
            Cancel
          </button>
        </div>
      </div>

      {error && (
        <div className="notice error" role="alert">
          {error}
        </div>
      )}

      {/* Essential 4-metric Resume summary */}
      <div className="cards" role="region" aria-label="Resume summary">
        <article className="metric ok">
          <div className="k">Completed Preserved</div>
          <div className="v">{preview.completed_count}</div>
          <div className="s">
            Untouched ({Object.entries(preservedVerdictSummary).map(([k, v]) => `${k}: ${v}`).join(', ') || 'None'})
          </div>
        </article>
        <article className="metric">
          <div className="k">Resume Starting Case</div>
          <div className="v">
            <code className="mono">{startingCaseId ?? 'None'}</code>
          </div>
          <div className="s">
            {startingIsUncertain
              ? 'Interrupted in-flight · potentially repeated'
              : startingCaseId
                ? 'Next queued testcase'
                : 'No cases selected'}
          </div>
        </article>
        <article className="metric">
          <div className="k">Remaining Cases</div>
          <div className="v">{remainingCount}</div>
          <div className="s">
            {includedUncertain.length > 0
              ? `${includedUncertain.length} uncertain (retry) + ${preview.pending_case_ids.length} pending`
              : `${preview.pending_case_ids.length} pending (${preview.uncertain_case_ids.length} uncertain excluded)`}
          </div>
        </article>
        <article className="metric">
          <div className="k">Request Budgets</div>
          <div className="v">
            {preview.target_request_budget} / {preview.judge_request_budget}
          </div>
          <div className="s">
            Target requests: {preview.target_request_budget} · Judge calls: {preview.judge_request_budget}
          </div>
        </article>
      </div>

      {/* Configuration & Authentication Readiness */}
      <div className="meta-strip" style={{ marginTop: '0.75rem' }}>
        <span>
          Dataset: <strong>{preview.dataset_consistent ? 'Verified' : 'Mismatch / Missing'}</strong>
        </span>
        <span>
          Configuration: <strong>{preview.config_consistent ? 'Verified' : 'Changed / Blocked'}</strong>
        </span>
        <span>
          Authentication ({preview.auth_source}):{' '}
          <strong>
            {preview.credential_availability === 'available'
              ? 'Ready'
              : preview.credential_availability === 'not_required'
                ? 'Not required'
                : 'Missing — re-supply required'}
          </strong>
        </span>
        {preview.use_judge && (
          <span>
            Judge: <strong>{preview.judge_status.judge_ready ? 'Ready' : `Unavailable (${preview.judge_status.reason})`}</strong>
          </span>
        )}
      </div>

      {/* Blockers */}
      {preview.blockers.length > 0 && (
        <div className="notice error" role="alert" style={{ marginTop: '0.75rem' }}>
          <strong>Resume blocked until resolved:</strong>
          <ul style={{ margin: '0.35rem 0 0 1.2rem' }}>
            {preview.blockers.map(code => (
              <li key={code}>
                <code className="mono">{code}</code> — {formatBlocker(code)}
              </li>
            ))}
          </ul>
          {authMissing && (
            <div style={{ marginTop: '0.6rem', display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <span>
                Session credentials are stored in backend memory only and are cleared on restart. Re-supply the token for{' '}
                <code className="mono">{preview.target_id}</code> in Target Authentication without recreating your target, dataset, or Application Context, then click <strong>Re-check Readiness</strong>.
              </span>
              <a className="btn ghost" href="#targets">
                Open Target Authentication →
              </a>
            </div>
          )}
        </div>
      )}

      {/* Optional collapsed Advanced Resume Options */}
      <details style={{ marginTop: '0.75rem' }}>
        <summary style={{ cursor: 'pointer', fontWeight: 600 }}>
          Advanced Resume Options
          {preview.uncertain_case_ids.length > 0
            ? ` (Uncertain in-flight cases: ${includedUncertain.length} of ${preview.uncertain_case_ids.length} included)`
            : ''}
        </summary>
        <div style={{ marginTop: '0.6rem', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
          {preview.uncertain_case_ids.length > 0 && (
            <div>
              <strong>Uncertain In-Flight Testcases (potentially repeated executions)</strong>
              <p className="muted" style={{ margin: '0.25rem 0 0.4rem' }}>
                Included by default so Resume restarts from the interrupted testcase. Uncheck any case below to exclude
                it from this continuation run.
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                {preview.uncertain_case_ids.map(cid => {
                  const checked = selectedUncertainIds.includes(cid);
                  return (
                    <label key={cid} className="checkbox-row">
                      <input
                        type="checkbox"
                        checked={checked}
                        disabled={loading || starting}
                        onChange={e => onToggleUncertain(cid, e.target.checked)}
                      />
                      <span>
                        Include uncertain testcase <code className="mono">{cid}</code> (potentially repeated execution)
                      </span>
                    </label>
                  );
                })}
              </div>
            </div>
          )}
          <div className="split" style={{ gap: '0.75rem' }}>
            <div>
              <strong>Preserved Completed ({preview.completed_count})</strong>
              <p className="muted" style={{ margin: '0.2rem 0 0' }}>
                {preview.completed_case_ids.length > 0 ? (
                  <code className="mono">{preview.completed_case_ids.join(', ')}</code>
                ) : (
                  'None recorded.'
                )}
              </p>
            </div>
            <div>
              <strong>Definitely Pending ({preview.pending_case_ids.length})</strong>
              <p className="muted" style={{ margin: '0.2rem 0 0' }}>
                {preview.pending_case_ids.length > 0 ? (
                  <code className="mono">{preview.pending_case_ids.join(', ')}</code>
                ) : (
                  'None remaining.'
                )}
              </p>
            </div>
          </div>
        </div>
      </details>

      {/* Consolidated Disclosure & Single Confirmation Action */}
      <div className="notice warn" role="note" aria-label="Resume confirmation disclosure" style={{ marginTop: '0.85rem' }}>
        <strong>Before confirming Resume:</strong>
        <ul style={{ margin: '0.35rem 0 0.5rem 1.2rem' }}>
          <li>Interrupted in-flight requests may already have executed on the target.</li>
          {includedUncertain.length > 0 ? (
            <li>
              Selected uncertain testcase(s) (<code className="mono">{includedUncertain.join(', ')}</code>) will be
              retried as potentially repeated executions.
            </li>
          ) : (
            <li>Uncertain in-flight testcase(s) are currently excluded via Advanced Resume Options.</li>
          )}
          <li>SecAgent does not automatically restore target state.</li>
          <li>Verify relevant target state before confirming.</li>
        </ul>
        <p className="muted" style={{ margin: 0 }}>
          Clicking <strong>Confirm &amp; Resume</strong> explicitly authorizes a linked continuation run for{' '}
          <strong>{remainingCount}</strong> testcase(s) (Target requests: <strong>{preview.target_request_budget}</strong>,
          Judge calls: <strong>{preview.judge_request_budget}</strong>), acknowledges live target state without automatic
          rollback{includedUncertain.length > 0 ? ', and confirms retrying the selected uncertain testcase(s)' : ''}.
          Completed results ({preview.completed_count}) remain untouched and immutable.
        </p>
      </div>

      <div className="actions" style={{ marginTop: '0.8rem' }}>
        <button
          type="button"
          className="btn primary"
          disabled={!canConfirm}
          onClick={onConfirmAndResume}
        >
          {starting ? 'Starting Resumed Scan…' : `Confirm & Resume (${remainingCount} cases)`}
        </button>
        <button type="button" className="btn ghost" onClick={onCancel} disabled={starting}>
          Cancel
        </button>
      </div>
    </section>
  );
}
