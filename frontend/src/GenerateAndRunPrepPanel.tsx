import { useState } from 'react';
import type { TargetPreset } from './testingApi';
import GeneratorConfigForm from './GeneratorConfigForm';
import {
  GENERATE_AND_RUN_STAGES,
  extractActiveCounts,
  type GenerateAndRunContractDraft,
  type GeneratorConfigState,
  type GeneratorProviderStatus,
  type TargetReadinessReport,
} from './generatorApi';

export type GenerateAndRunPrepPanelProps = {
  targets: TargetPreset[];
  config: GeneratorConfigState;
  onChangeConfig: (next: GeneratorConfigState) => void;
  providerStatus: GeneratorProviderStatus | null;
  providerStatusError?: string;
  readiness: TargetReadinessReport | null;
  readinessLoading: boolean;
  readinessError?: string;
  onCheckReadiness: () => void;
  onSwitchToGenerateOnly?: () => void;
  onSwitchToRunExisting?: () => void;
};

/**
 * Mode 1 — Generate & Run (Primary Workflow) UI Contract Preparation.
 *
 * Architectural contract (G11.1 Addendum + G11.4):
 * - Primary product workflow: Configure -> Generate -> Validate -> Auto-Save Dataset ->
 *   Preflight/Authorization -> Execute -> Judge -> Report.
 * - Explicitly does NOT require Preview/Edit/Manual Save between Generate and Run.
 * - Backend orchestration is scheduled for G11.6 (post-merge with G12). Until then,
 *   submission is strictly disabled and NEVER calls any execution or generation endpoint.
 */
export default function GenerateAndRunPrepPanel({
  targets,
  config,
  onChangeConfig,
  providerStatus,
  providerStatusError = '',
  readiness,
  readinessLoading,
  readinessError = '',
  onCheckReadiness,
  onSwitchToGenerateOnly,
  onSwitchToRunExisting,
}: GenerateAndRunPrepPanelProps) {
  const [evaluationMode, setEvaluationMode] = useState<'rule_only' | 'hybrid'>('rule_only');
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);

  const selectedTarget = targets.find((t) => t.id === config.targetId) ?? null;
  const { total, selectedList, error: countError } = extractActiveCounts(config);

  const contractDraft: GenerateAndRunContractDraft = {
    mode: 'generate_and_run',
    requiresPreviewOrManualSave: false,
    orchestrationAvailable: false,
    generationConfig: config,
    evaluationMode,
    authorizationConfirmed,
    plannedStages: GENERATE_AND_RUN_STAGES.map((s) => s.id),
    plannedDatasetLink: null,
    plannedRunLink: null,
  };

  function handleBlockedSubmit(event: React.FormEvent) {
    event.preventDefault();
    // Intentional hard no-op until G11.6 backend orchestration is wired.
  }

  return (
    <form
      onSubmit={handleBlockedSubmit}
      data-testid="generate-and-run-panel"
      aria-label="Generate and Run workflow"
    >
      {/* Clear status banner: Primary UX, backend orchestration pending G11.6 */}
      <div
        role="status"
        data-testid="g11-6-unavailable-banner"
        style={{
          padding: 14,
          marginBottom: 14,
          borderRadius: 8,
          border: '1px solid var(--warn)',
          background: 'var(--warn-soft)',
          color: 'var(--ink)',
        }}
      >
        <strong>Generate &amp; Run (Primary Workflow) — Awaiting G11.6 Backend Orchestration</strong>
        <p style={{ margin: '6px 0 0' }}>
          One-click automated flow: <code>Configure → Generate → Validate → Auto-Save Dataset → Preflight → Execute → Judge → Report</code> (no mandatory Preview/Edit/Manual Save step). Execution orchestration is scheduled for <strong>G11.6</strong> after merging with G12; this panel prepares the configuration contract and will not trigger Target execution yet.
        </p>
        <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
          {onSwitchToGenerateOnly && (
            <button type="button" onClick={onSwitchToGenerateOnly}>
              Use Generate Only (Available Now)
            </button>
          )}
          {onSwitchToRunExisting && (
            <button type="button" onClick={onSwitchToRunExisting}>
              Run Existing Dataset
            </button>
          )}
        </div>
      </div>

      {/* Shared Context-aware Generation Form (reused cleanly across Mode 1 & Mode 2) */}
      <GeneratorConfigForm
        targets={targets}
        config={config}
        onChange={onChangeConfig}
        providerStatus={providerStatus}
        providerStatusError={providerStatusError}
        readiness={readiness}
        readinessLoading={readinessLoading}
        readinessError={readinessError}
        onCheckReadiness={onCheckReadiness}
        showExecutionScopeSelector={true}
      />

      {/* Execution, Authorization & Fail-Closed Guardrails */}
      <section aria-label="Execution and authorization contract" className="panel" style={{ marginTop: 14, padding: 14 }}>
        <h3 style={{ marginTop: 0 }}>Execution Scope, Evaluation &amp; Authorization Preflight</h3>
        <div style={{ display: 'grid', gap: 10 }}>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span>Evaluation Mode</span>
              <select
                aria-label="Planned evaluation mode"
                value={evaluationMode}
                onChange={(e) => setEvaluationMode(e.target.value as 'rule_only' | 'hybrid')}
              >
                <option value="rule_only">Deterministic Rules / Evidence Only</option>
                <option value="hybrid">Hybrid (Rules + LLM Judge)</option>
              </select>
            </label>

            <span data-testid="preflight-target-auth-status">
              Target review:{' '}
              <strong>
                {selectedTarget
                  ? selectedTarget.authorization_status === 'reviewed_for_offline_configuration'
                    ? 'Reviewed'
                    : 'Unreviewed (required before live execution)'
                  : 'No target selected'}
              </strong>
            </span>
          </div>

          <ul style={{ margin: 0, paddingLeft: 18, color: 'var(--muted)', fontSize: 13 }}>
            <li>Dataset will be automatically persisted as immutable before Target execution begins.</li>
            <li>Fail-closed: execution will NOT start if generation fails, returns partial counts, has invalid scope, or fails preflight consent.</li>
            <li>Rerun reuses the saved immutable dataset without calling Generator; Resume continues interrupted runs without regenerating prompts.</li>
          </ul>

          <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <input
              type="checkbox"
              aria-label="Confirm authorized Generate and Run scope"
              checked={authorizationConfirmed}
              onChange={(e) => setAuthorizationConfirmed(e.target.checked)}
            />
            <span>
              Confirm authorized local testbed scope for {selectedList.length} ASI group(s) ({total} planned testcase(s))
            </span>
          </label>
        </div>

        <div style={{ marginTop: 14, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <button
            type="submit"
            disabled={true}
            aria-disabled="true"
            data-testid="generate-and-run-submit-btn"
            style={{ background: 'var(--teal)', color: '#fff', borderColor: 'var(--teal)' }}
          >
            Generate &amp; Run (Unavailable until G11.6)
          </button>
          {countError && <span style={{ color: 'var(--fail)', fontSize: 13 }}>{countError}</span>}
        </div>
      </section>

      {/* Planned 6-Stage Progress Pipeline & Output Links (Contract Preparation) */}
      <section aria-label="Planned orchestration pipeline" className="panel" style={{ marginTop: 14, padding: 14 }}>
        <h3 style={{ marginTop: 0 }}>Planned Automated Pipeline (G11.6)</h3>
        <ol
          data-testid="generate-and-run-stages"
          style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 8, listStyle: 'none', padding: 0, margin: 0 }}
        >
          {GENERATE_AND_RUN_STAGES.map((stage, idx) => (
            <li
              key={stage.id}
              data-testid={`planned-stage-${stage.id}`}
              style={{
                border: '1px solid var(--line)',
                borderRadius: 8,
                padding: 10,
                background: 'var(--surface-soft)',
              }}
            >
              <div style={{ fontWeight: 700 }}>
                {idx + 1}. {stage.label}
              </div>
              <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4 }}>{stage.description}</div>
              <div style={{ fontSize: 11, marginTop: 6, fontWeight: 600, color: 'var(--muted)' }}>
                Status: Planned (G11.6)
              </div>
            </li>
          ))}
        </ol>

        <div
          data-testid="planned-output-links"
          style={{ marginTop: 12, display: 'flex', gap: 16, flexWrap: 'wrap', fontSize: 13, color: 'var(--muted)' }}
        >
          <span>
            Auto-saved Dataset Link: <code>{contractDraft.plannedDatasetLink ?? 'Available after G11.6 run'}</code>
          </span>
          <span>
            Scan Run Report Link: <code>{contractDraft.plannedRunLink ?? 'Available after G11.6 run'}</code>
          </span>
        </div>
      </section>
    </form>
  );
}
