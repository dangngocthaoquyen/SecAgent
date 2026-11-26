import type { TargetPreset } from './testingApi';
import {
  ALLOWED_SCOPES_BY_ASI,
  ASI_LABELS,
  GENERATOR_LIMITS,
  SUPPORTED_ASI_CODES,
  extractActiveCounts,
  type AsiCode,
  type GeneratorConfigState,
  type GeneratorProviderStatus,
  type SupportedLanguage,
  type TargetReadinessReport,
} from './generatorApi';

export type GeneratorConfigFormProps = {
  targets: TargetPreset[];
  config: GeneratorConfigState;
  onChange: (next: GeneratorConfigState) => void;
  providerStatus: GeneratorProviderStatus | null;
  providerStatusError?: string;
  readiness: TargetReadinessReport | null;
  readinessLoading: boolean;
  readinessError?: string;
  onCheckReadiness: () => void;
  showExecutionScopeSelector?: boolean;
  disabled?: boolean;
};

export default function GeneratorConfigForm({
  targets,
  config,
  onChange,
  providerStatus,
  providerStatusError = '',
  readiness,
  readinessLoading,
  readinessError = '',
  onCheckReadiness,
  showExecutionScopeSelector = false,
  disabled = false,
}: GeneratorConfigFormProps) {
  const { total, error: countError } = extractActiveCounts(config);
  const selectedTarget = targets.find((t) => t.id === config.targetId) ?? null;

  function updateField<K extends keyof GeneratorConfigState>(
    key: K,
    value: GeneratorConfigState[K],
  ) {
    onChange({ ...config, [key]: value });
  }

  function toggleAsi(code: AsiCode, checked: boolean) {
    onChange({
      ...config,
      selectedAsi: { ...config.selectedAsi, [code]: checked },
    });
  }

  function updateAsiCount(code: AsiCode, rawValue: string) {
    const parsed = Number.parseInt(rawValue, 10);
    onChange({
      ...config,
      countsByAsi: {
        ...config.countsByAsi,
        [code]: Number.isNaN(parsed) ? 0 : parsed,
      },
    });
  }

  function updateScope(code: AsiCode, scopeValue: string) {
    const nextScopes = { ...config.requestedScopes };
    if (!scopeValue) {
      delete nextScopes[code];
    } else {
      nextScopes[code] = scopeValue;
    }
    onChange({ ...config, requestedScopes: nextScopes });
  }

  function updatePolicyId(code: AsiCode, policyId: string) {
    const nextPolicies = { ...config.policyIdsByAsi };
    if (!policyId) {
      delete nextPolicies[code];
    } else {
      nextPolicies[code] = policyId;
    }
    onChange({ ...config, policyIdsByAsi: nextPolicies });
  }

  return (
    <div className="generator-config-form" data-testid="generator-config-form">
      {/* Provider status (server-owned credentials only; never renders raw API key inputs) */}
      <section aria-label="Generator provider status" className="panel" style={{ marginBottom: 14, padding: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <div>
            <strong>Generator Provider</strong>{' '}
            {providerStatus ? (
              <span data-testid="provider-status-summary">
                <code>{providerStatus.provider_id}</code> · model <code>{providerStatus.model}</code>
              </span>
            ) : (
              <span className="muted">Loading provider status…</span>
            )}
          </div>
          {providerStatus && (
            <span
              data-testid="provider-ready-badge"
              style={{
                padding: '2px 8px',
                borderRadius: 6,
                fontWeight: 600,
                background: providerStatus.ready ? 'var(--ok-soft)' : 'var(--fail-soft)',
                color: providerStatus.ready ? 'var(--ok)' : 'var(--fail)',
              }}
            >
              {providerStatus.ready ? 'Ready' : `Unavailable (${providerStatus.reason})`}
            </span>
          )}
        </div>
        {providerStatus && !providerStatus.credential_available && (
          <p role="alert" style={{ color: 'var(--fail)', marginTop: 8, marginBottom: 0 }}>
            Server credential is missing (<code>DEEPSEEK_API_KEY</code>). Configure the key in the backend server environment; raw API keys are never accepted or displayed in the browser.
          </p>
        )}
        {providerStatusError && (
          <p role="alert" style={{ color: 'var(--fail)', marginTop: 8, marginBottom: 0 }}>
            {providerStatusError}
          </p>
        )}
      </section>

      {/* Target selection */}
      <section aria-label="Target selection" className="panel" style={{ marginBottom: 14, padding: 14 }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <label style={{ flex: '1 1 280px', display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span>Target</span>
            <select
              aria-label="Target"
              value={config.targetId}
              disabled={disabled || targets.length === 0}
              onChange={(e) => updateField('targetId', e.target.value)}
            >
              {targets.length === 0 && <option value="">No targets available</option>}
              {targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.protocol}) — {t.authorization_status === 'reviewed_for_offline_configuration' ? 'Reviewed' : 'Unreviewed'}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            disabled={disabled || !config.targetId || readinessLoading}
            onClick={onCheckReadiness}
          >
            {readinessLoading ? 'Checking Readiness…' : 'Check Context Readiness'}
          </button>
        </div>
        {selectedTarget && selectedTarget.protocol === 'mcp-jsonrpc' && (
          <p style={{ color: 'var(--warn)', marginTop: 8, marginBottom: 0 }}>
            Protocol <code>mcp-jsonrpc</code> is blocked for natural-language prompt generation; select an <code>openai-chat</code> or <code>http-json</code> target.
          </p>
        )}
        {readinessError && (
          <p role="alert" style={{ color: 'var(--fail)', marginTop: 8, marginBottom: 0 }}>
            {readinessError}
          </p>
        )}
      </section>

      {/* OWASP ASI selection, independent counts & per-ASI readiness */}
      <section aria-label="OWASP ASI configuration" className="panel" style={{ marginBottom: 14, padding: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
          <strong>OWASP Agentic ASI Categories &amp; Counts</strong>
          <span data-testid="total-requested-count" style={{ fontWeight: 600 }}>
            Total: {total} / {GENERATOR_LIMITS.maxTotalCases}
          </span>
        </div>

        <div style={{ display: 'grid', gap: 10 }}>
          {SUPPORTED_ASI_CODES.map((code) => {
            const isChecked = config.selectedAsi[code];
            const assessment = readiness?.asi_assessments?.[code] ?? null;
            const allowedScopes = ALLOWED_SCOPES_BY_ASI[code];

            return (
              <div
                key={code}
                data-testid={`asi-row-${code}`}
                style={{
                  border: '1px solid var(--line)',
                  borderRadius: 8,
                  padding: 10,
                  background: isChecked ? 'var(--surface)' : 'var(--surface-soft)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: 8, flex: '1 1 240px', fontWeight: 600 }}>
                    <input
                      type="checkbox"
                      aria-label={`Select ${code}`}
                      checked={isChecked}
                      disabled={disabled}
                      onChange={(e) => toggleAsi(code, e.target.checked)}
                    />
                    <span>{ASI_LABELS[code]}</span>
                  </label>

                  <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span>Count</span>
                    <input
                      type="number"
                      aria-label={`${code} testcase count`}
                      min={GENERATOR_LIMITS.minPerAsi}
                      max={GENERATOR_LIMITS.maxPerAsi}
                      value={config.countsByAsi[code]}
                      disabled={disabled || !isChecked}
                      onChange={(e) => updateAsiCount(code, e.target.value)}
                      style={{ width: 72 }}
                    />
                  </label>

                  {showExecutionScopeSelector && (
                    <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span>Scope</span>
                      <select
                        aria-label={`${code} evaluation scope`}
                        value={config.requestedScopes[code] ?? ''}
                        disabled={disabled || !isChecked}
                        onChange={(e) => updateScope(code, e.target.value)}
                      >
                        <option value="">Default ({allowedScopes[0]})</option>
                        {allowedScopes.map((scope) => (
                          <option key={scope} value={scope}>
                            {scope}
                          </option>
                        ))}
                      </select>
                    </label>
                  )}

                  {assessment && (
                    <span
                      data-testid={`readiness-badge-${code}`}
                      style={{
                        padding: '2px 8px',
                        borderRadius: 6,
                        fontSize: 12,
                        fontWeight: 600,
                        background:
                          assessment.status === 'ready'
                            ? 'var(--ok-soft)'
                            : assessment.status === 'ready_with_warnings'
                              ? 'var(--warn-soft)'
                              : 'var(--fail-soft)',
                        color:
                          assessment.status === 'ready'
                            ? 'var(--ok)'
                            : assessment.status === 'ready_with_warnings'
                              ? 'var(--warn)'
                              : 'var(--fail)',
                      }}
                    >
                      {assessment.status}
                    </span>
                  )}
                </div>

                {assessment && (
                  <div style={{ marginTop: 8, fontSize: 12, color: 'var(--muted)' }}>
                    <div>
                      Effective scope: <code>{assessment.effective_scope ?? 'none'}</code> · Capability:{' '}
                      <code>{assessment.scope_capability_state}</code> ({assessment.scope_capability_provenance})
                    </div>
                    {assessment.blockers.length > 0 && (
                      <div style={{ color: 'var(--fail)', marginTop: 4 }}>
                        Blockers: {assessment.blockers.join(', ')}
                      </div>
                    )}
                    {assessment.warnings.length > 0 && (
                      <div style={{ color: 'var(--warn)', marginTop: 4 }}>
                        Warnings: {assessment.warnings.join(', ')}
                      </div>
                    )}
                    {assessment.ambiguous_policy_candidates.length > 1 && (
                      <div style={{ marginTop: 6 }}>
                        <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span>Select Reviewed Policy ({code}):</span>
                          <select
                            aria-label={`Reviewed Policy for ${code}`}
                            value={config.policyIdsByAsi[code] ?? ''}
                            disabled={disabled}
                            onChange={(e) => updatePolicyId(code, e.target.value)}
                          >
                            <option value="">— Choose explicit policy —</option>
                            {assessment.ambiguous_policy_candidates.map((cand) => (
                              <option key={cand.policy_id} value={cand.policy_id}>
                                {cand.policy_id} ({cand.evaluation_scope})
                              </option>
                            ))}
                          </select>
                        </label>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {countError && (
          <p role="alert" style={{ color: 'var(--fail)', marginTop: 8, marginBottom: 0 }}>
            {countError}
          </p>
        )}
      </section>

      {/* Generation Options: Language, Focus Note, Cross-ASI Dedup (default false) */}
      <section aria-label="Generation options" className="panel" style={{ padding: 14 }}>
        <div style={{ display: 'grid', gap: 10 }}>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span>Language</span>
              <select
                aria-label="Generation language"
                value={config.language}
                disabled={disabled}
                onChange={(e) => updateField('language', e.target.value as SupportedLanguage)}
              >
                <option value="en">English (en)</option>
                <option value="vi">Vietnamese (vi)</option>
              </select>
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <input
                type="checkbox"
                aria-label="Deduplicate prompts across different ASI categories"
                checked={config.deduplicateAcrossAsi}
                disabled={disabled}
                onChange={(e) => updateField('deduplicateAcrossAsi', e.target.checked)}
              />
              <span>Deduplicate across ASI categories (default: off for independent per-ASI evaluation)</span>
            </label>
          </div>

          <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span>
              Optional Focus Note ({config.focusNote.length} / {GENERATOR_LIMITS.maxFocusNoteChars} chars — treated as untrusted data)
            </span>
            <input
              type="text"
              aria-label="Focus note"
              maxLength={GENERATOR_LIMITS.maxFocusNoteChars}
              value={config.focusNote}
              disabled={disabled}
              placeholder="e.g., Focus on synthetic ticket triage escalation boundaries"
              onChange={(e) => updateField('focusNote', e.target.value)}
            />
          </label>
        </div>
      </section>
    </div>
  );
}
