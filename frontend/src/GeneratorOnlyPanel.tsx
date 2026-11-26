import { useRef, useState } from 'react';
import type { TargetPreset } from './testingApi';
import GeneratorConfigForm from './GeneratorConfigForm';
import {
  GENERATOR_LIMITS,
  GeneratorApiError,
  SUPPORTED_ASI_CODES,
  extractActiveCounts,
  generatorApi,
  utf8ByteLength,
  type GeneratorConfigState,
  type GeneratorPreviewSnapshot,
  type GeneratorProviderStatus,
  type PreviewCandidateEditItem,
  type PreviewCandidateView,
  type PreviewSaveRecord,
  type TargetReadinessReport,
} from './generatorApi';

function cloneConfigState(cfg: GeneratorConfigState): GeneratorConfigState {
  return {
    targetId: cfg.targetId,
    selectedAsi: { ...cfg.selectedAsi },
    countsByAsi: { ...cfg.countsByAsi },
    language: cfg.language,
    focusNote: cfg.focusNote,
    deduplicateAcrossAsi: cfg.deduplicateAcrossAsi,
    requestedScopes: { ...cfg.requestedScopes },
    policyIdsByAsi: { ...cfg.policyIdsByAsi },
  };
}

function buildGenerationConfigFingerprint(cfg: GeneratorConfigState): string {
  const activeCounts: Record<string, number> = {};
  const activeScopes: Record<string, string> = {};
  const activePolicies: Record<string, string> = {};
  for (const code of SUPPORTED_ASI_CODES) {
    if (!cfg.selectedAsi[code]) continue;
    activeCounts[code] = cfg.countsByAsi[code];
    if (cfg.requestedScopes[code]) activeScopes[code] = cfg.requestedScopes[code]!;
    if (cfg.policyIdsByAsi[code]) activePolicies[code] = cfg.policyIdsByAsi[code]!;
  }
  return JSON.stringify({
    targetId: cfg.targetId,
    counts: activeCounts,
    language: cfg.language,
    focusNote: cfg.focusNote.trim(),
    deduplicateAcrossAsi: cfg.deduplicateAcrossAsi,
    requestedScopes: activeScopes,
    policyIdsByAsi: activePolicies,
  });
}

type CandidateLocalDraft = {
  selected: boolean;
  prompt: string;
  description: string;
  resetToOriginal: boolean;
};

export type GeneratorOnlyPanelProps = {
  targets: TargetPreset[];
  config: GeneratorConfigState;
  onChangeConfig: (next: GeneratorConfigState) => void;
  nonce: string;
  secret?: string;
  providerStatus: GeneratorProviderStatus | null;
  providerStatusError?: string;
  readiness: TargetReadinessReport | null;
  readinessLoading: boolean;
  readinessError?: string;
  onCheckReadiness: () => void;
  onDatasetSaved?: (record: PreviewSaveRecord) => void;
  onOpenDatasetLibrary?: (datasetId: string) => void;
  compactMode?: boolean;
};

const STALE_PREVIEW_CODES = new Set([
  'preview_expired',
  'preview_not_found',
  'preview_target_revision_stale',
  'preview_context_revision_stale',
  'preview_policy_revision_stale',
]);

function buildDraftMap(candidates: PreviewCandidateView[]): Record<string, CandidateLocalDraft> {
  const map: Record<string, CandidateLocalDraft> = {};
  for (const cand of candidates) {
    map[cand.candidate_id] = {
      selected: cand.selected,
      prompt: cand.effective_prompt,
      description: cand.effective_description,
      resetToOriginal: false,
    };
  }
  return map;
}

/**
 * Mode 2 — Generate Only workflow wired directly to G11.3C Generator API.
 *
 * Configure -> Generate -> Preview -> Edit / Select / Reset -> Explicit Save -> Dataset Library.
 * Never executes any Target, never invokes Judge, and never auto-saves on generation.
 */
export default function GeneratorOnlyPanel({
  targets,
  config,
  onChangeConfig,
  nonce,
  secret = '',
  providerStatus,
  providerStatusError = '',
  readiness,
  readinessLoading,
  readinessError = '',
  onCheckReadiness,
  onDatasetSaved,
  onOpenDatasetLibrary,
  compactMode = false,
}: GeneratorOnlyPanelProps) {
  const [generating, setGenerating] = useState(false);
  const [updatingPreview, setUpdatingPreview] = useState(false);
  const [savingDataset, setSavingDataset] = useState(false);

  const [preview, setPreview] = useState<GeneratorPreviewSnapshot | null>(null);
  const [previewConfigSnapshot, setPreviewConfigSnapshot] = useState<GeneratorConfigState | null>(null);
  const [drafts, setDrafts] = useState<Record<string, CandidateLocalDraft>>({});
  const [expandedOriginals, setExpandedOriginals] = useState<Record<string, boolean>>({});

  const [datasetName, setDatasetName] = useState('');
  const [saveConfirmed, setSaveConfirmed] = useState(false);
  const [partialSaveConfirmed, setPartialSaveConfirmed] = useState(false);
  const [saveRecord, setSaveRecord] = useState<PreviewSaveRecord | null>(null);
  const [saveIdempotencyKey, setSaveIdempotencyKey] = useState('');

  const [errorCode, setErrorCode] = useState('');
  const [errorMessage, setErrorMessage] = useState('');

  // R02: Synchronous ref lock prevents double-submit & overlapping Generate/Edit/Save races.
  const inFlightOpRef = useRef<'none' | 'generate' | 'edit' | 'save'>('none');
  const opSeqRef = useRef(0);

  const anyBusy = generating || updatingPreview || savingDataset;
  const { counts, error: countError } = extractActiveCounts(config);
  const isStaleError = STALE_PREVIEW_CODES.has(errorCode);
  const providerUnavailable = providerStatus !== null && !providerStatus.credential_available;

  // R01: Bind active Preview strictly to the exact configuration that produced it.
  const isConfigMismatched =
    preview !== null &&
    preview.status === 'active' &&
    previewConfigSnapshot !== null &&
    buildGenerationConfigFingerprint(config) !== buildGenerationConfigFingerprint(previewConfigSnapshot);

  async function handleGenerate() {
    if (inFlightOpRef.current !== 'none' || countError || !config.targetId) return;
    inFlightOpRef.current = 'generate';
    const seq = ++opSeqRef.current;
    const submittedConfig = cloneConfigState(config);
    setGenerating(true);
    setErrorCode('');
    setErrorMessage('');
    setSaveRecord(null);
    setSaveConfirmed(false);
    setPartialSaveConfirmed(false);

    try {
      const nextPreview = await generatorApi.generate(
        {
          target_id: submittedConfig.targetId,
          counts_by_asi: counts,
          language: submittedConfig.language,
          focus_note: submittedConfig.focusNote.trim() ? submittedConfig.focusNote.trim() : null,
          requested_scopes:
            Object.keys(submittedConfig.requestedScopes).length > 0
              ? submittedConfig.requestedScopes
              : undefined,
          policy_ids_by_asi:
            Object.keys(submittedConfig.policyIdsByAsi).length > 0
              ? submittedConfig.policyIdsByAsi
              : undefined,
          deduplicate_across_asi: submittedConfig.deduplicateAcrossAsi,
        },
        nonce,
        secret,
      );
      if (opSeqRef.current !== seq) return;
      setPreview(nextPreview);
      setPreviewConfigSnapshot(submittedConfig);
      setDrafts(buildDraftMap(nextPreview.candidates));
      setExpandedOriginals({});
      setDatasetName(`${nextPreview.target_id}-${nextPreview.asi_order.join('-').toLowerCase()}`);
      setSaveIdempotencyKey(`save-${nextPreview.preview_id.slice(5, 21)}`);
    } catch (err) {
      if (opSeqRef.current !== seq) return;
      if (err instanceof GeneratorApiError) {
        setErrorCode(err.code);
        setErrorMessage(err.message);
      } else {
        setErrorCode('generation_failed');
        setErrorMessage(err instanceof Error ? err.message : 'Generation request failed.');
      }
    } finally {
      if (inFlightOpRef.current === 'generate') {
        inFlightOpRef.current = 'none';
      }
      setGenerating(false);
    }
  }

  function updateCandidateDraft(
    candidateId: string,
    patch: Partial<CandidateLocalDraft>,
  ) {
    setDrafts((prev) => {
      const current = prev[candidateId];
      if (!current) return prev;
      return {
        ...prev,
        [candidateId]: { ...current, ...patch },
      };
    });
  }

  function handleResetCandidate(cand: PreviewCandidateView) {
    updateCandidateDraft(cand.candidate_id, {
      prompt: cand.original_prompt,
      description: cand.original_description,
      resetToOriginal: true,
    });
  }

  function computePendingEdits(): { edits: PreviewCandidateEditItem[]; validationError: string | null } {
    if (!preview) return { edits: [], validationError: null };
    const edits: PreviewCandidateEditItem[] = [];

    for (const cand of preview.candidates) {
      const d = drafts[cand.candidate_id];
      if (!d) continue;

      const trimmedPrompt = d.prompt.trim();
      const trimmedDesc = d.description.trim();

      if (!trimmedPrompt) {
        return { edits: [], validationError: `Prompt for ${cand.candidate_id} must not be empty.` };
      }
      if (utf8ByteLength(trimmedPrompt) > GENERATOR_LIMITS.maxPromptUtf8Bytes) {
        return {
          edits: [],
          validationError: `Prompt for ${cand.candidate_id} exceeds ${GENERATOR_LIMITS.maxPromptUtf8Bytes} UTF-8 bytes.`,
        };
      }
      if (!trimmedDesc || trimmedDesc.length > GENERATOR_LIMITS.maxDescriptionChars) {
        return {
          edits: [],
          validationError: `Description for ${cand.candidate_id} must be 1–${GENERATOR_LIMITS.maxDescriptionChars} characters.`,
        };
      }

      const selectedChanged = d.selected !== cand.selected;
      const promptChanged = trimmedPrompt !== cand.effective_prompt;
      const descChanged = trimmedDesc !== cand.effective_description;

      if (d.resetToOriginal && (cand.operator_edited || promptChanged || descChanged || selectedChanged)) {
        const item: PreviewCandidateEditItem = {
          candidate_id: cand.candidate_id,
          reset_to_original: true,
        };
        if (selectedChanged) item.selected = d.selected;
        edits.push(item);
      } else if (selectedChanged || promptChanged || descChanged) {
        const item: PreviewCandidateEditItem = { candidate_id: cand.candidate_id };
        if (selectedChanged) item.selected = d.selected;
        if (promptChanged) item.prompt = trimmedPrompt;
        if (descChanged) item.description = trimmedDesc;
        edits.push(item);
      }
    }

    return { edits, validationError: null };
  }

  const pendingEditInfo = computePendingEdits();
  const selectedIdsInDraft = preview
    ? preview.candidates
        .filter((c) => (drafts[c.candidate_id]?.selected ?? c.selected))
        .map((c) => c.candidate_id)
    : [];

  async function _runEditPreview(
    targetPreview: GeneratorPreviewSnapshot,
    edits: PreviewCandidateEditItem[],
    seq: number,
  ): Promise<GeneratorPreviewSnapshot | null> {
    setUpdatingPreview(true);
    try {
      const updated = await generatorApi.editPreview(
        targetPreview.preview_id,
        edits,
        nonce,
        secret,
      );
      if (opSeqRef.current !== seq) return null;
      setPreview(updated);
      setDrafts(buildDraftMap(updated.candidates));
      return updated;
    } catch (err) {
      if (opSeqRef.current !== seq) return null;
      if (err instanceof GeneratorApiError) {
        setErrorCode(err.code);
        setErrorMessage(err.message);
      } else {
        setErrorCode('preview_edit_failed');
        setErrorMessage(err instanceof Error ? err.message : 'Failed to update preview.');
      }
      return null;
    } finally {
      setUpdatingPreview(false);
    }
  }

  async function handleApplyPreviewEdits(): Promise<GeneratorPreviewSnapshot | null> {
    if (
      inFlightOpRef.current !== 'none' ||
      !preview ||
      pendingEditInfo.validationError ||
      pendingEditInfo.edits.length === 0
    ) {
      return null;
    }
    inFlightOpRef.current = 'edit';
    const seq = ++opSeqRef.current;
    setErrorCode('');
    setErrorMessage('');
    try {
      return await _runEditPreview(preview, pendingEditInfo.edits, seq);
    } finally {
      if (inFlightOpRef.current === 'edit') {
        inFlightOpRef.current = 'none';
      }
    }
  }

  async function handleExplicitSave() {
    // R02: Acquire synchronous save lock BEFORE any await (including pending preview edits)
    // to prevent double-submit and overlapping Generate/Edit/Save operations.
    if (inFlightOpRef.current !== 'none') return;
    if (!preview || !preview.can_save || isConfigMismatched) return;
    if (pendingEditInfo.validationError) {
      setErrorCode('invalid_edit');
      setErrorMessage(pendingEditInfo.validationError);
      return;
    }

    inFlightOpRef.current = 'save';
    const seq = ++opSeqRef.current;
    setSavingDataset(true);
    setErrorCode('');
    setErrorMessage('');

    try {
      let activePreview = preview;
      if (pendingEditInfo.edits.length > 0) {
        const updated = await _runEditPreview(preview, pendingEditInfo.edits, seq);
        if (!updated || opSeqRef.current !== seq) return;
        activePreview = updated;
      }

      const selectedIds = activePreview.candidates
        .filter((c) => c.selected)
        .map((c) => c.candidate_id);

      const record = await generatorApi.savePreview(
        activePreview.preview_id,
        {
          dataset_name: datasetName.trim(),
          selected_candidate_ids: selectedIds,
          save_confirmed: saveConfirmed,
          partial_save_confirmed: activePreview.requires_partial_confirmation
            ? partialSaveConfirmed
            : false,
          idempotency_key: saveIdempotencyKey || undefined,
        },
        nonce,
        secret,
      );
      if (opSeqRef.current !== seq) return;
      setSaveRecord(record);
      setPreview({
        ...activePreview,
        status: 'saved',
        can_save: false,
        save_record: record,
      });
      onDatasetSaved?.(record);
    } catch (err) {
      if (opSeqRef.current !== seq) return;
      if (err instanceof GeneratorApiError) {
        setErrorCode(err.code);
        setErrorMessage(err.message);
      } else {
        setErrorCode('dataset_save_failed');
        setErrorMessage(err instanceof Error ? err.message : 'Failed to save dataset.');
      }
    } finally {
      if (inFlightOpRef.current === 'save') {
        inFlightOpRef.current = 'none';
      }
      setSavingDataset(false);
    }
  }

  function handleRestorePreviewConfig() {
    if (!previewConfigSnapshot || anyBusy) return;
    onChangeConfig(cloneConfigState(previewConfigSnapshot));
  }

  const canSubmitSave =
    Boolean(preview?.can_save) &&
    !isConfigMismatched &&
    !anyBusy &&
    !pendingEditInfo.validationError &&
    selectedIdsInDraft.length > 0 &&
    datasetName.trim().length > 0 &&
    saveConfirmed &&
    (!preview?.requires_partial_confirmation || partialSaveConfirmed);

  return (
    <div data-testid="generate-only-panel" aria-label="Generate Only workflow">
      <div
        className="panel"
        style={{ padding: 12, marginBottom: 14, background: 'var(--surface-soft)' }}
      >
        <strong>Generate Only</strong> —{' '}
        <code>Configure → Generate → Preview → Edit/Select → Explicit Save</code>. Does NOT execute any Target, does NOT call Judge, and does NOT persist a dataset until you confirm Save.
      </div>

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
        showExecutionScopeSelector={false}
        hideTargetSelector={compactMode}
        compactAdvanced={compactMode}
        disabled={anyBusy}
      />

      {/* Primary Generate action */}
      <div style={{ marginTop: 14, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <button
          type="button"
          data-testid="generate-only-submit-btn"
          disabled={anyBusy || !config.targetId || Boolean(countError) || providerUnavailable}
          onClick={() => void handleGenerate()}
          style={{ background: 'var(--teal)', color: '#fff', borderColor: 'var(--teal)' }}
        >
          {generating ? 'Generating Testcases…' : 'Generate Preview'}
        </button>
        <span style={{ fontSize: 12, color: 'var(--muted)' }}>
          Cross-ASI dedup: <code>{config.deduplicateAcrossAsi ? 'enabled' : 'disabled (default)'}</code> · Auto-save: <code>off</code> · Target execution: <code>off</code>
        </span>
      </div>

      {/* Structured error / stale-preview banner */}
      {errorMessage && (
        <div
          role="alert"
          data-testid="generator-error-banner"
          style={{
            marginTop: 14,
            padding: 12,
            borderRadius: 8,
            border: '1px solid var(--fail)',
            background: 'var(--fail-soft)',
            color: 'var(--fail)',
          }}
        >
          <strong>Error ({errorCode || 'request_failed'}):</strong> {errorMessage}
          {isStaleError && (
            <div style={{ marginTop: 6, color: 'var(--ink)' }}>
              Target, Application Context, Reviewed Policy, or preview TTL changed. Re-check readiness and generate a fresh preview before saving.
            </div>
          )}
        </div>
      )}

      {/* Preview Section */}
      {preview && (
        <section
          aria-label="Generated candidate preview"
          data-testid="generator-preview-section"
          className="panel"
          style={{ marginTop: 16, padding: 14 }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
            <div>
              <h3 style={{ margin: 0 }}>
                Preview <code>{preview.preview_id}</code>
              </h3>
              <div data-testid="preview-binding-summary" style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>
                Bound Target: <code>{preview.target_id}</code> · Bound ASIs:{' '}
                <code>{preview.asi_order.join(', ')}</code> · Generation <code>{preview.generation_id}</code> · Provider{' '}
                <code>{preview.provider_id}</code> / <code>{preview.model}</code> · Status:{' '}
                <strong data-testid="preview-overall-status">{preview.overall_status}</strong>
              </div>
            </div>
            <div data-testid="preview-counts-summary" style={{ fontSize: 13, fontWeight: 600 }}>
              Requested: {preview.total_requested} · Generated: {preview.total_generated} · Accepted:{' '}
              {preview.total_accepted} · Rejected: {preview.total_rejected} · Selected: {selectedIdsInDraft.length}
            </div>
          </div>

          {isConfigMismatched && (
            <div
              role="alert"
              data-testid="preview-config-mismatch-banner"
              style={{
                marginTop: 10,
                padding: 10,
                borderRadius: 8,
                background: 'var(--warn-soft)',
                border: '1px solid var(--warn)',
              }}
            >
              <strong>Configuration changed since this preview was generated.</strong> This preview is permanently bound to Target{' '}
              <code>{preview.target_id}</code> and ASIs <code>{preview.asi_order.join(', ')}</code>. Saving is blocked until you either restore the preview&apos;s original configuration or generate a new preview for the updated configuration.
              {pendingEditInfo.edits.length > 0 && (
                <div style={{ marginTop: 4, color: 'var(--fail)' }}>
                  Warning: You have {pendingEditInfo.edits.length} unsaved local candidate edit(s); generating a new preview will replace this preview.
                </div>
              )}
              <div style={{ marginTop: 8 }}>
                <button
                  type="button"
                  data-testid="restore-preview-config-btn"
                  disabled={anyBusy}
                  onClick={handleRestorePreviewConfig}
                >
                  Restore Preview Configuration ({preview.target_id})
                </button>
              </div>
            </div>
          )}

          {preview.requires_partial_confirmation && (
            <div
              role="status"
              data-testid="partial-generation-notice"
              style={{
                marginTop: 10,
                padding: 10,
                borderRadius: 8,
                background: 'var(--warn-soft)',
                border: '1px solid var(--warn)',
              }}
            >
              <strong>Partial generation:</strong> Only {preview.total_accepted} of {preview.total_requested} requested testcases were accepted ({preview.total_rejected} rejected). Saving a subset requires explicit partial confirmation and will NOT mark requested counts as met.
            </div>
          )}

          {/* Per-ASI summary & diagnostics */}
          <div style={{ display: 'grid', gap: 6, marginTop: 12 }}>
            {preview.asi_order.map((code) => {
              const summary = preview.asi_summaries[code];
              if (!summary) return null;
              return (
                <div
                  key={code}
                  data-testid={`preview-asi-summary-${code}`}
                  style={{
                    fontSize: 12,
                    padding: 8,
                    borderRadius: 6,
                    background: 'var(--surface-soft)',
                    border: '1px solid var(--line)',
                  }}
                >
                  <strong>{code}</strong> ({summary.effective_scope ?? 'no scope'}): status{' '}
                  <code>{summary.status}</code> · req {summary.requested_count} / gen {summary.generated_count} / acc{' '}
                  {summary.accepted_count} / rej {summary.rejected_count}
                  {summary.error_code && (
                    <span style={{ color: 'var(--fail)' }}> · error: {summary.error_code}</span>
                  )}
                  {summary.context_gaps.length > 0 && (
                    <div style={{ color: 'var(--warn)', marginTop: 4 }}>
                      Context gaps: {summary.context_gaps.join('; ')}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Accepted candidate cards (Editable prompt/description & selectable; immutable taxonomy/scope) */}
          {preview.candidates.length === 0 ? (
            <p style={{ marginTop: 12, color: 'var(--muted)' }}>
              No accepted candidates in this preview. Empty datasets cannot be saved.
            </p>
          ) : (
            <div style={{ display: 'grid', gap: 12, marginTop: 14 }}>
              {preview.candidates.map((cand) => {
                const draft = drafts[cand.candidate_id] ?? {
                  selected: cand.selected,
                  prompt: cand.effective_prompt,
                  description: cand.effective_description,
                  resetToOriginal: false,
                };
                const promptBytes = utf8ByteLength(draft.prompt.trim());
                const promptOverBytes = promptBytes > GENERATOR_LIMITS.maxPromptUtf8Bytes;
                const localEdited =
                  draft.prompt.trim() !== cand.original_prompt ||
                  draft.description.trim() !== cand.original_description;
                const showOriginal = Boolean(expandedOriginals[cand.candidate_id]);

                return (
                  <article
                    key={cand.candidate_id}
                    data-testid={`candidate-card-${cand.candidate_id}`}
                    style={{
                      border: '1px solid var(--line)',
                      borderRadius: 8,
                      padding: 12,
                      background: draft.selected ? 'var(--surface)' : 'var(--surface-soft)',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 600 }}>
                        <input
                          type="checkbox"
                          aria-label={`Select candidate ${cand.candidate_id}`}
                          checked={draft.selected}
                          disabled={preview.status !== 'active' || savingDataset}
                          onChange={(e) =>
                            updateCandidateDraft(cand.candidate_id, { selected: e.target.checked })
                          }
                        />
                        <code>{cand.candidate_id}</code>
                      </label>

                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', fontSize: 12 }}>
                        <span><code>{cand.asi_code}</code></span>
                        <span>scope: <code>{cand.effective_scope}</code></span>
                        <span
                          data-testid={`origin-badge-${cand.candidate_id}`}
                          style={{
                            padding: '1px 6px',
                            borderRadius: 4,
                            background: localEdited || cand.operator_edited ? 'var(--warn-soft)' : 'var(--teal-soft)',
                            color: localEdited || cand.operator_edited ? 'var(--warn)' : 'var(--teal)',
                            fontWeight: 600,
                          }}
                        >
                          {localEdited || cand.operator_edited ? 'operator_edited' : 'ai_generated_original'}
                        </span>
                      </div>
                    </div>

                    <div style={{ display: 'grid', gap: 8, marginTop: 10 }}>
                      <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                        <span style={{ fontSize: 12 }}>
                          Prompt ({promptBytes} / {GENERATOR_LIMITS.maxPromptUtf8Bytes} UTF-8 bytes)
                        </span>
                        <textarea
                          aria-label={`Prompt for ${cand.candidate_id}`}
                          rows={3}
                          value={draft.prompt}
                          disabled={preview.status !== 'active' || savingDataset}
                          onChange={(e) =>
                            updateCandidateDraft(cand.candidate_id, {
                              prompt: e.target.value,
                              resetToOriginal: false,
                            })
                          }
                          style={{ width: '100%', fontFamily: 'inherit', padding: 8, borderRadius: 6, border: '1px solid var(--line)' }}
                        />
                        {promptOverBytes && (
                          <span role="alert" style={{ color: 'var(--fail)', fontSize: 12 }}>
                            Prompt exceeds {GENERATOR_LIMITS.maxPromptUtf8Bytes} UTF-8 bytes.
                          </span>
                        )}
                      </label>

                      <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                        <span style={{ fontSize: 12 }}>
                          Description ({draft.description.length} / {GENERATOR_LIMITS.maxDescriptionChars} chars)
                        </span>
                        <input
                          type="text"
                          aria-label={`Description for ${cand.candidate_id}`}
                          maxLength={GENERATOR_LIMITS.maxDescriptionChars}
                          value={draft.description}
                          disabled={preview.status !== 'active' || savingDataset}
                          onChange={(e) =>
                            updateCandidateDraft(cand.candidate_id, {
                              description: e.target.value,
                              resetToOriginal: false,
                            })
                          }
                        />
                      </label>
                    </div>

                    <div style={{ marginTop: 8, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', fontSize: 12, color: 'var(--muted)' }}>
                      <span>Strategy: <code>{cand.strategy_tag}</code></span>
                      <span>Basis: <code>{cand.context_basis.join(', ')}</code></span>
                      <button
                        type="button"
                        onClick={() =>
                          setExpandedOriginals((prev) => ({
                            ...prev,
                            [cand.candidate_id]: !prev[cand.candidate_id],
                          }))
                        }
                      >
                        {showOriginal ? 'Hide Original & Hashes' : 'View Original & Hashes'}
                      </button>
                      {(localEdited || cand.operator_edited) && preview.status === 'active' && (
                        <button
                          type="button"
                          onClick={() => handleResetCandidate(cand)}
                        >
                          Reset to Original
                        </button>
                      )}
                    </div>

                    {showOriginal && (
                      <div
                        data-testid={`original-panel-${cand.candidate_id}`}
                        style={{
                          marginTop: 8,
                          padding: 8,
                          borderRadius: 6,
                          background: 'var(--surface-soft)',
                          fontSize: 12,
                        }}
                      >
                        <div><strong>Original Prompt:</strong> {cand.original_prompt}</div>
                        <div><strong>Original SHA-256:</strong> <code>{cand.original_prompt_sha256}</code></div>
                        <div><strong>Effective SHA-256:</strong> <code>{cand.effective_prompt_sha256}</code></div>
                      </div>
                    )}
                  </article>
                );
              })}
            </div>
          )}

          {/* Apply preview edits button */}
          {preview.status === 'active' && preview.candidates.length > 0 && (
            <div style={{ marginTop: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  data-testid="apply-preview-edits-btn"
                  disabled={
                    anyBusy ||
                    pendingEditInfo.edits.length === 0 ||
                    Boolean(pendingEditInfo.validationError)
                  }
                  onClick={() => void handleApplyPreviewEdits()}
                >
                  {updatingPreview ? 'Updating Preview…' : `Apply Preview Changes (${pendingEditInfo.edits.length})`}
                </button>
              {pendingEditInfo.validationError && (
                <span role="alert" style={{ color: 'var(--fail)', fontSize: 12 }}>
                  {pendingEditInfo.validationError}
                </span>
              )}
            </div>
          )}

          {/* Explicit Save Section */}
          {preview.can_save && (
            <section
              aria-label="Explicit dataset save"
              data-testid="explicit-save-section"
              style={{
                marginTop: 16,
                paddingTop: 14,
                borderTop: '1px solid var(--line)',
                display: 'grid',
                gap: 10,
              }}
            >
              <h4 style={{ margin: 0 }}>Explicit Save to Dataset Library</h4>
              <label style={{ display: 'flex', flexDirection: 'column', gap: 4, maxWidth: 420 }}>
                <span>Dataset Name</span>
                <input
                  type="text"
                  aria-label="Dataset name"
                  maxLength={120}
                  value={datasetName}
                  disabled={savingDataset}
                  onChange={(e) => setDatasetName(e.target.value)}
                />
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <input
                  type="checkbox"
                  aria-label="Confirm explicit save to Dataset Library"
                  checked={saveConfirmed}
                  disabled={savingDataset}
                  onChange={(e) => setSaveConfirmed(e.target.checked)}
                />
                <span>
                  Confirm explicit save of {selectedIdsInDraft.length} selected testcase(s) into Dataset Library
                </span>
              </label>

              {preview.requires_partial_confirmation && (
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--warn)', fontWeight: 600 }}>
                  <input
                    type="checkbox"
                    aria-label="Confirm saving partial generation subset"
                    checked={partialSaveConfirmed}
                    disabled={savingDataset}
                    onChange={(e) => setPartialSaveConfirmed(e.target.checked)}
                  />
                  <span>
                    Confirm partial subset save ({selectedIdsInDraft.length} selected / {preview.total_accepted} accepted / {preview.total_requested} requested)
                  </span>
                </label>
              )}

              <div>
                <button
                  type="button"
                  data-testid="explicit-save-btn"
                  disabled={!canSubmitSave}
                  onClick={() => void handleExplicitSave()}
                  style={{ background: 'var(--teal)', color: '#fff', borderColor: 'var(--teal)' }}
                >
                  {savingDataset ? 'Saving Dataset…' : 'Save Selected to Dataset Library'}
                </button>
              </div>
            </section>
          )}

          {/* Save Result + Link to Dataset Library */}
          {saveRecord && (
            <div
              role="status"
              data-testid="save-success-banner"
              style={{
                marginTop: 14,
                padding: 12,
                borderRadius: 8,
                border: '1px solid var(--ok)',
                background: 'var(--ok-soft)',
              }}
            >
              <strong>Saved to Dataset Library:</strong> Dataset ID{' '}
              <code data-testid="saved-dataset-id">{saveRecord.dataset_id}</code> ({saveRecord.saved_count} testcase(s) saved; requested {saveRecord.requested_count}, accepted {saveRecord.accepted_count}, rejected {saveRecord.rejected_count}).
              {!saveRecord.meets_requested_counts && (
                <div style={{ color: 'var(--warn)', marginTop: 4 }}>
                  Note: Saved dataset is a partial subset and does not meet the full requested count ({saveRecord.requested_count}).
                </div>
              )}
              <div style={{ marginTop: 8 }}>
                <a
                  href="#datasets"
                  data-testid="open-dataset-library-link"
                  onClick={(e) => {
                    if (onOpenDatasetLibrary) {
                      e.preventDefault();
                      onOpenDatasetLibrary(saveRecord.dataset_id);
                    }
                  }}
                  style={{ fontWeight: 700, textDecoration: 'underline', color: 'var(--teal)' }}
                >
                  Open Dataset Library
                </a>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
