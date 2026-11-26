import { useEffect, useMemo, useRef, useState } from 'react';
import type { TargetPreset } from './testingApi';
import GeneratorConfigForm from './GeneratorConfigForm';
import {
  GENERATE_AND_RUN_STAGES,
  GeneratorApiError,
  LIVE_GENERATE_AND_RUN_STAGES,
  SUPPORTED_ASI_CODES,
  clearActiveWorkflowId,
  clearPendingGenerateAndRunSubmission,
  extractActiveCounts,
  generatorApi,
  loadPendingGenerateAndRunSubmission,
  saveActiveWorkflowId,
  savePendingGenerateAndRunSubmission,
  type ActiveTargetReservation,
  type GenerateAndRunContractDraft,
  type GenerateAndRunSnapshot,
  type GeneratorConfigState,
  type GeneratorJudgeStatus,
  type GeneratorProviderStatus,
  type PendingGenerateAndRunSubmission,
  type StageStatus,
  type TargetReadinessReport,
} from './generatorApi';

export type GenerateAndRunPrepPanelProps = {
  targets: TargetPreset[];
  config: GeneratorConfigState;
  onChangeConfig: (next: GeneratorConfigState) => void;
  nonce?: string;
  secret?: string;
  generateAndRunAvailable?: boolean;
  providerStatus: GeneratorProviderStatus | null;
  judgeStatus?: GeneratorJudgeStatus | null;
  providerStatusError?: string;
  readiness: TargetReadinessReport | null;
  readinessLoading: boolean;
  readinessError?: string;
  onCheckReadiness: () => void;
  onSwitchToGenerateOnly?: () => void;
  onSwitchToRunExisting?: () => void;
  onOpenDatasetLibrary?: (datasetId?: string) => void;
  onOpenRunReport?: (runId: string) => void;
  onDatasetPersisted?: (datasetId: string) => void;
  onWorkflowStarted?: (workflow: GenerateAndRunSnapshot) => void;
  onOpenActiveWorkflow?: (workflowId?: string | null, runId?: string | null) => void;
  externalActiveReservation?: ActiveTargetReservation | null;
  compactMode?: boolean;
  hideInlinePipeline?: boolean;
};

type RecoveryState = 'idle' | 'uncertain' | 'checking' | 'not_found_retryable' | 'expired';

const TERMINAL_WORKFLOW_STATUSES = new Set([
  'completed',
  'failed',
  'blocked',
  'partial_stopped',
  'interrupted',
]);

function randomHex32(): string {
  const bytes = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 16; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function computeConfigDigest(
  cfg: GeneratorConfigState,
  evaluationMode: 'rule_only' | 'hybrid',
  datasetName: string,
): string {
  // Deterministic non-secret fingerprint for binding a stable submission_id to a config.
  const active: Record<string, number> = {};
  const scopes: Record<string, string> = {};
  const policies: Record<string, string> = {};
  for (const code of SUPPORTED_ASI_CODES) {
    if (!cfg.selectedAsi[code]) continue;
    active[code] = cfg.countsByAsi[code];
    if (cfg.requestedScopes[code]) scopes[code] = cfg.requestedScopes[code]!;
    if (cfg.policyIdsByAsi[code]) policies[code] = cfg.policyIdsByAsi[code]!;
  }
  const raw = JSON.stringify({
    targetId: cfg.targetId,
    active,
    scopes,
    policies,
    language: cfg.language,
    dedup: cfg.deduplicateAcrossAsi,
    evaluationMode,
    datasetName: datasetName.trim(),
    focusLen: cfg.focusNote.trim().length,
  });
  let hash = 2166136261;
  for (let i = 0; i < raw.length; i++) {
    hash ^= raw.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

function isUncertainNetworkError(err: unknown): boolean {
  if (err instanceof GeneratorApiError) {
    return err.status === 408 || err.status === 502 || err.status === 503 || err.status === 504;
  }
  // TypeError (Failed to fetch), AbortError (timeout), or any non-API exception
  return true;
}

function stageBadgeColor(status: StageStatus): string {
  if (status === 'completed') return 'var(--pass, #0f766e)';
  if (status === 'running') return 'var(--teal, #0d9488)';
  if (status === 'failed' || status === 'blocked') return 'var(--fail, #b91c1c)';
  return 'var(--muted, #64748b)';
}

/**
 * Mode 1 — Generate & Run (Primary Workflow).
 *
 * Architectural contract (G11.6 + R01–R04 + Judge-Centric Product Default):
 * - Primary product workflow: Configure -> Generate -> Validate -> Auto-Save Dataset ->
 *   Preflight -> Execute -> Evaluate/Judge -> Report (no mandatory Preview/Manual Save gate).
 * - Judge-centric product default: prioritizes Hybrid Judge when Judge status is present;
 *   if Judge is unavailable, displays clear status and NEVER silently downgrades hybrid -> rule_only
 *   (operator may still explicitly select rule_only).
 * - R02: Binds a stable submission_id to the active submission; after uncertain network/timeout
 *   failures, locks duplicate starts and recovers via GET /generate-and-run/submission/<id>
 *   before allowing a retry with the SAME submission_id. Stores zero credentials or sensitive payloads.
 * - R01/R04: Clearly displays preflight skipped/unsupported cases separately from partial generation,
 *   and allows Rerun with explicit evaluation_mode without regenerating prompts.
 */
export default function GenerateAndRunPrepPanel({
  targets,
  config,
  onChangeConfig,
  nonce = '',
  secret = '',
  generateAndRunAvailable = false,
  providerStatus,
  judgeStatus = null,
  providerStatusError = '',
  readiness,
  readinessLoading,
  readinessError = '',
  onCheckReadiness,
  onSwitchToGenerateOnly,
  onSwitchToRunExisting,
  onOpenDatasetLibrary,
  onOpenRunReport,
  onDatasetPersisted,
  onWorkflowStarted,
  onOpenActiveWorkflow,
  externalActiveReservation = null,
  compactMode = false,
  hideInlinePipeline = false,
}: GenerateAndRunPrepPanelProps) {
  const [evaluationMode, setEvaluationMode] = useState<'rule_only' | 'hybrid'>(() =>
    judgeStatus ? 'hybrid' : 'rule_only',
  );
  const userSelectedEvalModeRef = useRef(false);
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [datasetName, setDatasetName] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [rerunning, setRerunning] = useState(false);
  const [workflow, setWorkflow] = useState<GenerateAndRunSnapshot | null>(null);
  const [submitError, setSubmitError] = useState('');
  const [recoveryNotice, setRecoveryNotice] = useState('');
  const [rerunMessage, setRerunMessage] = useState('');
  const [discoveredReservation, setDiscoveredReservation] =
    useState<ActiveTargetReservation | null>(null);
  const [conflictDetail, setConflictDetail] = useState<ActiveTargetReservation | null>(null);

  const [pendingSubmission, setPendingSubmission] =
    useState<PendingGenerateAndRunSubmission | null>(() => loadPendingGenerateAndRunSubmission());
  const [recoveryState, setRecoveryState] = useState<RecoveryState>(() =>
    loadPendingGenerateAndRunSubmission() ? 'uncertain' : 'idle',
  );

  const inFlightRef = useRef(false);
  const rerunInFlightRef = useRef(false);
  const notifiedDatasetRef = useRef<string | null>(null);

  const configDigest = useMemo(
    () => computeConfigDigest(config, evaluationMode, datasetName),
    [config, evaluationMode, datasetName],
  );

  // Judge-centric product default: prioritize Hybrid Judge whenever backend reports Judge status
  // and operator has not explicitly selected another mode. NEVER silently downgrade hybrid -> rule_only.
  useEffect(() => {
    if (judgeStatus && !userSelectedEvalModeRef.current) {
      setEvaluationMode('hybrid');
    }
  }, [judgeStatus]);

  const selectedTarget = targets.find((t) => t.id === config.targetId) ?? null;
  const { counts, total, selectedList, error: countError } = extractActiveCounts(config);
  const isTargetReviewed =
    !selectedTarget ||
    selectedTarget.authorization_status === 'reviewed_for_offline_configuration';
  const hasReadinessBlocker = Boolean(
    readiness &&
      selectedList.some((asi) => readiness.asi_assessments[asi]?.status === 'blocked'),
  );
  const hybridBlockedByJudge = Boolean(
    evaluationMode === 'hybrid' && judgeStatus !== null && judgeStatus.judge_ready === false,
  );
  const recoveryLocksSubmit =
    recoveryState === 'uncertain' || recoveryState === 'checking' || recoveryState === 'expired';
  const isWorkflowActive = Boolean(workflow && !TERMINAL_WORKFLOW_STATUSES.has(workflow.status));
  const activeTargetConflict = externalActiveReservation ?? conflictDetail ?? discoveredReservation;
  const orchestrationLive = Boolean(generateAndRunAvailable && nonce);

  // Discover active backend workflows/reservations on mount or target switch (P0 navigation/refresh lock).
  useEffect(() => {
    setConflictDetail(null);
    if (!orchestrationLive || !config.targetId || typeof generatorApi.listGenerateAndRunWorkflows !== 'function') {
      setDiscoveredReservation(null);
      return;
    }
    const controller = new AbortController();
    generatorApi
      .listGenerateAndRunWorkflows(nonce, secret, controller.signal)
      .then((res) => {
        if (controller.signal.aborted) return;
        const activeRes =
          (res.active_reservations ?? []).find((r) => r.target_id === config.targetId) ?? null;
        if (activeRes) {
          setDiscoveredReservation(activeRes);
          return;
        }
        const runningWf =
          (res.workflows ?? []).find(
            (w) => w.target_id === config.targetId && !TERMINAL_WORKFLOW_STATUSES.has(w.status),
          ) ?? null;
        if (runningWf) {
          setDiscoveredReservation({
            target_id: runningWf.target_id,
            owner_kind: 'generate_and_run',
            workflow_id: runningWf.workflow_id,
            run_id: runningWf.run_id,
            reserved_at: runningWf.created_at,
          });
        } else {
          setDiscoveredReservation(null);
        }
      })
      .catch(() => {
        // Non-fatal in legacy mocks/offline environments without workflow listing route.
      });
    return () => controller.abort();
  }, [orchestrationLive, config.targetId, nonce, secret]);

  const formLocked = recoveryLocksSubmit || submitting || isWorkflowActive;

  const canSubmit = Boolean(
    orchestrationLive &&
      !submitting &&
      !isWorkflowActive &&
      !activeTargetConflict &&
      !recoveryLocksSubmit &&
      !readinessLoading &&
      config.targetId &&
      isTargetReviewed &&
      !countError &&
      selectedList.length > 0 &&
      authorizationConfirmed &&
      providerStatus?.ready !== false &&
      !hasReadinessBlocker &&
      !hybridBlockedByJudge,
  );

  // Poll running Generate & Run workflow until terminal state (when not handed off to unified progress view).
  useEffect(() => {
    if (!workflow || !nonce) return;
    if (TERMINAL_WORKFLOW_STATUSES.has(workflow.status)) {
      clearActiveWorkflowId();
      setDiscoveredReservation(null);
      setConflictDetail(null);
      return;
    }
    if (hideInlinePipeline) {
      return;
    }
    const controller = new AbortController();
    const timer = window.setInterval(() => {
      generatorApi
        .getGenerateAndRunStatus(workflow.workflow_id, nonce, secret, controller.signal)
        .then((updated) => {
          if (!controller.signal.aborted) {
            setWorkflow(updated);
          }
        })
        .catch(() => {
          // Transient poll error; keep current snapshot visible until next tick.
        });
    }, 1000);
    return () => {
      window.clearInterval(timer);
      controller.abort();
    };
  }, [workflow?.workflow_id, workflow?.status, nonce, secret, hideInlinePipeline]);

  // Notify parent when a dataset is auto-persisted so Mode 3 list can refresh.
  useEffect(() => {
    if (
      workflow?.dataset_id &&
      workflow.dataset_id !== notifiedDatasetRef.current
    ) {
      notifiedDatasetRef.current = workflow.dataset_id;
      onDatasetPersisted?.(workflow.dataset_id);
    }
  }, [workflow?.dataset_id, onDatasetPersisted]);

  const contractDraft: GenerateAndRunContractDraft = {
    mode: 'generate_and_run',
    requiresPreviewOrManualSave: false,
    orchestrationAvailable: orchestrationLive,
    generationConfig: config,
    evaluationMode,
    authorizationConfirmed,
    plannedStages: GENERATE_AND_RUN_STAGES.map((s) => s.id),
    plannedDatasetLink: workflow?.dataset_id ? '#datasets' : null,
    plannedRunLink: workflow?.run_id ? `#scan/${workflow.run_id}` : null,
  };

  function clearRecovery() {
    clearPendingGenerateAndRunSubmission();
    setPendingSubmission(null);
    setRecoveryState('idle');
  }

  async function verifyPendingSubmission(targetPending: PendingGenerateAndRunSubmission) {
    if (!nonce) return;
    setRecoveryState('checking');
    setSubmitError('');
    try {
      const recovered = await generatorApi.getGenerateAndRunBySubmission(
        targetPending.submission_id,
        nonce,
        secret,
      );
      clearRecovery();
      setWorkflow(recovered);
      setRecoveryNotice(
        `Recovered existing workflow ${recovered.workflow_id} for submission ${targetPending.submission_id.slice(0, 10)} (no duplicate run started).`,
      );
    } catch (err) {
      if (err instanceof GeneratorApiError && err.status === 404 && err.code === 'workflow_submission_not_found') {
        // Confirmed server never accepted this submission_id; safe to retry with the SAME submission_id.
        setRecoveryState('not_found_retryable');
        setRecoveryNotice(
          `Server confirmed submission ${targetPending.submission_id.slice(0, 10)} was not started. You may safely retry with the same submission ID.`,
        );
      } else if (err instanceof GeneratorApiError && (err.status === 410 || err.code === 'workflow_submission_expired')) {
        // Issue B: Server confirmed submission_id WAS used, but snapshot expired — do NOT auto-retry same ID!
        setRecoveryState('expired');
        setSubmitError(
          `Submission ${targetPending.submission_id.slice(0, 10)} was already executed, but its in-memory workflow snapshot expired. Inspect Dataset Library or Scan Runs before acknowledging and starting a fresh run.`,
        );
      } else {
        setRecoveryState('uncertain');
        setSubmitError(
          err instanceof GeneratorApiError
            ? `${err.code}: ${err.message}`
            : err instanceof Error
              ? err.message
              : 'Could not verify submission status; retry verification before starting a new workflow.',
        );
      }
    }
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (!orchestrationLive || !canSubmit || inFlightRef.current) {
      return;
    }

    inFlightRef.current = true;
    setSubmitting(true);
    setSubmitError('');
    setRecoveryNotice('');
    setRerunMessage('');

    // R02: Reuse the exact same submission_id when retrying a confirmed-not-found identical config.
    const reuseExisting =
      pendingSubmission !== null &&
      recoveryState === 'not_found_retryable' &&
      pendingSubmission.config_digest === configDigest &&
      pendingSubmission.target_id === config.targetId;
    const submissionId = reuseExisting ? pendingSubmission.submission_id : randomHex32();
    const pendingEntry: PendingGenerateAndRunSubmission = {
      submission_id: submissionId,
      target_id: config.targetId,
      config_digest: configDigest,
      created_at: new Date().toISOString(),
    };
    setPendingSubmission(pendingEntry);
    savePendingGenerateAndRunSubmission(pendingEntry);

    const activeScopes: Partial<Record<(typeof selectedList)[number], string>> = {};
    const activePolicies: Partial<Record<(typeof selectedList)[number], string>> = {};
    for (const code of selectedList) {
      if (config.requestedScopes[code]) activeScopes[code] = config.requestedScopes[code];
      if (config.policyIdsByAsi[code]) activePolicies[code] = config.policyIdsByAsi[code];
    }

    try {
      const result = await generatorApi.startGenerateAndRun(
        {
          target_id: config.targetId,
          counts_by_asi: counts,
          language: config.language,
          focus_note: config.focusNote.trim() ? config.focusNote.trim() : null,
          requested_scopes: Object.keys(activeScopes).length > 0 ? activeScopes : undefined,
          policy_ids_by_asi: Object.keys(activePolicies).length > 0 ? activePolicies : undefined,
          deduplicate_across_asi: config.deduplicateAcrossAsi,
          evaluation_mode: evaluationMode,
          execution_mode: 'live',
          authorization_confirmed: true,
          allow_partial_execution: false,
          dataset_name: datasetName.trim() ? datasetName.trim() : null,
          submission_id: submissionId,
          async_execution: true,
          expected_target_revision: selectedTarget?.profile_revision ?? null,
        },
        nonce,
        secret,
      );
      clearRecovery();
      setConflictDetail(null);
      if (!TERMINAL_WORKFLOW_STATUSES.has(result.status)) {
        saveActiveWorkflowId(result.workflow_id);
      }
      setWorkflow(result);
      onWorkflowStarted?.(result);
    } catch (err) {
      if (isUncertainNetworkError(err)) {
        // R02: Network/timeout drop — keep exact submission_id and attempt automatic status recovery.
        setRecoveryState('uncertain');
        setSubmitError(
          err instanceof Error
            ? `Connection/timeout interrupted (${err.message}). Verifying submission ${submissionId.slice(0, 10)} before allowing retry.`
            : `Connection interrupted. Verifying submission ${submissionId.slice(0, 10)} before allowing retry.`,
        );
        inFlightRef.current = false;
        setSubmitting(false);
        await verifyPendingSubmission(pendingEntry);
        return;
      }
      // Definitive 4xx rejection from server — safe to clear pending submission.
      clearRecovery();
      if (err instanceof GeneratorApiError && err.status === 409 && err.conflict) {
        setConflictDetail(err.conflict);
      }
      setSubmitError(
        err instanceof GeneratorApiError
          ? `${err.code}: ${err.message}`
          : err instanceof Error
            ? err.message
            : 'Generate & Run request failed.',
      );
    } finally {
      inFlightRef.current = false;
      setSubmitting(false);
    }
  }

  const canRerunWorkflow = Boolean(
    workflow?.rerun_supported &&
      workflow?.dataset_id &&
      TERMINAL_WORKFLOW_STATUSES.has(workflow.status) &&
      !rerunning &&
      authorizationConfirmed &&
      !hybridBlockedByJudge,
  );

  async function handleRerunSavedDataset() {
    if (!canRerunWorkflow || !workflow?.dataset_id || !nonce || rerunInFlightRef.current) {
      return;
    }
    rerunInFlightRef.current = true;
    setRerunning(true);
    setSubmitError('');
    setRerunMessage('');
    try {
      const res = await generatorApi.rerunGenerateAndRun(
        workflow.workflow_id,
        {
          authorization_confirmed: true,
          evaluation_mode: evaluationMode,
          submission_id: randomHex32(),
          async_execution: true,
        },
        nonce,
        secret,
      );
      setWorkflow(res.workflow);
      setRerunMessage(
        `Rerun started on saved dataset ${res.dataset_id} (new Run ID: ${res.new_run_id}; mode: ${res.evaluation_mode ?? evaluationMode}; Generator called: no).`,
      );
    } catch (err) {
      setSubmitError(
        err instanceof GeneratorApiError
          ? `${err.code}: ${err.message}`
          : err instanceof Error
            ? err.message
            : 'Rerun failed.',
      );
    } finally {
      rerunInFlightRef.current = false;
      setRerunning(false);
    }
  }

  const stageById = new Map((workflow?.stages ?? []).map((s) => [s.stage, s]));

  return (
    <form
      onSubmit={handleSubmit}
      data-testid="generate-and-run-panel"
      aria-label="Generate and Run workflow"
    >
      {/* Status banner: live when G11.6 backend orchestration is active; fail-closed otherwise */}
      {!compactMode && (orchestrationLive ? (
        <div
          role="status"
          data-testid="g11-6-active-banner"
          style={{
            padding: 14,
            marginBottom: 14,
            borderRadius: 8,
            border: '1px solid var(--teal)',
            background: 'var(--teal-soft)',
            color: 'var(--ink)',
          }}
        >
          <strong>Generate &amp; Run (Primary Workflow) — Automated Pipeline Active</strong>
          <p style={{ margin: '6px 0 0' }}>
            One-click automated flow:{' '}
            <code>
              Configure → Generate → Validate → Auto-Save Dataset → Preflight → Execute → Evaluate → Report
            </code>{' '}
            (no mandatory Preview/Edit/Manual Save step).
          </p>
          <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
            {onSwitchToGenerateOnly && (
              <button type="button" onClick={onSwitchToGenerateOnly}>
                Switch to Generate Only (Preview &amp; Edit)
              </button>
            )}
            {onSwitchToRunExisting && (
              <button type="button" onClick={onSwitchToRunExisting}>
                Run Existing Dataset
              </button>
            )}
          </div>
        </div>
      ) : (
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
            One-click automated flow:{' '}
            <code>
              Configure → Generate → Validate → Auto-Save Dataset → Preflight → Execute → Judge → Report
            </code>{' '}
            (no mandatory Preview/Edit/Manual Save step). Execution orchestration is scheduled for{' '}
            <strong>G11.6</strong> after merging with G12; this panel prepares the configuration
            contract and will not trigger Target execution yet.
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
      ))}

      {/* P0 Active Target Reservation / Conflict Banner */}
      {activeTargetConflict && !isWorkflowActive && (
        <div
          role="alert"
          data-testid="active-target-conflict-banner"
          style={{
            padding: 12,
            marginBottom: 14,
            borderRadius: 8,
            border: '1px solid var(--warn)',
            background: 'var(--warn-soft)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: 12,
            flexWrap: 'wrap',
          }}
        >
          <div style={{ fontSize: 13 }}>
            <strong>Active Live Execution on Target <code>{activeTargetConflict.target_id}</code>:</strong>{' '}
            Another workflow or scan is currently running on this live target (
            {activeTargetConflict.workflow_id
              ? <>Workflow <code>{activeTargetConflict.workflow_id}</code></>
              : activeTargetConflict.run_id
                ? <>Run <code>{activeTargetConflict.run_id}</code></>
                : 'active execution'}
            ). Concurrent live execution on the same target is blocked to prevent conflicting runs.
          </div>
          {(activeTargetConflict.workflow_id || activeTargetConflict.run_id) && (
            <button
              type="button"
              data-testid="open-active-conflict-btn"
              onClick={() => {
                if (onOpenActiveWorkflow) {
                  onOpenActiveWorkflow(activeTargetConflict.workflow_id, activeTargetConflict.run_id);
                } else if (activeTargetConflict.run_id && onOpenRunReport) {
                  onOpenRunReport(activeTargetConflict.run_id);
                } else if (typeof window !== 'undefined') {
                  window.location.hash = activeTargetConflict.workflow_id
                    ? `#scan/wf/${activeTargetConflict.workflow_id}`
                    : `#scan/${activeTargetConflict.run_id}`;
                }
              }}
            >
              Open Active Progress →
            </button>
          )}
        </div>
      )}

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
        hideTargetSelector={compactMode}
        compactAdvanced={compactMode}
        disabled={formLocked}
      />

      {/* Execution, Authorization & Fail-Closed Guardrails */}
      <section
        aria-label="Execution and authorization contract"
        className="panel"
        style={{ marginTop: 14, padding: 14 }}
      >
        <h3 style={{ marginTop: 0 }}>Execution Scope, Evaluation &amp; Authorization Preflight</h3>
        <div style={{ display: 'grid', gap: 10 }}>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span>Evaluation Mode</span>
              <select
                aria-label="Planned evaluation mode"
                disabled={formLocked}
                value={evaluationMode}
                onChange={(e) => {
                  userSelectedEvalModeRef.current = true;
                  setEvaluationMode(e.target.value as 'rule_only' | 'hybrid');
                }}
              >
                <option value="hybrid">Hybrid (LLM Judge + Evidence + Rules — Recommended)</option>
                <option value="rule_only">Deterministic Rules / Evidence Only</option>
              </select>
            </label>

            {judgeStatus && (
              <span
                data-testid="judge-readiness-status"
                style={{
                  fontSize: 13,
                  fontWeight: 600,
                  color: judgeStatus.judge_ready ? 'var(--pass, #0f766e)' : 'var(--fail, #b91c1c)',
                }}
              >
                Judge:{' '}
                {judgeStatus.judge_ready
                  ? `Ready (${judgeStatus.provider ?? 'judge'} / ${judgeStatus.model ?? 'default'})`
                  : `Unavailable (${judgeStatus.reason})`}
              </span>
            )}

            <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span>Auto-saved Dataset Label (optional)</span>
              <input
                type="text"
                aria-label="Auto-saved dataset label"
                disabled={formLocked}
                value={datasetName}
                onChange={(e) => setDatasetName(e.target.value)}
                placeholder="Auto-generated if blank"
                maxLength={120}
              />
            </label>

            <span data-testid="preflight-target-auth-status">
              Target review:{' '}
              <strong>
                {selectedTarget
                  ? isTargetReviewed
                    ? 'Reviewed'
                    : 'Unreviewed (required before live execution)'
                  : 'No target selected'}
              </strong>
            </span>
          </div>

          {hybridBlockedByJudge && judgeStatus && (
            <div
              role="alert"
              data-testid="hybrid-judge-unavailable-alert"
              style={{
                padding: 10,
                borderRadius: 8,
                border: '1px solid var(--warn)',
                background: 'var(--warn-soft)',
                fontSize: 13,
              }}
            >
              <strong>Hybrid Judge unavailable ({judgeStatus.reason}).</strong> SecAgent will not
              silently downgrade Hybrid evaluation to <code>rule_only</code>. Configure Judge
              credentials on the server or explicitly select{' '}
              <em>Deterministic Rules / Evidence Only</em> above to proceed.
            </div>
          )}

          <ul style={{ margin: 0, paddingLeft: 18, color: 'var(--muted)', fontSize: 13 }}>
            <li>
              Dataset will be automatically persisted as immutable before Target execution begins.
            </li>
            <li>
              Fail-closed: execution will NOT start if generation fails, returns partial counts,
              preflight skips unsupported testcases, or consent is missing.
            </li>
            <li>
              Rerun reuses the saved immutable dataset without calling Generator; Resume continues
              interrupted runs without regenerating prompts.
            </li>
          </ul>

          <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <input
              type="checkbox"
              aria-label="Confirm authorized Generate and Run scope"
              disabled={formLocked}
              checked={authorizationConfirmed}
              onChange={(e) => setAuthorizationConfirmed(e.target.checked)}
            />
            <span>
              Confirm authorized local testbed scope for {selectedList.length} ASI group(s) ({total}{' '}
              planned testcase(s))
            </span>
          </label>
        </div>

        {/* R02: Pending submission recovery banner */}
        {pendingSubmission && recoveryState !== 'idle' && (
          <div
            role="status"
            data-testid="pending-submission-recovery"
            style={{
              marginTop: 12,
              padding: 12,
              borderRadius: 8,
              border: '1px solid var(--warn)',
              background: 'var(--warn-soft)',
              fontSize: 13,
            }}
          >
            <div>
              <strong>Pending Submission Recovery:</strong>{' '}
              <code data-testid="pending-submission-id">{pendingSubmission.submission_id}</code>{' '}
              (status: <code>{recoveryState}</code>)
            </div>
            <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
              {recoveryState !== 'expired' && (
                <button
                  type="button"
                  data-testid="verify-submission-btn"
                  disabled={recoveryState === 'checking'}
                  onClick={() => verifyPendingSubmission(pendingSubmission)}
                >
                  {recoveryState === 'checking'
                    ? 'Checking Server Status…'
                    : 'Check Status / Recover Workflow'}
                </button>
              )}
              {(recoveryState === 'not_found_retryable' || recoveryState === 'expired') && (
                <button
                  type="button"
                  data-testid="discard-recovery-btn"
                  onClick={() => {
                    clearRecovery();
                    setRecoveryNotice('');
                    setSubmitError('');
                  }}
                >
                  {recoveryState === 'expired'
                    ? 'Acknowledge Expired Submission & Start Fresh'
                    : 'Clear & Use Fresh Submission'}
                </button>
              )}
            </div>
          </div>
        )}

        {recoveryNotice && (
          <div
            role="status"
            data-testid="workflow-recovery-notice"
            style={{
              marginTop: 10,
              padding: 8,
              borderRadius: 6,
              border: '1px solid var(--teal)',
              background: 'var(--teal-soft)',
              fontSize: 13,
            }}
          >
            {recoveryNotice}
          </div>
        )}

        <div
          style={{ marginTop: 14, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}
        >
          <button
            type="submit"
            disabled={!canSubmit}
            aria-disabled={!canSubmit}
            data-testid="generate-and-run-submit-btn"
            style={{ background: 'var(--teal)', color: '#fff', borderColor: 'var(--teal)' }}
          >
            {!orchestrationLive
              ? 'Generate & Run (Unavailable until G11.6)'
              : submitting
                ? 'Starting Generate & Run…'
                : isWorkflowActive
                  ? 'Workflow Running…'
                  : activeTargetConflict
                    ? 'Target Busy — Active Execution in Progress'
                    : recoveryState === 'not_found_retryable' &&
                        pendingSubmission?.config_digest === configDigest
                      ? 'Retry Generate & Run (Same Submission ID)'
                      : 'Generate & Run'}
          </button>
          {countError && <span style={{ color: 'var(--fail)', fontSize: 13 }}>{countError}</span>}
          {!isTargetReviewed && selectedTarget && (
            <span style={{ color: 'var(--fail)', fontSize: 13 }}>
              Review and authorize this Target before starting live Generate &amp; Run.
            </span>
          )}
          {hasReadinessBlocker && (
            <span style={{ color: 'var(--fail)', fontSize: 13 }}>
              One or more selected ASIs are blocked by readiness; resolve blockers before running.
            </span>
          )}
        </div>

        {submitError && (
          <div
            role="alert"
            data-testid="generate-and-run-error"
            style={{
              marginTop: 12,
              padding: 10,
              borderRadius: 8,
              border: '1px solid var(--fail)',
              background: 'var(--fail-soft, #fef2f2)',
              color: 'var(--fail)',
            }}
          >
            <strong>Generate &amp; Run Error:</strong> {submitError}
          </div>
        )}
      </section>

      {/* Pipeline Stages & Live Status (hidden when unified #scan handles live progress) */}
      {!hideInlinePipeline && (
      <section
        aria-label={
          orchestrationLive ? 'Automated orchestration pipeline' : 'Planned orchestration pipeline'
        }
        className="panel"
        style={{ marginTop: 14, padding: 14 }}
      >
        <h3 style={{ marginTop: 0 }}>
          {orchestrationLive
            ? 'Automated Generate & Run Pipeline'
            : 'Planned Automated Pipeline (G11.6)'}
        </h3>

        {orchestrationLive ? (
          <ol
            data-testid="generate-and-run-stages"
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(165px, 1fr))',
              gap: 8,
              listStyle: 'none',
              padding: 0,
              margin: 0,
            }}
          >
            {LIVE_GENERATE_AND_RUN_STAGES.map((stage, idx) => {
              const live = stageById.get(stage.id);
              const status: StageStatus = live?.status ?? 'pending';
              return (
                <li
                  key={stage.id}
                  data-testid={`workflow-stage-${stage.id}`}
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
                  <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4 }}>
                    {live?.detail || stage.description}
                  </div>
                  <div
                    style={{
                      fontSize: 11,
                      marginTop: 6,
                      fontWeight: 700,
                      color: stageBadgeColor(status),
                    }}
                  >
                    Status: {status}
                  </div>
                  {live?.error_message && (
                    <div style={{ fontSize: 11, marginTop: 4, color: 'var(--fail)' }}>
                      {live.error_code ? `${live.error_code}: ` : ''}
                      {live.error_message}
                    </div>
                  )}
                </li>
              );
            })}
          </ol>
        ) : (
          <ol
            data-testid="generate-and-run-stages"
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
              gap: 8,
              listStyle: 'none',
              padding: 0,
              margin: 0,
            }}
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
                <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4 }}>
                  {stage.description}
                </div>
                <div
                  style={{ fontSize: 11, marginTop: 6, fontWeight: 600, color: 'var(--muted)' }}
                >
                  Status: Planned (G11.6)
                </div>
              </li>
            ))}
          </ol>
        )}

        {/* Active / Completed Workflow Summary, Provenance, Links & Rerun */}
        {workflow ? (
          <div
            data-testid="generate-and-run-result"
            style={{
              marginTop: 14,
              padding: 12,
              borderRadius: 8,
              border: '1px solid var(--line)',
              background: 'var(--surface)',
              display: 'grid',
              gap: 10,
            }}
          >
            <div
              style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}
            >
              <div>
                <strong>Workflow:</strong> <code>{workflow.workflow_id}</code> · Status:{' '}
                <strong data-testid="workflow-overall-status">{workflow.status}</strong> · Stage:{' '}
                <code>{workflow.current_stage}</code>
              </div>
              <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                Provider: <code>{workflow.provider_id ?? 'n/a'}</code> /{' '}
                <code>{workflow.model ?? 'n/a'}</code> · Active Evaluation:{' '}
                <code data-testid="workflow-eval-mode">{workflow.evaluation_mode}</code>
              </div>
            </div>

            {workflow.error_message && (
              <div
                role="alert"
                data-testid="workflow-stage-error"
                style={{
                  padding: 10,
                  borderRadius: 6,
                  border: '1px solid var(--fail)',
                  background: 'var(--fail-soft, #fef2f2)',
                  color: 'var(--fail)',
                }}
              >
                <strong>
                  Stopped at stage <code>{workflow.error_stage ?? workflow.current_stage}</code> (
                  <code>{workflow.error_code ?? 'error'}</code>):
                </strong>{' '}
                {workflow.error_message}
              </div>
            )}

            {/* Separate Generation vs Preflight/Dataset vs Execution/Verdict metrics */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
                gap: 10,
                fontSize: 13,
              }}
            >
              <div style={{ padding: 10, border: '1px solid var(--line)', borderRadius: 6 }}>
                <div style={{ fontWeight: 700, marginBottom: 4 }}>1. Generation Outcome</div>
                <div>
                  Generation ID: <code>{workflow.generation_id ?? '—'}</code>
                </div>
                <div>
                  Counts: requested <strong>{workflow.requested_count}</strong> · generated{' '}
                  <strong>{workflow.generated_count}</strong> · accepted{' '}
                  <strong>{workflow.accepted_count}</strong> · rejected{' '}
                  <strong>{workflow.rejected_count}</strong>
                </div>
                <div>
                  Meets requested: <strong>{workflow.meets_requested_counts ? 'Yes' : 'No'}</strong>
                </div>
              </div>

              <div style={{ padding: 10, border: '1px solid var(--line)', borderRadius: 6 }}>
                <div style={{ fontWeight: 700, marginBottom: 4 }}>
                  2. Auto-Persisted Dataset &amp; Preflight
                </div>
                <div>
                  Dataset ID:{' '}
                  <code data-testid="workflow-dataset-id">{workflow.dataset_id ?? 'Not saved'}</code>
                </div>
                <div>Name: {workflow.dataset_name ?? '—'}</div>
                <div>
                  Testcases: {workflow.testcase_ids.length}
                  {(workflow.preflight_skipped_count ?? 0) > 0 && (
                    <span>
                      {' '}
                      (ready: {workflow.preflight_ready_count}, skipped/unsupported:{' '}
                      {workflow.preflight_skipped_count})
                    </span>
                  )}
                </div>
              </div>

              <div style={{ padding: 10, border: '1px solid var(--line)', borderRadius: 6 }}>
                <div style={{ fontWeight: 700, marginBottom: 4 }}>3. Execution &amp; Verdicts</div>
                <div>
                  Run ID:{' '}
                  <code data-testid="workflow-run-id">{workflow.run_id ?? 'Not started'}</code>
                </div>
                <div>
                  Run status: <strong>{workflow.run_status ?? '—'}</strong> (
                  {workflow.executed_cases}/{workflow.total_cases})
                </div>
                <div>
                  Verdicts:{' '}
                  <code>
                    {Object.keys(workflow.verdict_counts).length > 0
                      ? JSON.stringify(workflow.verdict_counts)
                      : 'Pending / None'}
                  </code>
                  {(workflow.evaluation_summary?.technical_failure_count ?? 0) > 0 && (
                    <span style={{ marginLeft: 8, color: 'var(--fail)', fontWeight: 600 }}>
                      · Technical Failures: {workflow.evaluation_summary!.technical_failure_count}
                    </span>
                  )}
                </div>
              </div>
            </div>

            {rerunMessage && (
              <div
                role="status"
                data-testid="workflow-rerun-status"
                style={{
                  padding: 8,
                  borderRadius: 6,
                  border: '1px solid var(--teal)',
                  background: 'var(--teal-soft)',
                  fontSize: 13,
                }}
              >
                {rerunMessage}
              </div>
            )}

            {/* Navigation Links + Rerun (distinct from Resume) */}
            <div
              data-testid="workflow-output-links"
              style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}
            >
              {workflow.dataset_id && (
                <a
                  href="#datasets"
                  data-testid="workflow-open-dataset-link"
                  onClick={(e) => {
                    if (onOpenDatasetLibrary) {
                      e.preventDefault();
                      onOpenDatasetLibrary(workflow.dataset_id ?? undefined);
                    }
                  }}
                  style={{ fontWeight: 600, color: 'var(--teal)', textDecoration: 'underline' }}
                >
                  Inspect Saved Dataset ({workflow.dataset_id.slice(0, 10)})
                </a>
              )}
              {workflow.run_id && (
                <a
                  href={`#scan/${workflow.run_id}`}
                  data-testid="workflow-open-report-link"
                  onClick={(e) => {
                    if (onOpenRunReport) {
                      e.preventDefault();
                      onOpenRunReport(workflow.run_id!);
                    }
                  }}
                  style={{ fontWeight: 600, color: 'var(--teal)', textDecoration: 'underline' }}
                >
                  Open Run Report ({workflow.run_id.slice(0, 10)})
                </a>
              )}
              {workflow.dataset_id && (workflow.rerun_supported || workflow.status === 'running') && (
                <button
                  type="button"
                  data-testid="workflow-rerun-btn"
                  disabled={!canRerunWorkflow}
                  onClick={handleRerunSavedDataset}
                >
                  {rerunning
                    ? 'Starting Rerun…'
                    : workflow.status === 'running'
                      ? 'Rerun Unavailable While Active'
                      : 'Rerun Saved Dataset (No AI Regeneration)'}
                </button>
              )}
            </div>

            <div style={{ fontSize: 12, color: 'var(--muted)' }}>
              {workflow.resume_note}
              {workflow.resume_supported && workflow.run_id && (
                <>
                  {' '}
                  Interrupted run can be resumed from{' '}
                  <a
                    href={`#scan/${workflow.run_id}`}
                    onClick={(e) => {
                      if (onOpenRunReport) {
                        e.preventDefault();
                        onOpenRunReport(workflow.run_id!);
                      }
                    }}
                  >
                    Scan View (Resume Checkpoint)
                  </a>
                  .
                </>
              )}
            </div>
          </div>
        ) : (
          <div
            data-testid="planned-output-links"
            style={{
              marginTop: 12,
              display: 'flex',
              gap: 16,
              flexWrap: 'wrap',
              fontSize: 13,
              color: 'var(--muted)',
            }}
          >
            <span>
              Auto-saved Dataset Link:{' '}
              <code>
                {contractDraft.plannedDatasetLink ??
                  (orchestrationLive ? 'Created automatically on run' : 'Available after G11.6 run')}
              </code>
            </span>
            <span>
              Scan Run Report Link:{' '}
              <code>
                {contractDraft.plannedRunLink ??
                  (orchestrationLive ? 'Created automatically on run' : 'Available after G11.6 run')}
              </code>
            </span>
          </div>
        )}
      </section>
      )}
    </form>
  );
}
