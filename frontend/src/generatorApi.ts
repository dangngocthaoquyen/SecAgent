/**
 * Typed HTTP client and UI contracts for SecAgent G11 Generator API (G11.3C)
 * and G11.6 Generate & Run UI contract preparation.
 *
 * Security & scope invariants:
 * - Never accepts, stores, renders, or transmits raw DeepSeek API keys or custom provider URLs.
 * - API default `deduplicate_across_asi` is explicitly `false` for independent per-ASI testing.
 * - Uses SecAgent's exact `X-SecAgent-Validation` nonce and optional `X-SecAgent-Operator` header.
 * - Contains ZERO Target execution or Judge invocation endpoints; Generate & Run backend
 *   orchestration is strictly deferred to G11.6.
 */

export type AsiCode = 'ASI01' | 'ASI02' | 'ASI03' | 'ASI05';
export type AsiCategory =
  | 'goal_hijacking'
  | 'tool_misuse'
  | 'identity_privilege_abuse'
  | 'unexpected_code_execution';
export type SupportedLanguage = 'en' | 'vi';
export type GeneratorOperatingMode =
  | 'generate_and_run'
  | 'generate_only'
  | 'run_existing_dataset';

export const SUPPORTED_ASI_CODES: readonly AsiCode[] = [
  'ASI01',
  'ASI02',
  'ASI03',
  'ASI05',
] as const;

export const ASI_LABELS: Record<AsiCode, string> = {
  ASI01: 'ASI01 — Goal Hijacking',
  ASI02: 'ASI02 — Tool Misuse & Exploitation',
  ASI03: 'ASI03 — Identity & Privilege Abuse',
  ASI05: 'ASI05 — Unexpected Code Execution',
};

export const ALLOWED_SCOPES_BY_ASI: Record<AsiCode, readonly string[]> = {
  ASI01: ['goal_hijack_response', 'web_fetch', 'web_callback', 'agent_run'],
  ASI02: ['tool_intent_response', 'agent_run', 'direct_request'],
  ASI03: ['identity_claim_response'],
  ASI05: ['response_command_artifact', 'execution_action', 'agent_run', 'direct_request'],
};

export const GENERATOR_LIMITS = {
  minPerAsi: 1,
  defaultPerAsi: 5,
  maxPerAsi: 15,
  maxTotalCases: 50,
  maxPromptUtf8Bytes: 4096,
  maxDescriptionChars: 512,
  maxFocusNoteChars: 300,
} as const;

export const API_DEFAULT_DEDUPLICATE_ACROSS_ASI = false;

export type GeneratorProviderStatus = {
  provider_id: string;
  model: string;
  configured: boolean;
  credential_available: boolean;
  ready: boolean;
  reason: string;
  supports_json_mode: boolean;
  max_output_tokens_ceiling: number;
  retry_policy: 'caller_managed_single_attempt';
};

export type GeneratorSkillSummary = {
  id: string;
  version: string;
  asi_code: AsiCode;
  asi_category: AsiCategory;
  sha256: string;
};

export type GeneratorJudgeStatus = {
  judge_configured: boolean;
  credential_available: boolean;
  judge_ready: boolean;
  provider: string | null;
  model: string | null;
  reason: string;
};

export type GeneratorStatusResponse = {
  workflow_schema_version: '1.0.0';
  provider: GeneratorProviderStatus;
  generate_and_run_available?: boolean;
  judge?: GeneratorJudgeStatus | null;
  supported_asi: AsiCode[];
  limits: {
    min_per_asi: number;
    default_per_asi: number;
    max_per_asi: number;
    max_total_cases: number;
    hard_max_per_asi: number;
    hard_max_total_cases: number;
  };
  defaults: {
    deduplicate_across_asi: boolean;
    max_calls_per_asi: number;
    language: SupportedLanguage;
  };
  skills: GeneratorSkillSummary[];
  skill_error: string | null;
};

export type ReadinessFinding = {
  severity: 'blocker' | 'warning';
  code: string;
  message: string;
};

export type ReviewedPolicyCandidateRef = {
  policy_id: string;
  revision_sha256: string;
  evaluation_scope: string;
  reviewed_at: string | null;
};

export type AsiReadinessAssessment = {
  asi_code: AsiCode;
  asi_category: AsiCategory;
  status: 'ready' | 'ready_with_warnings' | 'blocked';
  effective_scope: string | null;
  requested_scope: string | null;
  scope_capability_state: 'supported' | 'unsupported' | 'unverified' | 'unknown';
  scope_capability_provenance:
    | 'runtime_confirmed'
    | 'operator_declared'
    | 'discovery_suggested'
    | 'undeclared';
  blockers: string[];
  warnings: string[];
  findings: ReadinessFinding[];
  has_reviewed_policy: boolean;
  reviewed_policy_id: string | null;
  reviewed_policy_revision_sha256: string | null;
  ambiguous_policy_candidates: ReviewedPolicyCandidateRef[];
  deterministic_limitations: string[];
};

export type TargetReadinessReport = {
  target_id: string;
  target_exists: boolean;
  overall_status: 'ready' | 'ready_with_warnings' | 'blocked';
  asi_assessments: Partial<Record<AsiCode, AsiReadinessAssessment>>;
};

export type TokenUsage = {
  prompt_tokens: number | null;
  completion_tokens: number | null;
  total_tokens: number | null;
};

export type PreviewCandidateView = {
  candidate_id: string;
  candidate_id_scope: 'ephemeral_generation_candidate';
  asi_code: AsiCode;
  asi_category: AsiCategory;
  effective_scope: string;
  source_index: number;
  origin: 'ai_generated_original' | 'operator_edited';
  operator_edited: boolean;
  selected: boolean;
  original_prompt: string;
  original_description: string;
  original_prompt_sha256: string;
  effective_prompt: string;
  effective_description: string;
  effective_prompt_sha256: string;
  strategy_tag: string;
  context_basis: string[];
  scope_note: string;
  reviewed_policy_id: string | null;
  reviewed_policy_revision_sha256: string | null;
};

export type PreviewAsiSummary = {
  asi_code: AsiCode;
  asi_category: AsiCategory;
  status:
    | 'completed'
    | 'partial'
    | 'empty_with_context_gaps'
    | 'empty_all_rejected'
    | 'blocked'
    | 'provider_error'
    | 'truncated'
    | 'invalid_output';
  effective_scope: string | null;
  readiness_status: 'ready' | 'ready_with_warnings' | 'blocked';
  readiness_blockers: string[];
  readiness_warnings: string[];
  requested_count: number;
  generated_count: number;
  accepted_count: number;
  rejected_count: number;
  duplicate_rejected_count: number;
  rejection_reason_counts: Record<string, number>;
  context_gaps: string[];
  error_code: string | null;
  error_message: string | null;
  skill_id: string | null;
  skill_version: string | null;
  skill_sha256: string | null;
  sanitized_request_sha256: string | null;
  reviewed_policy_id: string | null;
  reviewed_policy_revision_sha256: string | null;
  call_count: number;
  duration_ms: number;
};

export type PreviewSaveRecord = {
  save_status: 'saved';
  dataset_id: string;
  dataset_name: string;
  dataset_file_sha256: string;
  dataset_content_sha256: string;
  saved_at: string;
  created: boolean;
  idempotent_replay: boolean;
  saved_candidate_ids: string[];
  saved_count: number;
  requested_count: number;
  generated_count: number;
  accepted_count: number;
  rejected_count: number;
  selected_for_save_count: number;
  partial_generation: boolean;
  partial_save_confirmed: boolean;
  meets_requested_counts: boolean;
  save_request_digest: string;
};

export type GeneratorPreviewSnapshot = {
  preview_id: string;
  status: 'active' | 'saved' | 'expired';
  created_at: string;
  updated_at: string;
  expires_at: string;
  generation_id: string;
  target_id: string;
  target_revision_sha256: string | null;
  application_context_revision_sha256: string | null;
  context_snapshot_sha256: string | null;
  reviewed_policy_revisions: Partial<
    Record<AsiCode, { policy_id: string; revision_sha256: string }>
  >;
  provider_id: string;
  model: string;
  language: SupportedLanguage;
  deduplicate_across_asi: boolean;
  overall_status:
    | 'completed'
    | 'partial'
    | 'empty_with_context_gaps'
    | 'blocked'
    | 'failed';
  meets_requested_counts: boolean;
  has_accepted_candidates: boolean;
  can_save: boolean;
  requires_partial_confirmation: boolean;
  total_requested: number;
  total_generated: number;
  total_accepted: number;
  total_rejected: number;
  selected_count: number;
  edited_count: number;
  total_call_count: number;
  total_duration_ms: number;
  total_token_usage: TokenUsage | null;
  asi_order: AsiCode[];
  asi_summaries: Partial<Record<AsiCode, PreviewAsiSummary>>;
  candidates: PreviewCandidateView[];
  rejection_reason_counts: Record<string, number>;
  save_record: PreviewSaveRecord | null;
  auto_persisted: false;
  auto_executed: false;
};

export type PreviewSaveStatusResponse = {
  workflow_schema_version: '1.0.0';
  preview_id: string;
  generation_id: string;
  preview_status: 'active' | 'saved' | 'expired';
  saved: boolean;
  dataset_id: string | null;
  save_record: PreviewSaveRecord | null;
};

export type ReadinessRequestPayload = {
  target_id: string;
  selected_asi?: AsiCode[];
  requested_scopes?: Partial<Record<AsiCode, string>>;
  policy_ids_by_asi?: Partial<Record<AsiCode, string>>;
};

export type GenerateRequestPayload = {
  target_id: string;
  counts_by_asi: Partial<Record<AsiCode, number>>;
  language: SupportedLanguage;
  focus_note?: string | null;
  requested_scopes?: Partial<Record<AsiCode, string>>;
  policy_ids_by_asi?: Partial<Record<AsiCode, string>>;
  deduplicate_across_asi: boolean;
  max_calls_per_asi?: 1 | 2;
};

export type PreviewCandidateEditItem = {
  candidate_id: string;
  selected?: boolean;
  prompt?: string;
  description?: string;
  reset_to_original?: boolean;
};

export type PreviewSavePayload = {
  dataset_name: string;
  selected_candidate_ids?: string[];
  save_confirmed: boolean;
  partial_save_confirmed?: boolean;
  idempotency_key?: string;
};

/**
 * Shared generation configuration state reused across Mode 1 (Generate & Run)
 * and Mode 2 (Generate Only) so G11.6 does not duplicate form state or validation.
 */
export type GeneratorConfigState = {
  targetId: string;
  selectedAsi: Record<AsiCode, boolean>;
  countsByAsi: Record<AsiCode, number>;
  language: SupportedLanguage;
  focusNote: string;
  deduplicateAcrossAsi: boolean;
  requestedScopes: Partial<Record<AsiCode, string>>;
  policyIdsByAsi: Partial<Record<AsiCode, string>>;
};

export function createDefaultGeneratorConfig(targetId = ''): GeneratorConfigState {
  return {
    targetId,
    selectedAsi: {
      ASI01: true,
      ASI02: false,
      ASI03: false,
      ASI05: false,
    },
    countsByAsi: {
      ASI01: GENERATOR_LIMITS.defaultPerAsi,
      ASI02: GENERATOR_LIMITS.defaultPerAsi,
      ASI03: GENERATOR_LIMITS.defaultPerAsi,
      ASI05: GENERATOR_LIMITS.defaultPerAsi,
    },
    language: 'en',
    focusNote: '',
    deduplicateAcrossAsi: API_DEFAULT_DEDUPLICATE_ACROSS_ASI,
    requestedScopes: {},
    policyIdsByAsi: {},
  };
}

/**
 * G11.6 UI Contract Preparation types for Mode 1 (Generate & Run).
 * Explicitly enforces `requiresPreviewOrManualSave: false` and `orchestrationAvailable: false`
 * until G11.6 backend orchestration is integrated post-merge with G12.
 */
export type GenerateAndRunStage =
  | 'generating'
  | 'validating'
  | 'saving_dataset'
  | 'executing'
  | 'judging'
  | 'reporting';

export const GENERATE_AND_RUN_STAGES: readonly {
  id: GenerateAndRunStage;
  label: string;
  description: string;
}[] = [
  {
    id: 'generating',
    label: 'Generating',
    description: 'Context-aware generation per selected ASI via server-owned provider.',
  },
  {
    id: 'validating',
    label: 'Validating',
    description: 'Strict JSON contract, ASI consistency, confirmed context_basis & dedup.',
  },
  {
    id: 'saving_dataset',
    label: 'Saving Dataset',
    description: 'Automatic immutable dataset persistence before any Target execution.',
  },
  {
    id: 'executing',
    label: 'Executing',
    description: 'Generic Scan preflight, operator consent verification & bounded Target run.',
  },
  {
    id: 'judging',
    label: 'Judging',
    description: 'Rule / Evidence / Hybrid Judge evaluation & Verdict Resolver.',
  },
  {
    id: 'reporting',
    label: 'Reporting',
    description: 'Persisted report with generation provenance, dataset ID & run lineage.',
  },
] as const;

export type GenerateAndRunContractDraft = {
  mode: 'generate_and_run';
  requiresPreviewOrManualSave: false;
  orchestrationAvailable: boolean;
  generationConfig: GeneratorConfigState;
  evaluationMode: 'rule_only' | 'hybrid';
  authorizationConfirmed: boolean;
  plannedStages: readonly GenerateAndRunStage[];
  plannedDatasetLink: string | null;
  plannedRunLink: string | null;
};

export type WorkflowStageName =
  | 'generating'
  | 'validating'
  | 'saving_dataset'
  | 'preflight'
  | 'executing'
  | 'evaluating'
  | 'reporting';

export type StageStatus = 'pending' | 'running' | 'completed' | 'failed' | 'blocked' | 'skipped';

export type WorkflowOverallStatus =
  | 'running'
  | 'completed'
  | 'failed'
  | 'blocked'
  | 'partial_stopped';

export const LIVE_GENERATE_AND_RUN_STAGES: readonly {
  id: WorkflowStageName;
  label: string;
  description: string;
}[] = [
  {
    id: 'generating',
    label: 'Generating',
    description: 'Context-aware generation per selected ASI via server-owned provider.',
  },
  {
    id: 'validating',
    label: 'Validating',
    description: 'Strict JSON contract, ASI alignment, confirmed context_basis & dedup.',
  },
  {
    id: 'saving_dataset',
    label: 'Saving Dataset',
    description: 'Automatic immutable dataset persistence before any Target execution.',
  },
  {
    id: 'preflight',
    label: 'Preflight',
    description: 'Target authorization, revision binding, policy & scope verification.',
  },
  {
    id: 'executing',
    label: 'Executing',
    description: 'Generic Runner bounded Target execution on persisted dataset.',
  },
  {
    id: 'evaluating',
    label: 'Evaluating',
    description: 'Rule / Evidence / Hybrid Judge evaluation & Verdict Resolver.',
  },
  {
    id: 'reporting',
    label: 'Reporting',
    description: 'Persisted report with generation provenance, dataset ID & run lineage.',
  },
] as const;

export type WorkflowStageRecord = {
  stage: WorkflowStageName;
  status: StageStatus;
  started_at: string | null;
  finished_at: string | null;
  detail: string | null;
  error_code: string | null;
  error_message: string | null;
};

export type RerunHistoryEntry = {
  operation: 'rerun';
  run_id: string;
  previous_run_id: string | null;
  dataset_id: string;
  evaluation_mode: 'rule_only' | 'hybrid';
  started_at: string;
  run_status: string;
  generator_called: false;
  regenerated: false;
};

export type GenerateAndRunRequestPayload = {
  target_id: string;
  counts_by_asi: Partial<Record<AsiCode, number>>;
  language: SupportedLanguage;
  focus_note?: string | null;
  requested_scopes?: Partial<Record<AsiCode, string>>;
  policy_ids_by_asi?: Partial<Record<AsiCode, string>>;
  deduplicate_across_asi: boolean;
  max_calls_per_asi?: 1 | 2;
  evaluation_mode: 'rule_only' | 'hybrid';
  execution_mode?: 'live';
  authorization_confirmed: true;
  allow_partial_execution?: boolean;
  dataset_name?: string | null;
  submission_id?: string;
  async_execution?: boolean;
  expected_target_revision?: string | null;
};

export type GenerateAndRunRerunPayload = {
  authorization_confirmed: true;
  evaluation_mode?: 'rule_only' | 'hybrid';
  allow_partial_execution?: boolean;
  submission_id?: string;
  async_execution?: boolean;
};

export type PreflightSkippedReason = {
  case_id: string;
  status: string;
  reason: string;
};

export type PendingGenerateAndRunSubmission = {
  submission_id: string;
  target_id: string;
  config_digest: string;
  created_at: string;
};

const PENDING_GNR_SUBMISSION_KEY = 'secagent_pending_gnr_submission';

export function savePendingGenerateAndRunSubmission(
  entry: PendingGenerateAndRunSubmission,
): void {
  // Store ONLY non-sensitive recovery coordinates (never credentials, prompts, or focus notes).
  try {
    sessionStorage.setItem(
      PENDING_GNR_SUBMISSION_KEY,
      JSON.stringify({
        submission_id: entry.submission_id,
        target_id: entry.target_id,
        config_digest: entry.config_digest,
        created_at: entry.created_at,
      }),
    );
  } catch {
    // Ignore storage unavailability in constrained browser contexts.
  }
}

export function loadPendingGenerateAndRunSubmission(): PendingGenerateAndRunSubmission | null {
  try {
    const raw = sessionStorage.getItem(PENDING_GNR_SUBMISSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<PendingGenerateAndRunSubmission>;
    if (
      parsed &&
      typeof parsed.submission_id === 'string' &&
      /^[a-f0-9]{32}$/.test(parsed.submission_id) &&
      typeof parsed.target_id === 'string' &&
      typeof parsed.config_digest === 'string' &&
      typeof parsed.created_at === 'string'
    ) {
      return {
        submission_id: parsed.submission_id,
        target_id: parsed.target_id,
        config_digest: parsed.config_digest,
        created_at: parsed.created_at,
      };
    }
  } catch {
    // Ignore malformed storage entries.
  }
  return null;
}

export function clearPendingGenerateAndRunSubmission(): void {
  try {
    sessionStorage.removeItem(PENDING_GNR_SUBMISSION_KEY);
  } catch {
    // Ignore storage errors.
  }
}

export type GenerateAndRunSnapshot = {
  workflow_id: string;
  mode: 'generate_and_run';
  submission_id: string | null;
  idempotent_replay: boolean;
  status: WorkflowOverallStatus;
  current_stage: WorkflowStageName;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  target_id: string;
  target_revision_sha256: string | null;
  application_context_revision_sha256: string | null;
  context_snapshot_sha256: string | null;
  selected_asi: AsiCode[];
  requested_scopes: Partial<Record<AsiCode, string>>;
  policy_ids_by_asi: Partial<Record<AsiCode, string>>;
  language: SupportedLanguage;
  evaluation_mode: 'rule_only' | 'hybrid';
  initial_evaluation_mode?: 'rule_only' | 'hybrid';
  execution_mode: 'live';
  allow_partial_execution: boolean;
  stages: WorkflowStageRecord[];
  generation_id: string | null;
  provider_id: string | null;
  model: string | null;
  generation_overall_status: string | null;
  requested_count: number;
  generated_count: number;
  accepted_count: number;
  rejected_count: number;
  meets_requested_counts: boolean;
  partial_generation: boolean;
  rejection_reason_counts: Record<string, number>;
  asi_generation_summaries: Record<string, Record<string, unknown>>;
  generation_token_usage: TokenUsage | null;
  quality_summary: Record<string, unknown> | null;
  auto_persisted: boolean;
  dataset_id: string | null;
  dataset_name: string | null;
  dataset_file_sha256: string | null;
  testcase_ids: string[];
  partial_execution?: boolean;
  preflight_selected_cases?: number;
  preflight_ready_count?: number;
  preflight_skipped_count?: number;
  preflight_unsupported_count?: number;
  preflight_skipped_reasons?: PreflightSkippedReason[];
  run_id: string | null;
  run_status: string | null;
  executed_cases: number;
  total_cases: number;
  progress_percent: number;
  verdict_counts: Record<string, number>;
  evidence_summary: Record<string, unknown>;
  judge_metadata: Record<string, unknown> | null;
  evaluation_error_code: string | null;
  cases_summary: Array<Record<string, unknown>>;
  dataset_url: string | null;
  report_url: string | null;
  report_export_url: string | null;
  rerun_supported: boolean;
  rerun_history: RerunHistoryEntry[];
  resume_supported: boolean;
  resume_endpoint: string | null;
  resume_note: string;
  error_stage: WorkflowStageName | null;
  error_code: string | null;
  error_message: string | null;
  provenance: Record<string, unknown>;
};

export type GenerateAndRunRerunResponse = {
  workflow_schema_version: '1.0.0';
  operation: 'rerun';
  generator_called: false;
  regenerated: false;
  dataset_id: string;
  previous_run_id: string | null;
  new_run_id: string;
  evaluation_mode?: 'rule_only' | 'hybrid';
  workflow: GenerateAndRunSnapshot;
};

export function utf8ByteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

export function extractActiveCounts(
  config: GeneratorConfigState,
): {
  counts: Partial<Record<AsiCode, number>>;
  selectedList: AsiCode[];
  total: number;
  error: string | null;
} {
  const counts: Partial<Record<AsiCode, number>> = {};
  const selectedList: AsiCode[] = [];
  let total = 0;

  for (const code of SUPPORTED_ASI_CODES) {
    if (!config.selectedAsi[code]) continue;
    selectedList.push(code);
    const val = config.countsByAsi[code];
    if (
      !Number.isInteger(val) ||
      val < GENERATOR_LIMITS.minPerAsi ||
      val > GENERATOR_LIMITS.maxPerAsi
    ) {
      return {
        counts,
        selectedList,
        total,
        error: `${code} count must be an integer between ${GENERATOR_LIMITS.minPerAsi} and ${GENERATOR_LIMITS.maxPerAsi}.`,
      };
    }
    counts[code] = val;
    total += val;
  }

  if (selectedList.length === 0) {
    return {
      counts,
      selectedList,
      total: 0,
      error: 'Select at least one OWASP ASI category.',
    };
  }
  if (total > GENERATOR_LIMITS.maxTotalCases) {
    return {
      counts,
      selectedList,
      total,
      error: `Total requested testcases (${total}) exceeds the maximum limit of ${GENERATOR_LIMITS.maxTotalCases}.`,
    };
  }
  return { counts, selectedList, total, error: null };
}

export class GeneratorApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = 'GeneratorApiError';
    this.code = code;
    this.status = status;
  }
}

async function generatorFetch<T>(
  path: string,
  options: {
    method: 'GET' | 'POST';
    nonce: string;
    secret?: string;
    body?: unknown;
    signal?: AbortSignal;
  },
): Promise<T> {
  const headers: Record<string, string> = {};
  if (options.nonce) {
    headers['X-SecAgent-Validation'] = options.nonce;
  }
  if (options.secret) {
    headers['X-SecAgent-Operator'] = options.secret;
  }
  if (options.method === 'POST') {
    headers['Content-Type'] = 'application/json';
  }

  const res = await fetch(`/api/testing/generator/${path}`, {
    method: options.method,
    credentials: 'omit',
    cache: 'no-store',
    headers,
    body: options.method === 'POST' ? JSON.stringify(options.body ?? {}) : undefined,
    signal: options.signal,
  });

  let parsed: unknown = null;
  try {
    parsed = await res.json();
  } catch {
    parsed = null;
  }

  if (!res.ok) {
    const errObj =
      parsed &&
      typeof parsed === 'object' &&
      'error' in parsed &&
      parsed.error &&
      typeof parsed.error === 'object'
        ? (parsed.error as { code?: unknown; message?: unknown })
        : null;
    const code = typeof errObj?.code === 'string' ? errObj.code : `http_${res.status}`;
    const message =
      typeof errObj?.message === 'string'
        ? errObj.message
        : `Generator API request failed (HTTP ${res.status}).`;
    throw new GeneratorApiError(code, message, res.status);
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new GeneratorApiError('invalid_response', 'Generator API returned an invalid response.', res.status);
  }
  return parsed as T;
}

export const generatorApi = {
  getStatus: (nonce: string, secret = '', signal?: AbortSignal) =>
    generatorFetch<GeneratorStatusResponse>('status', {
      method: 'GET',
      nonce,
      secret,
      signal,
    }),

  checkReadiness: (
    payload: ReadinessRequestPayload,
    nonce: string,
    secret = '',
    signal?: AbortSignal,
  ) =>
    generatorFetch<{ workflow_schema_version: '1.0.0'; readiness: TargetReadinessReport }>(
      'readiness',
      {
        method: 'POST',
        nonce,
        secret,
        body: payload,
        signal,
      },
    ).then((r) => r.readiness),

  generate: (
    payload: GenerateRequestPayload,
    nonce: string,
    secret = '',
    signal?: AbortSignal,
  ) =>
    generatorFetch<{ workflow_schema_version: '1.0.0'; preview: GeneratorPreviewSnapshot }>(
      'generate',
      {
        method: 'POST',
        nonce,
        secret,
        body: payload,
        signal,
      },
    ).then((r) => r.preview),

  getPreview: (previewId: string, nonce: string, secret = '', signal?: AbortSignal) =>
    generatorFetch<{ workflow_schema_version: '1.0.0'; preview: GeneratorPreviewSnapshot }>(
      `previews/${encodeURIComponent(previewId)}`,
      {
        method: 'GET',
        nonce,
        secret,
        signal,
      },
    ).then((r) => r.preview),

  editPreview: (
    previewId: string,
    edits: PreviewCandidateEditItem[],
    nonce: string,
    secret = '',
  ) =>
    generatorFetch<{ workflow_schema_version: '1.0.0'; preview: GeneratorPreviewSnapshot }>(
      `previews/${encodeURIComponent(previewId)}/edit`,
      {
        method: 'POST',
        nonce,
        secret,
        body: { edits },
      },
    ).then((r) => r.preview),

  savePreview: (
    previewId: string,
    payload: PreviewSavePayload,
    nonce: string,
    secret = '',
  ) =>
    generatorFetch<{ workflow_schema_version: '1.0.0'; save_record: PreviewSaveRecord }>(
      `previews/${encodeURIComponent(previewId)}/save`,
      {
        method: 'POST',
        nonce,
        secret,
        body: payload,
      },
    ).then((r) => r.save_record),

  getSaveStatus: (previewId: string, nonce: string, secret = '', signal?: AbortSignal) =>
    generatorFetch<PreviewSaveStatusResponse>(
      `previews/${encodeURIComponent(previewId)}/save-status`,
      {
        method: 'GET',
        nonce,
        secret,
        signal,
      },
    ),

  startGenerateAndRun: (
    payload: GenerateAndRunRequestPayload,
    nonce: string,
    secret = '',
    signal?: AbortSignal,
  ) =>
    generatorFetch<{ workflow_schema_version: '1.0.0'; workflow: GenerateAndRunSnapshot }>(
      'generate-and-run',
      {
        method: 'POST',
        nonce,
        secret,
        body: payload,
        signal,
      },
    ).then((r) => r.workflow),

  getGenerateAndRunStatus: (
    workflowId: string,
    nonce: string,
    secret = '',
    signal?: AbortSignal,
  ) =>
    generatorFetch<{ workflow_schema_version: '1.0.0'; workflow: GenerateAndRunSnapshot }>(
      `generate-and-run/${encodeURIComponent(workflowId)}`,
      {
        method: 'GET',
        nonce,
        secret,
        signal,
      },
    ).then((r) => r.workflow),

  getGenerateAndRunBySubmission: (
    submissionId: string,
    nonce: string,
    secret = '',
    signal?: AbortSignal,
  ) =>
    generatorFetch<{ workflow_schema_version: '1.0.0'; workflow: GenerateAndRunSnapshot }>(
      `generate-and-run/submission/${encodeURIComponent(submissionId)}`,
      {
        method: 'GET',
        nonce,
        secret,
        signal,
      },
    ).then((r) => r.workflow),

  rerunGenerateAndRun: (
    workflowId: string,
    payload: GenerateAndRunRerunPayload,
    nonce: string,
    secret = '',
  ) =>
    generatorFetch<GenerateAndRunRerunResponse>(
      `generate-and-run/${encodeURIComponent(workflowId)}/rerun`,
      {
        method: 'POST',
        nonce,
        secret,
        body: payload,
      },
    ),
};
