import type {
  GenericEvidenceItem,
  GenericJudgeMetadata,
  GenericRunCaseResult,
  GenericRunRecord,
  GenericRunSummary,
} from './testingApi';

const EVIDENCE_LABELS: Record<string, string> = {
  none: 'No evidence',
  response_only: 'Response only',
  model_reported_intent: 'Model-reported intent',
  target_reported_claim: 'Target-reported claim',
  adapter_observed_request: 'Adapter-observed request',
  independently_verified_execution: 'Independently verified execution',
  runtime_observed: 'Runtime observed',
  independently_verified: 'Independently verified',
  telemetry_correlated: 'Telemetry correlated',
  mixed_evidence: 'Mixed evidence',
};

const CLASSIFICATION_LABELS: Record<string, string> = {
  TOOL_BOUNDARY_PRESERVED: 'Boundary preserved',
  UNSAFE_TOOL_INTENT: 'Unsafe tool intent',
  ORIGINAL_GOAL: 'Original goal',
  ATTACKER_GOAL: 'Attacker goal',
  ROLE_PRESERVED: 'Role preserved',
  ROLE_BREACH: 'Role breach',
  DATA_PROTECTED: 'Data protected',
  DATA_EXPOSURE: 'Data exposure',
  UNCLEAR: 'Unclear classification',
  INCONCLUSIVE: 'Inconclusive',
};

const FAULT_LABELS: Record<string, string> = {
  timeout: 'Judge timeout',
  provider_timeout: 'Judge timeout',
  rate_limit: 'Judge rate limit',
  http_error: 'Judge HTTP error',
  connection_error: 'Judge connection error',
  invalid_json: 'Invalid Judge JSON',
  schema_validation_failed: 'Invalid Judge schema',
  credential_missing: 'Judge credential missing',
  unavailable: 'Judge unavailable',
};

const INVOCATION_LABELS: Record<string, string> = {
  not_requested: 'Not requested (Rule-only)',
  running: 'Running',
  succeeded: 'Succeeded',
  partial_failure: 'Partial failure',
  failed: 'Failed',
  not_invoked: 'Not invoked',
  unknown_unverified: 'Unknown / unverified',
};

const RUN_STATUS_LABELS: Record<string, string> = {
  preparing: 'Preparing',
  queued: 'Queued',
  starting: 'Starting',
  running: 'Running',
  completed: 'Completed',
  completed_with_errors: 'Completed with errors',
  failed: 'Failed',
  interrupted: 'Interrupted',
  cancelled: 'Cancelled',
};

const ASI_CODE_BY_CATEGORY: Record<string, string> = {
  goal_hijacking: 'ASI01',
  tool_misuse: 'ASI02',
  identity_privilege_abuse: 'ASI03',
  unexpected_code_execution: 'ASI05',
  asi01: 'ASI01',
  asi02: 'ASI02',
  asi03: 'ASI03',
  asi05: 'ASI05',
};

const INDEPENDENT_PROVENANCE_VALUES = new Set([
  'independently_verified',
  'independent_observer',
  'independent_local_collector',
]);

const NON_INDEPENDENT_PROVENANCE_VALUES = new Set([
  'model_reported',
  'target_reported',
  'adapter_observed',
  'secagent_request',
  'secagent_observed_request',
  'secagent_policy',
]);

const TRUSTED_INDEPENDENT_OBSERVER_SOURCES = new Set([
  'local_tool_fixture',
  'runtime_trace',
  'adapter',
  'offline-trusted-observer',
]);

const TRUSTED_LOCAL_COLLECTOR_SOURCES = new Set([
  'local_collector',
]);

const COLLECTOR_EVIDENCE_SOURCES = new Set([
  'generic_evidence_collector',
  'http_callback_collector',
  'sandbox_log_collector',
  'file_artifact_collector',
  'custom_audit_log_collector',
  'mcp_receipt_collector',
]);

const OBSERVER_PROVENANCE_VALUES = new Set([
  'independent_observer',
  'independently_verified',
]);

const LOCAL_COLLECTOR_PROVENANCE_VALUES = new Set([
  'independent_local_collector',
  'independently_verified',
]);

const NEGATIVE_CORRELATION_STATUSES = new Set([
  'uncorrelated',
  'unverified',
  'failed',
  'mismatch',
  'conflicting',
  'invalid',
  'none',
  'missing',
]);

const NEGATIVE_VERIFICATION_STATUSES = new Set([
  'unverified',
  'not_verified',
  'conflicting',
  'conflicting_execution_metadata',
  'failed',
  'rejected',
  'invalid',
]);

const NON_EXECUTION_SEMANTICS = new Set([
  'declared_only',
  'direct_tool_request',
  'target_reported_result',
  'simulated_handler_invocation',
]);

const WRAPPER_EVIDENCE_KINDS = new Set([
  'http_response_metadata',
  'stored_response',
]);

export function normalizeAsiCode(raw: string | null | undefined): string | null {
  if (!raw || typeof raw !== 'string') return null;
  const key = raw.trim().toLowerCase();
  if (!key || key === 'auto' || key === 'unmapped' || key === 'unknown') return null;
  return ASI_CODE_BY_CATEGORY[key] ?? null;
}

export function formatCaseAsiCategory(raw: string | null | undefined, includeRaw = false): string {
  if (!raw || typeof raw !== 'string') return 'Unknown';
  const trimmed = raw.trim();
  if (!trimmed || ['auto', 'unmapped', 'unknown'].includes(trimmed.toLowerCase())) {
    return 'Unknown';
  }
  const code = normalizeAsiCode(trimmed);
  if (code) {
    if (includeRaw && trimmed.toUpperCase() !== code) {
      return `${code} (${trimmed})`;
    }
    return code;
  }
  return trimmed;
}

export function deriveRunAsiSummary(
  record:
    | {
        asi_category?: string | null;
        asi_categories?: string[];
        cases?: { category?: string | null }[];
        skipped_cases?: { asi_code?: string | null; category?: string | null }[];
        case_statuses?: { asi_code?: string | null; category?: string | null }[];
      }
    | null
    | undefined,
): {
  label: string;
  codes: string[];
  hasUnknown: boolean;
} {
  if (!record) {
    return { label: 'Not recorded', codes: [], hasUnknown: true };
  }
  const codesSet = new Set<string>();
  let sawAnyCaseOrCategory = false;
  let sawUnknown = false;

  const collect = (raw: string | null | undefined) => {
    if (!raw || typeof raw !== 'string') return;
    const t = raw.trim();
    if (!t || t.toLowerCase() === 'auto') return;
    sawAnyCaseOrCategory = true;
    const norm = normalizeAsiCode(t);
    if (norm) {
      codesSet.add(norm);
    } else {
      sawUnknown = true;
    }
  };

  for (const c of record.cases ?? []) {
    collect(c?.category);
  }
  for (const s of record.skipped_cases ?? []) {
    collect(s?.asi_code || s?.category);
  }
  if (codesSet.size === 0 && (record.case_statuses?.length ?? 0) > 0) {
    for (const cs of record.case_statuses ?? []) {
      collect(cs?.asi_code || cs?.category);
    }
  }
  if (Array.isArray(record.asi_categories)) {
    for (const cat of record.asi_categories) {
      collect(cat);
    }
  }
  if (codesSet.size === 0) {
    collect(record.asi_category);
  }

  const codes = Array.from(codesSet).sort();
  if (codes.length === 1 && !sawUnknown) {
    return { label: codes[0], codes, hasUnknown: false };
  }
  if (codes.length > 1) {
    return { label: `Mixed (${codes.join(', ')})`, codes, hasUnknown: sawUnknown };
  }
  if (codes.length === 1 && sawUnknown) {
    return { label: `Mixed (${codes[0]}, Unknown)`, codes, hasUnknown: true };
  }
  return {
    label: sawAnyCaseOrCategory || record.asi_category ? 'Unknown' : 'Not recorded',
    codes: [],
    hasUnknown: true,
  };
}

export function formatEvidenceLevel(level: string | null | undefined, includeRaw = false): string {
  if (!level) return 'Not recorded';
  const label = EVIDENCE_LABELS[level] ?? level.replace(/_/g, ' ');
  return includeRaw && label !== level ? `${label} (${level})` : label;
}

export function formatResponseCompleteness(responseComplete: boolean | null | undefined): string {
  if (responseComplete === true) return 'Complete response';
  if (responseComplete === false) return 'Incomplete response';
  return 'Completeness not recorded';
}

export function classifyJudgeFault(
  c: GenericRunCaseResult,
  options?: { useJudge?: boolean | null; judgeMode?: 'rule_only' | 'hybrid' | null },
): {
  primary: string;
  secondary: string | null;
  rawCode: string | null;
  isProviderFault: boolean;
} {
  const fault = c.provider_fault_code?.trim() || null;
  if (fault) {
    const extraStatus =
      c.json_validation_status && c.json_validation_status !== 'valid' && c.json_validation_status !== fault
        ? ` · ${c.json_validation_status}`
        : '';
    return {
      primary: FAULT_LABELS[fault] ?? `Provider fault (${fault})`,
      secondary: `Provider fault · ${fault}${extraStatus}`,
      rawCode: fault,
      isProviderFault: true,
    };
  }
  if (
    c.json_validation_status &&
    ['invalid', 'schema_error', 'parse_error', 'provider_fault'].includes(c.json_validation_status)
  ) {
    return {
      primary: FAULT_LABELS[c.json_validation_status] ?? 'Judge schema fault',
      secondary: `Provider fault · ${c.json_validation_status}`,
      rawCode: c.json_validation_status,
      isProviderFault: true,
    };
  }
  const cls = c.judge_classification?.trim() || null;
  if (cls) {
    const label = CLASSIFICATION_LABELS[cls] ?? cls.replace(/_/g, ' ');
    return {
      primary: label,
      secondary: label !== cls ? cls : null,
      rawCode: cls,
      isProviderFault: false,
    };
  }
  const isRuleOnly = options?.judgeMode === 'rule_only' || options?.useJudge === false;
  if (isRuleOnly) {
    return {
      primary: 'Judge not requested',
      secondary: 'Rule-only mode',
      rawCode: null,
      isProviderFault: false,
    };
  }
  if (c.semantic_invoked === false) {
    return {
      primary: 'Judge not invoked',
      secondary: 'Hybrid mode',
      rawCode: null,
      isProviderFault: false,
    };
  }
  return {
    primary: 'Not recorded',
    secondary: null,
    rawCode: null,
    isProviderFault: false,
  };
}

export function formatJudgeClassification(classification: string | null | undefined, includeRaw = false): string {
  if (!classification) return 'Not recorded';
  const label = CLASSIFICATION_LABELS[classification] ?? classification.replace(/_/g, ' ');
  return includeRaw && label !== classification ? `${label} (${classification})` : label;
}

export function formatInvocationStatus(
  status: GenericJudgeMetadata['invocation_status'] | string | null | undefined,
): string {
  if (!status) return 'Not recorded';
  return INVOCATION_LABELS[status] ?? status.replace(/_/g, ' ');
}

export function formatRunStatus(status: string | null | undefined): string {
  if (!status) return 'Unknown';
  const key = status.toLowerCase();
  return RUN_STATUS_LABELS[key] ?? status;
}

export function normalizeVerdict(verdict: string | null | undefined): 'PASS' | 'FAIL' | 'INCONCLUSIVE' | 'ERROR' {
  const upper = (verdict || 'ERROR').toUpperCase();
  if (upper === 'PASS' || upper === 'FAIL' || upper === 'INCONCLUSIVE' || upper === 'ERROR') {
    return upper;
  }
  return 'ERROR';
}

export function verdictBadgeClass(verdict: string | null | undefined): string {
  const v = normalizeVerdict(verdict);
  if (v === 'PASS') return 'badge pass';
  if (v === 'FAIL') return 'badge fail';
  if (v === 'INCONCLUSIVE') return 'badge warn';
  return 'badge err';
}

export function runStatusBadgeClass(status: string | null | undefined): string {
  const s = (status || '').toLowerCase();
  if (s === 'completed') return 'badge pass';
  if (s === 'completed_with_errors') return 'badge warn';
  if (s === 'preparing' || s === 'running' || s === 'starting' || s === 'queued') return 'badge run';
  if (s === 'interrupted' || s === 'cancelled') return 'badge warn';
  return 'badge err';
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return 'Not recorded';
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return iso;
  return new Date(ms).toLocaleString();
}

export function formatDurationBetween(startIso: string | null | undefined, endIso: string | null | undefined): string {
  if (!startIso || !endIso) return 'Not recorded';
  const start = Date.parse(startIso);
  const end = Date.parse(endIso);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return 'Not recorded';
  const totalSec = Math.round((end - start) / 1000);
  if (totalSec < 60) return `${totalSec}s`;
  const mins = Math.floor(totalSec / 60);
  const secs = totalSec % 60;
  if (mins < 60) return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
  const hours = Math.floor(mins / 60);
  return `${hours}h ${mins % 60}m`;
}

export function formatProviderModel(meta: GenericJudgeMetadata | null | undefined): string {
  if (!meta) return 'Not recorded';
  const parts = [meta.provider, meta.model].filter((v): v is string => Boolean(v && v.trim()));
  return parts.length > 0 ? parts.join(' / ') : 'Not recorded';
}

export function computeVerdictCounts(record: GenericRunRecord | GenericRunSummary | null | undefined): {
  PASS: number;
  FAIL: number;
  INCONCLUSIVE: number;
  ERROR: number;
} {
  const vc = record?.verdict_counts;
  return {
    PASS: Number(vc?.PASS ?? 0),
    FAIL: Number(vc?.FAIL ?? 0),
    INCONCLUSIVE: Number(vc?.INCONCLUSIVE ?? 0),
    ERROR: Number(vc?.ERROR ?? 0),
  };
}

export interface EvidenceItemVerificationInfo {
  ev: GenericEvidenceItem;
  provenance: string | null;
  executionVerified: boolean | null;
  verificationStatus: string | null;
  correlationStatus: string | null;
  isExecutionVerified: boolean;
  verificationLabel: 'Execution verified' | 'Execution not verified' | 'Verification not recorded';
}

export function inspectEvidenceItemVerification(ev: GenericEvidenceItem): EvidenceItemVerificationInfo {
  const data = ev.data && typeof ev.data === 'object' && !Array.isArray(ev.data) ? ev.data : {};
  // Keep raw untrimmed strings for positive allowlist validation (strict parity with Backend),
  // and trimmed strings only for display and negative/restriction checks.
  const rawProvenance = typeof data.provenance === 'string' ? data.provenance : null;
  const provenance =
    rawProvenance !== null && rawProvenance.trim() ? rawProvenance.trim() : null;
  const executionVerified = typeof data.execution_verified === 'boolean' ? data.execution_verified : null;
  const rawVerificationStatus =
    typeof data.verification_status === 'string' ? data.verification_status : null;
  const verificationStatus =
    rawVerificationStatus !== null && rawVerificationStatus.trim()
      ? rawVerificationStatus.trim()
      : null;
  const rawCorrelationStatus =
    typeof data.correlation_status === 'string' ? data.correlation_status : null;
  const correlationStatus =
    rawCorrelationStatus !== null && rawCorrelationStatus.trim()
      ? rawCorrelationStatus.trim()
      : null;
  const rawCorrelationStrength =
    typeof data.correlation_strength === 'string' ? data.correlation_strength : null;
  const normCorrelationStrength =
    rawCorrelationStrength !== null && rawCorrelationStrength.trim()
      ? rawCorrelationStrength.trim().toLowerCase()
      : null;
  const source = typeof ev.source === 'string' && ev.source.trim() ? ev.source.trim() : null;
  const kind = typeof ev.kind === 'string' && ev.kind.trim() ? ev.kind.trim() : null;
  const rawExecutionSemantics =
    typeof data.execution_semantics === 'string' ? data.execution_semantics : null;
  const executionSemantics =
    rawExecutionSemantics !== null && rawExecutionSemantics.trim()
      ? rawExecutionSemantics.trim()
      : null;

  // Fail closed on malformed non-scalar verification/correlation metadata (parity with backend).
  const hasMalformedMetadata =
    (data.provenance !== undefined && data.provenance !== null && typeof data.provenance !== 'string') ||
    (data.correlation_status !== undefined &&
      data.correlation_status !== null &&
      typeof data.correlation_status !== 'string') ||
    (data.correlation_strength !== undefined &&
      data.correlation_strength !== null &&
      typeof data.correlation_strength !== 'string') ||
    (data.verification_status !== undefined &&
      data.verification_status !== null &&
      typeof data.verification_status !== 'string') ||
    (data.execution_semantics !== undefined &&
      data.execution_semantics !== null &&
      typeof data.execution_semantics !== 'string') ||
    (data.execution_verified !== undefined &&
      data.execution_verified !== null &&
      typeof data.execution_verified !== 'boolean') ||
    (data.correlation_valid !== undefined &&
      data.correlation_valid !== null &&
      typeof data.correlation_valid !== 'boolean') ||
    (data.executed !== undefined && data.executed !== null && typeof data.executed !== 'boolean') ||
    (data.effect_verified !== undefined &&
      data.effect_verified !== null &&
      typeof data.effect_verified !== 'boolean') ||
    (data.effect_observed !== undefined &&
      data.effect_observed !== null &&
      typeof data.effect_observed !== 'boolean') ||
    (data.page_served !== undefined && data.page_served !== null && typeof data.page_served !== 'boolean') ||
    (data.synthetic_mock !== undefined &&
      data.synthetic_mock !== null &&
      typeof data.synthetic_mock !== 'boolean');

  // Strict canonical (untrimmed) positive provenance match; normalized negative checks.
  const hasIndependentProvenance =
    rawProvenance !== null && INDEPENDENT_PROVENANCE_VALUES.has(rawProvenance);
  const hasNonIndependentProvenance =
    provenance !== null && NON_INDEPENDENT_PROVENANCE_VALUES.has(provenance);
  const isWrapper = kind !== null && WRAPPER_EVIDENCE_KINDS.has(kind);

  const normCorrStatus = correlationStatus ? correlationStatus.toLowerCase() : null;
  const normVerStatus = verificationStatus ? verificationStatus.toLowerCase() : null;
  const hasNegativeVerificationStatus =
    normVerStatus !== null &&
    (NEGATIVE_VERIFICATION_STATUSES.has(normVerStatus) ||
      normVerStatus.endsWith('_unverified') ||
      normVerStatus.endsWith('_not_verified') ||
      normVerStatus.startsWith('conflicting_'));
  const hasInvalidExecutionSemantics =
    rawExecutionSemantics !== null &&
    (rawExecutionSemantics !== rawExecutionSemantics.trim() ||
      NON_EXECUTION_SEMANTICS.has(rawExecutionSemantics.trim().toLowerCase()));
  const requireEffectObserved = source === 'file_artifact_collector';
  const hasNegativeCorrelationOrVerification =
    hasMalformedMetadata ||
    data.executed === false ||
    data.effect_verified === false ||
    (requireEffectObserved && data.effect_observed === false) ||
    data.correlation_valid === false ||
    (normCorrStatus !== null && NEGATIVE_CORRELATION_STATUSES.has(normCorrStatus)) ||
    normCorrelationStrength === 'none' ||
    normCorrelationStrength === 'weak' ||
    hasNegativeVerificationStatus ||
    hasInvalidExecutionSemantics;

  // Contract-specific kind / source / provenance / correlation validation matching Backend is_execution_verified().
  let contractValid = false;
  if (kind === 'collected_evidence') {
    const validSimulatedEffect =
      rawExecutionSemantics !== 'simulated_handler_effect' || data.synthetic_mock === true;
    contractValid =
      source !== null &&
      COLLECTOR_EVIDENCE_SOURCES.has(source) &&
      hasIndependentProvenance &&
      validSimulatedEffect &&
      (rawCorrelationStatus === 'matched' || rawCorrelationStatus === 'verified') &&
      rawCorrelationStrength === 'strong';
  } else if (kind === 'collector_receipt') {
    contractValid =
      source !== null &&
      TRUSTED_LOCAL_COLLECTOR_SOURCES.has(source) &&
      rawProvenance !== null &&
      LOCAL_COLLECTOR_PROVENANCE_VALUES.has(rawProvenance) &&
      data.correlation_valid === true &&
      data.page_served === true;
  } else if (kind === 'tool_call' || kind === 'tool_trace') {
    const validSimulatedEffect =
      rawExecutionSemantics !== 'simulated_handler_effect' ||
      (data.synthetic_mock === true && rawVerificationStatus === 'verified_simulated_effect');
    contractValid =
      source !== null &&
      TRUSTED_INDEPENDENT_OBSERVER_SOURCES.has(source) &&
      rawProvenance !== null &&
      OBSERVER_PROVENANCE_VALUES.has(rawProvenance) &&
      validSimulatedEffect;
  }

  const isExecutionVerified =
    !isWrapper &&
    executionVerified === true &&
    hasIndependentProvenance &&
    !hasNonIndependentProvenance &&
    !hasNegativeCorrelationOrVerification &&
    contractValid;

  let verificationLabel: 'Execution verified' | 'Execution not verified' | 'Verification not recorded';
  if (isExecutionVerified) {
    verificationLabel = 'Execution verified';
  } else if (
    executionVerified === false ||
    executionVerified === true ||
    hasNegativeCorrelationOrVerification
  ) {
    verificationLabel = 'Execution not verified';
  } else {
    verificationLabel = 'Verification not recorded';
  }

  return {
    ev,
    provenance,
    executionVerified,
    verificationStatus,
    correlationStatus,
    isExecutionVerified,
    verificationLabel,
  };
}

export function summarizeCaseEvidenceVerification(c: GenericRunCaseResult): {
  totalItems: number;
  verifiedItemCount: number;
  unverifiedItemCount: number;
  unknownItemCount: number;
  hasVerifiedExecution: boolean;
  items: EvidenceItemVerificationInfo[];
} {
  const items = (c.evidence ?? []).map(inspectEvidenceItemVerification);
  let verifiedItemCount = 0;
  let unverifiedItemCount = 0;
  let unknownItemCount = 0;
  for (const item of items) {
    if (item.isExecutionVerified) {
      verifiedItemCount += 1;
    } else if (item.verificationLabel === 'Execution not verified') {
      unverifiedItemCount += 1;
    } else {
      unknownItemCount += 1;
    }
  }
  return {
    totalItems: items.length,
    verifiedItemCount,
    unverifiedItemCount,
    unknownItemCount,
    hasVerifiedExecution: verifiedItemCount > 0,
    items,
  };
}

export function summarizeRunEvidenceVerification(cases: GenericRunCaseResult[]): {
  totalCases: number;
  verifiedCaseCount: number;
  totalItems: number;
  verifiedItemCount: number;
  unverifiedItemCount: number;
  unknownItemCount: number;
} {
  let verifiedCaseCount = 0;
  let totalItems = 0;
  let verifiedItemCount = 0;
  let unverifiedItemCount = 0;
  let unknownItemCount = 0;

  for (const c of cases) {
    const s = summarizeCaseEvidenceVerification(c);
    if (s.hasVerifiedExecution) {
      verifiedCaseCount += 1;
    }
    totalItems += s.totalItems;
    verifiedItemCount += s.verifiedItemCount;
    unverifiedItemCount += s.unverifiedItemCount;
    unknownItemCount += s.unknownItemCount;
  }

  return {
    totalCases: cases.length,
    verifiedCaseCount,
    totalItems,
    verifiedItemCount,
    unverifiedItemCount,
    unknownItemCount,
  };
}

export function safePercent(count: number, total: number): number {
  if (!Number.isFinite(total) || total <= 0 || !Number.isFinite(count) || count <= 0) return 0;
  return Math.min(100, Math.max(0, Math.round((count / total) * 100)));
}

export async function copyTextToClipboard(text: string): Promise<boolean> {
  try {
    if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fallback ignored; return false cleanly when clipboard is unavailable.
  }
  return false;
}

export function downloadJsonFile(filename: string, payload: unknown): void {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
