import type {
  GenericEvaluationSummary,
  GenericRunRecord,
  GenericRunSummary,
  LogicalScanStatus,
} from './testingApi';

export interface LogicalScanGroup {
  logicalScanId: string;
  rootRunId: string;
  latestRunId: string;
  target_id: string;
  target_name: string;
  dataset_id?: string | null;
  dataset_name?: string | null;
  mode: 'live' | 'offline';
  use_judge: boolean;
  asi_category: string;
  asi_categories: string[];
  testcase_ids: string[];
  started_at?: string | null;
  completed_at?: string | null;
  selected_cases: number;
  ready_count: number;
  executed_cases: number;
  skipped_count: number;
  verdict_counts: Record<string, number>;
  verdict_schema_version?: string | null;
  verdict_policy_version?: string | null;
  evaluation_summary?: GenericEvaluationSummary | null;
  logical_status: LogicalScanStatus;
  integrity_status: 'valid' | 'invalid_checkpoint';
  integrity_warning: string | null;
  session_count: number;
  resume_count: number;
  has_continuations: boolean;
  sessions: GenericRunSummary[];
  rootSession: GenericRunSummary;
}

export function resolveRootRunId(
  run: Pick<GenericRunSummary, 'generic_run_id' | 'root_run_id' | 'continuation_of_run_id' | 'lineage_summary'>,
): string {
  return (
    run.lineage_summary?.root_run_id ||
    run.root_run_id ||
    run.continuation_of_run_id ||
    run.generic_run_id
  );
}

export function deriveLogicalScanStatus(params: {
  explicitLogicalStatus?: LogicalScanStatus | null;
  activeSessionPresent: boolean;
  readyCount: number;
  recordedOutcomes: number;
  errorCount: number;
  latestSessionStatus: string;
  anyInterrupted: boolean;
}): LogicalScanStatus {
  if (params.explicitLogicalStatus) {
    return params.explicitLogicalStatus;
  }
  if (params.activeSessionPresent) {
    return 'running';
  }
  if (params.readyCount > 0 && params.recordedOutcomes >= params.readyCount) {
    return params.errorCount > 0 ? 'completed_with_errors' : 'completed';
  }
  if (params.latestSessionStatus === 'interrupted' || params.latestSessionStatus === 'cancelled' || params.latestSessionStatus === 'failed') {
    return params.latestSessionStatus;
  }
  if (params.anyInterrupted) {
    return 'interrupted';
  }
  return 'failed';
}

/**
 * Group persisted GenericRunSummary rows strictly by `root_run_id`.
 * Never merges unrelated scans merely because they share a target or dataset.
 */
export function groupLogicalScans(runs: GenericRunSummary[]): LogicalScanGroup[] {
  const buckets = new Map<string, GenericRunSummary[]>();
  for (const r of runs) {
    const rootId = resolveRootRunId(r);
    const list = buckets.get(rootId);
    if (list) {
      list.push(r);
    } else {
      buckets.set(rootId, [r]);
    }
  }

  const groups: LogicalScanGroup[] = [];
  for (const [rootId, members] of buckets.entries()) {
    const sessions = [...members].sort((a, b) => {
      if (a.generic_run_id === rootId && b.generic_run_id !== rootId) return -1;
      if (b.generic_run_id === rootId && a.generic_run_id !== rootId) return 1;
      const sa = a.started_at || '';
      const sb = b.started_at || '';
      if (sa !== sb) return sa.localeCompare(sb);
      return a.generic_run_id.localeCompare(b.generic_run_id);
    });

    const rootSession = sessions.find(s => s.generic_run_id === rootId) ?? sessions[0];
    const latestSession = sessions[sessions.length - 1];
    const summaryWithLineage =
      sessions.find(s => Boolean(s.lineage_summary))?.lineage_summary ??
      rootSession.lineage_summary ??
      null;

    const hasContinuations =
      sessions.length > 1 ||
      (summaryWithLineage?.session_count ?? 1) > 1 ||
      Boolean(rootSession.child_run_ids && rootSession.child_run_ids.length > 0);

    const asiSet = new Set<string>();
    const tcSet = new Set<string>();
    for (const s of sessions) {
      for (const cat of s.asi_categories ?? []) {
        if (cat) asiSet.add(cat);
      }
      for (const tc of s.testcase_ids ?? []) {
        if (tc) tcSet.add(tc);
      }
    }

    const activeSessionPresent =
      Boolean(summaryWithLineage?.active_lineage_run_id) ||
      sessions.some(s => s.status === 'preparing' || s.status === 'running');

    const selectedCases =
      summaryWithLineage?.original_selected_cases ?? rootSession.selected_cases;
    const skippedCount =
      summaryWithLineage?.skipped_count ?? rootSession.skipped_count;
    const readyCount =
      summaryWithLineage?.ready_count ??
      rootSession.ready_count ??
      Math.max(0, selectedCases - skippedCount);

    let verdictCounts: Record<string, number>;
    let executedCases: number;
    if (summaryWithLineage?.lineage_verdict_counts) {
      verdictCounts = { ...summaryWithLineage.lineage_verdict_counts };
      executedCases = summaryWithLineage.lineage_completed_count;
    } else if (sessions.length === 1) {
      verdictCounts = { ...(rootSession.verdict_counts ?? {}) };
      executedCases = rootSession.executed_cases;
    } else {
      // Fallback deduplication when lineage_summary isn't present in mocked/legacy payloads
      verdictCounts = {};
      for (const s of sessions) {
        for (const [k, v] of Object.entries(s.verdict_counts ?? {})) {
          verdictCounts[k] = (verdictCounts[k] ?? 0) + Number(v ?? 0);
        }
      }
      executedCases = tcSet.size > 0
        ? Math.min(readyCount || tcSet.size, tcSet.size)
        : sessions.reduce((acc, s) => acc + s.executed_cases, 0);
    }

    const evaluationSummary =
      latestSession.evaluation_summary ?? rootSession.evaluation_summary ?? null;
    const errorCount =
      Number(verdictCounts.ERROR ?? 0) +
      Number(evaluationSummary?.not_evaluated_reasons?.EXECUTION_ERROR ?? 0);
    const logicalStatus = deriveLogicalScanStatus({
      explicitLogicalStatus: summaryWithLineage?.logical_status ?? null,
      activeSessionPresent,
      readyCount,
      recordedOutcomes: executedCases,
      errorCount,
      latestSessionStatus: latestSession.status,
      anyInterrupted: sessions.some(s => s.status === 'interrupted'),
    });

    const sessionCount = Math.max(sessions.length, summaryWithLineage?.session_count ?? 1);
    groups.push({
      logicalScanId: rootId,
      rootRunId: rootId,
      latestRunId: summaryWithLineage?.latest_run_id ?? latestSession.generic_run_id,
      target_id: rootSession.target_id,
      target_name: rootSession.target_name,
      dataset_id: rootSession.dataset_id,
      dataset_name: rootSession.dataset_name,
      mode: rootSession.mode,
      use_judge: rootSession.use_judge,
      asi_category: rootSession.asi_category,
      asi_categories: Array.from(asiSet).sort(),
      testcase_ids: Array.from(tcSet),
      started_at: summaryWithLineage?.started_at ?? rootSession.started_at,
      completed_at: activeSessionPresent
        ? null
        : (summaryWithLineage?.completed_at ?? latestSession.completed_at),
      selected_cases: selectedCases,
      ready_count: readyCount,
      executed_cases: executedCases,
      skipped_count: skippedCount,
      verdict_counts: verdictCounts,
      verdict_schema_version: latestSession.verdict_schema_version ?? rootSession.verdict_schema_version ?? null,
      verdict_policy_version: latestSession.verdict_policy_version ?? rootSession.verdict_policy_version ?? null,
      evaluation_summary: evaluationSummary,
      logical_status: logicalStatus,
      integrity_status: summaryWithLineage?.integrity_status ?? 'valid',
      integrity_warning: summaryWithLineage?.integrity_warning ?? null,
      session_count: sessionCount,
      resume_count: Math.max(0, sessionCount - 1),
      has_continuations: hasContinuations,
      sessions,
      rootSession,
    });
  }

  // Preserve exact backend newest-first ordering without re-sorting unrelated scans
  return groups;
}

/**
 * Derive a unified view model for live progress and scan results from a GenericRunRecord.
 * Single-session runs without continuations pass through unchanged (except deriving
 * completed_with_errors when all cases finished with ERROR verdicts).
 */
export function resolveUnifiedDisplay(record: GenericRunRecord): {
  isUnified: boolean;
  logicalScanId: string;
  activeSessionId: string;
  logicalStatus: LogicalScanStatus;
  integrityStatus: 'valid' | 'invalid_checkpoint';
  integrityWarning: string | null;
  selectedCount: number;
  readyCount: number;
  executedCount: number;
  skippedCount: number;
  progressPercent: number;
  verdictCounts: Record<string, number>;
  evidenceSummary: Record<string, number>;
  judgeMetadata: GenericRunRecord['judge_metadata'] | null;
  targetRequestsUsed: number | null;
  judgeRequestsUsed: number | null;
  currentCaseId: string | null;
  currentStage: string | null;
  activeSessionStartedAt: string | null | undefined;
  activeSessionTargetUsed: number | null;
  activeSessionTargetBudget: number | null;
  activeSessionJudgeUsed: number | null;
  activeSessionJudgeBudget: number | null;
  activeSessionEvents: NonNullable<GenericRunRecord['events']>;
  startedAt: string | null | undefined;
  completedAt: string | null | undefined;
  sessionCount: number;
  resumeCount: number;
  resumableRunId: string | null;
  hasResumableWork: boolean;
  cases: GenericRunRecord['cases'];
  caseStatuses: NonNullable<GenericRunRecord['case_statuses']>;
  sessions: NonNullable<NonNullable<GenericRunRecord['unified_lineage']>['sessions']>;
} {
  const ul = record.unified_lineage;
  if (ul) {
    const integrityStatus = ul.integrity_status ?? 'valid';
    const judgeMetadata = ul.judge_metadata !== undefined ? ul.judge_metadata : (record.judge_metadata ?? null);
    return {
      isUnified: true,
      logicalScanId: ul.logical_scan_id || ul.root_run_id,
      activeSessionId: ul.active_session_run_id || record.generic_run_id,
      logicalStatus: ul.logical_status,
      integrityStatus,
      integrityWarning: ul.integrity_warning ?? null,
      selectedCount: ul.selected_cases,
      readyCount: ul.ready_count,
      executedCount: ul.executed_cases,
      skippedCount: ul.skipped_count,
      progressPercent: ul.progress_percent,
      verdictCounts: ul.verdict_counts,
      evidenceSummary: ul.evidence_summary,
      judgeMetadata,
      targetRequestsUsed: ul.target_requests_used ?? null,
      judgeRequestsUsed: ul.judge_requests_used ?? null,
      currentCaseId: ul.current_case_id !== undefined ? ul.current_case_id : (record.current_case_id ?? null),
      currentStage: ul.current_stage !== undefined ? ul.current_stage : (record.current_stage ?? null),
      activeSessionStartedAt: ul.active_session_started_at ?? record.started_at,
      activeSessionTargetUsed: ul.active_session_target_requests_used !== undefined ? ul.active_session_target_requests_used : (record.target_requests_used ?? null),
      activeSessionTargetBudget: ul.active_session_target_request_budget !== undefined ? ul.active_session_target_request_budget : (record.target_request_budget ?? null),
      activeSessionJudgeUsed: ul.active_session_judge_requests_used !== undefined ? ul.active_session_judge_requests_used : (record.judge_requests_used ?? null),
      activeSessionJudgeBudget: ul.active_session_judge_request_budget !== undefined ? ul.active_session_judge_request_budget : (record.judge_request_budget ?? null),
      activeSessionEvents: ul.active_session_events ?? record.events ?? [],
      startedAt: ul.started_at,
      completedAt: ul.completed_at,
      sessionCount: ul.session_count,
      resumeCount: ul.resume_count,
      resumableRunId: integrityStatus === 'valid' ? ul.resumable_run_id : null,
      hasResumableWork:
        integrityStatus === 'valid' &&
        Boolean(ul.resumable_run_id && record.lineage_summary?.has_resumable_work !== false),
      cases: ul.cases,
      caseStatuses: ul.case_statuses,
      sessions: ul.sessions,
    };
  }

  const cases = record.cases ?? [];
  const skippedCases = record.skipped_cases ?? [];
  const rawStatus = (record.status ?? 'completed') as LogicalScanStatus;
  const selectedCount = record.selected_cases ?? (record.total_cases + skippedCases.length);
  const readyCount = record.ready_count ?? record.total_cases;
  const executedCount = record.executed_cases ?? (rawStatus === 'completed' ? record.total_cases : cases.length);
  const skippedCount = record.skipped_count ?? skippedCases.length;
  const verdictCounts = record.verdict_counts ?? {};
  const errorCount =
    Number(verdictCounts.ERROR ?? 0) +
    Number(record.evaluation_summary?.not_evaluated_reasons?.EXECUTION_ERROR ?? 0);
  const integrityStatus = record.lineage_summary?.integrity_status ?? 'valid';
  const logicalStatus: LogicalScanStatus =
    record.lineage_summary?.logical_status ??
    (rawStatus === 'completed' && errorCount > 0 ? 'completed_with_errors' : rawStatus);

  const fallbackStatuses =
    record.case_statuses ??
    cases.map(c => ({
      case_id: c.case_id,
      category: c.category,
      status: (c.verdict === 'ERROR' || c.evaluation_status === 'EXECUTION_ERROR' ? 'error' : 'completed') as 'error' | 'completed',
      stage: 'completed',
      verdict: c.verdict,
      reason: c.reason,
      evidence_level: c.evidence_level,
      run_id: c.run_id,
    }));

  const hasResumableWork =
    integrityStatus === 'valid' &&
    (record.lineage_summary !== undefined && record.lineage_summary !== null
      ? record.lineage_summary.has_resumable_work
      : rawStatus === 'interrupted' && executedCount < readyCount);

  return {
    isUnified: false,
    logicalScanId: record.root_run_id || record.generic_run_id,
    activeSessionId: record.generic_run_id,
    logicalStatus,
    integrityStatus,
    integrityWarning: record.lineage_summary?.integrity_warning ?? null,
    selectedCount,
    readyCount,
    executedCount,
    skippedCount,
    progressPercent:
      typeof record.progress_percent === 'number'
        ? record.progress_percent
        : readyCount > 0
          ? Math.round((executedCount / readyCount) * 100)
          : 0,
    verdictCounts,
    evidenceSummary: record.evidence_summary ?? {},
    judgeMetadata: record.judge_metadata ?? null,
    targetRequestsUsed: record.target_requests_used ?? (record.mode === 'offline' ? 0 : null),
    judgeRequestsUsed: record.judge_requests_used ?? (record.judge_metadata ? record.judge_metadata.request_count : null),
    currentCaseId: record.current_case_id ?? null,
    currentStage: record.current_stage ?? null,
    activeSessionStartedAt: record.started_at,
    activeSessionTargetUsed: record.target_requests_used ?? null,
    activeSessionTargetBudget: record.target_request_budget ?? null,
    activeSessionJudgeUsed: record.judge_requests_used ?? null,
    activeSessionJudgeBudget: record.judge_request_budget ?? null,
    activeSessionEvents: record.events ?? [],
    startedAt: record.started_at,
    completedAt: record.completed_at,
    sessionCount: record.lineage_summary?.session_count ?? 1,
    resumeCount: record.lineage_summary?.resume_count ?? 0,
    resumableRunId: hasResumableWork ? (record.lineage_summary?.resumable_run_id ?? record.generic_run_id) : null,
    hasResumableWork,
    cases,
    caseStatuses: fallbackStatuses,
    sessions: [],
  };
}
