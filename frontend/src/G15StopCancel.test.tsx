import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import SecurityScanWizard from './SecurityScanWizard';
import { generatorApi, type GenerateAndRunSnapshot } from './generatorApi';
import { testingApi, type GenericRunRecord } from './testingApi';

const NONCE = 'A'.repeat(43);
const RUN_ID = 'c'.repeat(32);
const WF_ID = `gnr-${'d'.repeat(32)}`;

function makeRunRecord(overrides: Partial<GenericRunRecord> = {}): GenericRunRecord {
  return {
    workflow_schema_version: '1.0.0',
    verdict_schema_version: '2.0',
    verdict_policy_version: '2.2.0-observation-binary',
    generic_run_id: RUN_ID,
    status: 'running',
    cancellation_requested: false,
    cancellation_requested_at: null,
    cancelled_at: null,
    started_at: '2026-11-27T08:00:00Z',
    completed_at: null,
    mode: 'live',
    target_id: 'target-live-a',
    target_name: 'Live Demo Agent',
    dataset_id: 'e'.repeat(32),
    dataset_name: 'demo-15.json',
    asi_category: 'ASI01',
    use_judge: true,
    policy_id: null,
    policy_revision_sha256: null,
    capability_states: { chat: 'supported' },
    selected_cases: 15,
    ready_count: 15,
    executed_cases: 3,
    total_cases: 15,
    skipped_count: 0,
    skipped_cases: [],
    progress_percent: 20,
    current_case_id: 'TC-04',
    current_stage: 'sending_request_to_target',
    target_request_budget: 15,
    target_requests_used: 3,
    judge_request_budget: 15,
    judge_requests_used: 3,
    verdict_counts: { PASS: 2, FAIL: 1 },
    evaluation_summary: {
      schema_version: '2.0',
      policy_version: '2.2.0-observation-binary',
      total_cases: 15,
      evaluated_cases: 3,
      pass_count: 2,
      fail_count: 1,
      not_evaluated_count: 0,
      evaluation_coverage: 0.2,
      evaluation_coverage_percent: 20,
      not_evaluated_reasons: {},
      evaluation_status_counts: { EVALUATED: 3 },
    },
    evidence_summary: { response_only: 3 },
    case_statuses: [
      { case_id: 'TC-01', category: 'goal_hijacking', asi_code: 'ASI01', status: 'completed', stage: 'completed', verdict: 'PASS', reason: 'ok', evidence_level: 'response_only', run_id: '1'.repeat(32) },
      { case_id: 'TC-02', category: 'goal_hijacking', asi_code: 'ASI01', status: 'completed', stage: 'completed', verdict: 'PASS', reason: 'ok', evidence_level: 'response_only', run_id: '2'.repeat(32) },
      { case_id: 'TC-03', category: 'goal_hijacking', asi_code: 'ASI01', status: 'completed', stage: 'completed', verdict: 'FAIL', reason: 'violation', evidence_level: 'response_only', run_id: '3'.repeat(32) },
      { case_id: 'TC-04', category: 'goal_hijacking', asi_code: 'ASI01', status: 'running', stage: 'sending_request_to_target', verdict: null, reason: null, evidence_level: null, run_id: null },
    ],
    events: [{ at: '2026-11-27T08:00:05Z', stage: 'case_completed', case_id: 'TC-03', verdict: 'FAIL' }],
    cases: [
      { case_id: 'TC-01', run_id: '1'.repeat(32), category: 'goal_hijacking', prompt: 'p1', response_text: 'r1', response_complete: true, verdict: 'PASS', evaluation_status: 'EVALUATED', reason: 'ok', judge_reason: 'ok', judge_classification: 'ORIGINAL_GOAL', evidence_level: 'response_only', provenance_tiers: [], execution_status: 'succeeded', collector_diagnostics: [], evidence: [], report_path: '/tmp/1.json' },
      { case_id: 'TC-02', run_id: '2'.repeat(32), category: 'goal_hijacking', prompt: 'p2', response_text: 'r2', response_complete: true, verdict: 'PASS', evaluation_status: 'EVALUATED', reason: 'ok', judge_reason: 'ok', judge_classification: 'ORIGINAL_GOAL', evidence_level: 'response_only', provenance_tiers: [], execution_status: 'succeeded', collector_diagnostics: [], evidence: [], report_path: '/tmp/2.json' },
      { case_id: 'TC-03', run_id: '3'.repeat(32), category: 'goal_hijacking', prompt: 'p3', response_text: 'r3', response_complete: true, verdict: 'FAIL', evaluation_status: 'EVALUATED', reason: 'violation', judge_reason: 'violation', judge_classification: 'ATTACKER_GOAL', evidence_level: 'response_only', provenance_tiers: [], execution_status: 'succeeded', collector_diagnostics: [], evidence: [], report_path: '/tmp/3.json' },
    ],
    ...overrides,
  };
}

function makeWorkflowSnapshot(overrides: Partial<GenerateAndRunSnapshot> = {}): GenerateAndRunSnapshot {
  return {
    workflow_id: WF_ID,
    mode: 'generate_and_run',
    submission_id: null,
    idempotent_replay: false,
    status: 'running',
    cancellation_requested: false,
    cancellation_requested_at: null,
    cancelled_at: null,
    current_stage: 'generating',
    created_at: '2026-11-27T08:00:00Z',
    updated_at: '2026-11-27T08:00:01Z',
    completed_at: null,
    target_id: 'target-live-a',
    target_revision_sha256: 'a'.repeat(64),
    application_context_revision_sha256: null,
    context_snapshot_sha256: null,
    selected_asi: ['ASI01'],
    requested_scopes: {},
    policy_ids_by_asi: {},
    language: 'en',
    evaluation_mode: 'hybrid',
    execution_mode: 'live',
    allow_partial_execution: false,
    stages: [
      { stage: 'generating', status: 'running', started_at: '2026-11-27T08:00:00Z', finished_at: null, detail: 'Generating', error_code: null, error_message: null },
      { stage: 'validating', status: 'pending', started_at: null, finished_at: null, detail: null, error_code: null, error_message: null },
      { stage: 'saving_dataset', status: 'pending', started_at: null, finished_at: null, detail: null, error_code: null, error_message: null },
      { stage: 'preflight', status: 'pending', started_at: null, finished_at: null, detail: null, error_code: null, error_message: null },
      { stage: 'executing', status: 'pending', started_at: null, finished_at: null, detail: null, error_code: null, error_message: null },
      { stage: 'evaluating', status: 'pending', started_at: null, finished_at: null, detail: null, error_code: null, error_message: null },
      { stage: 'reporting', status: 'pending', started_at: null, finished_at: null, detail: null, error_code: null, error_message: null },
    ],
    generation_id: null,
    provider_id: 'deepseek',
    model: 'deepseek-chat',
    generation_overall_status: null,
    requested_count: 5,
    generated_count: 0,
    accepted_count: 0,
    rejected_count: 0,
    meets_requested_counts: false,
    partial_generation: false,
    rejection_reason_counts: {},
    asi_generation_summaries: {},
    generation_token_usage: null,
    quality_summary: null,
    auto_persisted: false,
    dataset_id: null,
    dataset_name: null,
    dataset_file_sha256: null,
    testcase_ids: [],
    run_id: null,
    run_status: null,
    executed_cases: 0,
    total_cases: 0,
    progress_percent: 0,
    verdict_counts: {},
    evidence_summary: {},
    judge_metadata: null,
    evaluation_error_code: null,
    cases_summary: [],
    dataset_url: null,
    report_url: null,
    report_export_url: null,
    rerun_supported: false,
    rerun_history: [],
    resume_supported: false,
    resume_endpoint: null,
    resume_note: 'Resume continues cancelled or interrupted runs.',
    error_stage: null,
    error_code: null,
    error_message: null,
    provenance: {},
    ...overrides,
  };
}

describe('G15-P1 Frontend Stop/Cancel and Reload Recovery', () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.restoreAllMocks();
    vi.spyOn(testingApi, 'health').mockResolvedValue({
      nonce: NONCE,
      evaluationModes: ['rule_only', 'hybrid'],
      managementEnabled: true,
      controlledRunsEnabled: true,
      localSingleUser: true,
      offlineBatchEnabled: false,
      asi01BatchEnabled: false,
      asi01TextTargets: [],
      webLabBatchEnabled: false,
      toolbotLabBatchEnabled: false,
      customImportedBatchEnabled: true,
      importedLiveLocalEnabled: true,
      importedLiveLocalMocked: false,
      judgeSetupReason: 'ready_to_validate_at_run',
      mcpActionSetupReason: 'configured',
      genericRunnerEnabled: true,
      piJudgeReady: true,
    });
    vi.spyOn(testingApi, 'targets').mockResolvedValue({ targets: [], protocols: [] });
    vi.spyOn(testingApi, 'listDatasets').mockResolvedValue([]);
    vi.spyOn(testingApi, 'listGenericRuns').mockResolvedValue([]);
    vi.spyOn(generatorApi, 'listGenerateAndRunWorkflows').mockResolvedValue({
      workflow_schema_version: '1.0.0',
      workflows: [],
      active_reservations: [],
    });
  });

  afterEach(() => {
    cleanup();
    sessionStorage.clear();
  });

  it('shows Stop Scan, transitions to disabled Stopping..., keeps polling to Cancelled, preserves completed results, and recovers state after reload', async () => {
    const runningRec = makeRunRecord();
    const stoppingRec = makeRunRecord({
      status: 'running',
      cancellation_requested: true,
      cancellation_requested_at: '2026-11-27T08:00:06Z',
      current_stage: 'cancelling',
      cancel_outcome: 'cancel_requested',
    });
    const cancelledRec = makeRunRecord({
      status: 'cancelled',
      cancellation_requested: true,
      cancellation_requested_at: '2026-11-27T08:00:06Z',
      cancelled_at: '2026-11-27T08:00:07Z',
      completed_at: '2026-11-27T08:00:07Z',
      current_case_id: null,
      current_stage: 'cancelled',
      lineage_summary: {
        root_run_id: RUN_ID,
        parent_run_id: null,
        child_run_ids: [],
        lineage_run_ids: [RUN_ID],
        latest_run_id: RUN_ID,
        active_lineage_run_id: null,
        resumable_run_id: RUN_ID,
        logical_status: 'cancelled',
        integrity_status: 'valid',
        integrity_warning: null,
        session_count: 1,
        resume_count: 0,
        original_selected_cases: 15,
        ready_count: 15,
        skipped_count: 0,
        lineage_completed_count: 3,
        lineage_verdict_counts: { PASS: 2, FAIL: 1 },
        remaining_pending_count: 12,
        remaining_uncertain_count: 0,
        has_resumable_work: true,
      },
    });

    let backendState: GenericRunRecord = runningRec;
    const getRunSpy = vi.spyOn(testingApi, 'getGenericRun').mockImplementation(async () => backendState);
    const cancelSpy = vi.spyOn(testingApi, 'cancelGenericRun').mockImplementation(async () => {
      backendState = stoppingRec;
      return stoppingRec;
    });

    const firstRender = render(<SecurityScanWizard initialRunId={RUN_ID} />);

    // 1. Stop Scan button visible while scan is running.
    const stopBtn = await screen.findByTestId('stop-scan-btn');
    expect(stopBtn).toBeEnabled();
    expect(stopBtn).toHaveTextContent('Stop Scan');

    // 2. Clicking Stop invokes backend cancel endpoint, displays Stopping..., and disables duplicate clicks.
    fireEvent.click(stopBtn);
    await waitFor(() => expect(cancelSpy).toHaveBeenCalledTimes(1));
    expect(cancelSpy).toHaveBeenCalledWith(RUN_ID, '', NONCE);
    await waitFor(() => {
      expect(screen.getByTestId('stop-scan-btn')).toBeDisabled();
      expect(screen.getByTestId('stop-scan-btn')).toHaveTextContent('Stopping...');
    });
    // Clicking again while disabled does not send duplicate cancel request.
    fireEvent.click(screen.getByTestId('stop-scan-btn'));
    expect(cancelSpy).toHaveBeenCalledTimes(1);

    // 3. Simulate page reload WHILE backend is still Stopping... -> must restore Stopping... state!
    firstRender.unmount();
    const reloadStopping = render(<SecurityScanWizard initialRunId={RUN_ID} />);
    await waitFor(() => {
      expect(screen.getByTestId('stop-scan-btn')).toBeDisabled();
      expect(screen.getByTestId('stop-scan-btn')).toHaveTextContent('Stopping...');
      expect(screen.getByTestId('scan-stopping-notice')).toBeInTheDocument();
    });

    // 4. Backend transitions to terminal cancelled -> polling picks it up, shows Cancelled results,
    //    preserves the 3 completed cases, and offers Resume Scan!
    backendState = cancelledRec;
    await waitFor(
      () => {
        expect(screen.getByText(/STEP 3 OF 3 · SCAN CANCELLED/i)).toBeInTheDocument();
      },
      { timeout: 3000 },
    );
    expect(screen.getByRole('button', { name: /Resume Scan/i })).toBeInTheDocument();
    expect(screen.getByText('TC-01')).toBeInTheDocument();
    expect(screen.getByText('TC-03')).toBeInTheDocument();
    expect(getRunSpy.mock.calls.length).toBeGreaterThanOrEqual(2);

    // 5. Simulate page reload AFTER cancelled -> restores Cancelled view & Resume Scan button.
    reloadStopping.unmount();
    render(<SecurityScanWizard initialRunId={RUN_ID} />);
    await waitFor(() => {
      expect(screen.getByText(/STEP 3 OF 3 · SCAN CANCELLED/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Resume Scan/i })).toBeInTheDocument();
    });
  });

  it('cancels an active Generate & Run workflow via cancelGenerateAndRun and shows Cancelled (not Failed)', async () => {
    let wfState = makeWorkflowSnapshot();
    vi.spyOn(generatorApi, 'getGenerateAndRunStatus').mockImplementation(async () => wfState);
    const cancelWfSpy = vi.spyOn(generatorApi, 'cancelGenerateAndRun').mockImplementation(async () => {
      wfState = makeWorkflowSnapshot({
        status: 'cancelled',
        cancellation_requested: true,
        cancelled_at: '2026-11-27T08:00:03Z',
        completed_at: '2026-11-27T08:00:03Z',
        stages: wfState.stages.map((s) =>
          s.stage === 'generating'
            ? { ...s, status: 'cancelled', detail: 'Cancelled by operator.' }
            : { ...s, status: 'skipped' },
        ),
      });
      return { workflow_schema_version: '1.0.0', cancel_outcome: 'cancel_requested', workflow: wfState };
    });

    render(<SecurityScanWizard initialWorkflowId={WF_ID} />);

    const stopBtn = await screen.findByTestId('stop-scan-btn');
    expect(stopBtn).toBeEnabled();
    fireEvent.click(stopBtn);

    await waitFor(() => expect(cancelWfSpy).toHaveBeenCalledWith(WF_ID, NONCE, ''));
    await waitFor(() => {
      expect(screen.getByTestId('unified-workflow-status')).toHaveTextContent('cancelled');
      expect(screen.getByTestId('unified-workflow-cancelled-notice')).toBeInTheDocument();
    });
  });
});
