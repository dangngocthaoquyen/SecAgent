import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import SavedRuns from './SavedRuns';
import SecurityScanWizard from './SecurityScanWizard';
import { groupLogicalScans } from './scanLineage';
import type { GenericResumePreview, GenericRunRecord, GenericRunSummary, TargetPreset } from './testingApi';

const httpTarget: TargetPreset = {
  id: 'local-http-8000-api-agent-runs',
  name: 'Local HTTP Agent',
  profile_revision: '1'.repeat(64),
  policy_ref: 'local-v1',
  platform_id: 'custom-http',
  platform_name: 'Custom HTTP',
  authorization_status: 'reviewed_for_offline_configuration',
  endpoint: 'http://127.0.0.1:8000/api/agent/runs',
  protocol: 'http-json',
  method: 'POST',
  models: [],
  default_model: '',
  timeout_min: 1,
  timeout_max: 600,
  timeout_default: 300,
  credential_alias: null,
  credential_availability: 'available',
  auth_source: 'session_memory',
  session_auth: { ref_id: 'sess_' + 'a'.repeat(24), auth_type: 'bearer', header_name: 'Authorization' },
  request_mapping: 'http-json-template-v1',
  response_parser: 'output',
  connection_probe: {
    status: 'supported',
    reason: 'reviewed_exact_endpoint',
    active_probe_authorized: true,
    security_execution_authorized: false,
  },
  capabilities: ['chat'],
  capability_basis: 'operator_reviewed',
  limitations: [],
};

const PARENT_RUN_ID = 'a'.repeat(32);
const CHILD_RUN_ID = 'b'.repeat(32);
const DATASET_ID = 'd'.repeat(32);
const DIGEST_PENDING_ONLY = 'e'.repeat(64);
const DIGEST_WITH_UNCERTAIN = 'f'.repeat(64);

function makeInterruptedRecord(overrides: Partial<GenericRunRecord> = {}): GenericRunRecord {
  return {
    workflow_schema_version: '1.0.0',
    generic_run_id: PARENT_RUN_ID,
    status: 'interrupted',
    interrupted_reason: 'process_restarted_before_completion',
    started_at: '2026-11-25T10:00:00Z',
    completed_at: null,
    mode: 'live',
    target_id: httpTarget.id,
    target_name: httpTarget.name,
    dataset_id: DATASET_ID,
    dataset_name: 'testcases_agent_asi02.json',
    asi_category: 'ASI02',
    use_judge: true,
    policy_id: null,
    policy_revision_sha256: null,
    capability_states: { chat: 'supported' },
    selected_cases: 35,
    ready_count: 35,
    executed_cases: 6,
    total_cases: 35,
    skipped_count: 0,
    skipped_cases: [],
    progress_percent: 17,
    verdict_counts: { FAIL: 1, INCONCLUSIVE: 5 },
    cases: Array.from({ length: 6 }, (_, i) => ({
      case_id: `TC00${11 + i}`,
      run_id: `${i + 1}`.repeat(32),
      category: 'tool_misuse',
      prompt: `Prompt ${i + 1}`,
      response_text: 'Agent response',
      response_complete: true,
      verdict: i === 0 ? 'FAIL' : 'INCONCLUSIVE',
      reason: 'Recorded verdict',
      judge_reason: 'Judge note',
      judge_classification: i === 0 ? 'unsafe' : 'uncertain',
      semantic_invoked: true,
      evidence_level: 'response_only',
      provenance_tiers: ['response'],
      execution_status: 'completed',
      collector_diagnostics: [],
      evidence: [],
      report_path: `/tmp/r${i}.json`,
    })),
    lineage_summary: {
      root_run_id: PARENT_RUN_ID,
      parent_run_id: null,
      child_run_ids: [],
      lineage_run_ids: [PARENT_RUN_ID],
      active_lineage_run_id: null,
      original_selected_cases: 35,
      lineage_completed_count: 6,
      lineage_verdict_counts: { FAIL: 1, INCONCLUSIVE: 5 },
      remaining_pending_count: 28,
      remaining_uncertain_count: 1,
      has_resumable_work: true,
    },
    ...overrides,
  };
}

function makeResumePreview(overrides: Partial<GenericResumePreview> = {}): GenericResumePreview {
  const pending = Array.from({ length: 28 }, (_, i) => `TC00${18 + i}`);
  return {
    workflow_schema_version: '1.0.0',
    parent_run_id: PARENT_RUN_ID,
    root_run_id: PARENT_RUN_ID,
    parent_status: 'interrupted',
    original_selected_cases: 35,
    completed_count: 6,
    completed_case_ids: ['TC0011', 'TC0012', 'TC0013', 'TC0014', 'TC0015', 'TC0016'],
    completed_cases_summary: [
      { case_id: 'TC0011', verdict: 'FAIL', run_id: '1'.repeat(32), generic_run_id: PARENT_RUN_ID },
      { case_id: 'TC0012', verdict: 'INCONCLUSIVE', run_id: '2'.repeat(32), generic_run_id: PARENT_RUN_ID },
      { case_id: 'TC0013', verdict: 'INCONCLUSIVE', run_id: '3'.repeat(32), generic_run_id: PARENT_RUN_ID },
      { case_id: 'TC0014', verdict: 'INCONCLUSIVE', run_id: '4'.repeat(32), generic_run_id: PARENT_RUN_ID },
      { case_id: 'TC0015', verdict: 'INCONCLUSIVE', run_id: '5'.repeat(32), generic_run_id: PARENT_RUN_ID },
      { case_id: 'TC0016', verdict: 'INCONCLUSIVE', run_id: '6'.repeat(32), generic_run_id: PARENT_RUN_ID },
    ],
    pending_case_ids: pending,
    uncertain_case_ids: ['TC0017'],
    included_uncertain_case_ids: [],
    skipped_case_ids: [],
    selected_resume_case_ids: pending,
    target_id: httpTarget.id,
    target_name: httpTarget.name,
    target_revision_sha256: httpTarget.profile_revision,
    target_ready: true,
    auth_source: 'session_memory',
    credential_availability: 'available',
    session_credential_generation: 'c'.repeat(32),
    session_auth_type: 'bearer',
    session_auth_header: 'Authorization',
    dataset_id: DATASET_ID,
    dataset_name: 'testcases_agent_asi02.json',
    dataset_consistent: true,
    config_consistent: true,
    mode: 'live',
    asi_category: 'ASI02',
    use_judge: true,
    judge_status: {
      judge_configured: true,
      credential_available: true,
      judge_ready: true,
      provider: 'deepseek',
      model: 'deepseek-v4-flash',
      reason: 'ready',
    },
    target_request_budget: 28,
    judge_request_budget: 28,
    resume_digest: DIGEST_PENDING_ONLY,
    eligible: true,
    blocker: null,
    blockers: [],
    warnings: [],
    ...overrides,
  };
}

function mockBaseFetch(handlers: {
  runById: Record<string, GenericRunRecord>;
  onPreview?: (body: Record<string, unknown>) => GenericResumePreview;
  onStart?: (body: Record<string, unknown>) => GenericRunRecord;
}) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input);
    if (url.endsWith('/api/testing/health')) {
      return new Response(
        JSON.stringify({
          workflow_schema_version: '1.0.0',
          status: 'ok',
          mode: 'controlled_execution_enabled',
          target_network_access: true,
          validation_nonce: 'N'.repeat(43),
          operator_mode: 'local_single_user',
          target_management_enabled: true,
          evaluation_modes: ['rule_only', 'hybrid'],
          judge_configuration: 'configured_unverified',
          generic_runner_enabled: true,
          pi_judge_ready: true,
        }),
        { status: 200 },
      );
    }
    if (url.endsWith('/api/testing/targets')) {
      return new Response(
        JSON.stringify({ workflow_schema_version: '1.0.0', targets: [httpTarget], protocols: [] }),
        { status: 200 },
      );
    }
    if (url.endsWith('/api/testing/datasets')) {
      return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', datasets: [] }), { status: 200 });
    }
    if (url.endsWith('/api/testing/generic-runs')) {
      return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', runs: [] }), { status: 200 });
    }
    if (url.endsWith(`/api/testing/generic-runs/${PARENT_RUN_ID}/resume/preview`)) {
      const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
      const data = handlers.onPreview ? handlers.onPreview(body) : makeResumePreview();
      return new Response(JSON.stringify(data), { status: 200 });
    }
    if (url.endsWith(`/api/testing/generic-runs/${PARENT_RUN_ID}/resume/start`)) {
      const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
      const data = handlers.onStart!(body);
      return new Response(JSON.stringify(data), { status: 202 });
    }
    for (const [id, rec] of Object.entries(handlers.runById)) {
      if (url.endsWith(`/api/testing/generic-runs/${id}`)) {
        return new Response(JSON.stringify(rec), { status: 200 });
      }
    }
    return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', error: { code: 'not_found' } }), {
      status: 404,
    });
  });
}

describe('G10.2 Simplified Interrupted Generic Scan Resume UX', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    window.location.hash = '';
  });

  it('shows Resume Scan button on interrupted runs with remaining work and hides it on completed runs', async () => {
    mockBaseFetch({ runById: { [PARENT_RUN_ID]: makeInterruptedRecord() } });
    const { unmount } = render(<SecurityScanWizard initialRunId={PARENT_RUN_ID} />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Resume Scan' })).toBeTruthy();
    });
    unmount();

    vi.restoreAllMocks();
    const completedRecord = makeInterruptedRecord({
      status: 'completed',
      executed_cases: 35,
      progress_percent: 100,
      interrupted_reason: null,
      lineage_summary: undefined,
    });
    mockBaseFetch({ runById: { [PARENT_RUN_ID]: completedRecord } });
    render(<SecurityScanWizard initialRunId={PARENT_RUN_ID} />);
    await waitFor(() => {
      expect(screen.getByText(/Scan Results:/i)).toBeTruthy();
    });
    expect(screen.queryByRole('button', { name: 'Resume Scan' })).toBeNull();
  });

  it('includes uncertain TC0017 by default in read-only Preview, shows disclosure, and executes on single Confirm & Resume (29 cases)', async () => {
    const previewRequests: Record<string, unknown>[] = [];
    const startRequests: Record<string, unknown>[] = [];
    const childRecord: GenericRunRecord = {
      ...makeInterruptedRecord(),
      generic_run_id: CHILD_RUN_ID,
      status: 'running',
      continuation_of_run_id: PARENT_RUN_ID,
      root_run_id: PARENT_RUN_ID,
      selected_cases: 29,
      ready_count: 29,
      executed_cases: 0,
      total_cases: 29,
      progress_percent: 0,
      cases: [],
      verdict_counts: {},
    };

    mockBaseFetch({
      runById: { [PARENT_RUN_ID]: makeInterruptedRecord(), [CHILD_RUN_ID]: childRecord },
      onPreview: body => {
        previewRequests.push(body);
        const inc = Array.isArray(body.include_uncertain_case_ids)
          ? (body.include_uncertain_case_ids as string[])
          : [];
        const pending = Array.from({ length: 28 }, (_, i) => `TC00${18 + i}`);
        const selected = inc.length > 0 ? [...inc, ...pending] : pending;
        return makeResumePreview({
          included_uncertain_case_ids: inc,
          selected_resume_case_ids: selected,
          target_request_budget: selected.length,
          judge_request_budget: selected.length,
          resume_digest: inc.length > 0 ? DIGEST_WITH_UNCERTAIN : DIGEST_PENDING_ONLY,
        });
      },
      onStart: body => {
        startRequests.push(body);
        return childRecord;
      },
    });

    render(<SecurityScanWizard initialRunId={PARENT_RUN_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Resume Scan' }));

    // Preview automatically includes uncertain TC0017 (29 cases starting at TC0017) WITHOUT issuing any start request!
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Confirm & Resume (29 cases)' })).toBeTruthy();
    });
    expect(startRequests.length).toBe(0);
    expect(previewRequests.at(-1)?.include_uncertain_case_ids).toEqual(['TC0017']);

    // Essential summary & disclosure shown clearly above confirmation button
    expect(screen.getByText(/Interrupted in-flight · potentially repeated/i)).toBeTruthy();
    const disclosure = screen.getByRole('note', { name: 'Resume confirmation disclosure' });
    expect(disclosure.textContent).toMatch(/Interrupted in-flight requests may already have executed/i);
    expect(disclosure.textContent).toMatch(/TC0017.*retried/i);
    expect(disclosure.textContent).toMatch(/does not automatically restore target state/i);
    expect(disclosure.textContent).toMatch(/Verify relevant target state before confirming/i);

    // Advanced Resume Options is collapsed by default
    const detailsEl = document.querySelector('details') as HTMLDetailsElement;
    expect(detailsEl).toBeTruthy();
    expect(detailsEl.open).toBe(false);

    // Single consolidated confirmation button submits all explicit backend acknowledgements!
    fireEvent.click(screen.getByRole('button', { name: 'Confirm & Resume (29 cases)' }));
    await waitFor(() => {
      expect(startRequests.length).toBe(1);
    });
    expect(startRequests[0]).toMatchObject({
      authorization_confirmed: true,
      expected_resume_digest: DIGEST_WITH_UNCERTAIN,
      include_uncertain_case_ids: ['TC0017'],
      uncertain_reexecution_confirmed: true,
      stateful_target_acknowledged: true,
      async_execution: true,
    });
    await waitFor(() => {
      expect(screen.getByText(/Live Scan Progress:/i)).toBeTruthy();
      // Keeps original logical Scan ID visible throughout Resume!
      expect(screen.getAllByText(PARENT_RUN_ID).length).toBeGreaterThanOrEqual(1);
    });
  });

  it('allows excluding uncertain TC0017 via collapsed Advanced Resume Options and submits Confirm & Resume (28 cases)', async () => {
    const startRequests: Record<string, unknown>[] = [];
    const childRecord: GenericRunRecord = {
      ...makeInterruptedRecord(),
      generic_run_id: CHILD_RUN_ID,
      status: 'running',
      continuation_of_run_id: PARENT_RUN_ID,
      root_run_id: PARENT_RUN_ID,
      selected_cases: 28,
      ready_count: 28,
      executed_cases: 0,
      total_cases: 28,
      progress_percent: 0,
      cases: [],
      verdict_counts: {},
    };

    mockBaseFetch({
      runById: { [PARENT_RUN_ID]: makeInterruptedRecord(), [CHILD_RUN_ID]: childRecord },
      onPreview: body => {
        const inc = Array.isArray(body.include_uncertain_case_ids)
          ? (body.include_uncertain_case_ids as string[])
          : [];
        const pending = Array.from({ length: 28 }, (_, i) => `TC00${18 + i}`);
        const selected = inc.length > 0 ? [...inc, ...pending] : pending;
        return makeResumePreview({
          included_uncertain_case_ids: inc,
          selected_resume_case_ids: selected,
          target_request_budget: selected.length,
          judge_request_budget: selected.length,
          resume_digest: inc.length > 0 ? DIGEST_WITH_UNCERTAIN : DIGEST_PENDING_ONLY,
        });
      },
      onStart: body => {
        startRequests.push(body);
        return childRecord;
      },
    });

    render(<SecurityScanWizard initialRunId={PARENT_RUN_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Resume Scan' }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Confirm & Resume (29 cases)' })).toBeTruthy();
    });

    // Open collapsed Advanced Resume Options and uncheck TC0017
    const uncertainCheckbox = screen.getByLabelText(/Include uncertain testcase TC0017/i) as HTMLInputElement;
    expect(uncertainCheckbox.checked).toBe(true);
    fireEvent.click(uncertainCheckbox);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Confirm & Resume (28 cases)' })).toBeTruthy();
    });
    expect(screen.getByText(/Next queued testcase/i)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Confirm & Resume (28 cases)' }));
    await waitFor(() => {
      expect(startRequests.length).toBe(1);
    });
    expect(startRequests[0]).toMatchObject({
      authorization_confirmed: true,
      expected_resume_digest: DIGEST_PENDING_ONLY,
      include_uncertain_case_ids: [],
      uncertain_reexecution_confirmed: false,
      stateful_target_acknowledged: true,
    });
  });

  it('keeps Confirm & Resume disabled when Session Auth is missing and shows Target Authentication guidance', async () => {
    mockBaseFetch({
      runById: { [PARENT_RUN_ID]: makeInterruptedRecord() },
      onPreview: body => {
        const inc = Array.isArray(body.include_uncertain_case_ids)
          ? (body.include_uncertain_case_ids as string[])
          : [];
        const pending = Array.from({ length: 28 }, (_, i) => `TC00${18 + i}`);
        const selected = inc.length > 0 ? [...inc, ...pending] : pending;
        return makeResumePreview({
          included_uncertain_case_ids: inc,
          selected_resume_case_ids: selected,
          eligible: false,
          target_ready: false,
          credential_availability: 'unavailable',
          session_credential_generation: null,
          blocker: 'credential_unavailable',
          blockers: ['credential_unavailable'],
        });
      },
    });

    render(<SecurityScanWizard initialRunId={PARENT_RUN_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Resume Scan' }));

    await waitFor(() => {
      expect(screen.getByText(/credential_unavailable/i)).toBeTruthy();
    });
    const targetsLink = screen.getByRole('link', { name: /Open Target Authentication/i });
    expect(targetsLink.getAttribute('href')).toBe('#targets');
    expect(screen.getByRole('button', { name: 'Re-check Readiness' })).toBeTruthy();
    const confirmBtn = screen.getByRole('button', { name: /Confirm & Resume/i }) as HTMLButtonElement;
    expect(confirmBtn.disabled).toBe(true);
  });

  it('displays parent <-> continuation navigation links and deduplicated cumulative progress on continuation runs', async () => {
    const childCompleted = makeInterruptedRecord({
      generic_run_id: CHILD_RUN_ID,
      status: 'completed',
      interrupted_reason: null,
      continuation_of_run_id: PARENT_RUN_ID,
      root_run_id: PARENT_RUN_ID,
      selected_cases: 29,
      ready_count: 29,
      executed_cases: 29,
      total_cases: 29,
      progress_percent: 100,
      resume_metadata: {
        parent_run_id: PARENT_RUN_ID,
        root_run_id: PARENT_RUN_ID,
        original_selected_cases: 35,
        preserved_completed_case_ids: ['TC0011', 'TC0012', 'TC0013', 'TC0014', 'TC0015', 'TC0016'],
        resumed_pending_case_ids: [],
        uncertain_case_ids: ['TC0017'],
        included_uncertain_case_ids: ['TC0017'],
        excluded_uncertain_case_ids: [],
        skipped_case_ids: [],
        selected_resume_case_ids: [],
        resume_digest: DIGEST_WITH_UNCERTAIN,
      },
      lineage_summary: {
        root_run_id: PARENT_RUN_ID,
        parent_run_id: PARENT_RUN_ID,
        child_run_ids: [],
        lineage_run_ids: [PARENT_RUN_ID, CHILD_RUN_ID],
        active_lineage_run_id: null,
        original_selected_cases: 35,
        lineage_completed_count: 35,
        lineage_verdict_counts: { FAIL: 2, INCONCLUSIVE: 5, PASS: 28 },
        remaining_pending_count: 0,
        remaining_uncertain_count: 0,
        has_resumable_work: false,
      },
    });
    const parentWithChild = makeInterruptedRecord({
      child_run_ids: [CHILD_RUN_ID],
    });

    mockBaseFetch({ runById: { [CHILD_RUN_ID]: childCompleted, [PARENT_RUN_ID]: parentWithChild } });
    render(<SecurityScanWizard initialRunId={CHILD_RUN_ID} />);

    await waitFor(() => {
      expect(screen.getByText(/Unified Logical Scan/i)).toBeTruthy();
      expect(screen.getByText(/deduplicated across sessions, no double-counting/i)).toBeTruthy();
    });
    fireEvent.click(screen.getByRole('button', { name: 'Open Parent Run' }));
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Open Continuation Run' })).toBeTruthy();
    });
  });

  it('groups original and continuation sessions into one logical scan row in SavedRuns without merging unrelated scans', async () => {
    const UNRELATED_ID = 'c'.repeat(32);
    const parentSummary: GenericRunSummary = {
      generic_run_id: PARENT_RUN_ID,
      status: 'interrupted',
      started_at: '2026-11-25T10:00:00Z',
      completed_at: null,
      mode: 'live',
      target_id: httpTarget.id,
      target_name: httpTarget.name,
      dataset_id: DATASET_ID,
      dataset_name: 'testcases_agent_asi02.json',
      asi_category: 'ASI02',
      asi_categories: ['ASI02'],
      testcase_ids: ['TC0011', 'TC0012', 'TC0013', 'TC0014', 'TC0015', 'TC0016'],
      use_judge: true,
      selected_cases: 35,
      ready_count: 35,
      executed_cases: 6,
      total_cases: 35,
      skipped_count: 0,
      progress_percent: 17,
      verdict_counts: { FAIL: 1, INCONCLUSIVE: 5 },
      child_run_ids: [CHILD_RUN_ID],
      lineage_summary: {
        root_run_id: PARENT_RUN_ID,
        parent_run_id: null,
        child_run_ids: [CHILD_RUN_ID],
        lineage_run_ids: [PARENT_RUN_ID, CHILD_RUN_ID],
        latest_run_id: CHILD_RUN_ID,
        active_lineage_run_id: null,
        resumable_run_id: null,
        logical_status: 'completed_with_errors',
        session_count: 2,
        resume_count: 1,
        started_at: '2026-11-25T10:00:00Z',
        completed_at: '2026-11-25T10:30:00Z',
        original_selected_cases: 35,
        ready_count: 35,
        skipped_count: 0,
        lineage_completed_count: 35,
        lineage_verdict_counts: { FAIL: 1, INCONCLUSIVE: 5, ERROR: 29 },
        remaining_pending_count: 0,
        remaining_uncertain_count: 0,
        has_resumable_work: false,
      },
    };
    const childSummary: GenericRunSummary = {
      ...parentSummary,
      generic_run_id: CHILD_RUN_ID,
      continuation_of_run_id: PARENT_RUN_ID,
      root_run_id: PARENT_RUN_ID,
      status: 'completed',
      started_at: '2026-11-25T10:20:00Z',
      completed_at: '2026-11-25T10:30:00Z',
      selected_cases: 29,
      ready_count: 29,
      executed_cases: 29,
      total_cases: 29,
      progress_percent: 100,
      verdict_counts: { ERROR: 29 },
      testcase_ids: Array.from({ length: 29 }, (_, i) => `TC00${17 + i}`),
      child_run_ids: [],
    };
    const unrelatedSummary: GenericRunSummary = {
      generic_run_id: UNRELATED_ID,
      status: 'completed',
      started_at: '2026-11-25T08:00:00Z',
      completed_at: '2026-11-25T08:05:00Z',
      mode: 'live',
      target_id: httpTarget.id,
      target_name: httpTarget.name,
      dataset_id: DATASET_ID,
      dataset_name: 'testcases_agent_asi02.json',
      asi_category: 'ASI02',
      asi_categories: ['ASI02'],
      testcase_ids: ['TC0011'],
      use_judge: true,
      selected_cases: 1,
      ready_count: 1,
      executed_cases: 1,
      total_cases: 1,
      skipped_count: 0,
      progress_percent: 100,
      verdict_counts: { PASS: 1 },
    };

    // Pure grouping verification: 3 persisted session rows -> 2 logical scans (unrelated scan never merged!)
    const grouped = groupLogicalScans([parentSummary, childSummary, unrelatedSummary]);
    expect(grouped.length).toBe(2);
    expect(grouped[0].logicalScanId).toBe(PARENT_RUN_ID);
    expect(grouped[0].selected_cases).toBe(35);
    expect(grouped[0].executed_cases).toBe(35);
    expect(grouped[0].verdict_counts).toEqual({ FAIL: 1, INCONCLUSIVE: 5, ERROR: 29 });
    expect(grouped[0].logical_status).toBe('completed_with_errors');
    expect(grouped[0].resume_count).toBe(1);
    expect(grouped[0].session_count).toBe(2);
    expect(grouped[1].logicalScanId).toBe(UNRELATED_ID);
    expect(grouped[1].logical_status).toBe('completed');

    // Render SavedRuns and verify 1 row per logical scan + collapsed Execution History
    const unifiedDetail = makeInterruptedRecord({
      unified_lineage: {
        logical_scan_id: PARENT_RUN_ID,
        root_run_id: PARENT_RUN_ID,
        latest_run_id: CHILD_RUN_ID,
        active_session_run_id: null,
        resumable_run_id: null,
        logical_status: 'completed_with_errors',
        execution_completed: true,
        has_evaluation_errors: true,
        started_at: '2026-11-25T10:00:00Z',
        completed_at: '2026-11-25T10:30:00Z',
        session_count: 2,
        resume_count: 1,
        selected_cases: 35,
        ready_count: 35,
        executed_cases: 35,
        skipped_count: 0,
        skipped_cases: [],
        progress_percent: 100,
        verdict_counts: { FAIL: 1, INCONCLUSIVE: 5, ERROR: 29 },
        evidence_summary: { response_only: 6 },
        target_requests_used: 35,
        judge_requests_used: 6,
        sessions: [
          {
            session_index: 1,
            generic_run_id: PARENT_RUN_ID,
            status: 'interrupted',
            started_at: '2026-11-25T10:00:00Z',
            completed_at: null,
            selected_cases: 35,
            ready_count: 35,
            executed_cases: 6,
            verdict_counts: { FAIL: 1, INCONCLUSIVE: 5 },
          },
          {
            session_index: 2,
            generic_run_id: CHILD_RUN_ID,
            continuation_of_run_id: PARENT_RUN_ID,
            status: 'completed',
            started_at: '2026-11-25T10:20:00Z',
            completed_at: '2026-11-25T10:30:00Z',
            selected_cases: 29,
            ready_count: 29,
            executed_cases: 29,
            verdict_counts: { ERROR: 29 },
          },
        ],
        case_statuses: [],
        cases: makeInterruptedRecord().cases,
      },
    });

    vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
      const url = String(input);
      if (url.endsWith('/api/testing/generic-runs')) {
        return new Response(
          JSON.stringify({ workflow_schema_version: '1.0.0', runs: [parentSummary, childSummary, unrelatedSummary] }),
          { status: 200 },
        );
      }
      if (url.endsWith(`/api/testing/generic-runs/${PARENT_RUN_ID}`)) {
        return new Response(JSON.stringify(unifiedDetail), { status: 200 });
      }
      if (url.startsWith('/api/reports/')) {
        return new Response(
          JSON.stringify({ total: 0, page: 1, page_size: 25, invalid_artifact_count: 0, items: [] }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', error: { code: 'not_found' } }), {
        status: 404,
      });
    });

    render(<SavedRuns />);
    await waitFor(() => {
      expect(screen.getByText('Grouped Scan Runs (2)')).toBeTruthy();
    });
    expect(screen.getByText('Completed with errors')).toBeTruthy();
    expect(screen.getByText(/1 resume · 2 sessions/i)).toBeTruthy();
    expect(screen.getByText('Export Unified Report JSON')).toBeTruthy();

    fireEvent.click(screen.getAllByRole('button', { name: 'View Cases' })[0]);
    await waitFor(() => {
      expect(screen.getByText(/Execution History \(2 sessions\)/i)).toBeTruthy();
    });
    const detailsEl = document.querySelector('details') as HTMLDetailsElement;
    expect(detailsEl.open).toBe(false);
  });

  it('displays cumulative 6/35 progress during live Resume and unified Completed with errors results view', async () => {
    const runningUnified: GenericRunRecord = {
      ...makeInterruptedRecord(),
      generic_run_id: CHILD_RUN_ID,
      continuation_of_run_id: PARENT_RUN_ID,
      root_run_id: PARENT_RUN_ID,
      status: 'running',
      selected_cases: 29,
      ready_count: 29,
      executed_cases: 0,
      total_cases: 29,
      progress_percent: 0,
      cases: [],
      verdict_counts: {},
      unified_lineage: {
        logical_scan_id: PARENT_RUN_ID,
        root_run_id: PARENT_RUN_ID,
        latest_run_id: CHILD_RUN_ID,
        active_session_run_id: CHILD_RUN_ID,
        resumable_run_id: null,
        logical_status: 'running',
        execution_completed: false,
        has_evaluation_errors: false,
        started_at: '2026-11-25T10:00:00Z',
        completed_at: null,
        session_count: 2,
        resume_count: 1,
        selected_cases: 35,
        ready_count: 35,
        executed_cases: 6,
        skipped_count: 0,
        skipped_cases: [],
        progress_percent: 17,
        verdict_counts: { FAIL: 1, INCONCLUSIVE: 5 },
        evidence_summary: { response_only: 6 },
        target_requests_used: 6,
        judge_requests_used: 6,
        sessions: [
          {
            session_index: 1,
            generic_run_id: PARENT_RUN_ID,
            status: 'interrupted',
            started_at: '2026-11-25T10:00:00Z',
            completed_at: null,
            selected_cases: 35,
            ready_count: 35,
            executed_cases: 6,
            verdict_counts: { FAIL: 1, INCONCLUSIVE: 5 },
          },
          {
            session_index: 2,
            generic_run_id: CHILD_RUN_ID,
            continuation_of_run_id: PARENT_RUN_ID,
            status: 'running',
            started_at: '2026-11-25T10:20:00Z',
            completed_at: null,
            selected_cases: 29,
            ready_count: 29,
            executed_cases: 0,
            verdict_counts: {},
          },
        ],
        case_statuses: Array.from({ length: 35 }, (_, i) => ({
          case_id: `TC00${11 + i}`,
          category: 'tool_misuse',
          asi_code: 'ASI02',
          status: i < 6 ? 'completed' : i === 6 ? 'running' : 'queued',
          stage: i < 6 ? 'completed' : i === 6 ? 'sending_request_to_target' : 'queued',
          verdict: i === 0 ? 'FAIL' : i < 6 ? 'INCONCLUSIVE' : null,
          reason: null,
          evidence_level: i < 6 ? 'response_only' : null,
          run_id: i < 6 ? `${i + 1}`.repeat(32) : null,
        })),
        cases: makeInterruptedRecord().cases,
      },
    };

    mockBaseFetch({ runById: { [CHILD_RUN_ID]: runningUnified } });
    const { unmount } = render(<SecurityScanWizard initialRunId={CHILD_RUN_ID} />);
    await waitFor(() => {
      // Cumulative progress starts at 6/35, NOT 0/29!
      expect(screen.getByText('6 / 35 ready cases')).toBeTruthy();
      expect(screen.getByText('Testcase Status List (35)')).toBeTruthy();
      expect(screen.getAllByText(PARENT_RUN_ID).length).toBeGreaterThanOrEqual(1);
    });
    unmount();

    // Now verify Completed with errors unified results view (opening CHILD_RUN_ID resolves unified 35/35!)
    vi.restoreAllMocks();
    const completedWithErrors: GenericRunRecord = {
      ...runningUnified,
      status: 'completed',
      lineage_summary: {
        ...makeInterruptedRecord().lineage_summary!,
        logical_status: 'completed_with_errors',
        lineage_completed_count: 35,
        lineage_verdict_counts: { FAIL: 1, INCONCLUSIVE: 5, ERROR: 29 },
        has_resumable_work: false,
      },
      unified_lineage: {
        ...runningUnified.unified_lineage!,
        active_session_run_id: null,
        logical_status: 'completed_with_errors',
        execution_completed: true,
        has_evaluation_errors: true,
        executed_cases: 35,
        progress_percent: 100,
        verdict_counts: { FAIL: 1, INCONCLUSIVE: 5, ERROR: 29 },
        completed_at: '2026-11-25T10:30:00Z',
      },
    };
    mockBaseFetch({ runById: { [CHILD_RUN_ID]: completedWithErrors } });
    render(<SecurityScanWizard initialRunId={CHILD_RUN_ID} />);
    await waitFor(() => {
      expect(screen.getByText('Completed with errors')).toBeTruthy();
      expect(screen.getByText('Export Unified Report JSON')).toBeTruthy();
      expect(screen.getByText(/Execution History \(2 sessions\)/i)).toBeTruthy();
      expect(screen.getByText(/Selected Cases: 35 · Recorded Outcomes: 35/i)).toBeTruthy();
    });
    // No Resume Scan button on completed_with_errors (no automatic retry of ERRORs)
    expect(screen.queryByRole('button', { name: 'Resume Scan' })).toBeNull();
  });

  it('R04: renders unified Judge 6/6 stats from continuation ID, active session CurrentTestcase from root ID, and separates cumulative vs session budgets', async () => {
    // 1. Continuation session has 29 ERRORs & 0 Judge calls locally, while unified lineage has 6/6 Judge calls from original session!
    const childWithZeroLocalJudge: GenericRunRecord = {
      ...makeInterruptedRecord(),
      generic_run_id: CHILD_RUN_ID,
      continuation_of_run_id: PARENT_RUN_ID,
      root_run_id: PARENT_RUN_ID,
      status: 'completed',
      judge_metadata: {
        mode: 'hybrid',
        judge_configured: true,
        credential_available: true,
        judge_ready: true,
        provider: 'deepseek',
        model: 'deepseek-v4-flash',
        invocation_status: 'not_invoked',
        request_count: 0,
        success_count: 0,
        failure_count: 0,
        error_categories: [],
      },
      lineage_summary: {
        ...makeInterruptedRecord().lineage_summary!,
        logical_status: 'completed_with_errors',
        lineage_completed_count: 35,
        lineage_verdict_counts: { FAIL: 1, INCONCLUSIVE: 5, ERROR: 29 },
        has_resumable_work: false,
      },
      unified_lineage: {
        logical_scan_id: PARENT_RUN_ID,
        root_run_id: PARENT_RUN_ID,
        latest_run_id: CHILD_RUN_ID,
        active_session_run_id: null,
        resumable_run_id: null,
        logical_status: 'completed_with_errors',
        integrity_status: 'valid',
        execution_completed: true,
        has_evaluation_errors: true,
        started_at: '2026-11-25T10:00:00Z',
        completed_at: '2026-11-25T10:30:00Z',
        session_count: 2,
        resume_count: 1,
        selected_cases: 35,
        ready_count: 35,
        executed_cases: 35,
        skipped_count: 0,
        skipped_cases: [],
        progress_percent: 100,
        verdict_counts: { FAIL: 1, INCONCLUSIVE: 5, ERROR: 29 },
        evidence_summary: { response_only: 6 },
        judge_metadata: {
          mode: 'hybrid',
          judge_configured: true,
          credential_available: true,
          judge_ready: true,
          provider: 'deepseek',
          model: 'deepseek-v4-flash',
          invocation_status: 'succeeded',
          request_count: 6,
          success_count: 6,
          failure_count: 0,
          error_categories: [],
        },
        target_requests_used: 35,
        judge_requests_used: 6,
        sessions: [
          {
            session_index: 1,
            generic_run_id: PARENT_RUN_ID,
            status: 'interrupted',
            started_at: '2026-11-25T10:00:00Z',
            completed_at: null,
            selected_cases: 35,
            ready_count: 35,
            executed_cases: 6,
            verdict_counts: { FAIL: 1, INCONCLUSIVE: 5 },
          },
          {
            session_index: 2,
            generic_run_id: CHILD_RUN_ID,
            continuation_of_run_id: PARENT_RUN_ID,
            status: 'completed',
            started_at: '2026-11-25T10:20:00Z',
            completed_at: '2026-11-25T10:30:00Z',
            selected_cases: 29,
            ready_count: 29,
            executed_cases: 29,
            verdict_counts: { ERROR: 29 },
          },
        ],
        case_statuses: [],
        cases: makeInterruptedRecord().cases,
      },
    };

    mockBaseFetch({ runById: { [CHILD_RUN_ID]: childWithZeroLocalJudge } });
    const { unmount } = render(<SecurityScanWizard initialRunId={CHILD_RUN_ID} />);
    await waitFor(() => {
      // Must display unified 6 / 6 Judge calls (NOT session-local 0 / 0)!
      expect(screen.getByText('6 / 6')).toBeTruthy();
      expect(screen.getByText('deepseek')).toBeTruthy();
      expect(screen.getByText('deepseek-v4-flash')).toBeTruthy();
    });
    unmount();

    // 2. Opening PARENT_RUN_ID while continuation CHILD_RUN_ID is actively running shows active continuation's
    // CurrentTestcase (TC0017) and distinguishes Cumulative Requests vs Current Session Budget!
    vi.restoreAllMocks();
    const rootWhileChildRunning: GenericRunRecord = {
      ...makeInterruptedRecord(),
      generic_run_id: PARENT_RUN_ID,
      status: 'interrupted',
      current_case_id: null,
      current_stage: 'interrupted',
      lineage_summary: {
        ...makeInterruptedRecord().lineage_summary!,
        active_lineage_run_id: CHILD_RUN_ID,
        logical_status: 'running',
        has_resumable_work: false,
      },
      unified_lineage: {
        ...childWithZeroLocalJudge.unified_lineage!,
        active_session_run_id: CHILD_RUN_ID,
        logical_status: 'running',
        execution_completed: false,
        executed_cases: 6,
        progress_percent: 17,
        current_case_id: 'TC0017',
        current_stage: 'sending_request_to_target',
        target_requests_used: 6,
        judge_requests_used: 6,
        active_session_target_requests_used: 0,
        active_session_target_request_budget: 29,
        active_session_judge_requests_used: 0,
        active_session_judge_request_budget: 29,
        active_session_events: [{ at: '2026-11-25T10:20:01Z', stage: 'sending_request_to_target', case_id: 'TC0017' }],
        case_statuses: Array.from({ length: 35 }, (_, i) => ({
          case_id: `TC00${11 + i}`,
          category: 'tool_misuse',
          asi_code: 'ASI02',
          status: i < 6 ? 'completed' : i === 6 ? 'running' : 'queued',
          stage: i < 6 ? 'completed' : i === 6 ? 'sending_request_to_target' : 'queued',
          verdict: i === 0 ? 'FAIL' : i < 6 ? 'INCONCLUSIVE' : null,
          reason: null,
          evidence_level: i < 6 ? 'response_only' : null,
          run_id: i < 6 ? `${i + 1}`.repeat(32) : null,
        })),
      },
    };
    mockBaseFetch({ runById: { [PARENT_RUN_ID]: rootWhileChildRunning } });
    render(<SecurityScanWizard initialRunId={PARENT_RUN_ID} />);
    await waitFor(() => {
      expect(screen.getByText(/Current case:/i)).toBeTruthy();
      expect(screen.getAllByText('TC0017').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText('Cumulative Target Requests')).toBeTruthy();
      expect(screen.getByText('Current Session Target Budget')).toBeTruthy();
      expect(screen.getAllByText('0 / 29').length).toBeGreaterThanOrEqual(1);
    });
  });

  it('R05: surfaces integrity warning and disables Unified Report export on invalid checkpoint lineage while preserving session exports', async () => {
    const invalidLineageRecord: GenericRunRecord = {
      ...makeInterruptedRecord(),
      unified_lineage: {
        logical_scan_id: PARENT_RUN_ID,
        root_run_id: PARENT_RUN_ID,
        latest_run_id: CHILD_RUN_ID,
        active_session_run_id: null,
        resumable_run_id: null,
        logical_status: 'interrupted',
        integrity_status: 'invalid_checkpoint',
        integrity_warning: 'Lineage checkpoint integrity failed (resume_state_incomplete): out-of-scope testcase(s) detected (TC0099).',
        out_of_scope_case_ids: ['TC0099'],
        execution_completed: false,
        has_evaluation_errors: true,
        started_at: '2026-11-25T10:00:00Z',
        completed_at: null,
        session_count: 2,
        resume_count: 1,
        selected_cases: 35,
        ready_count: 35,
        executed_cases: 34,
        skipped_count: 0,
        skipped_cases: [],
        progress_percent: 97,
        verdict_counts: { FAIL: 1, INCONCLUSIVE: 5, ERROR: 28 },
        evidence_summary: {},
        target_requests_used: 34,
        judge_requests_used: 6,
        sessions: [
          {
            session_index: 1,
            generic_run_id: PARENT_RUN_ID,
            status: 'interrupted',
            started_at: '2026-11-25T10:00:00Z',
            completed_at: null,
            selected_cases: 35,
            ready_count: 35,
            executed_cases: 6,
            verdict_counts: { FAIL: 1, INCONCLUSIVE: 5 },
          },
          {
            session_index: 2,
            generic_run_id: CHILD_RUN_ID,
            continuation_of_run_id: PARENT_RUN_ID,
            status: 'completed',
            started_at: '2026-11-25T10:20:00Z',
            completed_at: '2026-11-25T10:30:00Z',
            selected_cases: 29,
            ready_count: 29,
            executed_cases: 29,
            verdict_counts: { ERROR: 29 },
          },
        ],
        case_statuses: [],
        cases: makeInterruptedRecord().cases,
      },
    };

    mockBaseFetch({ runById: { [PARENT_RUN_ID]: invalidLineageRecord } });
    render(<SecurityScanWizard initialRunId={PARENT_RUN_ID} />);
    await waitFor(() => {
      expect(screen.getByText(/Lineage Checkpoint Integrity Warning:/i)).toBeTruthy();
      expect(screen.getByText(/out-of-scope testcase\(s\) detected \(TC0099\)/i)).toBeTruthy();
    });
    expect(screen.queryByText('Export Unified Report JSON')).toBeNull();
    expect(screen.getByText('Export Session Report JSON')).toBeTruthy();
    expect(screen.getAllByText('Export Session JSON').length).toBe(2);
  });

  it('R06: invalidates stale Resume Preview after a failed refresh when uncertain selection changes and disables Confirm & Resume until fresh preview succeeds', async () => {
    const startRequests: Record<string, unknown>[] = [];
    let shouldFailRefresh = false;

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/api/testing/health')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            status: 'ok',
            mode: 'controlled_execution_enabled',
            target_network_access: true,
            validation_nonce: 'N'.repeat(43),
            operator_mode: 'local_single_user',
            target_management_enabled: true,
            evaluation_modes: ['rule_only', 'hybrid'],
            judge_configuration: 'configured_unverified',
            generic_runner_enabled: true,
            pi_judge_ready: true,
          }),
          { status: 200 },
        );
      }
      if (url.endsWith('/api/testing/targets')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', targets: [httpTarget], protocols: [] }), {
          status: 200,
        });
      }
      if (url.endsWith('/api/testing/datasets')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', datasets: [] }), { status: 200 });
      }
      if (url.endsWith('/api/testing/generic-runs')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', runs: [] }), { status: 200 });
      }
      if (url.endsWith(`/api/testing/generic-runs/${PARENT_RUN_ID}`)) {
        return new Response(JSON.stringify(makeInterruptedRecord()), { status: 200 });
      }
      if (url.endsWith(`/api/testing/generic-runs/${PARENT_RUN_ID}/resume/preview`)) {
        if (shouldFailRefresh) {
          return new Response(
            JSON.stringify({
              workflow_schema_version: '1.0.0',
              error: { code: 'preview_failed', message: 'Backend temporarily unreachable during preview refresh.' },
            }),
            { status: 503 },
          );
        }
        const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
        const inc = Array.isArray(body.include_uncertain_case_ids) ? (body.include_uncertain_case_ids as string[]) : [];
        const pending = Array.from({ length: 28 }, (_, i) => `TC00${18 + i}`);
        const selected = inc.length > 0 ? [...inc, ...pending] : pending;
        return new Response(
          JSON.stringify(
            makeResumePreview({
              included_uncertain_case_ids: inc,
              selected_resume_case_ids: selected,
              target_request_budget: selected.length,
              judge_request_budget: selected.length,
              resume_digest: inc.length > 0 ? DIGEST_WITH_UNCERTAIN : DIGEST_PENDING_ONLY,
            }),
          ),
          { status: 200 },
        );
      }
      if (url.endsWith(`/api/testing/generic-runs/${PARENT_RUN_ID}/resume/start`)) {
        const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
        startRequests.push(body);
        return new Response(JSON.stringify(makeInterruptedRecord({ generic_run_id: CHILD_RUN_ID })), { status: 202 });
      }
      return new Response('{}', { status: 404 });
    });

    render(<SecurityScanWizard initialRunId={PARENT_RUN_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Resume Scan' }));
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Confirm & Resume (29 cases)' })).toBeTruthy();
    });

    // Inject preview refresh failure, then uncheck uncertain TC0017!
    shouldFailRefresh = true;
    const uncertainCheckbox = screen.getByLabelText(/Include uncertain testcase TC0017/i);
    fireEvent.click(uncertainCheckbox);

    await waitFor(() => {
      expect(screen.getByText(/Backend temporarily unreachable during preview refresh/i)).toBeTruthy();
      expect(screen.getByText(/previous preview was invalidated/i)).toBeTruthy();
    });
    // Confirm & Resume MUST be disabled and cannot submit stale 29-case preview!
    const disabledBtn = screen.getByRole('button', { name: /Confirm & Resume/i }) as HTMLButtonElement;
    expect(disabledBtn.disabled).toBe(true);
    fireEvent.click(disabledBtn);
    expect(startRequests.length).toBe(0);

    // Recover backend and click Re-check Readiness -> loads fresh 28-case preview and re-enables Confirm & Resume!
    shouldFailRefresh = false;
    fireEvent.click(screen.getByRole('button', { name: 'Re-check Readiness' }));
    await waitFor(() => {
      const freshBtn = screen.getByRole('button', { name: 'Confirm & Resume (28 cases)' }) as HTMLButtonElement;
      expect(freshBtn.disabled).toBe(false);
    });
  });
});
