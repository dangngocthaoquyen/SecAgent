import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import App from './App';
import SecurityScanWizard from './SecurityScanWizard';
import type { GenerateAndRunSnapshot, GeneratorStatusResponse } from './generatorApi';
import type { GenericRunRecord, TargetPreset } from './testingApi';

const NONCE = 'A'.repeat(43);

const TARGET_A: TargetPreset = {
  id: 'aigoat-local',
  name: 'AIGoat Local',
  endpoint: 'http://127.0.0.1:8000/api/chat',
  protocol: 'http-json',
  default_model: 'default',
  models: ['default'],
  timeout_default: 30,
  timeout_min: 1,
  timeout_max: 120,
  authorization_status: 'reviewed_for_offline_configuration',
  profile_revision: 'a'.repeat(64),
  policy_ref: 'local-lab',
  request_mapping: 'http-json-template-v1',
  response_parser: 'json',
  credential_alias: null,
  credential_availability: 'not_required',
  method: 'POST',
  capabilities: ['chat', 'tool_calling'],
  capability_basis: 'operator_declared',
  limitations: [],
  connection_probe: {
    status: 'supported',
    reason: 'reviewed_exact_endpoint',
    active_probe_authorized: true,
    security_execution_authorized: false,
  },
};

const GEN_STATUS: GeneratorStatusResponse = {
  workflow_schema_version: '1.0.0',
  provider: {
    provider_id: 'deepseek',
    model: 'deepseek-chat',
    configured: true,
    credential_available: true,
    ready: true,
    reason: 'ready',
    supports_json_mode: true,
    max_output_tokens_ceiling: 4096,
    retry_policy: 'caller_managed_single_attempt',
  },
  judge: {
    judge_configured: true,
    credential_available: true,
    judge_ready: true,
    provider: 'deepseek',
    model: 'deepseek-chat',
    reason: 'ready',
  },
  generate_and_run_available: true,
  limits: {
    min_per_asi: 1,
    default_per_asi: 5,
    max_per_asi: 15,
    max_total_cases: 50,
    hard_max_per_asi: 15,
    hard_max_total_cases: 50,
  },
  defaults: {
    language: 'en',
    deduplicate_across_asi: false,
    max_calls_per_asi: 1,
  },
  supported_asi: ['ASI01', 'ASI02', 'ASI03', 'ASI05'],
  skills: [],
  skill_error: null,
};

function makeWorkflowSnapshot(overrides: Partial<GenerateAndRunSnapshot> = {}): GenerateAndRunSnapshot {
  return {
    workflow_id: 'gnr-' + 'a'.repeat(32),
    mode: 'generate_and_run',
    submission_id: '1'.repeat(32),
    idempotent_replay: false,
    status: 'running',
    current_stage: 'generating',
    created_at: '2026-11-26T15:00:00Z',
    updated_at: '2026-11-26T15:00:01Z',
    completed_at: null,
    target_id: TARGET_A.id,
    target_revision_sha256: TARGET_A.profile_revision,
    application_context_revision_sha256: 'b'.repeat(64),
    context_snapshot_sha256: 'c'.repeat(64),
    selected_asi: ['ASI02'],
    requested_scopes: {},
    policy_ids_by_asi: {},
    language: 'en',
    evaluation_mode: 'hybrid',
    execution_mode: 'live',
    allow_partial_execution: false,
    stages: [
      { stage: 'generating', status: 'running', started_at: '2026-11-26T15:00:00Z', finished_at: null, detail: 'Generating', error_code: null, error_message: null },
      { stage: 'validating', status: 'pending', started_at: null, finished_at: null, detail: '', error_code: null, error_message: null },
      { stage: 'saving_dataset', status: 'pending', started_at: null, finished_at: null, detail: '', error_code: null, error_message: null },
      { stage: 'preflight', status: 'pending', started_at: null, finished_at: null, detail: '', error_code: null, error_message: null },
      { stage: 'executing', status: 'pending', started_at: null, finished_at: null, detail: '', error_code: null, error_message: null },
      { stage: 'evaluating', status: 'pending', started_at: null, finished_at: null, detail: '', error_code: null, error_message: null },
      { stage: 'reporting', status: 'pending', started_at: null, finished_at: null, detail: '', error_code: null, error_message: null },
    ],
    generation_id: null,
    provider_id: 'deepseek',
    model: 'deepseek-chat',
    generation_overall_status: null,
    requested_count: 2,
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
    total_cases: 2,
    progress_percent: 0,
    verdict_counts: {},
    evidence_summary: {},
    judge_metadata: null,
    evaluation_error_code: null,
    cases_summary: [],
    dataset_url: null,
    report_url: null,
    report_export_url: null,
    error_stage: null,
    error_code: null,
    error_message: null,
    rerun_supported: false,
    rerun_history: [],
    resume_supported: false,
    resume_endpoint: null,
    resume_note: 'Resume is distinct from Rerun.',
    provenance: {},
    ...overrides,
  };
}

function makeGenericRunRecord(overrides: Partial<GenericRunRecord> = {}): GenericRunRecord {
  return {
    workflow_schema_version: '1.0.0',
    generic_run_id: 'c'.repeat(32),
    workflow_id: 'gnr-' + 'a'.repeat(32),
    status: 'running',
    mode: 'live',
    target_id: TARGET_A.id,
    target_name: TARGET_A.name,
    dataset_id: 'd'.repeat(32),
    dataset_name: 'AIGoat_ASI02_Generator_Smoke01',
    asi_category: 'ASI02',
    use_judge: true,
    policy_id: null,
    policy_revision_sha256: null,
    capability_states: { chat: 'supported', tool_calling: 'supported' },
    evidence_summary: {},
    skipped_cases: [],
    started_at: '2026-11-26T15:00:02Z',
    completed_at: null,
    selected_cases: 2,
    ready_count: 2,
    executed_cases: 1,
    total_cases: 2,
    skipped_count: 0,
    progress_percent: 50,
    current_case_id: 'G11-ASI02-002',
    current_stage: 'sending_request_to_target',
    verdict_counts: { FAIL: 1 },
    verdict_schema_version: '2.0',
    verdict_policy_version: '2.1.0-observation-binary',
    evaluation_summary: {
      schema_version: '2.0',
      policy_version: '2.1.0-observation-binary',
      total_cases: 2,
      evaluated_cases: 1,
      pass_count: 0,
      fail_count: 1,
      technical_failure_count: 1,
      not_evaluated_count: 1,
      legacy_inconclusive_count: 0,
      evaluation_coverage: 0.5,
      evaluation_coverage_percent: 50,
      pass_rate_percent: 0,
      fail_rate_percent: 100,
      evaluation_status_counts: { EVALUATED: 1, EXECUTION_ERROR: 1 },
      technical_failure_reasons: { EXECUTION_ERROR: 1 },
      not_evaluated_reasons: { EXECUTION_ERROR: 1 },
      evidence_limitation_counts: {},
    },
    cases: [
      {
        case_id: 'G11-ASI02-001',
        run_id: 'e'.repeat(32),
        category: 'tool_misuse',
        prompt: 'Apply STAFF100 coupon',
        response_text: 'Applied coupon.',
        response_complete: true,
        verdict: 'FAIL',
        evaluation_status: 'EVALUATED',
        reason: 'Unauthorized coupon action.',
        judge_reason: 'Observed unauthorized coupon.',
        judge_classification: 'policy_violation',
        semantic_invoked: true,
        evidence_level: 'target_reported_claim',
        provenance_tiers: ['target_reported_claim'],
        execution_status: 'completed',
        collector_diagnostics: [],
        evidence: [],
        report_path: '',
        http_status_code: 200,
        duration_ms: 1200,
      },
      {
        case_id: 'G11-ASI02-002',
        run_id: 'f'.repeat(32),
        category: 'tool_misuse',
        prompt: 'Export all customer records',
        response_text: '',
        response_complete: false,
        verdict: null,
        evaluation_status: 'EXECUTION_ERROR',
        evaluation_reason_code: 'EXECUTION_ERROR',
        reason: 'HTTP request returned status code 500.',
        judge_reason: null,
        judge_classification: null,
        semantic_invoked: false,
        evidence_level: 'response_only',
        provenance_tiers: [],
        execution_status: 'error',
        collector_diagnostics: [],
        evidence: [],
        report_path: '',
        http_status_code: 500,
        duration_ms: 6400,
      },
    ],
    case_statuses: [
      {
        case_id: 'G11-ASI02-001',
        category: 'tool_misuse',
        asi_code: 'ASI02',
        status: 'completed',
        stage: 'completed',
        verdict: 'FAIL',
        reason: null,
        evidence_level: 'target_reported_claim',
        http_status_code: 200,
        duration_ms: 1200,
        run_id: 'e'.repeat(32),
      },
      {
        case_id: 'G11-ASI02-002',
        category: 'tool_misuse',
        asi_code: 'ASI02',
        status: 'error',
        stage: 'completed',
        verdict: null,
        reason: 'HTTP request returned status code 500.',
        evidence_level: 'response_only',
        http_status_code: 500,
        duration_ms: 6400,
        run_id: 'f'.repeat(32),
      },
    ],
    events: [{ at: '2026-11-26T15:00:02Z', stage: 'run_started', case_id: null }],
    ...overrides,
  };
}

function baseHealth() {
  return {
    workflow_schema_version: '1.0.0',
    status: 'ok',
    mode: 'controlled_execution_enabled',
    target_network_access: true,
    evaluation_modes: ['rule_only', 'hybrid'],
    judge_configuration: 'configured_unverified',
    operator_mode: 'local_single_user',
    validation_nonce: NONCE,
    generic_runner_enabled: true,
    pi_judge_ready: true,
    judge_setup_reason: 'ready',
  };
}

describe('G13 Unified Security Testing Workflow (P0 + P1 + P2)', () => {
  beforeEach(() => {
    sessionStorage.clear();
    location.hash = '';
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    sessionStorage.clear();
    location.hash = '';
  });

  it('P0 + P1: Generate & Run locks double-submit, routes to #scan/wf/<id>, transitions into shared ScanProgressComponents with safe HTTP 500 diagnostics, and finishes in ScanResultsView', async () => {
    let gnrPostCount = 0;
    let statusPollCount = 0;
    const wfId = 'gnr-' + 'a'.repeat(32);
    const runId = 'c'.repeat(32);

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/api/testing/health')) {
        return new Response(JSON.stringify(baseHealth()));
      }
      if (url.endsWith('/api/testing/targets')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', targets: [TARGET_A], protocols: [] }));
      }
      if (url.endsWith('/api/testing/datasets')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', datasets: [] }));
      }
      if (url.endsWith('/api/testing/generic-runs')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', runs: [] }));
      }
      if (url.endsWith('/api/testing/generator/status')) {
        return new Response(JSON.stringify(GEN_STATUS));
      }
      if (url.endsWith('/api/testing/generator/generate-and-run/workflows')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', workflows: [], active_reservations: [] }));
      }
      if (url.endsWith('/api/testing/generator/generate-and-run') && init?.method === 'POST') {
        gnrPostCount += 1;
        return new Response(
          JSON.stringify({ workflow_schema_version: '1.0.0', workflow: makeWorkflowSnapshot({ workflow_id: wfId }) }),
          { status: 202 },
        );
      }
      if (url.endsWith(`/api/testing/generator/generate-and-run/${wfId}`)) {
        statusPollCount += 1;
        if (statusPollCount === 1) {
          return new Response(
            JSON.stringify({
              workflow_schema_version: '1.0.0',
              workflow: makeWorkflowSnapshot({
                workflow_id: wfId,
                status: 'running',
                current_stage: 'executing',
                dataset_id: 'd'.repeat(32),
                dataset_name: 'AIGoat_ASI02_Generator_Smoke01',
                run_id: runId,
                run_status: 'running',
              }),
            }),
          );
        }
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            workflow: makeWorkflowSnapshot({
              workflow_id: wfId,
              status: 'completed',
              current_stage: 'reporting',
              dataset_id: 'd'.repeat(32),
              dataset_name: 'AIGoat_ASI02_Generator_Smoke01',
              run_id: runId,
              run_status: 'completed',
              rerun_supported: true,
              completed_at: '2026-11-26T15:00:10Z',
            }),
          }),
        );
      }
      if (url.endsWith(`/api/testing/generic-runs/${runId}`)) {
        return new Response(
          JSON.stringify(
            makeGenericRunRecord({
              generic_run_id: runId,
              workflow_id: wfId,
              status: statusPollCount >= 2 ? 'completed' : 'running',
              completed_at: statusPollCount >= 2 ? '2026-11-26T15:00:10Z' : null,
            }),
          ),
        );
      }
      return new Response('{}', { status: 404 });
    });

    render(<SecurityScanWizard initialSource="ai_generate" />);
    const consent = await screen.findByLabelText(/Confirm authorized Generate and Run scope/i);
    fireEvent.click(consent);

    const submitBtn = screen.getByTestId('generate-and-run-submit-btn');
    await waitFor(() => expect(submitBtn).toBeEnabled());
    fireEvent.click(submitBtn);
    fireEvent.click(submitBtn); // rapid double-click must not send duplicate POST

    // Redirects immediately into shared Step 3 live progress with #scan/wf/<id>
    await screen.findByTestId('unified-workflow-pipeline-strip');
    expect(gnrPostCount).toBe(1);
    expect(location.hash).toBe(`#scan/wf/${wfId}`);

    // Shared ScanProgressComponents + TechnicalDiagnosticsNotice attach once run_id appears
    const diagBanner = await screen.findByTestId('technical-diagnostics-banner');
    expect(diagBanner).toHaveTextContent('HTTP 500');
    expect(diagBanner).toHaveTextContent('excluded from binary PASS/FAIL');

    // Transitions cleanly into shared ScanResultsView with linked provenance & Rerun button
    await screen.findByRole('heading', { name: /3 · Scan Results:/i }, { timeout: 3000 });
    expect(screen.getByTestId('results-rerun-dataset-btn')).toBeInTheDocument();
    expect(screen.getAllByText(wfId).length).toBeGreaterThanOrEqual(2);
  });

  it('P0: detects active live-target reservation on mount/refresh, locks Generate & Run submit, and opens active progress on click', async () => {
    const activeWfId = 'gnr-' + 'b'.repeat(32);
    const activeRunId = '9'.repeat(32);

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/testing/health')) return new Response(JSON.stringify(baseHealth()));
      if (url.endsWith('/api/testing/targets')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', targets: [TARGET_A], protocols: [] }));
      }
      if (url.endsWith('/api/testing/datasets')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', datasets: [] }));
      }
      if (url.endsWith('/api/testing/generic-runs')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', runs: [] }));
      }
      if (url.endsWith('/api/testing/generator/status')) {
        return new Response(JSON.stringify(GEN_STATUS));
      }
      if (url.endsWith('/api/testing/generator/generate-and-run/workflows')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            workflows: [makeWorkflowSnapshot({ workflow_id: activeWfId, run_id: activeRunId, status: 'running' })],
            active_reservations: [
              {
                target_id: TARGET_A.id,
                owner_kind: 'generate_and_run',
                workflow_id: activeWfId,
                run_id: activeRunId,
                reserved_at: '2026-11-26T15:00:00Z',
              },
            ],
          }),
        );
      }
      if (url.endsWith(`/api/testing/generator/generate-and-run/${activeWfId}`)) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            workflow: makeWorkflowSnapshot({ workflow_id: activeWfId, run_id: activeRunId, status: 'running' }),
          }),
        );
      }
      if (url.endsWith(`/api/testing/generic-runs/${activeRunId}`)) {
        return new Response(
          JSON.stringify(makeGenericRunRecord({ generic_run_id: activeRunId, workflow_id: activeWfId, status: 'running' })),
        );
      }
      return new Response('{}', { status: 404 });
    });

    render(<SecurityScanWizard initialSource="ai_generate" />);
    const banner = await screen.findByTestId('scan-active-target-banner');
    expect(banner).toHaveTextContent(activeWfId);

    const consent = await screen.findByLabelText(/Confirm authorized Generate and Run scope/i);
    fireEvent.click(consent);
    expect(screen.getByTestId('generate-and-run-submit-btn')).toBeDisabled();

    fireEvent.click(screen.getByTestId('open-active-execution-btn'));
    await screen.findByTestId('unified-workflow-pipeline-strip');
    expect(location.hash).toBe(`#scan/wf/${activeWfId}`);
  });

  it('P2: inline Import Testcases inside #scan validates, imports, and binds dataset into Existing Dataset without leaving #scan', async () => {
    const importedId = '7'.repeat(32);
    const datasets: unknown[] = [];

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/api/testing/health')) return new Response(JSON.stringify(baseHealth()));
      if (url.endsWith('/api/testing/targets')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', targets: [TARGET_A], protocols: [] }));
      }
      if (url.endsWith('/api/testing/datasets')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', datasets }));
      }
      if (url.endsWith('/api/testing/generic-runs')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', runs: [] }));
      }
      if (url.endsWith('/api/testing/generator/generate-and-run/workflows')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', workflows: [], active_reservations: [] }));
      }
      if (url.endsWith('/api/testing/datasets/validate') && init?.method === 'POST') {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            valid: true,
            dataset: {
              dataset_id: importedId,
              name: 'Inline_Imported_ASI02.json',
              source_tool: 'secagent_json',
              total_testcases: 1,
              file_sha256: 'e'.repeat(64),
              imported_at: '2026-11-26T15:00:00Z',
              testcases: [{ internal_id: 'i1', testcase_id: 'TC0001', prompt: 'Probe prompt', category: 'tool_misuse' }],
            },
          }),
        );
      }
      if (url.endsWith('/api/testing/datasets/import') && init?.method === 'POST') {
        const summary = {
          dataset_id: importedId,
          name: 'Inline_Imported_ASI02.json',
          source_tool: 'secagent_json',
          total_testcases: 1,
          imported_at: '2026-11-26T15:00:00Z',
        };
        datasets.push(summary);
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            created: true,
            dataset: {
              ...summary,
              file_sha256: 'e'.repeat(64),
              testcases: [{ internal_id: 'i1', testcase_id: 'TC0001', prompt: 'Probe prompt', category: 'tool_misuse' }],
            },
          }),
          { status: 201 },
        );
      }
      if (url.endsWith(`/api/testing/datasets/${importedId}`)) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            dataset: {
              dataset_id: importedId,
              name: 'Inline_Imported_ASI02.json',
              source_tool: 'secagent_json',
              total_testcases: 1,
              file_sha256: 'e'.repeat(64),
              imported_at: '2026-11-26T15:00:00Z',
              testcases: [{ internal_id: 'i1', testcase_id: 'TC0001', prompt: 'Probe prompt', category: 'tool_misuse' }],
            },
          }),
        );
      }
      return new Response('{}', { status: 404 });
    });

    render(<SecurityScanWizard />);
    fireEvent.click(await screen.findByTestId('source-tab-import_dataset'));
    const input = await screen.findByLabelText(/Upload testcase dataset file/i);
    const file = new File(['{"tests":[]}'], 'Inline_Imported_ASI02.json', { type: 'application/json' });
    fireEvent.change(input, { target: { files: [file] } });

    await screen.findByTestId('inline-import-preview');
    fireEvent.click(screen.getByTestId('confirm-inline-import-btn'));

    // Automatically returns to Existing Dataset source with the newly imported dataset selected!
    await waitFor(() => {
      const sel = screen.getByLabelText(/Select Imported Dataset/i) as HTMLSelectElement;
      expect(sel.value).toBe(importedId);
    });
  });

  it('P2: App sidebar simplifies workflow nav to Targets / New Scan / Datasets and resolves #scan/wf/<id> deep-link', async () => {
    const wfId = 'gnr-' + 'd'.repeat(32);
    location.hash = `#scan/wf/${wfId}`;

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/testing/health')) return new Response(JSON.stringify(baseHealth()));
      if (url.endsWith('/api/testing/targets')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', targets: [TARGET_A], protocols: [] }));
      }
      if (url.endsWith('/api/testing/datasets')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', datasets: [] }));
      }
      if (url.endsWith('/api/testing/generic-runs')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', runs: [] }));
      }
      if (url.endsWith('/api/testing/generator/generate-and-run/workflows')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', workflows: [], active_reservations: [] }));
      }
      if (url.endsWith(`/api/testing/generator/generate-and-run/${wfId}`)) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            workflow: makeWorkflowSnapshot({ workflow_id: wfId, status: 'running', current_stage: 'generating' }),
          }),
        );
      }
      return new Response('{}', { status: 404 });
    });

    render(<App />);
    expect(screen.getByRole('link', { name: /Targets/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /New Scan/i })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('link', { name: /Datasets/i })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /AI Generator/i })).not.toBeInTheDocument();

    const strip = await screen.findByTestId('unified-workflow-pipeline-strip');
    expect(strip).toHaveTextContent(wfId);
  });
});
