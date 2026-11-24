import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import SavedRuns from './SavedRuns';
import { ScanProgressBar, BudgetUsage } from './ScanProgressComponents';
import ScanResultsView from './ScanResultsView';
import SecurityScanWizard from './SecurityScanWizard';
import { health, overview, page } from './test/fixtures';
import type { GenericRunCaseResult, GenericRunRecord, TargetPreset } from './testingApi';

const savedTarget: TargetPreset = {
  id: 'codebot-chat',
  name: 'DVAA CodeBot',
  profile_revision: '1'.repeat(64),
  policy_ref: 'local-v1',
  platform_id: 'dvaa',
  platform_name: 'DVAA',
  authorization_status: 'reviewed_for_offline_configuration',
  endpoint: 'http://127.0.0.1:7004/v1/chat/completions',
  protocol: 'openai-chat',
  method: 'POST',
  models: ['codebot'],
  default_model: 'codebot',
  timeout_min: 1,
  timeout_max: 60,
  timeout_default: 30,
  credential_alias: null,
  credential_availability: 'none',
  request_mapping: 'openai-chat-user-message-v1',
  response_parser: 'choices.0.message.content',
  connection_probe: {
    status: 'supported',
    reason: 'reviewed_exact_endpoint',
    active_probe_authorized: true,
    security_execution_authorized: false,
  },
  connection_verification: {
    status: 'compatible',
    basis: 'benign_chat_probe',
    profile_revision: '1'.repeat(64),
    security_execution_authorized: false,
  },
  capabilities: ['chat'],
  capability_basis: 'operator_reviewed',
  limitations: [],
};

function makeCase(overrides: Partial<GenericRunCaseResult> & { case_id: string }): GenericRunCaseResult {
  return {
    case_id: overrides.case_id,
    run_id: overrides.run_id ?? `run-${overrides.case_id}`.replace(/[^a-f0-9]/gi, 'a').padEnd(32, '0').slice(0, 32),
    category: overrides.category ?? 'tool_misuse',
    prompt: overrides.prompt ?? `Prompt for ${overrides.case_id}`,
    response_text: overrides.response_text === undefined ? `Response for ${overrides.case_id}` : overrides.response_text,
    response_complete: overrides.response_complete === undefined ? true : overrides.response_complete,
    verdict: overrides.verdict ?? 'PASS',
    reason: overrides.reason ?? 'Evaluated against policy.',
    judge_reason: overrides.judge_reason === undefined ? 'Policy boundary held.' : overrides.judge_reason,
    judge_classification:
      overrides.judge_classification === undefined ? 'TOOL_BOUNDARY_PRESERVED' : overrides.judge_classification,
    semantic_invoked: overrides.semantic_invoked,
    provider_fault_code: overrides.provider_fault_code ?? null,
    json_validation_status: overrides.json_validation_status ?? 'valid',
    provider_duration_ms: overrides.provider_duration_ms ?? 120,
    evidence_level: overrides.evidence_level ?? 'response_only',
    provenance_tiers: overrides.provenance_tiers ?? ['target_reported'],
    execution_status: overrides.execution_status ?? 'succeeded',
    collector_diagnostics: overrides.collector_diagnostics ?? [],
    evidence: overrides.evidence ?? [],
    report_path: overrides.report_path ?? `results/${overrides.case_id}.secagent.json`,
  };
}

function makeRunRecord(cases: GenericRunCaseResult[], overrides?: Partial<GenericRunRecord>): GenericRunRecord {
  const vc: Record<string, number> = { PASS: 0, FAIL: 0, INCONCLUSIVE: 0, ERROR: 0 };
  const es: Record<string, number> = {};
  for (const c of cases) {
    vc[c.verdict] = (vc[c.verdict] ?? 0) + 1;
    if (c.evidence_level) {
      es[c.evidence_level] = (es[c.evidence_level] ?? 0) + 1;
    }
  }
  return {
    workflow_schema_version: '1.0.0',
    generic_run_id: '4cb9995ab434410eb427e88c7ac202b7',
    status: 'completed',
    mode: 'live',
    target_id: 'local-agent-7004',
    target_name: 'DVAA CodeBot',
    dataset_id: '8'.repeat(32),
    dataset_name: 'codebot_asi02_30.json',
    asi_category: 'auto',
    use_judge: true,
    policy_id: null,
    policy_revision_sha256: null,
    capability_states: { chat: 'supported' },
    selected_cases: cases.length,
    ready_count: cases.length,
    executed_cases: cases.length,
    total_cases: cases.length,
    skipped_count: 0,
    skipped_cases: [],
    progress_percent: 100,
    verdict_counts: vc,
    evidence_summary: es,
    judge_metadata: {
      mode: 'hybrid',
      judge_configured: true,
      credential_available: true,
      judge_ready: true,
      provider: 'deepseek',
      model: 'deepseek-v4-flash',
      invocation_status: 'succeeded',
      request_count: cases.length,
      success_count: cases.length,
      failure_count: 0,
      error_categories: [],
    },
    cases,
    ...overrides,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
  localStorage.clear();
  location.hash = '';
});

describe('Post UI/UX Redesign Targeted Correctness Fixes (P0 / P1 / P2)', () => {
  it('P0-2: separates canonical evidence_level from explicit data.execution_verified, never infers verification from kind alone, and counts verified cases vs verified items separately', async () => {
    const cases: GenericRunCaseResult[] = [
      // 1. Collected evidence with execution_verified=true and verified provenance
      makeCase({
        case_id: 'TC-EV-1',
        evidence_level: 'independently_verified_execution',
        provenance_tiers: ['independently_verified'],
        evidence: [
          {
            kind: 'collected_evidence',
            source: 'sandbox_log_collector',
            name: 'sbx-audit-1',
            data: {
              collector_id: 'sbx-audit-1',
              collector_kind: 'sandbox_command_log',
              provenance: 'independently_verified',
              execution_verified: true,
              verification_status: 'verified',
              correlation_status: 'matched',
              correlation_strength: 'strong',
            },
          },
        ],
      }),
      // 2. Collected evidence with execution_verified=false
      makeCase({
        case_id: 'TC-EV-2',
        evidence_level: 'target_reported_claim',
        provenance_tiers: ['target_reported'],
        evidence: [
          {
            kind: 'collected_evidence',
            source: 'sandbox_log_collector',
            name: 'sbx-unverified-2',
            data: {
              collector_id: 'sbx-unverified-2',
              collector_kind: 'sandbox_command_log',
              provenance: 'target_reported',
              execution_verified: false,
              verification_status: 'target_reported_unverified',
            },
          },
        ],
      }),
      // 3. Independently sourced observation WITHOUT verified execution (execution_verified=false)
      makeCase({
        case_id: 'TC-EV-3',
        evidence_level: 'independently_verified_execution',
        provenance_tiers: ['independently_verified'],
        evidence: [
          {
            kind: 'collected_evidence',
            source: 'sandbox_log_collector',
            name: 'sbx-indep-unverified-3',
            data: {
              collector_id: 'sbx-indep-unverified-3',
              collector_kind: 'sandbox_command_log',
              provenance: 'independently_verified',
              execution_verified: false,
              verification_status: 'independently_verified_unverified',
            },
          },
        ],
      }),
      // 4. Model-reported tool intent
      makeCase({
        case_id: 'TC-EV-4',
        evidence_level: 'model_reported_intent',
        provenance_tiers: ['model_reported'],
        evidence: [
          {
            kind: 'model_reported_tool_intent',
            source: 'response_output_dsml',
            name: 'dsml-intent',
            data: {
              provenance: 'model_reported',
              execution_verified: false,
              format: 'dsml_xml',
              invoked_tool_names: ['run_command'],
            },
          },
        ],
      }),
      // 5. Adapter-observed request
      makeCase({
        case_id: 'TC-EV-5',
        evidence_level: 'adapter_observed_request',
        provenance_tiers: ['adapter_observed'],
        evidence: [
          {
            kind: 'tool_request',
            source: 'mcp_jsonrpc_adapter',
            name: 'read_file',
            data: {
              provenance: 'secagent_request',
              execution_verified: false,
              verification_status: 'request_recorded',
            },
          },
        ],
      }),
      // 6. Missing verification metadata (no execution_verified boolean)
      makeCase({
        case_id: 'TC-EV-6',
        evidence_level: 'independently_verified_execution',
        provenance_tiers: ['independently_verified'],
        evidence: [
          {
            kind: 'collector_receipt',
            source: 'local_collector',
            name: 'receipt-no-bool',
            data: {
              provenance: 'independent_local_collector',
              status: 'collected',
            },
          },
        ],
      }),
      // 7. Multiple evidence items within one testcase (1 unverified metadata + 2 verified collected items)
      makeCase({
        case_id: 'TC-EV-7',
        evidence_level: 'independently_verified_execution',
        provenance_tiers: ['target_reported', 'independently_verified'],
        evidence: [
          {
            kind: 'http_response_metadata',
            source: 'http_response',
            name: null,
            data: {
              provenance: 'target_reported',
              execution_verified: false,
              finish_reason: 'stop',
            },
          },
          {
            kind: 'collected_evidence',
            source: 'file_artifact_collector',
            name: 'artifact-1',
            data: {
              provenance: 'independently_verified',
              execution_verified: true,
              verification_status: 'verified',
              correlation_status: 'matched',
              correlation_strength: 'strong',
            },
          },
          {
            kind: 'collected_evidence',
            source: 'mcp_receipt_collector',
            name: 'receipt-2',
            data: {
              provenance: 'independently_verified',
              execution_verified: true,
              verification_status: 'verified',
              correlation_status: 'matched',
              correlation_strength: 'strong',
            },
          },
        ],
      }),
    ];

    const record = makeRunRecord(cases);
    render(<ScanResultsView runRecord={record} localSingleUser={true} secret="" onNewScan={() => {}} />);

    // Only TC-EV-1 and TC-EV-7 have execution_verified=true (2 of 7 testcases, 3 of 9 evidence items)
    // TC-EV-3 and TC-EV-6 have independently_verified provenance/level but NOT verified execution!
    expect(screen.getByText('2 / 7 testcases with verified execution')).toBeInTheDocument();
    expect(screen.getByText(/3 \/ 9 evidence items execution-verified/)).toBeInTheDocument();

    // Open TC-EV-3 (independently sourced observation with execution_verified=false)
    const rows = screen.getAllByRole('row');
    const tc3Row = rows.find(r => r.textContent?.includes('TC-EV-3'))!;
    fireEvent.click(within(tc3Row).getByRole('button', { name: 'View details' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('tab', { name: 'Evidence' }));
    expect(within(dialog).getByText('0 of 1 items (Execution verified: No)')).toBeInTheDocument();
    expect(within(dialog).getByText('Execution not verified')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close testcase detail drawer' }));

    // Open TC-EV-6 (missing execution_verified metadata)
    const tc6Row = screen.getAllByRole('row').find(r => r.textContent?.includes('TC-EV-6'))!;
    fireEvent.click(within(tc6Row).getByRole('button', { name: 'View details' }));
    const dialog6 = await screen.findByRole('dialog');
    fireEvent.click(within(dialog6).getByRole('tab', { name: 'Evidence' }));
    expect(within(dialog6).getByText('Verification not recorded')).toBeInTheDocument();
    fireEvent.click(within(dialog6).getByRole('button', { name: 'Close testcase detail drawer' }));

    // Open TC-EV-7 (multiple evidence items: 2 of 3 verified)
    const tc7Row = screen.getAllByRole('row').find(r => r.textContent?.includes('TC-EV-7'))!;
    fireEvent.click(within(tc7Row).getByRole('button', { name: 'View details' }));
    const dialog7 = await screen.findByRole('dialog');
    fireEvent.click(within(dialog7).getByRole('tab', { name: 'Evidence' }));
    expect(within(dialog7).getByText('2 of 3 items (Execution verified: Yes)')).toBeInTheDocument();
  });

  it('P0-3: freezes Preview configuration and Select All / Select Ready Only while Start Scan is pending in flight', async () => {
    const dsId = '8'.repeat(32);
    const rId = 'a'.repeat(32);
    let previewCalls = 0;
    let startCalls = 0;
    let resolveStart!: (resp: Response) => void;

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/api/testing/health')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            status: 'ok',
            mode: 'controlled_execution_enabled',
            target_network_access: true,
            validation_nonce: 'A'.repeat(43),
            operator_mode: 'local_single_user',
            evaluation_modes: ['rule_only', 'hybrid'],
            judge_configuration: 'configured_unverified',
            generic_runner_enabled: true,
            pi_judge_ready: true,
            judge_setup_reason: 'ready',
          }),
          { status: 200 },
        );
      }
      if (url.endsWith('/api/testing/targets')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            targets: [savedTarget],
            protocols: [{ id: 'openai-chat', state: 'active' }],
          }),
          { status: 200 },
        );
      }
      if (url.endsWith('/api/testing/datasets')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            datasets: [
              {
                dataset_id: dsId,
                name: 'freeze_test.json',
                schema_version: '1.0',
                source_tool: 'promptfoo',
                imported_at: '2026-11-23T00:00:00Z',
                file_sha256: '1'.repeat(64),
                total_testcases: 2,
                has_stored_responses: true,
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.endsWith(`/api/testing/datasets/${dsId}`)) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            dataset: {
              dataset_id: dsId,
              name: 'freeze_test.json',
              schema_version: '1.0',
              source_tool: 'promptfoo',
              imported_at: '2026-11-23T00:00:00Z',
              file_sha256: '1'.repeat(64),
              total_testcases: 2,
              source_metadata: {},
              testcases: [
                {
                  testcase_id: 'TC-1',
                  internal_id: 'import-' + '1'.repeat(24),
                  description: null,
                  plugin_id: null,
                  strategy_id: null,
                  prompt: 'P1',
                  prompt_sha256: '2'.repeat(64),
                  assertions: [],
                  metadata: { asi_category: 'ASI02' },
                  options: {},
                  extra: { stored_response: 'R1' },
                  index: 0,
                },
                {
                  testcase_id: 'TC-2',
                  internal_id: 'import-' + '2'.repeat(24),
                  description: null,
                  plugin_id: null,
                  strategy_id: null,
                  prompt: 'P2',
                  prompt_sha256: '3'.repeat(64),
                  assertions: [],
                  metadata: { asi_category: 'ASI02' },
                  options: {},
                  extra: { stored_response: 'R2' },
                  index: 1,
                },
              ],
            },
          }),
          { status: 200 },
        );
      }
      if (url.endsWith('/api/testing/generic-runs')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', runs: [] }), { status: 200 });
      }
      if (url.endsWith('/api/testing/generic-runs/preview')) {
        previewCalls += 1;
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            mode: 'offline',
            target_id: 'codebot-chat',
            target_name: 'DVAA CodeBot',
            dataset_id: dsId,
            dataset_name: 'freeze_test.json',
            asi_category: 'auto',
            use_judge: true,
            pi_judge_ready: true,
            capability_states: { chat: 'supported' },
            evidence_source_count: 0,
            total_cases: 2,
            ready_count: 2,
            blocked_count: 0,
            unsupported_count: 0,
            has_stored_responses: true,
            target_request_budget: 0,
            judge_request_budget: 2,
            policy_id: null,
            policy_revision_sha256: null,
            policy_review_status: 'reviewed',
            blocker: null,
            items: [
              { case_id: 'TC-1', category: 'tool_misuse', asi_code: 'ASI02', status: 'ready', reason: null, prompt_preview: 'P1' },
              { case_id: 'TC-2', category: 'tool_misuse', asi_code: 'ASI02', status: 'ready', reason: null, prompt_preview: 'P2' },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.endsWith('/api/testing/generic-runs/start') && init?.method === 'POST') {
        startCalls += 1;
        return new Promise<Response>(resolve => {
          resolveStart = resolve;
        });
      }
      return new Response('{}', { status: 404 });
    });

    render(<SecurityScanWizard />);
    const continueBtn = await screen.findByRole('button', { name: /Continue to Scan Preview/ });
    await waitFor(() => expect(continueBtn).toBeEnabled());
    fireEvent.click(continueBtn);

    await screen.findByRole('heading', { name: '2 · Scan Preview' });
    expect(previewCalls).toBe(1);

    fireEvent.click(screen.getByLabelText(/I authorize SecAgent to run this/));
    fireEvent.click(screen.getByRole('button', { name: 'Start Scan' }));

    await waitFor(() => expect(startCalls).toBe(1));
    const pendingBefore = sessionStorage.getItem('secagent_pending_generic_submission');
    expect(pendingBefore).toBeTruthy();

    const selectAllBtn = screen.getByRole('button', { name: /Select All \(2\)/ });
    const selectReadyBtn = screen.getByRole('button', { name: /Select Ready Only \(2\)/ });
    expect(selectAllBtn).toBeDisabled();
    expect(selectReadyBtn).toBeDisabled();

    // Even if clicked or changed programmatically while busy, no preview request or submission_id replacement may occur
    fireEvent.click(selectAllBtn);
    fireEvent.click(selectReadyBtn);
    fireEvent.change(screen.getByLabelText('Execution Mode'), { target: { value: 'live' } });
    fireEvent.change(screen.getByLabelText('Evaluation Engine'), { target: { value: 'rule_only' } });

    expect(previewCalls).toBe(1);
    expect(startCalls).toBe(1);
    expect(sessionStorage.getItem('secagent_pending_generic_submission')).toBe(pendingBefore);

    resolveStart(
      new Response(
        JSON.stringify(
          makeRunRecord([makeCase({ case_id: 'TC-1' }), makeCase({ case_id: 'TC-2' })], {
            generic_run_id: rId,
          }),
        ),
        { status: 201 },
      ),
    );

    expect(await screen.findByRole('heading', { name: /3 · Scan Results:/ })).toBeInTheDocument();
  });

  it('P0-4: prevents cross-run detail races and collapse races in SavedRuns', async () => {
    const runA = 'a'.repeat(32);
    const runB = 'b'.repeat(32);
    let resolveRunA!: (resp: Response) => void;
    let resolveRunB!: (resp: Response) => void;

    vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
      const url = String(input);
      if (url.endsWith('/api/testing/generic-runs')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            runs: [
              {
                generic_run_id: runA,
                status: 'completed',
                started_at: '2026-11-23T08:00:00Z',
                mode: 'live',
                target_id: 't-a',
                target_name: 'Target A',
                asi_category: 'ASI01',
                use_judge: false,
                selected_cases: 1,
                ready_count: 1,
                executed_cases: 1,
                total_cases: 1,
                skipped_count: 0,
                progress_percent: 100,
                verdict_counts: { PASS: 1 },
              },
              {
                generic_run_id: runB,
                status: 'completed',
                started_at: '2026-11-23T09:00:00Z',
                mode: 'live',
                target_id: 't-b',
                target_name: 'Target B',
                asi_category: 'ASI02',
                use_judge: false,
                selected_cases: 1,
                ready_count: 1,
                executed_cases: 1,
                total_cases: 1,
                skipped_count: 0,
                progress_percent: 100,
                verdict_counts: { FAIL: 1 },
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.endsWith(`/api/testing/generic-runs/${runA}`)) {
        return new Promise<Response>(resolve => {
          resolveRunA = resolve;
        });
      }
      if (url.endsWith(`/api/testing/generic-runs/${runB}`)) {
        return new Promise<Response>(resolve => {
          resolveRunB = resolve;
        });
      }
      if (url.includes('/api/reports/saved-runs')) {
        return new Response(
          JSON.stringify({
            api_schema_version: '1.0.0',
            page: 1,
            page_size: 25,
            total: 0,
            invalid_artifact_count: 0,
            items: [],
          }),
          { status: 200 },
        );
      }
      return new Response('{}', { status: 404 });
    });

    render(<SavedRuns />);
    await screen.findByText('Target A');
    const viewButtons = screen.getAllByRole('button', { name: 'View Cases' });

    // 1. Open Run A (delayed)
    fireEvent.click(viewButtons[0]);
    // 2. Open Run B (faster)
    fireEvent.click(viewButtons[1]);

    // Resolve Run B first
    resolveRunB(
      new Response(
        JSON.stringify(
          makeRunRecord([makeCase({ case_id: 'TC-FROM-RUN-B', verdict: 'FAIL' })], {
            generic_run_id: runB,
          }),
        ),
        { status: 200 },
      ),
    );
    expect(await screen.findByText('TC-FROM-RUN-B')).toBeInTheDocument();

    // Now resolve Run A LAST — must NOT overwrite Run B's detail!
    resolveRunA(
      new Response(
        JSON.stringify(
          makeRunRecord([makeCase({ case_id: 'TC-FROM-RUN-A', verdict: 'PASS' })], {
            generic_run_id: runA,
          }),
        ),
        { status: 200 },
      ),
    );
    await new Promise(r => setTimeout(r, 30));

    expect(screen.getByText('TC-FROM-RUN-B')).toBeInTheDocument();
    expect(screen.queryByText('TC-FROM-RUN-A')).not.toBeInTheDocument();

    // 3. Collapse Run B while a new detail request is in flight -> late resolution must stay collapsed
    fireEvent.click(screen.getByRole('button', { name: 'Hide Cases' }));
    expect(screen.queryByText('TC-FROM-RUN-B')).not.toBeInTheDocument();

    // Re-open Run A (delayed) then immediately collapse before it resolves
    fireEvent.click(screen.getAllByRole('button', { name: 'View Cases' })[0]);
    fireEvent.click(screen.getByRole('button', { name: 'Hide Cases' }));
    resolveRunA(
      new Response(
        JSON.stringify(
          makeRunRecord([makeCase({ case_id: 'TC-LATE-COLLAPSED', verdict: 'PASS' })], {
            generic_run_id: runA,
          }),
        ),
        { status: 200 },
      ),
    );
    await new Promise(r => setTimeout(r, 30));
    expect(screen.queryByText('TC-LATE-COLLAPSED')).not.toBeInTheDocument();
  });

  it('P1-5 & P1-6: distinguishes Rule-only vs Hybrid Judge not invoked vs timeout vs UNCLEAR, handles null response_complete, and normalizes ASI categories', async () => {
    const cases: GenericRunCaseResult[] = [
      makeCase({
        case_id: 'TC-HYB-SKIPPED',
        category: 'goal_hijacking',
        semantic_invoked: false,
        judge_classification: null,
        judge_reason: null,
        response_complete: null,
      }),
      makeCase({
        case_id: 'TC-HYB-UNCLEAR',
        category: 'tool_misuse',
        semantic_invoked: true,
        judge_classification: 'UNCLEAR',
        verdict: 'INCONCLUSIVE',
        response_complete: false,
      }),
    ];
    const hybridRecord = makeRunRecord(cases, {
      use_judge: true,
      asi_category: 'auto',
    });

    const { unmount } = render(
      <ScanResultsView runRecord={hybridRecord} localSingleUser={true} secret="" onNewScan={() => {}} />,
    );

    // Hybrid mode with semantic_invoked=false must show "Judge not invoked", NOT "Rule-only"
    expect(screen.getByText('Judge not invoked')).toBeInTheDocument();
    expect(screen.queryByText('Rule-only')).not.toBeInTheDocument();

    // Multi-category auto run shows normalized ASI breakdown "Mixed (ASI01, ASI02)" and normalized ASI pills
    expect(screen.getByText('Mixed (ASI01, ASI02)')).toBeInTheDocument();
    const tbl = screen.getByRole('table');
    expect(within(tbl).getByText('ASI01')).toBeInTheDocument();
    expect(within(tbl).getByText('ASI02')).toBeInTheDocument();
    expect(within(tbl).getByText('Unclear classification')).toBeInTheDocument();

    // Open TC-HYB-SKIPPED drawer where response_complete is null -> must show "Completeness not recorded"
    fireEvent.click(screen.getAllByRole('button', { name: 'View details' })[0]);
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Completeness not recorded')).toBeInTheDocument();
    expect(within(dialog).getByText('ASI01 (goal_hijacking)')).toBeInTheDocument();
    unmount();

    // Rule-only mode with semantic_invoked=false must show "Judge not requested"
    const ruleOnlyRecord = makeRunRecord(
      [
        makeCase({
          case_id: 'TC-RULE-1',
          category: 'unexpected_code_execution',
          semantic_invoked: false,
          judge_classification: null,
        }),
      ],
      {
        use_judge: false,
        judge_metadata: {
          mode: 'rule_only',
          judge_configured: false,
          credential_available: false,
          judge_ready: false,
          provider: null,
          model: null,
          invocation_status: 'not_requested',
          request_count: 0,
          success_count: 0,
          failure_count: 0,
          error_categories: [],
        },
      },
    );
    render(<ScanResultsView runRecord={ruleOnlyRecord} localSingleUser={true} secret="" onNewScan={() => {}} />);
    expect(screen.getByText('Judge not requested')).toBeInTheDocument();
    expect(screen.getAllByText('ASI05').length).toBeGreaterThanOrEqual(1);
  });

  it('P1-7: keeps Generic Scan Runs accessible on #executions when Reporting snapshot loading fails and consolidates Scan Runs, Native Reports, and Selected Dataset into tabs', async () => {
    const runId = '1082079f46d343b0bec767d2caeaa76e';
    location.hash = '#executions';

    vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
      const url = String(input);
      if (url.endsWith('/api/testing/generic-runs')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            runs: [
              {
                generic_run_id: runId,
                status: 'completed',
                started_at: '2026-11-23T08:00:00Z',
                mode: 'live',
                target_id: 'local-agent-7004',
                target_name: 'DVAA CodeBot',
                asi_category: 'auto',
                asi_categories: ['ASI02'],
                use_judge: true,
                selected_cases: 30,
                ready_count: 30,
                executed_cases: 30,
                total_cases: 30,
                skipped_count: 0,
                progress_percent: 100,
                verdict_counts: { PASS: 20, FAIL: 7, INCONCLUSIVE: 3 },
              },
            ],
          }),
          { status: 200 },
        );
      }
      // Simulate Reporting API snapshot failure (503)
      if (url.includes('/api/reports/')) {
        return new Response('reporting-offline', { status: 503 });
      }
      return new Response('{}', { status: 404 });
    });

    const { unmount } = render(<App />);
    // Even though /api/reports/health and /api/reports/overview failed, Generic Scan Runs must remain accessible!
    expect(await screen.findByRole('heading', { name: /Grouped Scan Runs \(1\)/ })).toBeInTheDocument();
    expect(screen.getByText('1082079f46d3')).toBeInTheDocument();
    unmount();

    // Now test when Reporting API succeeds: 3 consolidated tabs (Scan Runs, Native Reports, Selected Dataset)
    vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
      const url = String(input);
      if (url.endsWith('/api/testing/generic-runs')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            runs: [
              {
                generic_run_id: runId,
                status: 'completed',
                started_at: '2026-11-23T08:00:00Z',
                mode: 'live',
                target_id: 'local-agent-7004',
                target_name: 'DVAA CodeBot',
                asi_category: 'auto',
                asi_categories: ['ASI02'],
                use_judge: true,
                selected_cases: 30,
                ready_count: 30,
                executed_cases: 30,
                total_cases: 30,
                skipped_count: 0,
                progress_percent: 100,
                verdict_counts: { PASS: 20, FAIL: 7, INCONCLUSIVE: 3 },
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.includes('/api/reports/health')) return new Response(JSON.stringify(health), { status: 200 });
      if (url.includes('/api/reports/overview')) return new Response(JSON.stringify(overview), { status: 200 });
      if (url.includes('/api/reports/saved-runs')) {
        return new Response(
          JSON.stringify({
            api_schema_version: '1.0.0',
            page: 1,
            page_size: 25,
            total: 1,
            invalid_artifact_count: 0,
            items: [
              {
                run_id: '9'.repeat(32),
                kind: 'controlled',
                testcase_id: 'LEGACY-GH-001',
                target_id: 'dvaa-researchbot',
                asi_category: 'ASI01',
                verdict: 'FAIL',
                started_at: '2026-11-20T01:00:00Z',
                report_sha256: 'e'.repeat(64),
                evidence_provenance: 'target_observation',
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.includes('/api/reports/executions')) return new Response(JSON.stringify(page), { status: 200 });
      return new Response('{}', { status: 404 });
    });

    location.hash = '#executions';
    render(<App />);
    expect(await screen.findByRole('tab', { name: /Scan Runs \(1\)/ })).toHaveAttribute('aria-selected', 'true');
    // Selected Dataset table is in its own tab, not stacked below Scan Runs
    expect(screen.queryByRole('button', { name: 'Apply filters' })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: /Selected Dataset/ }));
    expect(await screen.findByRole('button', { name: 'Apply filters' })).toBeInTheDocument();
    expect(await screen.findByText('GH-WEB-001')).toBeInTheDocument();
  });

  it('P2-8: displays live elapsed time for active runs, supports preparing status, filters SavedRuns by unknown ASI category, and preserves historical run counts for 1082079f46d343b0bec767d2caeaa76e and 4cb9995ab434410eb427e88c7ac202b7', async () => {
    const startedTenSecAgo = new Date(Date.now() - 12000).toISOString();
    const runningRec = makeRunRecord([], {
      status: 'preparing',
      started_at: startedTenSecAgo,
      completed_at: null,
      ready_count: 5,
      executed_cases: 2,
      total_cases: 5,
    });

    const { unmount } = render(
      <>
        <ScanProgressBar record={runningRec} />
        <BudgetUsage record={runningRec} />
      </>,
    );
    expect(screen.getByText('Elapsed')).toBeInTheDocument();
    expect(screen.queryByText('Not recorded')).not.toBeInTheDocument();
    unmount();

    // Filter SavedRuns by unknown ASI category and missing timestamp exclusion on date range
    const runKnown = '1082079f46d343b0bec767d2caeaa76e';
    const runUnknown = 'c'.repeat(32);
    vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
      const url = String(input);
      if (url.endsWith('/api/testing/generic-runs')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            runs: [
              {
                generic_run_id: runKnown,
                status: 'completed',
                started_at: '2026-11-23T08:00:00Z',
                mode: 'live',
                target_id: 'local-agent-7004',
                target_name: 'DVAA CodeBot',
                asi_category: 'auto',
                asi_categories: ['tool_misuse'],
                use_judge: true,
                selected_cases: 30,
                ready_count: 30,
                executed_cases: 30,
                total_cases: 30,
                skipped_count: 0,
                progress_percent: 100,
                verdict_counts: { PASS: 20, FAIL: 7, INCONCLUSIVE: 3 },
              },
              {
                generic_run_id: runUnknown,
                status: 'completed',
                started_at: null,
                mode: 'offline',
                target_id: 'custom-target',
                target_name: 'Custom Target',
                asi_category: 'unmapped',
                asi_categories: [],
                use_judge: false,
                selected_cases: 1,
                ready_count: 1,
                executed_cases: 1,
                total_cases: 1,
                skipped_count: 0,
                progress_percent: 100,
                verdict_counts: { INCONCLUSIVE: 1 },
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.includes('/api/reports/saved-runs')) {
        return new Response(
          JSON.stringify({
            api_schema_version: '1.0.0',
            page: 1,
            page_size: 25,
            total: 0,
            invalid_artifact_count: 0,
            items: [],
          }),
          { status: 200 },
        );
      }
      return new Response('{}', { status: 404 });
    });

    const { unmount: unmountHistory } = render(<SavedRuns />);
    expect(await screen.findByRole('heading', { name: /Grouped Scan Runs \(2\)/ })).toBeInTheDocument();
    expect(screen.getByText('20P')).toBeInTheDocument();
    expect(screen.getByText('7F')).toBeInTheDocument();
    expect(screen.getByText('3I')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('ASI'), { target: { value: 'unknown' } });
    fireEvent.click(screen.getByRole('button', { name: 'Filter' }));
    expect(await screen.findByRole('heading', { name: /Grouped Scan Runs \(1\)/ })).toBeInTheDocument();
    expect(screen.getByText('cccccccccccc')).toBeInTheDocument();
    expect(screen.queryByText('1082079f46d3')).not.toBeInTheDocument();
    unmountHistory();
  });

  it('P0-Final: blocks new Preview, config mutation, and second POST Start while pendingSubmission is unresolved after Start connection drop, preserves pendingSubmission when opening an unrelated historical Run, and unlocks after explicit Verify Submission Status recovery', async () => {
    const dsId = '8'.repeat(32);
    const recoveredRunId = '1082079f46d343b0bec767d2caeaa76e';
    const unrelatedRunId = '4cb9995ab434410eb427e88c7ac202b7';
    let previewCalls = 0;
    let startCalls = 0;
    let submissionLookupCalls = 0;
    let allowSubmissionRecovery = false;
    const submittedIds: string[] = [];

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/api/testing/health')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            status: 'ok',
            mode: 'controlled_execution_enabled',
            target_network_access: true,
            validation_nonce: 'A'.repeat(43),
            operator_mode: 'local_single_user',
            evaluation_modes: ['rule_only', 'hybrid'],
            judge_configuration: 'configured_unverified',
            generic_runner_enabled: true,
            pi_judge_ready: true,
            judge_setup_reason: 'ready',
          }),
          { status: 200 },
        );
      }
      if (url.endsWith('/api/testing/targets')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            targets: [savedTarget],
            protocols: [{ id: 'openai-chat', state: 'active' }],
          }),
          { status: 200 },
        );
      }
      if (url.endsWith('/api/testing/datasets')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            datasets: [
              {
                dataset_id: dsId,
                name: 'freeze_test.json',
                schema_version: '1.0',
                source_tool: 'promptfoo',
                imported_at: '2026-11-23T00:00:00Z',
                file_sha256: '1'.repeat(64),
                total_testcases: 2,
                has_stored_responses: true,
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.endsWith(`/api/testing/datasets/${dsId}`)) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            dataset: {
              dataset_id: dsId,
              name: 'freeze_test.json',
              schema_version: '1.0',
              source_tool: 'promptfoo',
              imported_at: '2026-11-23T00:00:00Z',
              file_sha256: '1'.repeat(64),
              total_testcases: 2,
              source_metadata: {},
              testcases: [
                {
                  testcase_id: 'TC-1',
                  internal_id: 'import-' + '1'.repeat(24),
                  description: null,
                  plugin_id: null,
                  strategy_id: null,
                  prompt: 'P1',
                  prompt_sha256: '2'.repeat(64),
                  assertions: [],
                  metadata: { asi_category: 'ASI02' },
                  options: {},
                  extra: { stored_response: 'R1' },
                  index: 0,
                },
                {
                  testcase_id: 'TC-2',
                  internal_id: 'import-' + '2'.repeat(24),
                  description: null,
                  plugin_id: null,
                  strategy_id: null,
                  prompt: 'P2',
                  prompt_sha256: '3'.repeat(64),
                  assertions: [],
                  metadata: { asi_category: 'ASI02' },
                  options: {},
                  extra: { stored_response: 'R2' },
                  index: 1,
                },
              ],
            },
          }),
          { status: 200 },
        );
      }
      if (url.endsWith('/api/testing/generic-runs')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            runs: [
              {
                generic_run_id: unrelatedRunId,
                status: 'completed',
                started_at: '2026-11-23T07:00:00Z',
                mode: 'offline',
                target_id: 'local-agent-7004',
                target_name: 'DVAA CodeBot',
                asi_category: 'auto',
                use_judge: false,
                selected_cases: 1,
                ready_count: 1,
                executed_cases: 1,
                total_cases: 1,
                skipped_count: 0,
                progress_percent: 100,
                verdict_counts: { PASS: 1 },
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.endsWith('/api/testing/generic-runs/preview')) {
        previewCalls += 1;
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            mode: 'offline',
            target_id: 'codebot-chat',
            target_name: 'DVAA CodeBot',
            dataset_id: dsId,
            dataset_name: 'freeze_test.json',
            asi_category: 'auto',
            use_judge: true,
            pi_judge_ready: true,
            capability_states: { chat: 'supported' },
            evidence_source_count: 0,
            total_cases: 2,
            ready_count: 2,
            blocked_count: 0,
            unsupported_count: 0,
            has_stored_responses: true,
            target_request_budget: 0,
            judge_request_budget: 2,
            policy_id: null,
            policy_revision_sha256: null,
            policy_review_status: 'reviewed',
            blocker: null,
            items: [
              { case_id: 'TC-1', category: 'tool_misuse', asi_code: 'ASI02', status: 'ready', reason: null, prompt_preview: 'P1' },
              { case_id: 'TC-2', category: 'tool_misuse', asi_code: 'ASI02', status: 'ready', reason: null, prompt_preview: 'P2' },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.endsWith('/api/testing/generic-runs/start') && init?.method === 'POST') {
        startCalls += 1;
        const body = JSON.parse(String(init?.body || '{}'));
        submittedIds.push(body.submission_id);
        throw new Error('Network connection dropped while starting scan');
      }
      if (url.includes('/api/testing/generic-runs/submission/')) {
        submissionLookupCalls += 1;
        const subId = url.split('/api/testing/generic-runs/submission/')[1];
        if (!allowSubmissionRecovery) {
          return new Response(JSON.stringify({ detail: 'Backend temporarily unreachable' }), { status: 503 });
        }
        return new Response(
          JSON.stringify(
            makeRunRecord([makeCase({ case_id: 'TC-1' }), makeCase({ case_id: 'TC-2' })], {
              generic_run_id: recoveredRunId,
              submission_id: subId,
              status: 'completed',
            }),
          ),
          { status: 200 },
        );
      }
      if (url.endsWith(`/api/testing/generic-runs/${unrelatedRunId}`)) {
        return new Response(
          JSON.stringify(
            makeRunRecord([makeCase({ case_id: 'TC-HIST-1' })], {
              generic_run_id: unrelatedRunId,
              submission_id: 'f'.repeat(32),
              status: 'completed',
            }),
          ),
          { status: 200 },
        );
      }
      return new Response('{}', { status: 404 });
    });

    const { rerender } = render(<SecurityScanWizard />);
    const continueBtn = await screen.findByRole('button', { name: /Continue to Scan Preview/ });
    await waitFor(() => expect(continueBtn).toBeEnabled());
    fireEvent.click(continueBtn);

    await screen.findByRole('heading', { name: '2 · Scan Preview' });
    expect(previewCalls).toBe(1);

    fireEvent.click(screen.getByLabelText(/I authorize SecAgent to run this/));
    fireEvent.click(screen.getByRole('button', { name: 'Start Scan' }));

    // Wait for startScan to fail after 3 automatic recovery checks and leave pendingSubmission unresolved with busy=false
    const pendingBanner = await screen.findByRole(
      'alert',
      { name: 'Pending Scan Submission Verification' },
      { timeout: 6000 },
    );
    expect(pendingBanner).toBeInTheDocument();
    expect(startCalls).toBe(1);
    expect(submissionLookupCalls).toBeGreaterThanOrEqual(3);

    const originalSubmissionId = submittedIds[0];
    expect(originalSubmissionId).toMatch(/^[0-9a-f]{32}$/);
    const storedBefore = JSON.parse(sessionStorage.getItem('secagent_pending_generic_submission') || 'null');
    expect(storedBefore?.submission_id).toBe(originalSubmissionId);

    // While pendingSubmission is unresolved, controls must be disabled and handlers must block any new Preview, config mutation, or second Start
    const selectAllBtn = screen.getByRole('button', { name: /Select All \(2\)/ });
    const selectReadyBtn = screen.getByRole('button', { name: /Select Ready Only \(2\)/ });
    const startBtn = screen.getByRole('button', { name: 'Start Scan' });
    const backBtn = screen.getByRole('button', { name: /Change Target or Dataset/ });
    expect(selectAllBtn).toBeDisabled();
    expect(selectReadyBtn).toBeDisabled();
    expect(startBtn).toBeDisabled();
    expect(backBtn).toBeDisabled();

    fireEvent.click(selectAllBtn);
    fireEvent.click(selectReadyBtn);
    fireEvent.change(screen.getByLabelText('Execution Mode'), { target: { value: 'live' } });
    fireEvent.change(screen.getByLabelText('Evaluation Engine'), { target: { value: 'rule_only' } });
    fireEvent.click(startBtn);
    fireEvent.click(backBtn);

    expect(previewCalls).toBe(1);
    expect(startCalls).toBe(1);
    expect(JSON.parse(sessionStorage.getItem('secagent_pending_generic_submission') || 'null')?.submission_id).toBe(
      originalSubmissionId,
    );

    // Opening an unrelated historical Run must NOT clear or overwrite the unresolved pendingSubmission
    rerender(<SecurityScanWizard initialRunId={unrelatedRunId} />);
    expect(await screen.findByRole('heading', { name: /3 · Scan Results:/ })).toBeInTheDocument();
    expect(screen.getByText(unrelatedRunId)).toBeInTheDocument();
    expect(JSON.parse(sessionStorage.getItem('secagent_pending_generic_submission') || 'null')?.submission_id).toBe(
      originalSubmissionId,
    );
    expect(screen.getByRole('alert', { name: 'Pending Scan Submission Verification' })).toBeInTheDocument();

    // Clicking New Scan while pendingSubmission is still unresolved must preserve pendingSubmission and keep Step 1 locked
    fireEvent.click(screen.getByRole('button', { name: 'New Scan' }));
    expect(await screen.findByRole('heading', { name: '1 · Select Target and Dataset' })).toBeInTheDocument();
    expect(JSON.parse(sessionStorage.getItem('secagent_pending_generic_submission') || 'null')?.submission_id).toBe(
      originalSubmissionId,
    );
    const step1ContinueBtn = screen.getByRole('button', { name: /Continue to Scan Preview/ });
    expect(step1ContinueBtn).toBeDisabled();
    fireEvent.click(step1ContinueBtn);
    expect(previewCalls).toBe(1);

    // Now allow Verify Submission Status to recover the original submission
    allowSubmissionRecovery = true;
    fireEvent.click(screen.getByRole('button', { name: 'Verify Submission Status' }));
    expect(await screen.findByRole('heading', { name: /3 · Scan Results:/ })).toBeInTheDocument();
    expect(await screen.findByText(recoveredRunId)).toBeInTheDocument();
    expect(sessionStorage.getItem('secagent_pending_generic_submission')).toBeNull();
    expect(screen.queryByRole('alert', { name: 'Pending Scan Submission Verification' })).not.toBeInTheDocument();
    expect(startCalls).toBe(1);

    // After legitimate resolution, New Scan unlocks normal Preview generation
    fireEvent.click(screen.getByRole('button', { name: 'New Scan' }));
    const unlockedContinue = await screen.findByRole('button', { name: /Continue to Scan Preview/ });
    await waitFor(() => expect(unlockedContinue).toBeEnabled());
    fireEvent.click(unlockedContinue);
    await waitFor(() => expect(previewCalls).toBe(2));
  }, 15000);
});
