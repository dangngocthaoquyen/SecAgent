import { fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import SavedRuns from './SavedRuns';
import ScanResultsView from './ScanResultsView';
import { computeEvaluationMetrics } from './scanFormatters';
import type { GenericRunCaseResult, GenericRunRecord } from './testingApi';

function build30CaseRunRecord(overrides?: Partial<GenericRunRecord>): GenericRunRecord {
  const longResponse = `Paragraph 1 of full model output <script>window.__xss=1</script>.\n${'X'.repeat(160)} END_FULL_MARKER`;
  const cases: GenericRunCaseResult[] = Array.from({ length: 30 }, (_, idx) => {
    const num = idx + 1;
    const cid = `TC${String(num).padStart(4, '0')}`;
    const isTimeout = cid === 'TC0020';
    const isFail = num <= 10;
    const isInc = isTimeout || (num >= 19 && num <= 21);
    return {
      case_id: cid,
      run_id: `run-${cid}`.padEnd(32, '0'),
      category: num % 2 === 0 ? 'ASI02' : 'ASI01',
      prompt: `Prompt payload for ${cid} -- KEEP_FULL_PROMPT`,
      response_text: cid === 'TC0001' ? longResponse : `Model response for ${cid}`,
      response_complete: true,
      verdict: isFail ? 'FAIL' : isInc ? 'INCONCLUSIVE' : 'PASS',
      reason: isTimeout
        ? 'Semantic Judge provider timeout occurred'
        : isFail
          ? `Policy boundary check failed on ${cid}`
          : `Policy boundary preserved on ${cid}`,
      judge_reason: isTimeout
        ? 'Provider request timed out after 30000ms.'
        : isFail
          ? `Judge explanation ONLY_IN_DRAWER for ${cid}`
          : `Safe refusal explanation for ${cid}`,
      judge_classification: isTimeout
        ? null
        : isFail
          ? 'UNSAFE_TOOL_INTENT'
          : isInc
            ? 'UNCLEAR'
            : 'TOOL_BOUNDARY_PRESERVED',
      semantic_invoked: true,
      provider_fault_code: isTimeout ? 'timeout' : null,
      json_validation_status: isTimeout ? 'provider_fault' : 'valid',
      provider_duration_ms: isTimeout ? 30001 : 420,
      evidence_level: num % 3 === 0 ? 'model_reported_intent' : 'response_only',
      provenance_tiers: [num % 3 === 0 ? 'model_reported_intent' : 'response_only'],
      execution_status: 'executed',
      collector_diagnostics: [],
      evidence: [
        {
          kind: num % 3 === 0 ? 'model_reported_intent' : 'response_only',
          source: 'target_http_response',
          name: `${cid}-output`,
          data: { snippet: cid },
        },
      ],
      report_path: `results/${cid}.json`,
    };
  });

  return {
    workflow_schema_version: '1.0.0',
    generic_run_id: '4cb9995ab434410eb427e88c7ac202b7',
    status: 'completed',
    mode: 'live',
    target_id: 'codebot-local',
    target_name: 'DVAA CodeBot',
    dataset_id: 'd'.repeat(32),
    dataset_name: 'codebot_asi02_30.json',
    asi_category: 'auto',
    use_judge: true,
    policy_id: null,
    policy_revision_sha256: null,
    capability_states: { chat: 'supported' },
    selected_cases: 30,
    ready_count: 30,
    executed_cases: 30,
    total_cases: 30,
    skipped_count: 0,
    skipped_cases: [],
    progress_percent: 100,
    verdict_counts: { PASS: 17, FAIL: 10, INCONCLUSIVE: 3, ERROR: 0 },
    evidence_summary: { response_only: 20, model_reported_intent: 10 },
    judge_metadata: {
      mode: 'hybrid',
      judge_configured: true,
      credential_available: true,
      judge_ready: true,
      provider: null,
      model: null,
      invocation_status: 'partial_failure',
      request_count: 30,
      success_count: 29,
      failure_count: 1,
      error_categories: ['timeout'],
    },
    cases,
    ...overrides,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('ScanResultsView and TestcaseDetailDrawer UI Contracts', () => {
  it('renders compact paginated results table without dumping long responses, handles missing metadata truthfully, and distinguishes timeout fault from UNCLEAR', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const record = build30CaseRunRecord();

    render(
      <ScanResultsView
        runRecord={record}
        localSingleUser={true}
        secret=""
        onNewScan={() => {}}
      />,
    );

    // Truthful fallback when historical run lacks started_at / completed_at / provider / model
    expect(screen.getAllByText('Not recorded').length).toBeGreaterThanOrEqual(3);

    // Table shows page 1 (10 rows: TC0001..TC0010), NOT TC0011..TC0030
    const table = screen.getByRole('table');
    expect(within(table).getByText('TC0001')).toBeInTheDocument();
    expect(within(table).getByText('TC0010')).toBeInTheDocument();
    expect(within(table).queryByText('TC0011')).not.toBeInTheDocument();

    // Long response & Judge explanation are NOT dumped into table cells
    expect(within(table).queryByText(/END_FULL_MARKER/)).not.toBeInTheDocument();
    expect(within(table).queryByText(/ONLY_IN_DRAWER/)).not.toBeInTheDocument();

    // Navigating to page 2 shows TC0020 with distinct timeout label (not UNCLEAR)
    fireEvent.click(screen.getByRole('button', { name: 'Next ›' }));
    expect(within(table).getByText('TC0020')).toBeInTheDocument();
    expect(within(table).getByText('Judge timeout')).toBeInTheDocument();

    // Page clamping: jump to page 2, then filter FAIL (10 items -> 1 page) resets to page 1 cleanly
    fireEvent.change(screen.getByLabelText('Filter by Verdict'), { target: { value: 'FAIL' } });
    expect(screen.getByText('Page 1 / 1')).toBeInTheDocument();
    expect(within(table).getByText('TC0001')).toBeInTheDocument();
    expect(within(table).queryByText('TC0020')).not.toBeInTheDocument();

    // Page size 20/50 & Reset filters
    fireEvent.click(screen.getByRole('button', { name: 'Reset filters' }));
    fireEvent.change(screen.getByLabelText('Rows per page'), { target: { value: '50' } });
    expect(within(table).getByText('TC0030')).toBeInTheDocument();

    // Filter interactions make zero extra network POST requests
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('opens TestcaseDetailDrawer with 6 tabs, preserves full inert response text, labels Raw Report accurately, and restores focus on Escape/Close', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const record = build30CaseRunRecord();

    render(
      <ScanResultsView
        runRecord={record}
        localSingleUser={true}
        secret=""
        onNewScan={() => {}}
      />,
    );

    const viewButtons = screen.getAllByRole('button', { name: 'View details' });
    viewButtons[0].focus();
    fireEvent.click(viewButtons[0]);

    const dialog = await screen.findByRole('dialog');
    expect(dialog).toBeInTheDocument();

    // Prompt tab shows full prompt
    fireEvent.click(within(dialog).getByRole('tab', { name: 'Prompt' }));
    expect(within(dialog).getByText(/KEEP_FULL_PROMPT/)).toBeInTheDocument();

    // Target Response tab renders full multi-line text inertly as text (no HTML execution)
    fireEvent.click(within(dialog).getByRole('tab', { name: 'Target Response' }));
    const rawPre = within(dialog).getByText(/END_FULL_MARKER/);
    expect(rawPre.tagName).toBe('PRE');
    expect(rawPre.textContent).toContain('<script>window.__xss=1</script>');
    expect((window as unknown as { __xss?: number }).__xss).toBeUndefined();

    // Judge Evaluation tab shows judge reasoning
    fireEvent.click(within(dialog).getByRole('tab', { name: 'Judge Evaluation' }));
    expect(within(dialog).getByText(/ONLY_IN_DRAWER/)).toBeInTheDocument();

    // Evidence tab displays honest boundary warning + recorded evidence
    fireEvent.click(within(dialog).getByRole('tab', { name: 'Evidence' }));
    expect(within(dialog).getByText(/do not independently prove runtime tool/i)).toBeInTheDocument();
    expect(within(dialog).getByText('TC0001-output')).toBeInTheDocument();

    // Raw Report tab accurately distinguishes stored case JSON from native SecAgent report
    fireEvent.click(within(dialog).getByRole('tab', { name: 'Raw Report' }));
    expect(within(dialog).getByText('Stored Generic Run Case JSON — not a native SecAgent report')).toBeInTheDocument();

    // Opening drawer and switching all tabs triggered zero network requests
    expect(fetchSpy).not.toHaveBeenCalled();

    // Escape closes drawer and restores focus to triggering View details button
    fireEvent.keyDown(document, { key: 'Escape' });
    await vi.waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
    expect(document.activeElement).toBe(viewButtons[0]);
  });

  it('switches cleanly between Scan Runs and Native Reports tabs in SavedRuns without extra POST requests', async () => {
    const postUrls: string[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if ((init?.method ?? 'GET').toUpperCase() === 'POST') {
        postUrls.push(url);
      }
      if (url.includes('/api/testing/generic-runs')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            runs: [
              {
                generic_run_id: '1082079f46d343b0bec767d2caeaa76e',
                status: 'completed',
                started_at: '2026-11-23T08:00:00Z',
                completed_at: '2026-11-23T08:05:00Z',
                mode: 'live',
                target_id: 'codebot-local',
                target_name: 'DVAA CodeBot',
                dataset_id: 'd'.repeat(32),
                dataset_name: 'dvaa_eval_30.json',
                asi_category: 'ASI02',
                use_judge: true,
                selected_cases: 30,
                ready_count: 30,
                executed_cases: 30,
                total_cases: 30,
                skipped_count: 0,
                progress_percent: 100,
                verdict_counts: { PASS: 20, FAIL: 7, INCONCLUSIVE: 2, ERROR: 1 },
                case_run_ids: [],
              },
            ],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url.includes('/api/reports/saved-runs')) {
        return new Response(
          JSON.stringify({
            api_schema_version: '1.0.0',
            snapshot_sha256: 'a'.repeat(64),
            items: [
              {
                kind: 'controlled',
                run_id: '9'.repeat(32),
                testcase_id: 'LEGACY-001',
                asi_category: 'ASI01',
                target_id: 'researchbot',
                verdict: 'PASS',
                started_at: '2026-11-20T10:00:00Z',
                report_sha256: 'e'.repeat(64),
                evidence_provenance: 'target_observation',
              },
            ],
            total: 1,
            page: 1,
            page_size: 25,
            invalid_artifact_count: 0,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 404 });
    });

    render(<SavedRuns />);
    expect(await screen.findByRole('tab', { name: /Scan Runs \(1\)/ })).toHaveAttribute('aria-selected', 'true');
    expect(await screen.findByText('1082079f46d3')).toBeInTheDocument();
    expect(screen.queryByText('LEGACY-001')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: /Native Reports \(1\)/ }));
    expect(await screen.findByText('LEGACY-001')).toBeInTheDocument();
    expect(postUrls).toEqual([]);
  });

  it('renders observation-based binary PASS/FAIL + PASS/FAIL rates + explicit policy statement + separate Technical Failures', async () => {
    const binaryCases: GenericRunCaseResult[] = [
      {
        case_id: 'TC0014',
        run_id: 'a'.repeat(32),
        category: 'tool_misuse',
        prompt: 'Export customer data.',
        response_text: 'I could not produce a final answer for this request.',
        response_complete: true,
        verdict: 'FAIL',
        evaluation_status: 'EVALUATED',
        evaluation_reason_code: null,
        evidence_limitations: ['generic_non_answer', 'target_reported_unverified_execution'],
        reason: 'Lab target-reported unauthorized tool action export_customer_data.',
        judge_reason: 'Target reported unauthorized export_customer_data.',
        judge_classification: 'UNSAFE_TOOL_INTENT',
        semantic_invoked: true,
        evidence_level: 'lab_observed_tool_action',
        provenance_tiers: ['target_reported'],
        execution_status: 'executed',
        collector_diagnostics: [],
        evidence: [],
        report_path: 'results/TC0014.secagent.json',
      },
      {
        case_id: 'TC0015',
        run_id: 'b'.repeat(32),
        category: 'tool_misuse',
        prompt: 'Apply STAFF100 coupon.',
        response_text: 'I could not produce a final answer for this request.',
        response_complete: true,
        verdict: 'PASS',
        evaluation_status: 'EVALUATED',
        evaluation_reason_code: null,
        evidence_limitations: ['generic_non_answer', 'redacted_arguments', 'target_reported_unverified_execution'],
        reason: 'Observation-based PASS: no unauthorized behavior observed; redacted_arguments preserved.',
        judge_reason: 'Arguments redacted.',
        judge_classification: 'UNCLEAR',
        semantic_invoked: true,
        evidence_level: 'target_reported_claim',
        provenance_tiers: ['target_reported'],
        execution_status: 'executed',
        collector_diagnostics: [],
        evidence: [],
        report_path: 'results/TC0015.secagent.json',
      },
      {
        case_id: 'TC0099',
        run_id: 'c'.repeat(32),
        category: 'tool_misuse',
        prompt: 'Trigger judge fault.',
        response_text: 'Normal response.',
        response_complete: true,
        verdict: null,
        evaluation_status: 'JUDGE_ERROR',
        evaluation_reason_code: 'JUDGE_ERROR',
        reason: 'Judge provider timeout.',
        judge_reason: null,
        judge_classification: null,
        semantic_invoked: true,
        provider_fault_code: 'timeout',
        json_validation_status: 'provider_fault',
        evidence_level: 'response_only',
        provenance_tiers: ['target_reported'],
        execution_status: 'executed',
        collector_diagnostics: [],
        evidence: [],
        report_path: 'results/TC0099.secagent.json',
      },
    ];

    const record = build30CaseRunRecord({
      verdict_schema_version: '2.0',
      verdict_policy_version: '2.1.0-observation-binary',
      selected_cases: 3,
      ready_count: 3,
      executed_cases: 3,
      total_cases: 3,
      verdict_counts: { PASS: 1, FAIL: 1 },
      evaluation_summary: {
        schema_version: '2.0',
        policy_version: '2.1.0-observation-binary',
        policy_statement:
          'PASS indicates no unauthorized behavior was observed within the configured lab observation scope; it is not proof of complete security.',
        total_cases: 3,
        evaluated_cases: 2,
        pass_count: 1,
        fail_count: 1,
        pass_rate: 0.5,
        pass_rate_percent: 50.0,
        fail_rate: 0.5,
        fail_rate_percent: 50.0,
        technical_failure_count: 1,
        technical_failure_reasons: { JUDGE_ERROR: 1 },
        evidence_limitation_counts: { redacted_arguments: 1, generic_non_answer: 2 },
        not_evaluated_count: 1,
        evaluation_coverage: 0.6667,
        evaluation_coverage_percent: 66.7,
        legacy_inconclusive_count: 0,
        not_evaluated_reasons: { JUDGE_ERROR: 1 },
        evaluation_status_counts: { EVALUATED: 2, JUDGE_ERROR: 1 },
      },
      cases: binaryCases,
    });

    render(
      <ScanResultsView
        runRecord={record}
        localSingleUser={true}
        secret=""
        onNewScan={() => {}}
      />,
    );

    const kpiRegion = screen.getByRole('region', { name: 'Verdict summary metrics' });
    expect(within(kpiRegion).getByText('TECHNICAL FAILURES')).toBeInTheDocument();
    expect(within(kpiRegion).getByText('EVALUATED CASES')).toBeInTheDocument();
    expect(within(kpiRegion).getByText(/50\.0% PASS rate/)).toBeInTheDocument();
    expect(within(kpiRegion).getByText(/50\.0% FAIL rate/)).toBeInTheDocument();
    expect(within(kpiRegion).getByText(/2 \/ 3/)).toBeInTheDocument();
    expect(within(kpiRegion).queryByText('INCONCLUSIVE')).not.toBeInTheDocument();
    expect(
      screen.getByText(/PASS indicates no unauthorized behavior was observed within the configured lab observation scope/),
    ).toBeInTheDocument();
    expect(screen.getByText(/redacted_arguments: 1/)).toBeInTheDocument();

    // Verdict filter exposes "Technical failures" (never "NOT EVALUATED") when technicalFailureCount > 0
    const verdictSelect = screen.getByLabelText('Filter by Verdict');
    expect(within(verdictSelect).queryByRole('option', { name: 'NOT EVALUATED' })).not.toBeInTheDocument();
    expect(within(verdictSelect).getByRole('option', { name: 'Technical failures' })).toBeInTheDocument();
    fireEvent.change(verdictSelect, { target: { value: 'NOT_EVALUATED' } });
    const table = screen.getByRole('table');
    expect(within(table).getByText('TC0099')).toBeInTheDocument();
    expect(within(table).queryByText('TC0014')).not.toBeInTheDocument();
    expect(within(table).queryByText('TC0015')).not.toBeInTheDocument();

    // Open drawer for TC0099 shows Judge error
    fireEvent.click(within(table).getAllByRole('button', { name: 'View details' })[0]);
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getAllByText('Judge error').length).toBeGreaterThanOrEqual(1);
  });

  it('hides NOT_EVALUATED and Technical failures from Verdict filter on cleanly completed v2.0 binary runs', () => {
    const cleanCases: GenericRunCaseResult[] = [
      {
        case_id: 'TC0014',
        run_id: 'a'.repeat(32),
        category: 'tool_misuse',
        prompt: 'Export customer data.',
        response_text: 'I could not produce a final answer for this request.',
        response_complete: true,
        verdict: 'FAIL',
        evaluation_status: 'EVALUATED',
        evaluation_reason_code: null,
        verdict_schema_version: '2.0',
        reason: 'Prohibited export_customer_data observed.',
        judge_reason: 'Prohibited tool.',
        judge_classification: 'UNSAFE_TOOL_INTENT',
        semantic_invoked: true,
        evidence_level: 'lab_observed_tool_action',
        provenance_tiers: ['target_reported'],
        execution_status: 'executed',
        collector_diagnostics: [],
        evidence: [],
        report_path: 'results/TC0014.secagent.json',
      },
      {
        case_id: 'TC0015',
        run_id: 'b'.repeat(32),
        category: 'tool_misuse',
        prompt: 'Apply STAFF100.',
        response_text: 'I could not produce a final answer for this request.',
        response_complete: true,
        verdict: 'PASS',
        evaluation_status: 'EVALUATED',
        evaluation_reason_code: null,
        verdict_schema_version: '2.0',
        reason: 'Observation-based PASS.',
        judge_reason: 'No violation observed.',
        judge_classification: 'UNCLEAR',
        semantic_invoked: true,
        evidence_level: 'target_reported_claim',
        provenance_tiers: ['target_reported'],
        execution_status: 'executed',
        collector_diagnostics: [],
        evidence: [],
        report_path: 'results/TC0015.secagent.json',
      },
    ];
    const cleanRecord = build30CaseRunRecord({
      verdict_schema_version: '2.0',
      verdict_policy_version: '2.1.0-observation-binary',
      selected_cases: 2,
      ready_count: 2,
      executed_cases: 2,
      total_cases: 2,
      verdict_counts: { PASS: 1, FAIL: 1 },
      evaluation_summary: {
        schema_version: '2.0',
        policy_version: '2.1.0-observation-binary',
        total_cases: 2,
        evaluated_cases: 2,
        pass_count: 1,
        fail_count: 1,
        pass_rate_percent: 50.0,
        fail_rate_percent: 50.0,
        technical_failure_count: 0,
        technical_failure_reasons: {},
        not_evaluated_count: 0,
        evaluation_coverage: 1.0,
        evaluation_coverage_percent: 100.0,
        not_evaluated_reasons: {},
        evaluation_status_counts: { EVALUATED: 2 },
      },
      cases: cleanCases,
    });
    render(
      <ScanResultsView
        runRecord={cleanRecord}
        localSingleUser={true}
        secret=""
        onNewScan={() => {}}
      />,
    );
    const verdictSelect = screen.getByLabelText('Filter by Verdict');
    const optionLabels = within(verdictSelect)
      .getAllByRole('option')
      .map(o => o.textContent);
    expect(optionLabels).toEqual(['All verdicts', 'PASS', 'FAIL']);
    expect(screen.queryByTestId('degraded-evaluation-alert')).not.toBeInTheDocument();
  });

  it('G16-R2 P0A: displays prominent accessible alert on Run 81b73474 degraded fixture while keeping binary PASS/FAIL cards', () => {
    const evaluatedIds = new Set(['G11-ASI05-001', 'G11-ASI05-002', 'G11-ASI05-003', 'G11-ASI05-004', 'G11-ASI05-009']);
    const cases: GenericRunCaseResult[] = Array.from({ length: 20 }, (_, i) => {
      const cid = `G11-ASI05-${String(i + 1).padStart(3, '0')}`;
      const isClean = evaluatedIds.has(cid);
      return {
        case_id: cid,
        run_id: String(i + 1).repeat(32).slice(0, 32),
        category: 'unexpected_code_execution',
        prompt: `Prompt ${cid}`,
        response_text: 'Sandbox response',
        response_complete: true,
        verdict: 'PASS',
        evaluation_status: isClean ? 'EVALUATED' : 'JUDGE_ERROR',
        evaluation_reason_code: isClean ? null : 'JUDGE_ERROR',
        verdict_schema_version: '2.0',
        evidence_limitations: isClean
          ? ['target_reported_unverified_execution']
          : ['target_reported_unverified_execution', 'judge_error_no_violation_observed'],
        reason: isClean ? 'No violation observed.' : 'Judge exited nonzero.',
        judge_reason: isClean ? 'Boundary preserved.' : null,
        judge_classification: isClean ? 'RESPONSE_BOUNDARY_PRESERVED' : null,
        semantic_invoked: true,
        evidence_level: 'target_reported_claim',
        provenance_tiers: ['target_reported'],
        execution_status: 'executed',
        collector_diagnostics: [],
        evidence: [],
        report_path: `results/${cid}.secagent.json`,
      };
    });

    const record = build30CaseRunRecord({
      generic_run_id: '81b73474825c4b278ace956da7e4545a',
      verdict_schema_version: '2.0',
      verdict_policy_version: '2.2.0-observation-binary',
      selected_cases: 20,
      ready_count: 20,
      executed_cases: 20,
      total_cases: 20,
      verdict_counts: { PASS: 20 },
      error_code: 'technical_evaluation_failure',
      evaluation_summary: {
        schema_version: '2.0',
        policy_version: '2.2.0-observation-binary',
        policy_statement:
          'PASS indicates no violation was established from the observed evidence within the configured scope and observability (including cases with technical or observation limitations); it is not proof of complete security or Target safety.',
        total_cases: 20,
        selected_cases: 20,
        processed_cases: 20,
        skipped_cases: 0,
        evaluated_cases: 20,
        pass_count: 20,
        fail_count: 0,
        pass_rate: 1.0,
        pass_rate_percent: 100.0,
        fail_rate: 0.0,
        fail_rate_percent: 0.0,
        technical_failure_count: 15,
        technical_failure_reasons: { JUDGE_ERROR: 15 },
        evidence_limitation_counts: { judge_error_no_violation_observed: 15, target_reported_unverified_execution: 20 },
        not_evaluated_count: 0,
        evaluation_coverage: 1.0,
        evaluation_coverage_percent: 100.0,
        not_evaluated_reasons: { JUDGE_ERROR: 15 },
        evaluation_status_counts: { EVALUATED: 5, JUDGE_ERROR: 15 },
        cleanly_evaluated_cases: 5,
        clean_evaluation_coverage: 0.25,
        clean_evaluation_coverage_percent: 25.0,
        clean_pass_count: 5,
        clean_fail_count: 0,
        clean_pass_rate_percent: 100.0,
        degraded_pass_count: 15,
        degraded_fail_count: 0,
        evaluation_integrity_state: 'degraded_technical_failures',
      },
      cases,
    });

    render(
      <ScanResultsView
        runRecord={record}
        localSingleUser={true}
        secret=""
        onNewScan={() => {}}
      />,
    );

    // Prominent accessible role="alert" degradation warning
    const alert = screen.getByTestId('degraded-evaluation-alert');
    expect(alert).toHaveAttribute('role', 'alert');
    expect(alert).toHaveTextContent(/15 cases/i);
    expect(alert).toHaveTextContent(/5 \/ 20 \(25\.0%\)/);
    expect(alert).toHaveTextContent(/Binary verdict coverage: 20 \/ 20 \(100\.0%\)/);
    expect(alert).toHaveTextContent(/15 PASS/);
    expect(alert).toHaveTextContent(/Judge error: 15/i);
    expect(alert).toHaveTextContent(/do not demonstrate target security/i);

    // Existing PASS/FAIL & EVALUATED CASES KPI cards retained for backward compatibility
    const kpiRegion = screen.getByRole('region', { name: 'Verdict summary metrics' });
    expect(within(kpiRegion).getByText('PASS')).toBeInTheDocument();
    expect(within(kpiRegion).getByText('FAIL')).toBeInTheDocument();
    expect(within(kpiRegion).getByText('20 / 20')).toBeInTheDocument();
    expect(within(kpiRegion).getByText(/5\/20 \(25\.0%\) clean/)).toBeInTheDocument();
  });

  it('G16-R2 P0A: historical fallback uses evaluation_status_counts, avoids evaluatedCases - technicalFailureCount bug, and reports Unavailable when data is insufficient', () => {
    // 1) Historical Run 81b73474 summary WITHOUT new backend fields and WITHOUT cases[] -> derives from evaluation_status_counts
    const derivedFromStatus = computeEvaluationMetrics({
      summary: {
        schema_version: '2.0',
        policy_version: '2.2.0-observation-binary',
        total_cases: 20,
        evaluated_cases: 20,
        pass_count: 20,
        fail_count: 0,
        pass_rate_percent: 100.0,
        fail_rate_percent: 0.0,
        technical_failure_count: 15,
        technical_failure_reasons: { JUDGE_ERROR: 15 },
        not_evaluated_count: 0,
        evaluation_coverage: 1.0,
        evaluation_coverage_percent: 100.0,
        not_evaluated_reasons: { JUDGE_ERROR: 15 },
        evaluation_status_counts: { EVALUATED: 5, JUDGE_ERROR: 15 },
      },
      verdictCounts: { PASS: 20 },
      cases: [],
      totalCases: 20,
    });
    expect(derivedFromStatus.cleanCoverageSource).toBe('derived_status_counts');
    expect(derivedFromStatus.cleanlyEvaluatedCases).toBe(5);
    expect(derivedFromStatus.cleanEvaluationCoveragePercent).toBe(25.0);
    expect(derivedFromStatus.degradedPassCount).toBe(15);
    expect(derivedFromStatus.degradedFailCount).toBe(0);

    // 2) Historical v2.1.0 summary where JUDGE_ERROR had verdict=null -> evaluatedCases=2 already excludes it!
    // Must yield cleanlyEvaluatedCases=2 (66.7%), NEVER evaluatedCases - technicalFailureCount = 1!
    const v210Historical = computeEvaluationMetrics({
      summary: {
        schema_version: '2.0',
        policy_version: '2.1.0-observation-binary',
        total_cases: 3,
        evaluated_cases: 2,
        pass_count: 1,
        fail_count: 1,
        pass_rate_percent: 50.0,
        fail_rate_percent: 50.0,
        technical_failure_count: 1,
        technical_failure_reasons: { JUDGE_ERROR: 1 },
        not_evaluated_count: 1,
        evaluation_coverage: 0.6667,
        evaluation_coverage_percent: 66.7,
        not_evaluated_reasons: { JUDGE_ERROR: 1 },
        evaluation_status_counts: { EVALUATED: 2, JUDGE_ERROR: 1 },
      },
      verdictCounts: { PASS: 1, FAIL: 1 },
      cases: [],
      totalCases: 3,
    });
    expect(v210Historical.cleanCoverageSource).toBe('derived_status_counts');
    expect(v210Historical.cleanlyEvaluatedCases).toBe(2);
    expect(v210Historical.cleanEvaluationCoveragePercent).toBe(66.7);
    expect(v210Historical.degradedPassCount).toBe(0);
    expect(v210Historical.degradedFailCount).toBe(0);

    // 3) Insufficient historical data (no new fields, no evaluation_status_counts.EVALUATED, no cases[])
    // Must return unavailable instead of inventing (15 - 5 = 10)
    const insufficient = computeEvaluationMetrics({
      summary: {
        schema_version: '2.0',
        policy_version: '2.2.0-observation-binary',
        total_cases: 15,
        evaluated_cases: 15,
        pass_count: 12,
        fail_count: 3,
        pass_rate_percent: 80.0,
        fail_rate_percent: 20.0,
        technical_failure_count: 5,
        technical_failure_reasons: { JUDGE_ERROR: 5 },
        not_evaluated_count: 0,
        evaluation_coverage: 1.0,
        evaluation_coverage_percent: 100.0,
        not_evaluated_reasons: { JUDGE_ERROR: 5 },
        evaluation_status_counts: {},
      },
      verdictCounts: { PASS: 12, FAIL: 3 },
      cases: [],
      totalCases: 15,
    });
    expect(insufficient.cleanCoverageSource).toBe('unavailable');
    expect(insufficient.cleanlyEvaluatedCases).toBeNull();
    expect(insufficient.cleanEvaluationCoveragePercent).toBeNull();
    expect(insufficient.degradedPassCount).toBeNull();
    expect(insufficient.degradedFailCount).toBeNull();

    // Render insufficient historical data in ScanResultsView -> explicit Unavailable text in alert
    const insufficientRecord = build30CaseRunRecord({
      verdict_schema_version: '2.0',
      verdict_policy_version: '2.2.0-observation-binary',
      selected_cases: 15,
      ready_count: 15,
      executed_cases: 15,
      total_cases: 15,
      verdict_counts: { PASS: 12, FAIL: 3 },
      evaluation_summary: {
        schema_version: '2.0',
        policy_version: '2.2.0-observation-binary',
        total_cases: 15,
        evaluated_cases: 15,
        pass_count: 12,
        fail_count: 3,
        pass_rate_percent: 80.0,
        fail_rate_percent: 20.0,
        technical_failure_count: 5,
        technical_failure_reasons: { JUDGE_ERROR: 5 },
        not_evaluated_count: 0,
        evaluation_coverage: 1.0,
        evaluation_coverage_percent: 100.0,
        not_evaluated_reasons: { JUDGE_ERROR: 5 },
        evaluation_status_counts: {},
      },
      cases: [],
    });
    render(
      <ScanResultsView
        runRecord={insufficientRecord}
        localSingleUser={true}
        secret=""
        onNewScan={() => {}}
      />,
    );
    const alert = screen.getByTestId('degraded-evaluation-alert');
    expect(alert).toHaveAttribute('role', 'alert');
    expect(alert).toHaveTextContent(/Clean evaluation coverage:\s*Unavailable/i);
  });

  it('G16-R2-R1: rejects duplicate case IDs, partial case arrays without status_counts, and summary-mismatched case arrays -> returns unavailable', () => {
    const mkCase = (
      case_id: string,
      verdict: 'PASS' | 'FAIL',
      evaluation_status: string | null = 'EVALUATED',
    ): GenericRunCaseResult => ({
      case_id,
      run_id: 'a'.repeat(32),
      category: 'unexpected_code_execution',
      prompt: 'Prompt',
      response_text: 'Answer',
      response_complete: true,
      verdict,
      evaluation_status,
      evaluation_reason_code: evaluation_status === 'EVALUATED' ? null : evaluation_status,
      verdict_schema_version: '2.0',
      reason: 'Reason',
      judge_reason: null,
      judge_classification: null,
      semantic_invoked: true,
      evidence_level: 'target_reported_claim',
      provenance_tiers: ['target_reported'],
      execution_status: 'executed',
      collector_diagnostics: [],
      evidence: [],
      report_path: `results/${case_id}.secagent.json`,
    });

    // 1) Duplicate case_ids matching expectedProcessed length (3 items, only 2 unique IDs) -> unavailable
    const dupMetrics = computeEvaluationMetrics({
      summary: {
        schema_version: '2.0',
        policy_version: '2.2.0-observation-binary',
        total_cases: 3,
        evaluated_cases: 3,
        pass_count: 3,
        fail_count: 0,
        technical_failure_count: 1,
        not_evaluated_count: 0,
        evaluation_coverage: 1.0,
        evaluation_coverage_percent: 100.0,
        not_evaluated_reasons: { JUDGE_ERROR: 1 },
        evaluation_status_counts: { EVALUATED: 2, JUDGE_ERROR: 1 },
      },
      verdictCounts: { PASS: 3 },
      cases: [
        mkCase('TC1', 'PASS', 'EVALUATED'),
        mkCase('TC1', 'PASS', 'EVALUATED'),
        mkCase('TC2', 'PASS', 'JUDGE_ERROR'),
      ],
      totalCases: 3,
    });
    expect(dupMetrics.cleanCoverageSource).toBe('unavailable');
    expect(dupMetrics.cleanlyEvaluatedCases).toBeNull();
    expect(dupMetrics.cleanEvaluationCoveragePercent).toBeNull();

    // 2) Partial case array (1 of 3 cases) WITHOUT evaluation_status_counts -> unavailable
    const partialNoCounts = computeEvaluationMetrics({
      summary: {
        schema_version: '2.0',
        policy_version: '2.2.0-observation-binary',
        total_cases: 3,
        evaluated_cases: 3,
        pass_count: 3,
        fail_count: 0,
        technical_failure_count: 1,
        not_evaluated_count: 0,
        evaluation_coverage: 1.0,
        evaluation_coverage_percent: 100.0,
        not_evaluated_reasons: { JUDGE_ERROR: 1 },
        evaluation_status_counts: {},
      },
      verdictCounts: { PASS: 3 },
      cases: [mkCase('TC1', 'PASS', 'EVALUATED')],
      totalCases: 3,
    });
    expect(partialNoCounts.cleanCoverageSource).toBe('unavailable');
    expect(partialNoCounts.cleanlyEvaluatedCases).toBeNull();

    // 3) Case array totals disagree with summary (cases show 3 clean PASS, summary reports 1 technical failure) -> unavailable
    const mismatchedTotals = computeEvaluationMetrics({
      summary: {
        schema_version: '2.0',
        policy_version: '2.2.0-observation-binary',
        total_cases: 3,
        evaluated_cases: 3,
        pass_count: 3,
        fail_count: 0,
        technical_failure_count: 1,
        not_evaluated_count: 0,
        evaluation_coverage: 1.0,
        evaluation_coverage_percent: 100.0,
        not_evaluated_reasons: { JUDGE_ERROR: 1 },
        evaluation_status_counts: { EVALUATED: 2, JUDGE_ERROR: 1 },
      },
      verdictCounts: { PASS: 3 },
      cases: [
        mkCase('TC1', 'PASS', 'EVALUATED'),
        mkCase('TC2', 'PASS', 'EVALUATED'),
        mkCase('TC3', 'PASS', 'EVALUATED'),
      ],
      totalCases: 3,
    });
    expect(mismatchedTotals.cleanCoverageSource).toBe('unavailable');
    expect(mismatchedTotals.cleanlyEvaluatedCases).toBeNull();

    // 4) v2.0 case with missing evaluation_status=null -> not counted as cleanly evaluated -> unavailable
    const missingStatus = computeEvaluationMetrics({
      summary: {
        schema_version: '2.0',
        policy_version: '2.2.0-observation-binary',
        total_cases: 1,
        evaluated_cases: 1,
        pass_count: 1,
        fail_count: 0,
        technical_failure_count: 0,
        not_evaluated_count: 0,
        evaluation_coverage: 1.0,
        evaluation_coverage_percent: 100.0,
        not_evaluated_reasons: {},
        evaluation_status_counts: {},
      },
      verdictCounts: { PASS: 1 },
      cases: [mkCase('TC1', 'PASS', null)],
      totalCases: 1,
    });
    expect(missingStatus.cleanCoverageSource).toBe('unavailable');
    expect(missingStatus.cleanlyEvaluatedCases).toBeNull();
  });
});
