import { fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import SavedRuns from './SavedRuns';
import ScanResultsView from './ScanResultsView';
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
});
