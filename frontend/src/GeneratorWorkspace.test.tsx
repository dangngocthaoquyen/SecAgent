import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import GeneratorModeWorkspace from './GeneratorModeWorkspace';
import { preset } from './test/targetFixtures';
import type {
  GeneratorPreviewSnapshot,
  GeneratorStatusResponse,
  PreviewSaveRecord,
  TargetReadinessReport,
} from './generatorApi';
import type { DatasetSummary } from './testingApi';

const NONCE = 'n'.repeat(43);

function mockStatusResponse(ready = true): GeneratorStatusResponse {
  return {
    workflow_schema_version: '1.0.0',
    provider: {
      provider_id: 'deepseek_http',
      model: 'deepseek-flash',
      configured: true,
      credential_available: ready,
      ready,
      reason: ready ? 'ready' : 'credential_missing',
      supports_json_mode: true,
      max_output_tokens_ceiling: 8192,
      retry_policy: 'caller_managed_single_attempt',
    },
    supported_asi: ['ASI01', 'ASI02', 'ASI03', 'ASI05'],
    limits: {
      min_per_asi: 1,
      default_per_asi: 5,
      max_per_asi: 15,
      max_total_cases: 50,
      hard_max_per_asi: 15,
      hard_max_total_cases: 50,
    },
    defaults: {
      deduplicate_across_asi: false,
      max_calls_per_asi: 1,
      language: 'en',
    },
    skills: [
      {
        id: 'secagent-g11-generator',
        version: '1.0.1',
        asi_code: 'ASI01',
        asi_category: 'goal_hijacking',
        sha256: 'a'.repeat(64),
      },
    ],
    skill_error: null,
  };
}

function mockReadinessReport(): TargetReadinessReport {
  return {
    target_id: preset.id,
    target_exists: true,
    overall_status: 'ready_with_warnings',
    asi_assessments: {
      ASI01: {
        asi_code: 'ASI01',
        asi_category: 'goal_hijacking',
        status: 'ready_with_warnings',
        effective_scope: 'goal_hijack_response',
        requested_scope: null,
        scope_capability_state: 'supported',
        scope_capability_provenance: 'operator_declared',
        blockers: [],
        warnings: ['capability_not_runtime_verified'],
        findings: [],
        has_reviewed_policy: false,
        reviewed_policy_id: null,
        reviewed_policy_revision_sha256: null,
        ambiguous_policy_candidates: [],
        deterministic_limitations: [],
      },
      ASI03: {
        asi_code: 'ASI03',
        asi_category: 'identity_privilege_abuse',
        status: 'blocked',
        effective_scope: 'identity_claim_response',
        requested_scope: null,
        scope_capability_state: 'supported',
        scope_capability_provenance: 'operator_declared',
        blockers: ['multiple_reviewed_policies_ambiguous'],
        warnings: [],
        findings: [],
        has_reviewed_policy: false,
        reviewed_policy_id: null,
        reviewed_policy_revision_sha256: null,
        ambiguous_policy_candidates: [
          {
            policy_id: 'pol-aaa',
            revision_sha256: '1'.repeat(64),
            evaluation_scope: 'identity_claim_response',
            reviewed_at: '2026-11-26T00:00:00Z',
          },
          {
            policy_id: 'pol-bbb',
            revision_sha256: '2'.repeat(64),
            evaluation_scope: 'identity_claim_response',
            reviewed_at: '2026-11-26T01:00:00Z',
          },
        ],
        deterministic_limitations: [],
      },
    },
  };
}

function mockPreviewSnapshot(overrides: Partial<GeneratorPreviewSnapshot> = {}): GeneratorPreviewSnapshot {
  return {
    preview_id: 'prev-' + 'a'.repeat(32),
    status: 'active',
    created_at: '2026-11-26T10:00:00Z',
    updated_at: '2026-11-26T10:00:00Z',
    expires_at: '2026-11-26T10:30:00Z',
    generation_id: 'gen-ui000001',
    target_id: preset.id,
    target_revision_sha256: '3'.repeat(64),
    application_context_revision_sha256: '4'.repeat(64),
    context_snapshot_sha256: '5'.repeat(64),
    reviewed_policy_revisions: {},
    provider_id: 'deepseek_http',
    model: 'deepseek-flash',
    language: 'en',
    deduplicate_across_asi: false,
    overall_status: 'completed',
    meets_requested_counts: true,
    has_accepted_candidates: true,
    can_save: true,
    requires_partial_confirmation: false,
    total_requested: 2,
    total_generated: 2,
    total_accepted: 2,
    total_rejected: 0,
    selected_count: 2,
    edited_count: 0,
    total_call_count: 1,
    total_duration_ms: 42.0,
    total_token_usage: { prompt_tokens: 120, completion_tokens: 180, total_tokens: 300 },
    asi_order: ['ASI01'],
    asi_summaries: {
      ASI01: {
        asi_code: 'ASI01',
        asi_category: 'goal_hijacking',
        status: 'completed',
        effective_scope: 'goal_hijack_response',
        readiness_status: 'ready_with_warnings',
        readiness_blockers: [],
        readiness_warnings: ['capability_not_runtime_verified'],
        requested_count: 2,
        generated_count: 2,
        accepted_count: 2,
        rejected_count: 0,
        duplicate_rejected_count: 0,
        rejection_reason_counts: {},
        context_gaps: [],
        error_code: null,
        error_message: null,
        skill_id: 'secagent-g11-generator',
        skill_version: '1.0.1',
        skill_sha256: 'a'.repeat(64),
        sanitized_request_sha256: 'b'.repeat(64),
        reviewed_policy_id: null,
        reviewed_policy_revision_sha256: null,
        call_count: 1,
        duration_ms: 42.0,
      },
    },
    candidates: [
      {
        candidate_id: 'gen-ui000001:asi01:001',
        candidate_id_scope: 'ephemeral_generation_candidate',
        asi_code: 'ASI01',
        asi_category: 'goal_hijacking',
        effective_scope: 'goal_hijack_response',
        source_index: 0,
        origin: 'ai_generated_original',
        operator_edited: false,
        selected: true,
        original_prompt: 'Synthetic ASI01 probe #1',
        original_description: 'Boundary check #1',
        original_prompt_sha256: 'c'.repeat(64),
        effective_prompt: 'Synthetic ASI01 probe #1',
        effective_description: 'Boundary check #1',
        effective_prompt_sha256: 'c'.repeat(64),
        strategy_tag: 'indirect_override',
        context_basis: ['purpose', 'trust_boundaries'],
        scope_note: 'Descriptive metadata only.',
        reviewed_policy_id: null,
        reviewed_policy_revision_sha256: null,
      },
      {
        candidate_id: 'gen-ui000001:asi01:002',
        candidate_id_scope: 'ephemeral_generation_candidate',
        asi_code: 'ASI01',
        asi_category: 'goal_hijacking',
        effective_scope: 'goal_hijack_response',
        source_index: 1,
        origin: 'ai_generated_original',
        operator_edited: false,
        selected: true,
        original_prompt: 'Synthetic ASI01 probe #2',
        original_description: 'Boundary check #2',
        original_prompt_sha256: 'd'.repeat(64),
        effective_prompt: 'Synthetic ASI01 probe #2',
        effective_description: 'Boundary check #2',
        effective_prompt_sha256: 'd'.repeat(64),
        strategy_tag: 'role_drift',
        context_basis: ['purpose', 'trust_boundaries'],
        scope_note: 'Descriptive metadata only.',
        reviewed_policy_id: null,
        reviewed_policy_revision_sha256: null,
      },
    ],
    rejection_reason_counts: {},
    save_record: null,
    auto_persisted: false,
    auto_executed: false,
    ...overrides,
  };
}

function mockSaveRecord(overrides: Partial<PreviewSaveRecord> = {}): PreviewSaveRecord {
  return {
    save_status: 'saved',
    dataset_id: 'f'.repeat(32),
    dataset_name: 'Saved G11 Set',
    dataset_file_sha256: '7'.repeat(64),
    dataset_content_sha256: '8'.repeat(64),
    saved_at: '2026-11-26T10:05:00Z',
    created: true,
    idempotent_replay: false,
    saved_candidate_ids: ['gen-ui000001:asi01:001'],
    saved_count: 1,
    requested_count: 2,
    generated_count: 2,
    accepted_count: 2,
    rejected_count: 0,
    selected_for_save_count: 1,
    partial_generation: false,
    partial_save_confirmed: false,
    meets_requested_counts: true,
    save_request_digest: '9'.repeat(64),
    ...overrides,
  };
}

afterEach(() => vi.restoreAllMocks());

describe('G11.4 GeneratorModeWorkspace — Three Operating Modes', () => {
  it('renders all three operating modes with Generate & Run as primary and strictly blocked until G11.6', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/testing/generator/status')) {
        return new Response(JSON.stringify(mockStatusResponse(true)));
      }
      return new Response('{}', { status: 404 });
    });

    render(<GeneratorModeWorkspace targets={[preset]} nonce={NONCE} />);

    // All three mode tabs visible
    expect(screen.getByTestId('mode-tab-generate_and_run')).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByTestId('mode-tab-generate_only')).toBeInTheDocument();
    expect(screen.getByTestId('mode-tab-run_existing_dataset')).toBeInTheDocument();

    // Mode 1 clearly states G11.6 unavailability, has NO preview/manual-save dependency, and shows 6 planned stages
    expect(screen.getByTestId('g11-6-unavailable-banner')).toHaveTextContent('Awaiting G11.6 Backend Orchestration');
    expect(screen.getByTestId('generate-and-run-panel')).not.toHaveTextContent('Explicit Save to Dataset Library');
    for (const stage of ['generating', 'validating', 'saving_dataset', 'executing', 'judging', 'reporting']) {
      expect(screen.getByTestId(`planned-stage-${stage}`)).toBeInTheDocument();
    }

    // Submit button is strictly disabled and submitting form NEVER triggers execution or generation calls
    const runBtn = screen.getByTestId('generate-and-run-submit-btn');
    expect(runBtn).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/Confirm authorized Generate and Run scope/i));
    expect(runBtn).toBeDisabled();
    fireEvent.submit(screen.getByTestId('generate-and-run-panel'));

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1));
    expect(String(fetchSpy.mock.calls[0][0])).toBe('/api/testing/generator/status');
    // Confirm ZERO execution endpoints or raw API key inputs exist
    expect(screen.queryByPlaceholderText(/api key/i)).not.toBeInTheDocument();
  });

  it('completes Generate Only -> Preview -> Edit/Select/Reset -> Explicit Save without calling Target/Judge', async () => {
    const calls: { url: string; method: string; body?: unknown }[] = [];
    const basePreview = mockPreviewSnapshot();
    const editedPreview = mockPreviewSnapshot({
      edited_count: 1,
      selected_count: 1,
      candidates: [
        {
          ...basePreview.candidates[0],
          origin: 'operator_edited',
          operator_edited: true,
          effective_prompt: 'Refined ASI01 prompt by operator',
          effective_prompt_sha256: 'e'.repeat(64),
        },
        {
          ...basePreview.candidates[1],
          selected: false,
        },
      ],
    });
    const savedRec = mockSaveRecord();

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      const method = init?.method ?? 'GET';
      const parsedBody = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
      calls.push({ url, method, body: parsedBody });

      if (url.endsWith('/api/testing/generator/status')) {
        return new Response(JSON.stringify(mockStatusResponse(true)));
      }
      if (url.endsWith('/api/testing/generator/readiness')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', readiness: mockReadinessReport() }));
      }
      if (url.endsWith('/api/testing/generator/generate')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', preview: basePreview }), { status: 201 });
      }
      if (url.endsWith('/edit')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', preview: editedPreview }));
      }
      if (url.endsWith('/save')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', save_record: savedRec }), { status: 201 });
      }
      return new Response('{}', { status: 404 });
    });

    const onOpenLib = vi.fn();
    render(
      <GeneratorModeWorkspace
        targets={[preset]}
        nonce={NONCE}
        initialMode="generate_only"
        onOpenDatasetLibrary={onOpenLib}
      />,
    );

    await screen.findByTestId('provider-status-summary');

    // Check Readiness & verify ambiguous policy dropdown renders for ASI03
    fireEvent.click(screen.getByRole('button', { name: 'Check Context Readiness' }));
    await screen.findByTestId('readiness-badge-ASI01');
    expect(screen.getByLabelText('Reviewed Policy for ASI03')).toBeInTheDocument();

    // Generate preview (verify API default deduplicate_across_asi=false is sent!)
    fireEvent.change(screen.getByLabelText('ASI01 testcase count'), { target: { value: '2' } });
    fireEvent.click(screen.getByTestId('generate-only-submit-btn'));
    await screen.findByTestId('generator-preview-section');

    const genCall = calls.find((c) => c.url.endsWith('/generate'));
    expect(genCall?.body).toMatchObject({
      target_id: preset.id,
      counts_by_asi: { ASI01: 2 },
      deduplicate_across_asi: false,
      language: 'en',
    });

    // Edit candidate #0 prompt, test Reset to Original, then re-edit and unselect candidate #1
    const promptInput = screen.getByLabelText('Prompt for gen-ui000001:asi01:001');
    fireEvent.change(promptInput, { target: { value: 'Temporary edit' } });
    fireEvent.click(screen.getByRole('button', { name: 'Reset to Original' }));
    expect(promptInput).toHaveValue('Synthetic ASI01 probe #1');

    fireEvent.change(promptInput, { target: { value: 'Refined ASI01 prompt by operator' } });
    fireEvent.click(screen.getByLabelText('Select candidate gen-ui000001:asi01:002'));
    fireEvent.click(screen.getByTestId('apply-preview-edits-btn'));
    await waitFor(() =>
      expect(screen.getByTestId('origin-badge-gen-ui000001:asi01:001')).toHaveTextContent('operator_edited'),
    );

    // Save button remains disabled until explicit save_confirmed is checked
    const saveBtn = screen.getByTestId('explicit-save-btn');
    expect(saveBtn).toBeDisabled();
    fireEvent.click(screen.getByLabelText('Confirm explicit save to Dataset Library'));
    expect(saveBtn).not.toBeDisabled();

    fireEvent.click(saveBtn);
    await screen.findByTestId('save-success-banner');
    expect(screen.getByTestId('saved-dataset-id')).toHaveTextContent('f'.repeat(32));

    // Clicking Dataset Library link triggers callback with created Dataset ID
    fireEvent.click(screen.getByTestId('open-dataset-library-link'));
    expect(onOpenLib).toHaveBeenCalledWith('f'.repeat(32));

    // Verify ZERO execution / generic-runs / target calls occurred
    expect(calls.some((c) => c.url.includes('/generic-runs') || c.url.includes('/runs'))).toBe(false);
  });

  it('requires explicit partial confirmation for partial generation and surfaces credential/stale errors', async () => {
    const partialPreview = mockPreviewSnapshot({
      overall_status: 'partial',
      meets_requested_counts: false,
      requires_partial_confirmation: true,
      total_requested: 5,
      total_generated: 5,
      total_accepted: 2,
      total_rejected: 3,
    });

    let saveAttempt = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/testing/generator/status')) {
        return new Response(JSON.stringify(mockStatusResponse(true)));
      }
      if (url.endsWith('/api/testing/generator/generate')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', preview: partialPreview }), { status: 201 });
      }
      if (url.endsWith('/save')) {
        saveAttempt += 1;
        if (saveAttempt === 1) {
          return new Response(
            JSON.stringify({
              workflow_schema_version: '1.0.0',
              error: {
                code: 'preview_target_revision_stale',
                message: 'Target profile revision changed after generation.',
              },
            }),
            { status: 409 },
          );
        }
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            save_record: mockSaveRecord({
              partial_generation: true,
              partial_save_confirmed: true,
              meets_requested_counts: false,
              requested_count: 5,
              accepted_count: 2,
              rejected_count: 3,
              saved_count: 2,
              selected_for_save_count: 2,
            }),
          }),
          { status: 201 },
        );
      }
      return new Response('{}', { status: 404 });
    });

    render(<GeneratorModeWorkspace targets={[preset]} nonce={NONCE} initialMode="generate_only" />);
    await screen.findByTestId('provider-status-summary');

    fireEvent.click(screen.getByTestId('generate-only-submit-btn'));
    await screen.findByTestId('partial-generation-notice');

    // Save button stays disabled until BOTH save_confirmed AND partial_save_confirmed are checked
    const saveBtn = screen.getByTestId('explicit-save-btn');
    fireEvent.click(screen.getByLabelText('Confirm explicit save to Dataset Library'));
    expect(saveBtn).toBeDisabled();
    fireEvent.click(screen.getByLabelText('Confirm saving partial generation subset'));
    expect(saveBtn).not.toBeDisabled();

    // First save returns 409 stale target revision -> surfaces recovery banner
    fireEvent.click(saveBtn);
    const errBanner = await screen.findByTestId('generator-error-banner');
    expect(errBanner).toHaveTextContent('preview_target_revision_stale');
    expect(errBanner).toHaveTextContent('generate a fresh preview');

    // Second save succeeds honestly with partial notice
    fireEvent.click(saveBtn);
    const okBanner = await screen.findByTestId('save-success-banner');
    expect(okBanner).toHaveTextContent('partial subset');
  });

  it('blocks Generate action when DeepSeek server credential is missing (R02)', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).endsWith('/api/testing/generator/status')) {
        return new Response(JSON.stringify(mockStatusResponse(false)));
      }
      return new Response('{}', { status: 404 });
    });

    render(<GeneratorModeWorkspace targets={[preset]} nonce={NONCE} initialMode="generate_only" />);
    const badge = await screen.findByTestId('provider-ready-badge');
    expect(badge).toHaveTextContent('Unavailable (credential_missing)');
    expect(screen.getByText(/DEEPSEEK_API_KEY/)).toBeInTheDocument();
    expect(screen.getByTestId('generate-only-submit-btn')).toBeDisabled();
  });

  it('Mode 3 (Run Existing Dataset) links to existing workflows and makes ZERO Generator API calls', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const onOpenScan = vi.fn();
    const onOpenLib = vi.fn();
    const sampleDatasets: DatasetSummary[] = [
      {
        dataset_id: 'b'.repeat(32),
        name: 'saved_g11_set.json',
        schema_version: '1.0',
        source_tool: 'secagent_g11_generator',
        platform: 'secagent_ai_generator',
        bot: preset.id,
        run_id: 'gen-demo001',
        imported_at: '2026-11-26T09:00:00Z',
        file_sha256: '1'.repeat(64),
        total_testcases: 5,
      },
    ];

    render(
      <GeneratorModeWorkspace
        targets={[preset]}
        nonce={NONCE}
        initialMode="run_existing_dataset"
        existingDatasets={sampleDatasets}
        onOpenExistingScan={onOpenScan}
        onOpenDatasetLibrary={onOpenLib}
      />,
    );

    expect(screen.getByTestId('run-existing-dataset-panel')).toBeInTheDocument();
    expect(screen.getByText('saved_g11_set.json')).toBeInTheDocument();
    expect(fetchSpy).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId('existing-open-scan-link'));
    fireEvent.click(screen.getByTestId('existing-open-library-link'));
    expect(onOpenScan).toHaveBeenCalledTimes(1);
    expect(onOpenLib).toHaveBeenCalledTimes(1);
  });

  it('R01: blocks Save on Target or ASI/count/policy drift, preserves unsaved edits, and allows restoring original config', async () => {
    const targetA = { ...preset, id: 'target-alpha', name: 'Target Alpha' };
    const targetB = { ...preset, id: 'target-beta', name: 'Target Beta' };
    const previewA = mockPreviewSnapshot({ target_id: 'target-alpha' });
    const saveCalls: string[] = [];

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/testing/generator/status')) {
        return new Response(JSON.stringify(mockStatusResponse(true)));
      }
      if (url.endsWith('/api/testing/generator/generate')) {
        return new Response(
          JSON.stringify({ workflow_schema_version: '1.0.0', preview: previewA }),
          { status: 201 },
        );
      }
      if (url.endsWith('/save')) {
        saveCalls.push(url);
        return new Response(
          JSON.stringify({ workflow_schema_version: '1.0.0', save_record: mockSaveRecord() }),
          { status: 201 },
        );
      }
      return new Response('{}', { status: 404 });
    });

    render(
      <GeneratorModeWorkspace
        targets={[targetA, targetB]}
        nonce={NONCE}
        initialMode="generate_only"
        initialTargetId="target-alpha"
      />,
    );
    await screen.findByTestId('provider-status-summary');

    fireEvent.change(screen.getByLabelText('ASI01 testcase count'), { target: { value: '2' } });
    fireEvent.click(screen.getByTestId('generate-only-submit-btn'));
    await screen.findByTestId('generator-preview-section');
    expect(screen.getByTestId('preview-binding-summary')).toHaveTextContent('target-alpha');

    // Make an unsaved local edit and confirm save checkbox
    const promptInput = screen.getByLabelText('Prompt for gen-ui000001:asi01:001');
    fireEvent.change(promptInput, { target: { value: 'Unsaved local edit on Target A' } });
    fireEvent.click(screen.getByLabelText('Confirm explicit save to Dataset Library'));
    expect(screen.getByTestId('explicit-save-btn')).not.toBeDisabled();

    // Switch Target from A -> B: mismatch banner appears, Save is blocked, unsaved edit is preserved!
    fireEvent.change(screen.getByLabelText('Target'), { target: { value: 'target-beta' } });
    const mismatchBanner = screen.getByTestId('preview-config-mismatch-banner');
    expect(mismatchBanner).toHaveTextContent('target-alpha');
    expect(mismatchBanner).toHaveTextContent('unsaved local candidate edit');
    expect(screen.getByTestId('explicit-save-btn')).toBeDisabled();
    expect(promptInput).toHaveValue('Unsaved local edit on Target A');

    // Restore original preview configuration -> mismatch clears, Save re-enables
    fireEvent.click(screen.getByTestId('restore-preview-config-btn'));
    expect(screen.queryByTestId('preview-config-mismatch-banner')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Target')).toHaveValue('target-alpha');
    expect(screen.getByTestId('explicit-save-btn')).not.toBeDisabled();

    // Changing ASI selection or count also triggers mismatch and blocks Save
    fireEvent.click(screen.getByLabelText('Select ASI02'));
    expect(screen.getByTestId('preview-config-mismatch-banner')).toBeInTheDocument();
    expect(screen.getByTestId('explicit-save-btn')).toBeDisabled();

    fireEvent.click(screen.getByTestId('restore-preview-config-btn'));
    fireEvent.change(screen.getByLabelText('ASI01 testcase count'), { target: { value: '4' } });
    expect(screen.getByTestId('preview-config-mismatch-banner')).toBeInTheDocument();
    expect(screen.getByTestId('explicit-save-btn')).toBeDisabled();
    expect(saveCalls).toHaveLength(0);
  });

  it('R02: invalidates stale readiness on target switch and ignores out-of-order readiness responses', async () => {
    const targetA = { ...preset, id: 'target-alpha', name: 'Target Alpha' };
    const targetB = { ...preset, id: 'target-beta', name: 'Target Beta' };

    let resolveReadinessA!: (res: Response) => void;
    let resolveReadinessB!: (res: Response) => void;

    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input);
      if (url.endsWith('/api/testing/generator/status')) {
        return Promise.resolve(new Response(JSON.stringify(mockStatusResponse(true))));
      }
      if (url.endsWith('/api/testing/generator/readiness')) {
        const body = JSON.parse(String(init?.body ?? '{}'));
        if (body.target_id === 'target-alpha') {
          return new Promise<Response>((resolve) => {
            resolveReadinessA = resolve;
          });
        }
        return new Promise<Response>((resolve) => {
          resolveReadinessB = resolve;
        });
      }
      return Promise.resolve(new Response('{}', { status: 404 }));
    });

    render(
      <GeneratorModeWorkspace
        targets={[targetA, targetB]}
        nonce={NONCE}
        initialMode="generate_only"
        initialTargetId="target-alpha"
      />,
    );
    await screen.findByTestId('provider-status-summary');

    // Start Readiness A (stays pending)
    fireEvent.click(screen.getByRole('button', { name: 'Check Context Readiness' }));

    // Switch to Target B and start Readiness B
    fireEvent.change(screen.getByLabelText('Target'), { target: { value: 'target-beta' } });
    fireEvent.click(screen.getByRole('button', { name: 'Check Context Readiness' }));

    // Resolve B FIRST with status='ready'
    const reportB: TargetReadinessReport = {
      target_id: 'target-beta',
      target_exists: true,
      overall_status: 'ready',
      asi_assessments: {
        ASI01: {
          ...mockReadinessReport().asi_assessments.ASI01!,
          status: 'ready',
          blockers: [],
          warnings: [],
        },
      },
    };
    resolveReadinessB(
      new Response(JSON.stringify({ workflow_schema_version: '1.0.0', readiness: reportB })),
    );
    await waitFor(() => expect(screen.getByTestId('readiness-badge-ASI01')).toHaveTextContent('ready'));

    // Now resolve stale A LATE with status='blocked' -> MUST BE IGNORED!
    const reportA: TargetReadinessReport = {
      target_id: 'target-alpha',
      target_exists: true,
      overall_status: 'blocked',
      asi_assessments: {
        ASI01: {
          ...mockReadinessReport().asi_assessments.ASI01!,
          status: 'blocked',
          blockers: ['application_context_missing'],
        },
      },
    };
    resolveReadinessA(
      new Response(JSON.stringify({ workflow_schema_version: '1.0.0', readiness: reportA })),
    );

    // Target B's 'ready' badge remains intact; Target A's blocker never overwrites it
    await waitFor(() => expect(screen.getByTestId('readiness-badge-ASI01')).toHaveTextContent('ready'));
    expect(screen.queryByText(/application_context_missing/)).not.toBeInTheDocument();

    // Switching back to Target A immediately invalidates Target B's readiness badge
    fireEvent.change(screen.getByLabelText('Target'), { target: { value: 'target-alpha' } });
    expect(screen.queryByTestId('readiness-badge-ASI01')).not.toBeInTheDocument();
  });

  it('R02: prevents Generate during pending Edit/Save and blocks double-click duplicate Save', async () => {
    const basePreview = mockPreviewSnapshot();
    const editedPreview = mockPreviewSnapshot({
      edited_count: 1,
      candidates: [
        {
          ...basePreview.candidates[0],
          origin: 'operator_edited',
          operator_edited: true,
          effective_prompt: 'Edited before save',
          effective_prompt_sha256: 'e'.repeat(64),
        },
        basePreview.candidates[1],
      ],
    });

    let resolveEdit!: (res: Response) => void;
    let resolveSave!: (res: Response) => void;
    let editCallCount = 0;
    let saveCallCount = 0;

    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input);
      if (url.endsWith('/api/testing/generator/status')) {
        return Promise.resolve(new Response(JSON.stringify(mockStatusResponse(true))));
      }
      if (url.endsWith('/api/testing/generator/generate')) {
        return Promise.resolve(
          new Response(JSON.stringify({ workflow_schema_version: '1.0.0', preview: basePreview }), {
            status: 201,
          }),
        );
      }
      if (url.endsWith('/edit')) {
        editCallCount += 1;
        return new Promise<Response>((resolve) => {
          resolveEdit = resolve;
        });
      }
      if (url.endsWith('/save')) {
        saveCallCount += 1;
        return new Promise<Response>((resolve) => {
          resolveSave = resolve;
        });
      }
      return Promise.resolve(new Response('{}', { status: 404 }));
    });

    render(<GeneratorModeWorkspace targets={[preset]} nonce={NONCE} initialMode="generate_only" />);
    await screen.findByTestId('provider-status-summary');

    fireEvent.change(screen.getByLabelText('ASI01 testcase count'), { target: { value: '2' } });
    fireEvent.click(screen.getByTestId('generate-only-submit-btn'));
    await screen.findByTestId('generator-preview-section');

    // Create a pending edit so Save must flush /edit before calling /save
    fireEvent.change(screen.getByLabelText('Prompt for gen-ui000001:asi01:001'), {
      target: { value: 'Edited before save' },
    });
    fireEvent.click(screen.getByLabelText('Confirm explicit save to Dataset Library'));

    // Rapid double-click on Save BEFORE /edit resolves!
    const saveBtn = screen.getByTestId('explicit-save-btn');
    fireEvent.click(saveBtn);
    fireEvent.click(saveBtn);

    // While Save (and its pre-save /edit) is in flight, Generate Preview MUST be disabled
    expect(screen.getByTestId('generate-only-submit-btn')).toBeDisabled();
    expect(saveBtn).toBeDisabled();
    expect(editCallCount).toBe(1);

    // Resolve /edit, then resolve /save
    resolveEdit(new Response(JSON.stringify({ workflow_schema_version: '1.0.0', preview: editedPreview })));
    await waitFor(() => expect(saveCallCount).toBe(1));

    resolveSave(
      new Response(JSON.stringify({ workflow_schema_version: '1.0.0', save_record: mockSaveRecord() }), {
        status: 201,
      }),
    );
    await screen.findByTestId('save-success-banner');
    expect(editCallCount).toBe(1);
    expect(saveCallCount).toBe(1);
  });
});

import App from './App';
import type { GenerateAndRunSnapshot } from './generatorApi';

function mockLiveWorkflow(
  overrides: Partial<GenerateAndRunSnapshot> = {},
): GenerateAndRunSnapshot {
  const dsId = 'd'.repeat(32);
  const runId = 'e'.repeat(32);
  return {
    workflow_id: 'gnr-' + '1'.repeat(32),
    mode: 'generate_and_run',
    submission_id: '2'.repeat(32),
    idempotent_replay: false,
    status: 'completed',
    current_stage: 'reporting',
    created_at: '2026-11-26T14:00:00Z',
    updated_at: '2026-11-26T14:00:05Z',
    completed_at: '2026-11-26T14:00:05Z',
    target_id: preset.id,
    target_revision_sha256: preset.profile_revision ?? '3'.repeat(64),
    application_context_revision_sha256: '4'.repeat(64),
    context_snapshot_sha256: '5'.repeat(64),
    selected_asi: ['ASI01'],
    requested_scopes: {},
    policy_ids_by_asi: {},
    language: 'en',
    evaluation_mode: 'rule_only',
    execution_mode: 'live',
    allow_partial_execution: false,
    stages: [
      { stage: 'generating', status: 'completed', started_at: '2026-11-26T14:00:00Z', finished_at: '2026-11-26T14:00:01Z', detail: 'Generated 2 candidate(s).', error_code: null, error_message: null },
      { stage: 'validating', status: 'completed', started_at: '2026-11-26T14:00:01Z', finished_at: '2026-11-26T14:00:01Z', detail: 'Accepted 2/2 testcase(s).', error_code: null, error_message: null },
      { stage: 'saving_dataset', status: 'completed', started_at: '2026-11-26T14:00:01Z', finished_at: '2026-11-26T14:00:02Z', detail: `Persisted immutable dataset ${dsId}.`, error_code: null, error_message: null },
      { stage: 'preflight', status: 'completed', started_at: '2026-11-26T14:00:02Z', finished_at: '2026-11-26T14:00:02Z', detail: 'Preflight passed.', error_code: null, error_message: null },
      { stage: 'executing', status: 'completed', started_at: '2026-11-26T14:00:02Z', finished_at: '2026-11-26T14:00:04Z', detail: 'Executed 2/2 testcase(s).', error_code: null, error_message: null },
      { stage: 'evaluating', status: 'completed', started_at: '2026-11-26T14:00:04Z', finished_at: '2026-11-26T14:00:05Z', detail: 'Evaluated 2 testcase(s).', error_code: null, error_message: null },
      { stage: 'reporting', status: 'completed', started_at: '2026-11-26T14:00:05Z', finished_at: '2026-11-26T14:00:05Z', detail: `Report persisted as ${runId}.`, error_code: null, error_message: null },
    ],
    generation_id: 'gen-live0001',
    provider_id: 'deepseek_http',
    model: 'deepseek-flash',
    generation_overall_status: 'completed',
    requested_count: 2,
    generated_count: 2,
    accepted_count: 2,
    rejected_count: 0,
    meets_requested_counts: true,
    partial_generation: false,
    rejection_reason_counts: {},
    asi_generation_summaries: {},
    generation_token_usage: { prompt_tokens: 100, completion_tokens: 150, total_tokens: 250 },
    quality_summary: null,
    auto_persisted: true,
    dataset_id: dsId,
    dataset_name: 'g11-auto-saved.json',
    dataset_file_sha256: '6'.repeat(64),
    testcase_ids: ['G11-ASI01-001', 'G11-ASI01-002'],
    run_id: runId,
    run_status: 'completed',
    executed_cases: 2,
    total_cases: 2,
    progress_percent: 100,
    verdict_counts: { PASS: 2 },
    evidence_summary: {},
    judge_metadata: null,
    evaluation_error_code: null,
    cases_summary: [],
    dataset_url: '#datasets',
    report_url: `#scan/${runId}`,
    report_export_url: `/api/testing/generic-runs/${runId}/report.json`,
    rerun_supported: true,
    rerun_history: [],
    resume_supported: false,
    resume_endpoint: `/api/testing/generic-runs/${runId}/resume/preview`,
    resume_note: 'Rerun executes the persisted dataset under a new run_id with zero Generator calls. Resume continues an interrupted run from Generic Runner checkpoints without regenerating prompts.',
    error_stage: null,
    error_code: null,
    error_message: null,
    provenance: {},
    ...overrides,
  };
}

describe('G11.6 — Live Generate & Run UI & App.tsx Integration', () => {
  it('unlocks Generate & Run, prevents double-click duplicate submit, renders all 7 stages, links dataset/report, and supports Rerun without Generator', async () => {
    let startCalls = 0;
    let rerunCalls = 0;
    let resolveStart!: (res: Response) => void;
    const completedWf = mockLiveWorkflow();
    const rerunRunId = 'f'.repeat(32);

    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input);
      if (url.endsWith('/api/testing/generator/status')) {
        return Promise.resolve(
          new Response(
            JSON.stringify({ ...mockStatusResponse(true), generate_and_run_available: true }),
          ),
        );
      }
      if (url.endsWith('/api/testing/generator/generate-and-run') && init?.method === 'POST') {
        startCalls += 1;
        return new Promise<Response>((resolve) => {
          resolveStart = resolve;
        });
      }
      if (url.endsWith('/rerun') && init?.method === 'POST') {
        rerunCalls += 1;
        return Promise.resolve(
          new Response(
            JSON.stringify({
              workflow_schema_version: '1.0.0',
              operation: 'rerun',
              generator_called: false,
              regenerated: false,
              dataset_id: completedWf.dataset_id,
              previous_run_id: completedWf.run_id,
              new_run_id: rerunRunId,
              workflow: { ...completedWf, run_id: rerunRunId },
            }),
            { status: 201 },
          ),
        );
      }
      return Promise.resolve(new Response('{}', { status: 404 }));
    });

    const onOpenDataset = vi.fn();
    const onOpenReport = vi.fn();
    render(
      <GeneratorModeWorkspace
        targets={[preset]}
        nonce={NONCE}
        onOpenDatasetLibrary={onOpenDataset}
        onOpenRunReport={onOpenReport}
      />,
    );

    await screen.findByTestId('g11-6-active-banner');
    const runBtn = screen.getByTestId('generate-and-run-submit-btn');
    // Disabled until operator checks authorization consent
    expect(runBtn).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/Confirm authorized Generate and Run scope/i));
    expect(runBtn).not.toBeDisabled();

    // Double-click guard: rapid double submit fires ONLY ONE POST
    fireEvent.click(runBtn);
    fireEvent.click(runBtn);
    expect(startCalls).toBe(1);
    expect(runBtn).toBeDisabled();

    resolveStart(
      new Response(JSON.stringify({ workflow_schema_version: '1.0.0', workflow: completedWf }), {
        status: 201,
      }),
    );

    await screen.findByTestId('generate-and-run-result');
    expect(screen.getByTestId('workflow-overall-status')).toHaveTextContent('completed');
    expect(screen.getByTestId('workflow-dataset-id')).toHaveTextContent(completedWf.dataset_id!);
    expect(screen.getByTestId('workflow-run-id')).toHaveTextContent(completedWf.run_id!);
    for (const stage of [
      'generating',
      'validating',
      'saving_dataset',
      'preflight',
      'executing',
      'evaluating',
      'reporting',
    ]) {
      expect(screen.getByTestId(`workflow-stage-${stage}`)).toHaveTextContent('Status: completed');
    }

    // Links to Dataset Library & Run Report work
    fireEvent.click(screen.getByTestId('workflow-open-dataset-link'));
    expect(onOpenDataset).toHaveBeenCalledWith(completedWf.dataset_id);
    fireEvent.click(screen.getByTestId('workflow-open-report-link'));
    expect(onOpenReport).toHaveBeenCalledWith(completedWf.run_id);

    // Rerun Saved Dataset calls /rerun without calling /generate or /generate-and-run
    fireEvent.click(screen.getByTestId('workflow-rerun-btn'));
    await screen.findByTestId('workflow-rerun-status');
    expect(rerunCalls).toBe(1);
    expect(startCalls).toBe(1);
    expect(screen.getByTestId('workflow-run-id')).toHaveTextContent(rerunRunId);
  });

  it('displays partial-stopped and stage-specific errors cleanly without claiming execution success', async () => {
    const partialWf = mockLiveWorkflow({
      status: 'partial_stopped',
      current_stage: 'validating',
      requested_count: 5,
      generated_count: 2,
      accepted_count: 2,
      rejected_count: 0,
      meets_requested_counts: false,
      partial_generation: true,
      auto_persisted: false,
      dataset_id: null,
      run_id: null,
      run_status: null,
      executed_cases: 0,
      total_cases: 0,
      rerun_supported: false,
      error_stage: 'validating',
      error_code: 'partial_generation_not_executed',
      error_message: 'Partial generation stopped before execution: accepted 2 of 5 requested.',
    });

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/api/testing/generator/status')) {
        return new Response(
          JSON.stringify({ ...mockStatusResponse(true), generate_and_run_available: true }),
        );
      }
      if (url.endsWith('/api/testing/generator/generate-and-run') && init?.method === 'POST') {
        return new Response(
          JSON.stringify({ workflow_schema_version: '1.0.0', workflow: partialWf }),
          { status: 201 },
        );
      }
      return new Response('{}', { status: 404 });
    });

    render(<GeneratorModeWorkspace targets={[preset]} nonce={NONCE} />);
    await screen.findByTestId('g11-6-active-banner');
    fireEvent.click(screen.getByLabelText(/Confirm authorized Generate and Run scope/i));
    fireEvent.click(screen.getByTestId('generate-and-run-submit-btn'));

    await screen.findByTestId('workflow-stage-error');
    expect(screen.getByTestId('workflow-overall-status')).toHaveTextContent('partial_stopped');
    expect(screen.getByTestId('workflow-stage-error')).toHaveTextContent('partial_generation_not_executed');
    expect(screen.getByTestId('workflow-dataset-id')).toHaveTextContent('Not saved');
    expect(screen.getByTestId('workflow-run-id')).toHaveTextContent('Not started');
  });

  it('routes legacy #generator bookmark cleanly into unified #scan (AI Generate source) and never triggers execution on source switch', async () => {
    location.hash = '#generator';
    const postUrls: string[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (init?.method === 'POST') postUrls.push(url);
      if (url.endsWith('/api/testing/health')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            status: 'ok',
            mode: 'controlled_execution_enabled',
            target_network_access: true,
            evaluation_modes: ['rule_only'],
            operator_mode: 'local_single_user',
            validation_nonce: NONCE,
            generic_runner_enabled: true,
          }),
        );
      }
      if (url.endsWith('/api/testing/targets')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            targets: [preset],
            protocols: [{ id: 'openai-chat', state: 'offline_configuration_supported' }],
          }),
        );
      }
      if (url.endsWith('/api/testing/datasets')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', datasets: [] }));
      }
      if (url.endsWith('/api/testing/generic-runs')) {
        return new Response(JSON.stringify({ workflow_schema_version: '1.0.0', runs: [] }));
      }
      if (url.endsWith('/api/testing/generator/status')) {
        return new Response(
          JSON.stringify({ ...mockStatusResponse(true), generate_and_run_available: true }),
        );
      }
      if (url.endsWith('/api/testing/generator/generate-and-run/workflows')) {
        return new Response(
          JSON.stringify({ workflow_schema_version: '1.0.0', workflows: [], active_reservations: [] }),
        );
      }
      return new Response('{}', { status: 404 });
    });

    render(<App />);
    // Legacy #generator bookmark highlights unified New Scan and opens on Source #1 (AI Generate)
    expect(screen.getByRole('link', { name: /New Scan/i })).toHaveAttribute('aria-current', 'page');
    await screen.findByTestId('generate-and-run-panel');

    // Switching across all unified test sources NEVER triggers generation or execution POSTs
    fireEvent.click(screen.getByTestId('ai-submode-generate_only'));
    await screen.findByTestId('generate-only-submit-btn');
    fireEvent.click(screen.getByTestId('source-tab-existing_dataset'));
    await screen.findByLabelText(/Select Imported Dataset/i);
    fireEvent.click(screen.getByTestId('source-tab-import_dataset'));
    await screen.findByTestId('inline-import-panel');
    fireEvent.click(screen.getByTestId('source-tab-ai_generate'));
    await screen.findByTestId('generate-only-submit-btn');

    expect(postUrls).toEqual([]);
    location.hash = '';
  });

  it('R02: recovers existing workflow after lost network response without duplicate POST and stores zero sensitive payloads', async () => {
    sessionStorage.clear();
    const recoveredWf = mockLiveWorkflow();
    const postSubmissionIds: string[] = [];
    const lookupSubmissionIds: string[] = [];

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/api/testing/generator/status')) {
        return new Response(
          JSON.stringify({ ...mockStatusResponse(true), generate_and_run_available: true }),
        );
      }
      if (url.endsWith('/api/testing/generator/generate-and-run') && init?.method === 'POST') {
        const body = JSON.parse(String(init.body));
        postSubmissionIds.push(body.submission_id);
        throw new TypeError('Failed to fetch');
      }
      const match = url.match(/\/api\/testing\/generator\/generate-and-run\/submission\/([a-f0-9]{32})$/);
      if (match) {
        lookupSubmissionIds.push(match[1]);
        // Inspect sessionStorage while pending recovery is active: must NOT contain focus notes or secrets
        const stored = sessionStorage.getItem('secagent_pending_gnr_submission') ?? '';
        expect(stored).not.toContain('secret-focus-note-sentinel');
        expect(stored).toContain(match[1]);
        return new Response(
          JSON.stringify({ workflow_schema_version: '1.0.0', workflow: { ...recoveredWf, submission_id: match[1] } }),
        );
      }
      return new Response('{}', { status: 404 });
    });

    render(<GeneratorModeWorkspace targets={[preset]} nonce={NONCE} />);
    await screen.findByTestId('g11-6-active-banner');
    fireEvent.change(screen.getByLabelText('Focus note'), {
      target: { value: 'secret-focus-note-sentinel' },
    });
    fireEvent.click(screen.getByLabelText(/Confirm authorized Generate and Run scope/i));
    fireEvent.click(screen.getByTestId('generate-and-run-submit-btn'));

    // Automatically recovers existing workflow via GET /submission/<same_id> with ZERO second POST
    await screen.findByTestId('workflow-recovery-notice');
    await screen.findByTestId('generate-and-run-result');
    expect(postSubmissionIds).toHaveLength(1);
    expect(lookupSubmissionIds).toEqual(postSubmissionIds);
    expect(sessionStorage.getItem('secagent_pending_gnr_submission')).toBeNull();
  });

  it('R02: keeps exact same submission_id when retrying after confirmed 404 on network timeout', async () => {
    sessionStorage.clear();
    const completedWf = mockLiveWorkflow();
    const postSubmissionIds: string[] = [];
    let attempt = 0;

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/api/testing/generator/status')) {
        return new Response(
          JSON.stringify({ ...mockStatusResponse(true), generate_and_run_available: true }),
        );
      }
      if (url.endsWith('/api/testing/generator/generate-and-run') && init?.method === 'POST') {
        attempt += 1;
        const body = JSON.parse(String(init.body));
        postSubmissionIds.push(body.submission_id);
        if (attempt === 1) {
          throw new DOMException('The operation was aborted', 'AbortError');
        }
        return new Response(
          JSON.stringify({ workflow_schema_version: '1.0.0', workflow: { ...completedWf, submission_id: body.submission_id } }),
          { status: 201 },
        );
      }
      if (url.includes('/api/testing/generator/generate-and-run/submission/')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            error: { code: 'workflow_submission_not_found', message: 'Not found' },
          }),
          { status: 404 },
        );
      }
      return new Response('{}', { status: 404 });
    });

    render(<GeneratorModeWorkspace targets={[preset]} nonce={NONCE} />);
    await screen.findByTestId('g11-6-active-banner');
    fireEvent.click(screen.getByLabelText(/Confirm authorized Generate and Run scope/i));
    fireEvent.click(screen.getByTestId('generate-and-run-submit-btn'));

    // After 404 lookup confirms server never received it, UI allows retry with EXACT SAME submission_id
    await screen.findByTestId('pending-submission-recovery');
    const retryBtn = screen.getByTestId('generate-and-run-submit-btn');
    expect(retryBtn).toHaveTextContent('Retry Generate & Run (Same Submission ID)');
    expect(retryBtn).not.toBeDisabled();

    fireEvent.click(retryBtn);
    await screen.findByTestId('generate-and-run-result');
    expect(postSubmissionIds).toHaveLength(2);
    expect(postSubmissionIds[0]).toBe(postSubmissionIds[1]);
  });

  it('Judge-centric default: defaults to hybrid when Judge is ready, and never silently downgrades hybrid when Judge is unavailable', async () => {
    sessionStorage.clear();
    const submittedModes: string[] = [];
    const completedWf = mockLiveWorkflow({ evaluation_mode: 'hybrid' });

    // Case 1: Judge ready -> defaults to hybrid!
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/api/testing/generator/status')) {
        return new Response(
          JSON.stringify({
            ...mockStatusResponse(true),
            generate_and_run_available: true,
            judge: {
              judge_configured: true,
              credential_available: true,
              judge_ready: true,
              provider: 'deepseek',
              model: 'deepseek-v4-flash',
              reason: 'ready',
            },
          }),
        );
      }
      if (url.endsWith('/api/testing/generator/generate-and-run') && init?.method === 'POST') {
        const body = JSON.parse(String(init.body));
        submittedModes.push(body.evaluation_mode);
        return new Response(
          JSON.stringify({ workflow_schema_version: '1.0.0', workflow: completedWf }),
          { status: 201 },
        );
      }
      return new Response('{}', { status: 404 });
    });

    const { unmount } = render(<GeneratorModeWorkspace targets={[preset]} nonce={NONCE} />);
    await screen.findByTestId('judge-readiness-status');
    const evalSelect = screen.getByLabelText('Planned evaluation mode') as HTMLSelectElement;
    await waitFor(() => expect(evalSelect.value).toBe('hybrid'));
    fireEvent.click(screen.getByLabelText(/Confirm authorized Generate and Run scope/i));
    fireEvent.click(screen.getByTestId('generate-and-run-submit-btn'));
    await screen.findByTestId('generate-and-run-result');
    expect(submittedModes).toEqual(['hybrid']);
    unmount();

    // Case 2: Judge unavailable -> stays hybrid (NO silent downgrade to rule_only), blocks submit until operator explicitly chooses rule_only
    vi.restoreAllMocks();
    const submittedCase2: string[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/api/testing/generator/status')) {
        return new Response(
          JSON.stringify({
            ...mockStatusResponse(true),
            generate_and_run_available: true,
            judge: {
              judge_configured: true,
              credential_available: false,
              judge_ready: false,
              provider: 'deepseek',
              model: 'deepseek-v4-flash',
              reason: 'credential_missing',
            },
          }),
        );
      }
      if (url.endsWith('/api/testing/generator/generate-and-run') && init?.method === 'POST') {
        const body = JSON.parse(String(init.body));
        submittedCase2.push(body.evaluation_mode);
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            workflow: { ...completedWf, evaluation_mode: 'rule_only' },
          }),
          { status: 201 },
        );
      }
      return new Response('{}', { status: 404 });
    });

    render(<GeneratorModeWorkspace targets={[preset]} nonce={NONCE} />);
    await screen.findByTestId('hybrid-judge-unavailable-alert');
    const select2 = screen.getByLabelText('Planned evaluation mode') as HTMLSelectElement;
    expect(select2.value).toBe('hybrid');
    fireEvent.click(screen.getByLabelText(/Confirm authorized Generate and Run scope/i));
    expect(screen.getByTestId('generate-and-run-submit-btn')).toBeDisabled();

    // Operator explicitly opts into rule_only -> unlocks and submits rule_only
    fireEvent.change(select2, { target: { value: 'rule_only' } });
    expect(screen.queryByTestId('hybrid-judge-unavailable-alert')).not.toBeInTheDocument();
    expect(screen.getByTestId('generate-and-run-submit-btn')).not.toBeDisabled();
    fireEvent.click(screen.getByTestId('generate-and-run-submit-btn'));
    await screen.findByTestId('generate-and-run-result');
    expect(submittedCase2).toEqual(['rule_only']);
  });

  it('Issue A: disables Rerun button while workflow is running and prevents active rerun requests', async () => {
    sessionStorage.clear();
    let rerunCalls = 0;
    const runningWf = mockLiveWorkflow({
      status: 'running',
      current_stage: 'executing',
      run_status: 'running',
      executed_cases: 0,
      progress_percent: 0,
      rerun_supported: false,
    });

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/api/testing/generator/status')) {
        return new Response(
          JSON.stringify({ ...mockStatusResponse(true), generate_and_run_available: true }),
        );
      }
      if (url.endsWith('/api/testing/generator/generate-and-run') && init?.method === 'POST') {
        return new Response(
          JSON.stringify({ workflow_schema_version: '1.0.0', workflow: runningWf }),
          { status: 202 },
        );
      }
      if (url.endsWith('/rerun')) {
        rerunCalls += 1;
        return new Response('{}', { status: 409 });
      }
      if (url.includes(`/api/testing/generator/generate-and-run/${runningWf.workflow_id}`)) {
        return new Response(
          JSON.stringify({ workflow_schema_version: '1.0.0', workflow: runningWf }),
        );
      }
      return new Response('{}', { status: 404 });
    });

    render(<GeneratorModeWorkspace targets={[preset]} nonce={NONCE} />);
    await screen.findByTestId('g11-6-active-banner');
    fireEvent.click(screen.getByLabelText(/Confirm authorized Generate and Run scope/i));
    fireEvent.click(screen.getByTestId('generate-and-run-submit-btn'));

    await screen.findByTestId('generate-and-run-result');
    const rerunBtn = screen.getByTestId('workflow-rerun-btn');
    expect(rerunBtn).toBeDisabled();
    expect(rerunBtn).toHaveTextContent('Rerun Unavailable While Active');
    fireEvent.click(rerunBtn);
    expect(rerunCalls).toBe(0);
  });

  it('Issue B: distinguishes 410 expired submission from 404 unknown and never auto-retries expired submission_id', async () => {
    sessionStorage.clear();
    const postSubmissionIds: string[] = [];
    const completedWf = mockLiveWorkflow();
    let postCount = 0;

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/api/testing/generator/status')) {
        return new Response(
          JSON.stringify({ ...mockStatusResponse(true), generate_and_run_available: true }),
        );
      }
      if (url.endsWith('/api/testing/generator/generate-and-run') && init?.method === 'POST') {
        postCount += 1;
        const body = JSON.parse(String(init.body));
        postSubmissionIds.push(body.submission_id);
        if (postCount === 1) {
          throw new TypeError('Failed to fetch');
        }
        return new Response(
          JSON.stringify({ workflow_schema_version: '1.0.0', workflow: completedWf }),
          { status: 201 },
        );
      }
      if (url.includes('/api/testing/generator/generate-and-run/submission/')) {
        return new Response(
          JSON.stringify({
            workflow_schema_version: '1.0.0',
            error: { code: 'workflow_submission_expired', message: 'Submission snapshot expired.' },
          }),
          { status: 410 },
        );
      }
      return new Response('{}', { status: 404 });
    });

    render(<GeneratorModeWorkspace targets={[preset]} nonce={NONCE} />);
    await screen.findByTestId('g11-6-active-banner');
    fireEvent.click(screen.getByLabelText(/Confirm authorized Generate and Run scope/i));
    fireEvent.click(screen.getByTestId('generate-and-run-submit-btn'));

    // 410 expired MUST lock Submit and NOT show "Retry with Same Submission ID"
    await screen.findByTestId('pending-submission-recovery');
    expect(screen.getByTestId('pending-submission-recovery')).toHaveTextContent('status: expired');
    expect(screen.getByTestId('generate-and-run-submit-btn')).toBeDisabled();
    expect(screen.getByTestId('generate-and-run-submit-btn')).not.toHaveTextContent(
      'Same Submission ID',
    );
    expect(screen.getByTestId('discard-recovery-btn')).toHaveTextContent(
      'Acknowledge Expired Submission & Start Fresh',
    );

    // After explicit operator acknowledgement, starting a fresh run MUST use a brand-new submission_id
    fireEvent.click(screen.getByTestId('discard-recovery-btn'));
    expect(screen.getByTestId('generate-and-run-submit-btn')).not.toBeDisabled();
    fireEvent.click(screen.getByTestId('generate-and-run-submit-btn'));
    await screen.findByTestId('generate-and-run-result');
    expect(postSubmissionIds).toHaveLength(2);
    expect(postSubmissionIds[1]).not.toBe(postSubmissionIds[0]);
  });
});
