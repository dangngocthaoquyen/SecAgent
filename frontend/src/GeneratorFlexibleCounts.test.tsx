import { describe, expect, it, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { useState } from 'react';
import GeneratorOnlyPanel from './GeneratorOnlyPanel';
import GenerateAndRunPrepPanel from './GenerateAndRunPrepPanel';
import {
  GENERATOR_LIMITS,
  createDefaultGeneratorConfig,
  extractActiveCounts,
  generatorApi,
  type GeneratorConfigState,
  type GeneratorProviderStatus,
  type TargetReadinessReport,
} from './generatorApi';
import type { TargetPreset } from './testingApi';

const SAMPLE_TARGET: TargetPreset = {
  id: 'flex-target',
  name: 'Flex Target',
  platform_id: 'test-platform',
  platform_name: 'Test Platform',
  protocol: 'openai-chat',
  endpoint: 'http://127.0.0.1:18080/v1/chat/completions',
  default_model: 'demo-bot',
  models: ['demo-bot'],
  timeout_default: 15,
  timeout_min: 1,
  timeout_max: 60,
  capabilities: ['chat'],
  authorization_status: 'reviewed_for_offline_configuration',
  profile_revision: 'a'.repeat(64),
  policy_ref: 'flex-policy',
  method: 'POST',
  request_mapping: 'openai-chat-user-message-v1',
  response_parser: 'choices.0.message.content',
  credential_alias: null,
  credential_availability: 'not_required',
  connection_probe: {
    status: 'supported',
    reason: 'reviewed_exact_endpoint',
    active_probe_authorized: true,
    security_execution_authorized: false,
  },
  capability_basis: 'configured_claim_not_probed',
  limitations: [],
};

const READY_PROVIDER: GeneratorProviderStatus = {
  provider_id: 'mock',
  model: 'mock-generator-v1',
  configured: true,
  credential_available: true,
  ready: true,
  reason: 'ready',
  supports_json_mode: true,
  max_output_tokens_ceiling: 8192,
  retry_policy: 'caller_managed_single_attempt',
};

const READY_READINESS: TargetReadinessReport = {
  target_id: 'flex-target',
  target_exists: true,
  overall_status: 'ready',
  asi_assessments: {
    ASI01: {
      asi_code: 'ASI01',
      asi_category: 'goal_hijacking',
      status: 'ready',
      effective_scope: 'goal_hijack_response',
      scope_capability_state: 'supported',
      scope_capability_provenance: 'operator_declared',
      blockers: [],
      warnings: [],
      has_reviewed_policy: true,
      reviewed_policy_id: 'pol-asi01',
      reviewed_policy_revision_sha256: 'b'.repeat(64),
      ambiguous_policy_candidates: [],
      requested_scope: null,
      deterministic_limitations: [],
      findings: [],
    },
    ASI02: {
      asi_code: 'ASI02',
      asi_category: 'tool_misuse',
      status: 'ready',
      effective_scope: 'tool_intent_response',
      scope_capability_state: 'supported',
      scope_capability_provenance: 'operator_declared',
      blockers: [],
      warnings: [],
      has_reviewed_policy: true,
      reviewed_policy_id: 'pol-asi02',
      reviewed_policy_revision_sha256: 'b'.repeat(64),
      ambiguous_policy_candidates: [],
      requested_scope: null,
      deterministic_limitations: [],
      findings: [],
    },
    ASI03: {
      asi_code: 'ASI03',
      asi_category: 'identity_privilege_abuse',
      status: 'ready',
      effective_scope: 'identity_claim_response',
      scope_capability_state: 'supported',
      scope_capability_provenance: 'operator_declared',
      blockers: [],
      warnings: [],
      has_reviewed_policy: true,
      reviewed_policy_id: 'pol-asi03',
      reviewed_policy_revision_sha256: 'b'.repeat(64),
      ambiguous_policy_candidates: [],
      requested_scope: null,
      deterministic_limitations: [],
      findings: [],
    },
    ASI05: {
      asi_code: 'ASI05',
      asi_category: 'unexpected_code_execution',
      status: 'ready',
      effective_scope: 'response_command_artifact',
      scope_capability_state: 'supported',
      scope_capability_provenance: 'operator_declared',
      blockers: [],
      warnings: [],
      has_reviewed_policy: true,
      reviewed_policy_id: 'pol-asi05',
      reviewed_policy_revision_sha256: 'b'.repeat(64),
      ambiguous_policy_candidates: [],
      requested_scope: null,
      deterministic_limitations: [],
      findings: [],
    },
  },
};

function GenerateOnlyHarness() {
  const [config, setConfig] = useState<GeneratorConfigState>(() =>
    createDefaultGeneratorConfig('flex-target'),
  );
  return (
    <GeneratorOnlyPanel
      targets={[SAMPLE_TARGET]}
      config={config}
      onChangeConfig={setConfig}
      nonce={'n'.repeat(43)}
      providerStatus={READY_PROVIDER}
      readiness={READY_READINESS}
      readinessLoading={false}
      onCheckReadiness={() => {}}
    />
  );
}

function GenerateAndRunHarness() {
  const [config, setConfig] = useState<GeneratorConfigState>(() =>
    createDefaultGeneratorConfig('flex-target'),
  );
  return (
    <GenerateAndRunPrepPanel
      targets={[SAMPLE_TARGET]}
      config={config}
      onChangeConfig={setConfig}
      nonce={'n'.repeat(43)}
      generateAndRunAvailable={true}
      providerStatus={READY_PROVIDER}
      judgeStatus={{
        judge_configured: true,
        credential_available: true,
        judge_ready: true,
        provider: 'deepseek',
        model: 'deepseek-flash',
        reason: 'ready',
      }}
      readiness={READY_READINESS}
      readinessLoading={false}
      onCheckReadiness={() => {}}
    />
  );
}

describe('Generator Flexible Per-ASI Counts (Phase 1)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    window.sessionStorage.clear();
  });

  it('validates all acceptance boundaries (1, 20, 49, 50, 51, single & multi-ASI) and ignores unchecked ASIs', () => {
    expect(GENERATOR_LIMITS.minPerAsi).toBe(1);
    expect(GENERATOR_LIMITS.defaultPerAsi).toBe(5);
    expect(GENERATOR_LIMITS.maxPerAsi).toBe(50);
    expect(GENERATOR_LIMITS.maxTotalCases).toBe(50);

    const base = createDefaultGeneratorConfig('flex-target');
    expect(base.countsByAsi.ASI01).toBe(5);
    expect(base.countsByAsi.ASI03).toBe(5);

    // Single-ASI allowed boundaries: 1, 20, 49, 50
    for (const val of [1, 20, 49, 50]) {
      const res = extractActiveCounts({
        ...base,
        selectedAsi: { ASI01: false, ASI02: false, ASI03: true, ASI05: false },
        countsByAsi: { ...base.countsByAsi, ASI03: val, ASI01: 40 }, // unchecked ASI01=40 MUST NOT count
      });
      expect(res.error).toBeNull();
      expect(res.total).toBe(val);
      expect(res.counts).toEqual({ ASI03: val });
    }

    // Multi-ASI allowed combinations: 20+20=40 and 10+20+20=50
    const combo40 = extractActiveCounts({
      ...base,
      selectedAsi: { ASI01: false, ASI02: false, ASI03: true, ASI05: true },
      countsByAsi: { ...base.countsByAsi, ASI03: 20, ASI05: 20 },
    });
    expect(combo40.error).toBeNull();
    expect(combo40.total).toBe(40);
    expect(combo40.counts).toEqual({ ASI03: 20, ASI05: 20 });

    const combo50 = extractActiveCounts({
      ...base,
      selectedAsi: { ASI01: true, ASI02: false, ASI03: true, ASI05: true },
      countsByAsi: { ...base.countsByAsi, ASI01: 10, ASI03: 20, ASI05: 20 },
    });
    expect(combo50.error).toBeNull();
    expect(combo50.total).toBe(50);
    expect(combo50.counts).toEqual({ ASI01: 10, ASI03: 20, ASI05: 20 });

    // Rejected: 30 + 30 = 60 > 50
    const over60 = extractActiveCounts({
      ...base,
      selectedAsi: { ASI01: false, ASI02: false, ASI03: true, ASI05: true },
      countsByAsi: { ...base.countsByAsi, ASI03: 30, ASI05: 30 },
    });
    expect(over60.total).toBe(60);
    expect(over60.error).toContain('Total requested testcases (60) exceeds the maximum limit of 50.');

    // Rejected: 51 > 50 (still reports accurate Total: 51)
    const over51 = extractActiveCounts({
      ...base,
      selectedAsi: { ASI01: false, ASI02: false, ASI03: true, ASI05: false },
      countsByAsi: { ...base.countsByAsi, ASI03: 51 },
    });
    expect(over51.total).toBe(51);
    expect(over51.error).toContain('ASI03 count must be an integer between 1 and 50.');
  });

  it('enforces flexible 1..50 counts, live total/errors, and unchecked-ASI preservation in Generate Only', async () => {
    const genSpy = vi.spyOn(generatorApi, 'generate').mockResolvedValue({
      preview_id: 'prev-' + 'a'.repeat(32),
      status: 'active',
      created_at: '2026-11-27T00:00:00Z',
      updated_at: '2026-11-27T00:00:00Z',
      expires_at: '2026-11-27T00:30:00Z',
      generation_id: 'gen-1234567890abcdef',
      target_id: 'flex-target',
      target_revision_sha256: 'a'.repeat(64),
      application_context_revision_sha256: 'b'.repeat(64),
      context_snapshot_sha256: 'c'.repeat(64),
      reviewed_policy_revisions: {},
      provider_id: 'mock',
      model: 'mock-generator-v1',
      language: 'en',
      deduplicate_across_asi: false,
      overall_status: 'completed',
      meets_requested_counts: true,
      has_accepted_candidates: true,
      can_save: true,
      requires_partial_confirmation: false,
      total_requested: 50,
      total_generated: 50,
      total_accepted: 50,
      total_rejected: 0,
      selected_count: 50,
      edited_count: 0,
      total_call_count: 1,
      total_duration_ms: 10,
      total_token_usage: null,
      asi_order: ['ASI03'],
      asi_summaries: {},
      candidates: [],
      rejection_reason_counts: {},
      save_record: null,
      auto_persisted: false,
      auto_executed: false,
    });

    render(<GenerateOnlyHarness />);
    const asi01Check = screen.getByLabelText('Select ASI01');
    const asi03Check = screen.getByLabelText('Select ASI03');
    const asi05Check = screen.getByLabelText('Select ASI05');
    const asi03Input = screen.getByLabelText('ASI03 testcase count') as HTMLInputElement;
    const asi05Input = screen.getByLabelText('ASI05 testcase count') as HTMLInputElement;
    const submitBtn = screen.getByTestId('generate-only-submit-btn');

    expect(asi03Input.max).toBe('50');

    // Uncheck ASI01, check ASI03 & ASI05, enter 30 + 30 -> rejected & disabled
    fireEvent.click(asi01Check);
    fireEvent.click(asi03Check);
    fireEvent.click(asi05Check);
    fireEvent.change(asi03Input, { target: { value: '30' } });
    fireEvent.change(asi05Input, { target: { value: '30' } });

    expect(screen.getByTestId('total-requested-count')).toHaveTextContent('Total: 60 / 50');
    expect(screen.getByRole('alert')).toHaveTextContent('Total requested testcases (60) exceeds the maximum limit of 50.');
    expect(submitBtn).toBeDisabled();

    // Unchecking ASI05 removes 30 from total WITHOUT altering ASI05's typed count (30)
    fireEvent.click(asi05Check);
    expect(screen.getByTestId('total-requested-count')).toHaveTextContent('Total: 30 / 50');
    expect(asi05Input.value).toBe('30');
    expect(submitBtn).not.toBeDisabled();

    // Entering 51 on ASI03 -> shows Total: 51 / 50 and blocks Generate
    fireEvent.change(asi03Input, { target: { value: '51' } });
    expect(screen.getByTestId('total-requested-count')).toHaveTextContent('Total: 51 / 50');
    expect(screen.getByRole('alert')).toHaveTextContent('ASI03 count must be an integer between 1 and 50.');
    expect(submitBtn).toBeDisabled();

    // Entering 50 on ASI03 -> allowed and submits { ASI03: 50 }
    fireEvent.change(asi03Input, { target: { value: '50' } });
    expect(screen.getByTestId('total-requested-count')).toHaveTextContent('Total: 50 / 50');
    expect(submitBtn).not.toBeDisabled();

    fireEvent.click(submitBtn);
    await waitFor(() => expect(genSpy).toHaveBeenCalledTimes(1));
    expect(genSpy.mock.calls[0][0].counts_by_asi).toEqual({ ASI03: 50 });
  });

  it('blocks Generate & Run when total exceeds 50 and submits ASI05=50 cleanly', async () => {
    vi.spyOn(generatorApi, 'listGenerateAndRunWorkflows').mockResolvedValue({
      workflow_schema_version: '1.0.0',
      workflows: [],
      active_reservations: [],
    });
    const startSpy = vi.spyOn(generatorApi, 'startGenerateAndRun').mockResolvedValue({
      workflow_id: 'gnr-' + 'b'.repeat(32),
      mode: 'generate_and_run',
      submission_id: '1'.repeat(32),
      idempotent_replay: false,
      status: 'running',
      current_stage: 'generating',
      created_at: '2026-11-27T00:00:00Z',
      updated_at: '2026-11-27T00:00:00Z',
      completed_at: null,
      target_id: 'flex-target',
      target_revision_sha256: 'a'.repeat(64),
      application_context_revision_sha256: 'b'.repeat(64),
      context_snapshot_sha256: 'c'.repeat(64),
      selected_asi: ['ASI05'],
      requested_scopes: {},
      policy_ids_by_asi: {},
      language: 'en',
      evaluation_mode: 'hybrid',
      initial_evaluation_mode: 'hybrid',
      execution_mode: 'live',
      allow_partial_execution: false,
      stages: [],
      generation_id: null,
      provider_id: 'mock',
      model: 'mock-generator-v1',
      generation_overall_status: null,
      requested_count: 50,
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
      partial_execution: false,
      preflight_selected_cases: 0,
      preflight_ready_count: 0,
      preflight_skipped_count: 0,
      preflight_unsupported_count: 0,
      preflight_skipped_reasons: [],
      run_id: null,
      run_status: null,
      executed_cases: 0,
      total_cases: 0,
      progress_percent: 0,
      verdict_counts: {},
      evidence_summary: {},
      judge_metadata: null,
      cases_summary: [],
      dataset_url: null,
      report_url: null,
      report_export_url: null,
      error_stage: null,
      error_code: null,
      error_message: null,
      evaluation_error_code: null,
      rerun_supported: false,
      resume_supported: false,
      resume_endpoint: null,
      resume_note: '',
      rerun_history: [],
      provenance: {},
    });

    render(<GenerateAndRunHarness />);
    const authCheckbox = screen.getByLabelText('Confirm authorized Generate and Run scope');
    fireEvent.click(authCheckbox);

    const asi01Check = screen.getByLabelText('Select ASI01');
    const asi03Check = screen.getByLabelText('Select ASI03');
    const asi05Check = screen.getByLabelText('Select ASI05');
    const asi03Input = screen.getByLabelText('ASI03 testcase count');
    const asi05Input = screen.getByLabelText('ASI05 testcase count');
    const submitBtn = screen.getByTestId('generate-and-run-submit-btn');

    // ASI01=5 (checked) + ASI03=30 + ASI05=30 -> Total 65 / 50 -> blocked
    fireEvent.click(asi03Check);
    fireEvent.click(asi05Check);
    fireEvent.change(asi03Input, { target: { value: '30' } });
    fireEvent.change(asi05Input, { target: { value: '30' } });
    expect(screen.getByTestId('total-requested-count')).toHaveTextContent('Total: 65 / 50');
    expect(submitBtn).toBeDisabled();

    // Uncheck ASI01 & ASI03, set ASI05=50 -> enabled & submits { ASI05: 50 }
    fireEvent.click(asi01Check);
    fireEvent.click(asi03Check);
    fireEvent.change(asi05Input, { target: { value: '50' } });
    expect(screen.getByTestId('total-requested-count')).toHaveTextContent('Total: 50 / 50');
    expect(submitBtn).not.toBeDisabled();

    fireEvent.click(submitBtn);
    await waitFor(() => expect(startSpy).toHaveBeenCalledTimes(1));
    expect(startSpy.mock.calls[0][0].counts_by_asi).toEqual({ ASI05: 50 });
  });
});
