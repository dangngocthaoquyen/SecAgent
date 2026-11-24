import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import DiscoveryPanel from './DiscoveryPanel';
import ScanPreviewPanel from './ScanPreviewPanel';
import TargetManager from './TargetManager';
import { testingApi, type DiscoveryResult, type GenericRunPreview } from './testingApi';

describe('G08 Universal HTTP Target & Assisted OpenAPI Discovery UI', () => {
  it('renders discovered OpenAPI candidates and hands off an http-json draft on explicit selection', async () => {
    const discoveryRow: DiscoveryResult = {
      discovery_id: 'a'.repeat(32),
      input_url: 'http://127.0.0.1:8000/',
      canonical_endpoint: null,
      status: 'metadata_found',
      connection_status: 'reachable',
      request_count: 3,
      request_budget: 3,
      metadata_sources: [
        { url: 'http://127.0.0.1:8000/v1/models', status: 'missing', classification: 'unverified' },
        { url: 'http://127.0.0.1:8000/openapi.json', status: 'advertised', classification: 'advertised_metadata' },
        { url: 'http://127.0.0.1:8000/.well-known/agent.json', status: 'missing', classification: 'unverified' },
      ],
      protocol_candidates: [
        { id: 'openapi-http', classification: 'advertised_metadata', source: 'http://127.0.0.1:8000/openapi.json', runtime_verified: false },
      ],
      openapi_candidates: [
        {
          path: '/api/agent/runs',
          endpoint: 'http://127.0.0.1:8000/api/agent/runs',
          method: 'POST',
          operation_id: 'create_agent_run',
          summary: 'Run Agent Lab',
          requires_auth: true,
          input_field: 'goal',
          unresolved_required_fields: ['lab_id'],
          response_text_path_discovered: true,
          suggested_http_config: {
            method: 'POST',
            body_template: { lab_id: '<REQUIRED:lab_id>', goal: '{{input}}', defense_level: 0 },
            headers: {},
            response: { text_path: 'answer', correlation_id_path: 'run_id', status_path: 'status' },
          },
          classification: 'advertised_metadata',
          runtime_verified: false,
          operator_confirmed: false,
        },
      ],
      advertised_models: [],
      advertised_agent: null,
      advertised_tools: [],
      advertised_skills: [],
      possible_contracts: [],
      protocol_hint: null,
      unknown_fields: ['unresolved_required_request_parameters', 'authentication_credential_alias'],
      warnings: ['OpenAPI candidates require explicit operator confirmation.'],
      recommendations: [],
      proposed_profile: null,
      security_test_executed: false,
      security_verdict: null,
    };

    const discoverSpy = vi.spyOn(testingApi, 'discover').mockResolvedValue(discoveryRow);
    const onUse = vi.fn().mockResolvedValue(undefined);
    render(<DiscoveryPanel nonce={'N'.repeat(43)} secret="secret" onUse={onUse} onReset={() => {}} />);

    fireEvent.change(screen.getByLabelText('AI Agent URL'), { target: { value: 'http://127.0.0.1:8000/' } });
    fireEvent.click(screen.getByLabelText(/I authorize up to three bounded metadata requests/i));
    fireEvent.click(screen.getByRole('button', { name: 'Discover & Test Connection' }));

    await waitFor(() => expect(discoverSpy).toHaveBeenCalled());
    // Must NOT auto-call onUse when proposed_profile is null (requires explicit selection).
    expect(onUse).not.toHaveBeenCalled();
    expect(screen.getByText(/Unresolved required fields: lab_id/i)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: /Select & Review Draft/i }));
    await waitFor(() =>
      expect(onUse).toHaveBeenCalledWith(
        expect.objectContaining({
          endpoint: 'http://127.0.0.1:8000/api/agent/runs',
          protocol: 'http-json',
          model: null,
        }),
        discoveryRow.discovery_id,
        discoveryRow,
        discoveryRow.openapi_candidates![0],
      ),
    );
    discoverSpy.mockRestore();
  });

  it('allows configuring a custom http-json profile with capability states without fabricating a model', async () => {
    const validateSpy = vi.spyOn(testingApi, 'validateManaged').mockResolvedValue(true);
    const saveSpy = vi.spyOn(testingApi, 'saveManaged').mockResolvedValue({
      id: 'custom-http-1',
      name: 'Custom HTTP Target',
      platform_id: 'custom',
      platform_name: 'Custom',
      profile_revision: 'b'.repeat(64),
      policy_ref: 'managed-lab-v1',
      authorization_status: 'review_required',
      endpoint: 'http://127.0.0.1:8000/api/agent/runs',
      protocol: 'http-json',
      method: 'POST',
      models: [],
      default_model: '',
      timeout_min: 1,
      timeout_max: 60,
      timeout_default: 30,
      credential_alias: null,
      credential_availability: 'not_required',
      request_mapping: 'http-json-template-v1',
      response_parser: 'answer',
      connection_probe: { status: 'unsupported', reason: 'safe_probe_not_verified', active_probe_authorized: false, security_execution_authorized: false },
      capabilities: ['http_json'],
      capability_basis: 'configured_claim_not_probed',
      limitations: [],
    });

    render(
      <TargetManager
        enabled={true}
        localSingleUser={true}
        nonce={'N'.repeat(43)}
        onChanged={() => {}}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Add Target' }));
    fireEvent.change(screen.getByLabelText('Protocol'), { target: { value: 'http-json' } });
    fireEvent.change(screen.getByLabelText('Platform identifier'), { target: { value: 'custom' } });
    fireEvent.change(screen.getByLabelText('Platform name'), { target: { value: 'Custom' } });
    fireEvent.change(screen.getByLabelText('Target identifier'), { target: { value: 'custom-http-1' } });
    fireEvent.change(screen.getByLabelText('Target display name'), { target: { value: 'Custom HTTP Target' } });
    fireEvent.change(screen.getByLabelText('Endpoint URL'), { target: { value: 'http://127.0.0.1:8000/api/agent/runs' } });
    fireEvent.change(screen.getByLabelText(/Actual runtime \/ code execution/i), { target: { value: 'unsupported' } });

    fireEvent.click(screen.getByRole('button', { name: 'Validate Target Details' }));
    await waitFor(() =>
      expect(validateSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          id: 'custom-http-1',
          protocol: 'http-json',
          model: null,
          capability_states: { runtime_execution: 'unsupported' },
        }),
        null,
        '',
        'N'.repeat(43),
      ),
    );
    fireEvent.click(screen.getByRole('button', { name: 'Save Configuration' }));
    await waitFor(() => expect(saveSpy).toHaveBeenCalled());
    validateSpy.mockRestore();
    saveSpy.mockRestore();
  });

  it('displays capability summary and evidence availability in ScanPreviewPanel', () => {
    const preview: GenericRunPreview = {
      workflow_schema_version: '1.0.0',
      mode: 'live',
      target_id: 'custom-http-1',
      target_name: 'Custom HTTP Target',
      asi_category: 'ASI05',
      use_judge: false,
      pi_judge_ready: false,
      capability_states: { response_behavior: 'supported', runtime_execution: 'unsupported' },
      capability_summary: {
        compatible_scopes: ['goal_hijack_response', 'response_command_artifact'],
        unsupported_scopes: ['execution_action'],
        unverified_scopes: ['agent_run'],
        evidence_availability: ['response_text', 'inline_structured_evidence'],
        limitations: ['Execution-level verdicts require independent execution evidence.'],
      },
      evidence_source_count: 0,
      ready_count: 1,
      blocked_count: 0,
      unsupported_count: 1,
      policy_id: null,
      policy_revision_sha256: null,
      policy_review_status: 'not_required',
      blocker: null,
      items: [{ case_id: 'C1', category: 'unexpected_code_execution', status: 'ready', reason: null, prompt_preview: 'hi' }],
    };
    render(
      <ScanPreviewPanel
        preview={preview}
        datasetDetail={null}
        scanMode="live"
        useJudge={false}
        datasetHasStoredResponses={false}
        judgeSetupReason="judge_configuration_missing"
        selectedCaseIds={['C1']}
        authorized={false}
        busy={false}
        onBackToStep1={() => {}}
        onChangeMode={() => {}}
        onChangeEngine={() => {}}
        onSelectCases={() => {}}
        onToggleAuthorized={() => {}}
        onStartScan={() => {}}
      />,
    );
    expect(screen.getByText(/inline_structured_evidence/i)).toBeTruthy();
    expect(screen.getByText(/Unsupported: execution_action/i)).toBeTruthy();
  });
});

describe('G08 Acceptance Corrections UI (FIX 1, FIX 2, FIX 3, FIX 6)', () => {
  it('FIX 1 & FIX 6: allows distinct http-json profile on shared endpoint and exposes status completeness inputs', async () => {
    const existingShared = {
      id: 'shared-lab-1',
      name: 'Shared Lab 1',
      platform_id: 'lab',
      platform_name: 'Lab',
      profile_revision: 'a'.repeat(64),
      policy_ref: 'managed-lab-v1',
      authorization_status: 'reviewed_for_offline_configuration' as const,
      endpoint: 'http://127.0.0.1:8000/api/agent/runs',
      protocol: 'http-json' as const,
      method: 'POST' as const,
      models: [],
      default_model: '',
      timeout_min: 1,
      timeout_max: 60,
      timeout_default: 30,
      credential_alias: null,
      credential_availability: 'not_required',
      request_mapping: 'http-json-template-v1' as const,
      response_parser: 'answer',
      http_config: {
        method: 'POST' as const,
        body_template: { lab_id: 'asi02-1', goal: '{{input}}' },
        headers: {},
        response: { text_path: 'answer', status_path: 'status', complete_status_values: ['completed'], incomplete_status_values: ['failed'] },
      },
      connection_probe: { status: 'unsupported' as const, reason: 'safe_probe_not_verified', active_probe_authorized: false, security_execution_authorized: false as const },
      capabilities: ['http_json'],
      capability_basis: 'configured_claim_not_probed',
      limitations: [],
    };
    const validateSpy = vi.spyOn(testingApi, 'validateManaged').mockResolvedValue(true);

    render(
      <TargetManager
        enabled={true}
        localSingleUser={true}
        nonce={'N'.repeat(43)}
        existingTargetIds={['shared-lab-1']}
        existingProfiles={[existingShared]}
        onChanged={() => {}}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Add Target' }));
    fireEvent.change(screen.getByLabelText('Protocol'), { target: { value: 'http-json' } });
    fireEvent.change(screen.getByLabelText('Platform identifier'), { target: { value: 'lab' } });
    fireEvent.change(screen.getByLabelText('Platform name'), { target: { value: 'Lab' } });
    fireEvent.change(screen.getByLabelText('Target identifier'), { target: { value: 'shared-lab-2' } });
    fireEvent.change(screen.getByLabelText('Target display name'), { target: { value: 'Shared Lab 2' } });
    fireEvent.change(screen.getByLabelText('Endpoint URL'), { target: { value: 'http://127.0.0.1:8000/api/agent/runs' } });
    fireEvent.change(screen.getByLabelText(/Request JSON body template/i), {
      target: { value: JSON.stringify({ lab_id: 'asi03-1', goal: '{{input}}' }) },
    });
    fireEvent.change(screen.getByLabelText(/Response status path/i), { target: { value: 'status' } });
    fireEvent.change(screen.getByLabelText(/^Complete status values/i), { target: { value: 'completed, DONE' } });
    fireEvent.change(screen.getByLabelText(/^Incomplete status values/i), { target: { value: 'awaiting_approval, failed' } });

    // Must NOT show existing-endpoint duplicate block because body_template differs!
    expect(screen.queryByText(/Existing target:/i)).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Validate Target Details' }));
    await waitFor(() =>
      expect(validateSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          id: 'shared-lab-2',
          http_config: expect.objectContaining({
            response: expect.objectContaining({
              status_path: 'status',
              complete_status_values: ['completed', 'DONE'],
              incomplete_status_values: ['awaiting_approval', 'failed'],
            }),
          }),
        }),
        null,
        '',
        'N'.repeat(43),
      ),
    );
    validateSpy.mockRestore();
  });

  it('FIX 2: blocks unresolved discovery placeholders until resolved via guided typed inputs', async () => {
    const discoveryRow: DiscoveryResult = {
      discovery_id: 'c'.repeat(32),
      input_url: 'http://127.0.0.1:8000/',
      canonical_endpoint: null,
      status: 'metadata_found',
      connection_status: 'reachable',
      request_count: 3,
      request_budget: 3,
      metadata_sources: [
        { url: 'http://127.0.0.1:8000/v1/models', status: 'missing', classification: 'unverified' },
        { url: 'http://127.0.0.1:8000/openapi.json', status: 'advertised', classification: 'advertised_metadata' },
        { url: 'http://127.0.0.1:8000/.well-known/agent.json', status: 'missing', classification: 'unverified' },
      ],
      protocol_candidates: [{ id: 'openapi-http', classification: 'advertised_metadata', source: 'http://127.0.0.1:8000/openapi.json', runtime_verified: false }],
      openapi_candidates: [
        {
          path: '/api/agent/runs',
          endpoint: 'http://127.0.0.1:8000/api/agent/runs',
          method: 'POST',
          operation_id: 'run_agent',
          summary: 'Run Agent',
          requires_auth: false,
          input_field: 'goal',
          unresolved_required_fields: ['lab_id', 'max_steps'],
          unresolved_required_field_specs: [
            { name: 'lab_id', type: 'string', location: 'body' },
            { name: 'max_steps', type: 'integer', location: 'body' },
          ],
          response_text_path_discovered: true,
          suggested_http_config: {
            method: 'POST',
            body_template: { lab_id: '<REQUIRED:lab_id>', max_steps: '<REQUIRED:max_steps>', goal: '{{input}}' },
            headers: {},
            response: { text_path: 'answer' },
          },
          classification: 'advertised_metadata',
          runtime_verified: false,
          operator_confirmed: false,
        },
      ],
      advertised_models: [],
      advertised_agent: null,
      advertised_tools: [],
      advertised_skills: [],
      possible_contracts: [],
      protocol_hint: null,
      unknown_fields: ['unresolved_required_request_parameters'],
      warnings: [],
      recommendations: [],
      proposed_profile: null,
      security_test_executed: false,
      security_verdict: null,
    };

    const discoverSpy = vi.spyOn(testingApi, 'discover').mockResolvedValue(discoveryRow);
    const validateSpy = vi.spyOn(testingApi, 'validateManaged').mockResolvedValue(true);

    render(
      <TargetManager
        enabled={true}
        localSingleUser={true}
        initialConnect={true}
        nonce={'N'.repeat(43)}
        onChanged={() => {}}
      />,
    );

    fireEvent.change(screen.getByLabelText('AI Agent URL'), { target: { value: 'http://127.0.0.1:8000/' } });
    fireEvent.click(screen.getByLabelText(/I authorize up to three bounded metadata requests/i));
    fireEvent.click(screen.getByRole('button', { name: 'Discover & Test Connection' }));

    await waitFor(() => expect(screen.getByRole('button', { name: /Select & Review Draft/i })).toBeTruthy());
    fireEvent.click(screen.getByRole('button', { name: /Select & Review Draft/i }));

    // Validate & Save MUST be disabled while unresolved placeholders exist!
    await waitFor(() => expect(screen.getByText(/Unresolved required discovery placeholders remain/i)).toBeTruthy());
    expect((screen.getByRole('button', { name: 'Validate Draft Details' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Save Target' }) as HTMLButtonElement).disabled).toBe(true);

    // Fill guided typed inputs -> preserves integer type for max_steps!
    fireEvent.change(screen.getByPlaceholderText(/Enter lab_id/i), { target: { value: 'asi02-1' } });
    fireEvent.change(screen.getByPlaceholderText(/Enter max_steps/i), { target: { value: '6' } });

    await waitFor(() => expect((screen.getByRole('button', { name: 'Validate Draft Details' }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole('button', { name: 'Validate Draft Details' }));

    await waitFor(() =>
      expect(validateSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          http_config: expect.objectContaining({
            body_template: { lab_id: 'asi02-1', max_steps: 6, goal: '{{input}}' },
          }),
        }),
        null,
        '',
        'N'.repeat(43),
        discoveryRow.discovery_id,
      ),
    );
    discoverSpy.mockRestore();
    validateSpy.mockRestore();
  });

  it('FIX 3: omits credential_alias when editing an existing authenticated legacy OpenAI target', async () => {
    const legacyTarget = {
      id: 'legacy-auth-1',
      name: 'Legacy Auth One',
      platform_id: 'dvaa',
      platform_name: 'DVAA',
      profile_revision: 'd'.repeat(64),
      policy_ref: 'managed-lab-v1',
      authorization_status: 'reviewed_for_offline_configuration' as const,
      endpoint: 'http://127.0.0.1:7001/v1/chat/completions',
      protocol: 'openai-chat' as const,
      method: 'POST' as const,
      models: ['m1'],
      default_model: 'm1',
      timeout_min: 1,
      timeout_max: 60,
      timeout_default: 30,
      credential_alias: 'registered_openai_alias',
      credential_availability: 'available',
      request_mapping: 'openai-chat-user-message-v1' as const,
      response_parser: 'choices.0.message.content',
      connection_probe: { status: 'supported' as const, reason: 'reviewed_exact_endpoint', active_probe_authorized: true, security_execution_authorized: false as const },
      capabilities: ['chat'],
      capability_basis: 'configured_claim_not_probed',
      limitations: [],
    };
    const validateSpy = vi.spyOn(testingApi, 'validateManaged').mockResolvedValue(true);

    render(
      <TargetManager
        enabled={true}
        localSingleUser={true}
        nonce={'N'.repeat(43)}
        target={legacyTarget}
        existingProfiles={[legacyTarget]}
        existingTargetIds={[legacyTarget.id]}
        onChanged={() => {}}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    expect(screen.getByText(/registered_openai_alias/i)).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Target display name'), { target: { value: 'Legacy Auth Renamed' } });
    fireEvent.click(screen.getByRole('button', { name: 'Validate Target Details' }));

    await waitFor(() => expect(validateSpy).toHaveBeenCalled());
    const submittedProfile = validateSpy.mock.calls[0][0];
    expect('credential_alias' in submittedProfile).toBe(false);
    validateSpy.mockRestore();
  });

  it('Correction 3: blocks Validate and Save for discovered requires_auth candidate until credential_alias is provided, and blocks unsupported auth schemes', async () => {
    const discoveryRow: DiscoveryResult = {
      discovery_id: 'e'.repeat(32),
      input_url: 'http://127.0.0.1:8000/',
      canonical_endpoint: null,
      status: 'metadata_found',
      connection_status: 'reachable',
      request_count: 1,
      request_budget: 3,
      metadata_sources: [
        { url: 'http://127.0.0.1:8000/openapi.json', status: 'advertised', classification: 'advertised_metadata' },
      ],
      protocol_candidates: [
        { id: 'openapi-http', classification: 'advertised_metadata', source: 'http://127.0.0.1:8000/openapi.json', runtime_verified: false },
      ],
      openapi_candidates: [
        {
          path: '/api/bearer-chat',
          endpoint: 'http://127.0.0.1:8000/api/bearer-chat',
          method: 'POST',
          operation_id: 'bearer_chat',
          summary: 'Bearer Auth Chat',
          requires_auth: true,
          auth_schemes: ['http:bearer'],
          auth_scheme_supported: true,
          input_field: 'prompt',
          unresolved_required_fields: [],
          response_text_path_discovered: true,
          suggested_http_config: {
            method: 'POST',
            body_template: { prompt: '{{input}}' },
            headers: {},
            response: { text_path: 'answer' },
          },
          classification: 'advertised_metadata',
          runtime_verified: false,
          operator_confirmed: false,
        },
        {
          path: '/api/oauth-chat',
          endpoint: 'http://127.0.0.1:8000/api/oauth-chat',
          method: 'POST',
          operation_id: 'oauth_chat',
          summary: 'OAuth Chat',
          requires_auth: true,
          auth_schemes: ['oauth2'],
          auth_scheme_supported: false,
          input_field: 'prompt',
          unresolved_required_fields: [],
          response_text_path_discovered: true,
          suggested_http_config: {
            method: 'POST',
            body_template: { prompt: '{{input}}' },
            headers: {},
            response: { text_path: 'answer' },
          },
          classification: 'advertised_metadata',
          runtime_verified: false,
          operator_confirmed: false,
        },
      ],
      advertised_models: [],
      advertised_agent: null,
      advertised_tools: [],
      advertised_skills: [],
      possible_contracts: [],
      protocol_hint: null,
      unknown_fields: ['authentication_credential_alias'],
      warnings: [],
      recommendations: [],
      proposed_profile: null,
      security_test_executed: false,
      security_verdict: null,
    };

    const discoverSpy = vi.spyOn(testingApi, 'discover').mockResolvedValue(discoveryRow);
    const validateSpy = vi.spyOn(testingApi, 'validateManaged').mockResolvedValue(true);

    render(
      <TargetManager
        enabled={true}
        localSingleUser={true}
        initialConnect={true}
        nonce={'N'.repeat(43)}
        onChanged={() => {}}
      />,
    );

    fireEvent.change(screen.getByLabelText('AI Agent URL'), { target: { value: 'http://127.0.0.1:8000/' } });
    fireEvent.click(screen.getByLabelText(/I authorize up to three bounded metadata requests/i));
    fireEvent.click(screen.getByRole('button', { name: 'Discover & Test Connection' }));
    await waitFor(() => expect(discoverSpy).toHaveBeenCalled());

    // 1. Select Bearer requires_auth candidate: Validate & Save MUST be disabled until credential_alias is filled.
    const selectBtns = screen.getAllByRole('button', { name: /Select & Review Draft/i });
    fireEvent.click(selectBtns[0]);
    expect(screen.getByRole('alert').textContent).toMatch(/API specification requires authentication/i);
    const validateBtn = screen.getByRole('button', { name: 'Validate Draft Details' }) as HTMLButtonElement;
    const saveBtn = screen.getByRole('button', { name: 'Save Target' }) as HTMLButtonElement;
    expect(validateBtn.disabled).toBe(true);
    expect(saveBtn.disabled).toBe(true);
    expect(validateSpy).not.toHaveBeenCalled();

    // Provide registered alias -> Validate becomes enabled and passes discovery_id.
    fireEvent.change(screen.getByLabelText(/Credential alias/i), { target: { value: 'bearer_alias' } });
    expect(validateBtn.disabled).toBe(false);
    fireEvent.click(validateBtn);
    await waitFor(() =>
      expect(validateSpy).toHaveBeenCalledWith(
        expect.objectContaining({ credential_alias: 'bearer_alias', endpoint: 'http://127.0.0.1:8000/api/bearer-chat' }),
        null,
        '',
        'N'.repeat(43),
        discoveryRow.discovery_id,
      ),
    );
    expect(saveBtn.disabled).toBe(false);

    // 2. Select unsupported OAuth2 candidate: stays blocked even if a credential_alias is typed.
    fireEvent.click(selectBtns[1]);
    expect(screen.getByRole('alert').textContent).toMatch(/not supported by server-managed Bearer credential aliases/i);
    expect((screen.getByRole('button', { name: 'Validate Draft Details' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText(/Credential alias/i), { target: { value: 'bearer_alias' } });
    expect((screen.getByRole('button', { name: 'Validate Draft Details' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Save Target' }) as HTMLButtonElement).disabled).toBe(true);

    discoverSpy.mockRestore();
    validateSpy.mockRestore();
  });
});
