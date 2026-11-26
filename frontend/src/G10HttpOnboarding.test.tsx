import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import TargetManager from './TargetManager';
import { testingApi, type DiscoveryResult, type ProbeResult } from './testingApi';

afterEach(() => vi.restoreAllMocks());

describe('G10.1C Adaptive HTTP Target Onboarding UI', () => {
  it('auto-hands off an exact REST operation draft, supports model=null Test Connection, registered alias selector, and no Defense Level controls', async () => {
    const discoveryRow: DiscoveryResult = {
      discovery_id: 'f'.repeat(32),
      input_url: 'http://127.0.0.1:8000/api/agent/runs',
      canonical_endpoint: 'http://127.0.0.1:8000/api/agent/runs',
      status: 'metadata_found',
      connection_status: 'reachable',
      configuration_readiness: 'incomplete_configuration',
      exact_match_path: '/api/agent/runs',
      request_count: 3,
      request_budget: 3,
      metadata_sources: [
        { url: 'http://127.0.0.1:8000/v1/models', status: 'missing', classification: 'unverified' },
        { url: 'http://127.0.0.1:8000/openapi.json', status: 'advertised', classification: 'advertised_metadata' },
        { url: 'http://127.0.0.1:8000/.well-known/agent.json', status: 'missing', classification: 'unverified' },
      ],
      protocol_candidates: [
        { id: 'http-json', classification: 'advertised_metadata', source: 'http://127.0.0.1:8000/openapi.json', runtime_verified: false },
        { id: 'openapi-http', classification: 'advertised_metadata', source: 'http://127.0.0.1:8000/openapi.json', runtime_verified: false },
      ],
      openapi_candidates: [
        {
          path: '/api/agent/runs',
          endpoint: 'http://127.0.0.1:8000/api/agent/runs',
          method: 'POST',
          operation_id: 'create_run',
          summary: 'Create Agent Run',
          requires_auth: true,
          auth_status: 'required',
          auth_schemes: ['http:bearer'],
          auth_scheme_supported: true,
          input_field: 'goal',
          unresolved_required_fields: ['lab_id'],
          unresolved_required_field_specs: [{ name: 'lab_id', type: 'string', location: 'body' }],
          response_text_path_discovered: true,
          suggested_http_config: {
            method: 'POST',
            body_template: { lab_id: '<REQUIRED:lab_id>', goal: '{{input}}' },
            headers: {},
            response: { text_path: 'answer', correlation_id_path: 'run_id', status_path: 'status' },
          },
          classification: 'advertised_metadata',
          runtime_verified: false,
          operator_confirmed: false,
        },
        {
          path: '/api/secondary/ping',
          endpoint: 'http://127.0.0.1:8000/api/secondary/ping',
          method: 'POST',
          operation_id: 'ping',
          summary: 'Ping',
          requires_auth: false,
          auth_status: 'not_declared',
          input_field: 'message',
          unresolved_required_fields: [],
          response_text_path_discovered: true,
          suggested_http_config: {
            method: 'POST',
            body_template: { message: '{{input}}' },
            headers: {},
            response: { text_path: 'reply' },
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
      possible_contracts: [{ request: 'http-json-template-v1', response: 'answer', classification: 'advertised_metadata_unverified' }],
      protocol_hint: null,
      unknown_fields: ['runtime_http_contract', 'unresolved_required_request_parameters', 'authentication_credential_alias'],
      warnings: [],
      recommendations: [],
      proposed_profile: {
        id: 'local-http-8000-api-agent-runs',
        name: 'Create Agent Run',
        platform_id: 'local-agent',
        platform_name: 'Local Agent',
        endpoint: 'http://127.0.0.1:8000/api/agent/runs',
        protocol: 'http-json',
        model: null,
        timeout_seconds: 30,
        http_config: {
          method: 'POST',
          body_template: { lab_id: '<REQUIRED:lab_id>', goal: '{{input}}' },
          headers: {},
          response: { text_path: 'answer', correlation_id_path: 'run_id', status_path: 'status' },
        },
      },
      security_test_executed: false,
      security_verdict: null,
    };

    const probeResponse: ProbeResult = {
      connection_status: 'succeeded',
      reason: 'http_json_response',
      target_request_count: 1,
      connection_reachable: true,
      runtime_protocol_compatible: true,
      http_status: 200,
      diagnostic_category: 'response_extraction_succeeded',
      verification_state: 'connection_verified',
      guidance: 'Connection verified via shared generic_http adapter.',
      request_preview: {
        method: 'POST',
        url: 'http://127.0.0.1:8000/api/agent/runs',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer [REDACTED]' },
        body_preview: '{"goal":"Hello.","lab_id":"asi02-1"}',
      },
      response_preview: '{"run_id":"r1","status":"completed","answer":"Ready."}',
      response_sample: { run_id: 'r1', status: 'completed', answer: 'Ready.' },
      extracted_output: 'Ready.',
      mapping_diagnostics: {
        configured_text_path: 'answer',
        text_extracted: true,
        configured_status_path: 'status',
        observed_status_value: 'completed',
        configured_complete_status_values: [],
        configured_incomplete_status_values: [],
        response_complete: null,
        completeness_unresolved: true,
        evaluation_readiness_limitations: ['Status completion semantics unconfirmed.'],
      },
      security_test_executed: false,
      security_verdict: null,
    };

    const discoverSpy = vi.spyOn(testingApi, 'discover').mockResolvedValue(discoveryRow);
    const probeSpy = vi.spyOn(testingApi, 'probeDiscovery').mockResolvedValue(probeResponse);
    const validateSpy = vi.spyOn(testingApi, 'validateManaged').mockResolvedValue(true);

    render(
      <TargetManager
        enabled={true}
        localSingleUser={true}
        initialConnect={true}
        credentialAliases={['agent_bearer']}
        credentialAliasAvailability={{ agent_bearer: 'available' }}
        nonce={'N'.repeat(43)}
        onChanged={() => {}}
      />,
    );

    fireEvent.change(screen.getByLabelText('AI Agent URL'), { target: { value: 'http://127.0.0.1:8000/api/agent/runs' } });
    fireEvent.click(screen.getByLabelText(/I authorize up to three bounded metadata requests/i));
    fireEvent.click(screen.getByRole('button', { name: 'Discover & Test Connection' }));

    // Automatically hands off exact operation draft without requiring list selection!
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Auto-detected Configuration' })).toBeTruthy());
    // Other discovered operations stay collapsed!
    expect(screen.getByText(/Other discovered operations \(1\)/i).closest('details')).not.toHaveAttribute('open');
    // Advanced HTTP configuration starts collapsed when text_path is already resolved!
    expect(screen.getByText(/^Advanced HTTP Configuration \(/i).closest('details')).not.toHaveAttribute('open');
    // No Defense Level L0/L1/L2 controls exist!
    expect(screen.queryByText(/Defense Level/i)).toBeNull();
    // Does NOT automatically send POST probe during discovery!
    expect(probeSpy).not.toHaveBeenCalled();

    // Fill guided required parameter + select registered credential alias + configure timeout 360s.
    fireEvent.change(screen.getByPlaceholderText(/Enter lab_id/i), { target: { value: 'asi02-1' } });
    const aliasSelect = screen.getByLabelText(/Credential alias/i) as HTMLSelectElement;
    expect(aliasSelect.tagName).toBe('SELECT');
    expect(aliasSelect.textContent).toContain('agent_bearer (available)');
    fireEvent.change(aliasSelect, { target: { value: 'agent_bearer' } });

    const timeoutInput = screen.getByLabelText(/HTTP request timeout/i);
    fireEvent.change(timeoutInput, { target: { value: '360' } });

    // Test Connection works with model=null!
    fireEvent.click(screen.getByLabelText(/I authorize one benign connection probe/i));
    const testBtn = screen.getByRole('button', { name: 'Test Connection' }) as HTMLButtonElement;
    expect(testBtn.disabled).toBe(false);
    fireEvent.click(testBtn);

    await waitFor(() => expect(probeSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        protocol: 'http-json',
        model: null,
        credential_alias: 'agent_bearer',
        timeout_seconds: 360,
        http_config: expect.objectContaining({
          body_template: { lab_id: 'asi02-1', goal: '{{input}}' },
        }),
      }),
      discoveryRow.discovery_id,
      '',
      'N'.repeat(43),
      expect.any(String),
    ));

    // Diagnostics, extracted output, and unresolved status completeness notice are displayed!
    expect(await screen.findByText(/^Connection verified$/)).toBeTruthy();
    expect(screen.getByText('Ready.')).toBeTruthy();
    expect(screen.getByText(/Evaluation readiness limitation/i)).toBeTruthy();
    await waitFor(() => expect(validateSpy).toHaveBeenCalled());
    expect(discoverSpy).toHaveBeenCalledTimes(1);
  });

  it('avoids response-mapping deadlock via sample probe, applies suggested nested text_path locally without a second POST, and shows setup instructions when no aliases exist', async () => {
    const discoveryRow: DiscoveryResult = {
      discovery_id: 'd'.repeat(32),
      input_url: 'http://127.0.0.1:9200/v2/execute',
      canonical_endpoint: 'http://127.0.0.1:9200/v2/execute',
      status: 'metadata_found',
      connection_status: 'reachable',
      configuration_readiness: 'incomplete_configuration',
      exact_match_path: '/v2/execute',
      request_count: 3,
      request_budget: 3,
      metadata_sources: [],
      protocol_candidates: [{ id: 'http-json', classification: 'advertised_metadata', source: 'spec', runtime_verified: false }],
      openapi_candidates: [
        {
          path: '/v2/execute',
          endpoint: 'http://127.0.0.1:9200/v2/execute',
          method: 'POST',
          operation_id: 'exec',
          summary: 'Nested Execute',
          requires_auth: false,
          auth_status: 'not_declared',
          input_field: 'task.query',
          unresolved_required_fields: [],
          response_text_path_discovered: false,
          suggested_http_config: {
            method: 'POST',
            body_template: { workspace: 'w1', task: { query: '{{input}}' } },
            headers: {},
            response: { text_path: '' },
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
      unknown_fields: ['response_text_path'],
      warnings: [],
      recommendations: [],
      proposed_profile: {
        id: 'local-http-9200-v2-execute',
        name: 'Nested Execute',
        platform_id: 'local-agent',
        platform_name: 'Local Agent',
        endpoint: 'http://127.0.0.1:9200/v2/execute',
        protocol: 'http-json',
        model: null,
        timeout_seconds: 30,
        http_config: {
          method: 'POST',
          body_template: { workspace: 'w1', task: { query: '{{input}}' } },
          headers: {},
          response: { text_path: '' },
        },
      },
      security_test_executed: false,
      security_verdict: null,
    };

    const sampleProbeResult: ProbeResult = {
      connection_status: 'incompatible',
      reason: 'response_extraction_failed',
      target_request_count: 1,
      connection_reachable: true,
      runtime_protocol_compatible: false,
      http_status: 200,
      diagnostic_category: 'response_extraction_failure',
      verification_state: 'response_mapping_unresolved',
      guidance: 'HTTP 200 transport succeeded, but response text path is not yet configured.',
      response_preview: '{"data":{"result":{"text":"Nested hello"}}}',
      response_sample: { data: { result: { text: 'Nested hello' } } },
      extracted_output: null,
      mapping_diagnostics: {
        configured_text_path: '',
        text_extracted: false,
        suggestions: {
          text_path_candidates: [
            {
              path: 'data.result.text',
              sample_type: 'string',
              source: 'runtime_response_shape_heuristic',
              confidence: 'high',
              ambiguous: false,
              limitation: 'Confirm field.',
            },
          ],
        },
      },
      security_test_executed: false,
      security_verdict: null,
    };

    vi.spyOn(testingApi, 'discover').mockResolvedValue(discoveryRow);
    const probeSpy = vi.spyOn(testingApi, 'probeDiscovery').mockResolvedValue(sampleProbeResult);

    render(
      <TargetManager
        enabled={true}
        localSingleUser={true}
        initialConnect={true}
        credentialAliases={[]}
        nonce={'N'.repeat(43)}
        onChanged={() => {}}
      />,
    );

    fireEvent.change(screen.getByLabelText('AI Agent URL'), { target: { value: 'http://127.0.0.1:9200/v2/execute' } });
    fireEvent.click(screen.getByLabelText(/I authorize up to three bounded metadata requests/i));
    fireEvent.click(screen.getByRole('button', { name: 'Discover & Test Connection' }));

    await waitFor(() => expect(screen.getByRole('heading', { name: 'Auto-detected Configuration' })).toBeTruthy());
    // Advanced HTTP configuration stays collapsed by default.
    expect(screen.getByText(/^Advanced HTTP Configuration \(/i).closest('details')).not.toHaveAttribute('open');
    // Switching Authentication mode to Existing Credential when no aliases exist shows setup hint.
    fireEvent.change(screen.getByLabelText('Authentication'), { target: { value: 'existing' } });
    expect(screen.getByText(/No credential aliases registered/i)).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Authentication'), { target: { value: 'none' } });

    // Sample probe is allowed even while text_path is empty!
    fireEvent.click(screen.getByLabelText(/I authorize one benign connection probe/i));
    const sampleBtn = screen.getByRole('button', { name: 'Send Sample Probe' }) as HTMLButtonElement;
    expect(sampleBtn.disabled).toBe(false);
    fireEvent.click(sampleBtn);

    expect(await screen.findByText(/Transport connected · Response mapping unresolved/i)).toBeTruthy();
    expect(probeSpy).toHaveBeenCalledTimes(1);

    // Clicking "Apply text path" validates locally against response_sample WITHOUT sending another POST!
    fireEvent.click(screen.getByRole('button', { name: 'Apply text path' }));
    expect(await screen.findByText(/validated against the captured response sample.*Nested hello/i)).toBeTruthy();
    expect(probeSpy).toHaveBeenCalledTimes(1);
    expect((screen.getByLabelText('Response text path') as HTMLInputElement).value).toBe('data.result.text');
  });

  it('R-03: sends explicit authorization and exact endpoint for reviewed http-json probes, normalizes preview/sample input, and invalidates confirmation on sample change', async () => {
    const reviewedHttp = {
      id: 'reviewed-agent-http',
      name: 'Reviewed Agent HTTP',
      platform_id: 'lab',
      platform_name: 'Lab',
      profile_revision: 'a'.repeat(64),
      policy_ref: 'local-lab-offline-review-v1',
      authorization_status: 'reviewed_for_offline_configuration' as const,
      endpoint: 'http://127.0.0.1:8000/api/agent/runs',
      protocol: 'http-json' as const,
      method: 'POST' as const,
      models: [],
      default_model: '',
      timeout_min: 1,
      timeout_max: 600,
      timeout_default: 120,
      credential_alias: 'aigoat_bearer',
      credential_availability: 'available',
      request_mapping: 'http-json-template-v1' as const,
      response_parser: 'answer',
      http_config: {
        method: 'POST' as const,
        body_template: { lab_id: 'asi02-1', goal: '{{input}}' },
        headers: { 'X-Client': 'secagent' },
        response: { text_path: 'answer' },
      },
      connection_probe: {
        status: 'supported' as const,
        reason: 'reviewed_exact_endpoint',
        active_probe_authorized: true,
        security_execution_authorized: false as const,
      },
      capabilities: ['http_json'],
      capability_basis: 'configured_claim_not_probed',
      limitations: [],
    };
    const probeSpy = vi.spyOn(testingApi, 'probe').mockResolvedValue({
      connection_status: 'succeeded',
      reason: 'http_json_response',
      target_request_count: 1,
      connection_reachable: true,
      runtime_protocol_compatible: true,
      http_status: 200,
      diagnostic_category: 'response_extraction_succeeded',
      verification_state: 'connection_verified',
      extracted_output: 'All good',
      security_test_executed: false,
      security_verdict: null,
    });

    render(
      <TargetManager
        enabled={true}
        localSingleUser={true}
        nonce={'N'.repeat(43)}
        target={reviewedHttp}
        existingProfiles={[reviewedHttp]}
        onChanged={() => {}}
      />,
    );

    const consentCheckbox = screen.getByLabelText(/I confirm authorization for one benign probe/i) as HTMLInputElement;
    const testBtn = screen.getByRole('button', { name: 'Test Connection' }) as HTMLButtonElement;
    expect(testBtn.disabled).toBe(true);

    // Authorize, then edit sample input -> pending confirmation MUST be invalidated!
    fireEvent.click(consentCheckbox);
    expect(consentCheckbox.checked).toBe(true);
    expect(testBtn.disabled).toBe(false);

    const sampleField = screen.getByLabelText(/Benign connection-test sample input/i);
    fireEvent.change(sampleField, { target: { value: '   Normalized benign prompt   ' } });
    expect(consentCheckbox.checked).toBe(false);
    expect(testBtn.disabled).toBe(true);

    // Pre-probe preview matches the normalized sample input and headers!
    expect(screen.getByText(/Preview request payload before sending/i)).toBeTruthy();
    expect(document.body.textContent).toContain('"goal": "Normalized benign prompt"');
    expect(document.body.textContent).toContain('"X-Client":"secagent"');

    // Re-confirm and execute -> confirm=true and normalized sample input passed!
    fireEvent.click(consentCheckbox);
    fireEvent.click(testBtn);
    await waitFor(() =>
      expect(probeSpy).toHaveBeenCalledWith(
        reviewedHttp,
        '',
        'N'.repeat(43),
        true,
        'Normalized benign prompt',
      ),
    );
  });

  it('supports editable non-secret HTTP headers with validation & auth routing, and session Bearer authentication without catalog edits', async () => {
    const discoveryRow: DiscoveryResult = {
      discovery_id: 'c'.repeat(32),
      input_url: 'http://127.0.0.1:8000/api/agent/runs',
      canonical_endpoint: 'http://127.0.0.1:8000/api/agent/runs',
      status: 'metadata_found',
      connection_status: 'reachable',
      configuration_readiness: 'incomplete_configuration',
      exact_match_path: '/api/agent/runs',
      request_count: 2,
      request_budget: 3,
      metadata_sources: [],
      protocol_candidates: [{ id: 'http-json', classification: 'advertised_metadata', source: 'spec', runtime_verified: false }],
      openapi_candidates: [
        {
          path: '/api/agent/runs',
          endpoint: 'http://127.0.0.1:8000/api/agent/runs',
          method: 'POST',
          operation_id: 'run_agent',
          summary: 'Authenticated Agent Run',
          requires_auth: true,
          auth_status: 'required',
          auth_schemes: ['http:bearer'],
          auth_scheme_supported: true,
          input_field: 'goal',
          unresolved_required_fields: ['workspace'],
          unresolved_required_field_specs: [{ name: 'workspace', type: 'string', location: 'body' }],
          response_text_path_discovered: true,
          suggested_http_config: {
            method: 'POST',
            body_template: { workspace: '<REQUIRED:workspace>', goal: '{{input}}' },
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
      unknown_fields: ['unresolved_required_request_parameters', 'authentication_credential_alias'],
      warnings: [],
      recommendations: [],
      proposed_profile: {
        id: 'local-http-8000-api-agent-runs',
        name: 'Authenticated Agent Run',
        platform_id: 'local-agent',
        platform_name: 'Local Agent',
        endpoint: 'http://127.0.0.1:8000/api/agent/runs',
        protocol: 'http-json',
        model: null,
        timeout_seconds: 30,
        http_config: {
          method: 'POST',
          body_template: { workspace: '<REQUIRED:workspace>', goal: '{{input}}' },
          headers: {},
          response: { text_path: 'answer' },
        },
      },
      security_test_executed: false,
      security_verdict: null,
    };

    const sessionRef = 'sess_' + 'a1'.repeat(12);
    vi.spyOn(testingApi, 'discover').mockResolvedValue(discoveryRow);
    const setCredSpy = vi.spyOn(testingApi, 'setSessionCredential').mockResolvedValue({
      ref_id: sessionRef,
      scope_kind: 'discovery',
      scope_id: discoveryRow.discovery_id,
      bound_origin: 'http://127.0.0.1:8000',
      auth_type: 'bearer',
      header_name: 'Authorization',
      available: true,
      source: 'session_memory',
      generation: 'g'.repeat(32),
    });
    const probeSpy = vi.spyOn(testingApi, 'probeDiscovery').mockResolvedValue({
      connection_status: 'succeeded',
      reason: 'http_json_response',
      target_request_count: 1,
      connection_reachable: true,
      runtime_protocol_compatible: true,
      http_status: 200,
      diagnostic_category: 'response_extraction_succeeded',
      verification_state: 'connection_verified',
      extracted_output: 'Verified ok',
      security_test_executed: false,
      security_verdict: null,
    });
    const validateSpy = vi.spyOn(testingApi, 'validateManaged').mockResolvedValue(true);

    render(
      <TargetManager
        enabled={true}
        localSingleUser={true}
        initialConnect={true}
        credentialAliases={[]}
        nonce={'N'.repeat(43)}
        onChanged={() => {}}
      />,
    );

    fireEvent.change(screen.getByLabelText('AI Agent URL'), { target: { value: 'http://127.0.0.1:8000/api/agent/runs' } });
    fireEvent.click(screen.getByLabelText(/I authorize up to three bounded metadata requests/i));
    fireEvent.click(screen.getByRole('button', { name: 'Discover & Test Connection' }));
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Auto-detected Configuration' })).toBeTruthy());

    // Advanced HTTP configuration stays collapsed by default; Bearer Token selected automatically when no aliases exist.
    expect(screen.getByText(/^Advanced HTTP Configuration \(/i).closest('details')).not.toHaveAttribute('open');
    expect((screen.getByLabelText('Authentication') as HTMLSelectElement).value).toBe('bearer');
    expect(screen.getByText(/must be supplied again after a Backend restart/i)).toBeTruthy();

    // Fill required field.
    fireEvent.change(screen.getByPlaceholderText(/Enter workspace/i), { target: { value: 'lab-1' } });

    // Editable headers: default Content-Type shown; add non-secret header + test auth header routing + duplicate check.
    expect(screen.getByText('Content-Type')).toBeTruthy();
    expect(screen.getByText('application/json')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Add Header' }));
    fireEvent.change(screen.getByLabelText('Header name 1'), { target: { value: 'Authorization' } });
    fireEvent.change(screen.getByLabelText('Header value 1'), { target: { value: 'Bearer raw-secret' } });
    expect(screen.getByText(/cannot be saved as an ordinary header/i)).toBeTruthy();
    // Route auth header to Authentication control removes the header row cleanly.
    fireEvent.click(screen.getByRole('button', { name: 'Use Authentication control' }));
    expect(screen.queryByLabelText('Header name 1')).toBeNull();

    // Add valid non-secret header + test case-insensitive duplicate validation.
    fireEvent.click(screen.getByRole('button', { name: 'Add Header' }));
    fireEvent.change(screen.getByLabelText('Header name 1'), { target: { value: 'X-Tenant-Id' } });
    fireEvent.change(screen.getByLabelText('Header value 1'), { target: { value: 'tenant-42' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add Header' }));
    fireEvent.change(screen.getByLabelText('Header name 2'), { target: { value: 'x-tenant-id' } });
    fireEvent.change(screen.getByLabelText('Header value 2'), { target: { value: 'dup' } });
    expect(screen.getByText(/Duplicate HTTP header/i)).toBeTruthy();
    fireEvent.click(screen.getAllByRole('button', { name: 'Remove Header' })[1]);
    expect(screen.queryByText(/Duplicate HTTP header/i)).toBeNull();

    // Supply password-masked Bearer token -> stored in Backend RAM, plaintext cleared from input!
    const tokenInput = screen.getByLabelText(/Bearer Token \(session memory\)/i) as HTMLInputElement;
    expect(tokenInput.type).toBe('password');
    fireEvent.change(tokenInput, { target: { value: 'synthetic-session-bearer-9988' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply Session Credential' }));
    await waitFor(() => expect(setCredSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        scope_kind: 'discovery',
        scope_id: discoveryRow.discovery_id,
        endpoint: 'http://127.0.0.1:8000/api/agent/runs',
        auth_type: 'bearer',
        header_name: 'Authorization',
        secret_value: 'synthetic-session-bearer-9988',
      }),
      '',
      'N'.repeat(43),
    ));
    await waitFor(() => expect(tokenInput.value).toBe(''));
    expect(screen.getByText(/Session credential active \(Authorization\)/i)).toBeTruthy();

    // Pre-probe preview shows custom non-secret header and redacted auth header (never plaintext secret).
    const previewEl = screen.getByText(/Preview request payload before sending/i).closest('details')!;
    expect(previewEl.textContent).toContain('X-Tenant-Id');
    expect(previewEl.textContent).toContain('Bearer [REDACTED]');
    expect(previewEl.textContent).not.toContain('synthetic-session-bearer-9988');

    // Run authorized probe -> preserves discovered body_template, response text_path, custom header, and session_auth ref!
    fireEvent.click(screen.getByLabelText(/I authorize one benign connection probe/i));
    fireEvent.click(screen.getByRole('button', { name: 'Test Connection' }));
    await waitFor(() => expect(probeSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        session_auth: { ref_id: sessionRef, auth_type: 'bearer', header_name: 'Authorization' },
        http_config: expect.objectContaining({
          body_template: { workspace: 'lab-1', goal: '{{input}}' },
          headers: { 'X-Tenant-Id': 'tenant-42' },
          response: { text_path: 'answer' },
        }),
      }),
      discoveryRow.discovery_id,
      '',
      'N'.repeat(43),
      expect.any(String),
    ));
    await waitFor(() => expect(validateSpy).toHaveBeenCalled());
  });

  it('shows unavailable session credential recovery controls on saved target after Backend restart and supports update & clear', async () => {
    const sessionRef = 'sess_' + 'b2'.repeat(12);
    const savedTarget = {
      id: 'saved-api-key-target',
      name: 'Saved API Key Agent',
      platform_id: 'lab',
      platform_name: 'Lab',
      profile_revision: 'b'.repeat(64),
      policy_ref: 'local-lab-offline-review-v1',
      authorization_status: 'reviewed_for_offline_configuration' as const,
      endpoint: 'http://127.0.0.1:8080/api/invoke',
      protocol: 'http-json' as const,
      method: 'POST' as const,
      models: [],
      default_model: '',
      timeout_min: 1,
      timeout_max: 600,
      timeout_default: 60,
      credential_alias: null,
      credential_availability: 'unavailable',
      auth_source: 'session_memory' as const,
      session_auth: { ref_id: sessionRef, auth_type: 'api_key' as const, header_name: 'X-API-Key' },
      request_mapping: 'http-json-template-v1' as const,
      response_parser: 'answer',
      http_config: {
        method: 'POST' as const,
        body_template: { prompt: '{{input}}' },
        headers: { 'X-Client': 'secagent' },
        response: { text_path: 'answer' },
      },
      connection_probe: {
        status: 'supported' as const,
        reason: 'reviewed_exact_endpoint',
        active_probe_authorized: true,
        security_execution_authorized: false as const,
      },
      capabilities: ['http_json'],
      capability_basis: 'configured_claim_not_probed',
      limitations: [],
    };
    const setSpy = vi.spyOn(testingApi, 'setSessionCredential').mockResolvedValue({
      ref_id: sessionRef,
      scope_kind: 'target',
      scope_id: savedTarget.id,
      bound_origin: 'http://127.0.0.1:8080',
      auth_type: 'api_key',
      header_name: 'X-API-Key',
      available: true,
      source: 'session_memory',
      generation: 'h'.repeat(32),
    });
    const onChanged = vi.fn();

    render(
      <TargetManager
        enabled={true}
        localSingleUser={true}
        target={savedTarget}
        existingProfiles={[savedTarget]}
        nonce={'N'.repeat(43)}
        onChanged={onChanged}
      />,
    );

    expect(screen.getByText(/API Key Header: X-API-Key/i)).toBeTruthy();
    expect(screen.getByText(/Unavailable — supply credential again/i)).toBeTruthy();
    const input = screen.getByLabelText(/Supply or replace X-API-Key/i) as HTMLInputElement;
    expect(input.type).toBe('password');
    fireEvent.change(input, { target: { value: 'synthetic-api-key-5544' } });
    fireEvent.click(screen.getByRole('button', { name: 'Supply Session Credential' }));
    await waitFor(() => expect(setSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        scope_kind: 'target',
        scope_id: savedTarget.id,
        endpoint: savedTarget.endpoint,
        auth_type: 'api_key',
        header_name: 'X-API-Key',
        secret_value: 'synthetic-api-key-5544',
        ref_id: sessionRef,
      }),
      '',
      'N'.repeat(43),
    ));
    await waitFor(() => expect(input.value).toBe(''));
    expect(onChanged).toHaveBeenCalledWith(savedTarget.id);
  });

  it('R-05 & R-06: Edit Target uses draft scope without reusing target ref, displays real availability, cleans up cancelled draft refs, and never gets stuck busy on async race', async () => {
    const savedRef = 'sess_' + 'c3'.repeat(12);
    const pendingRef = 'sess_' + 'd4'.repeat(12);
    const savedTarget = {
      id: 'saved-edit-auth-target',
      name: 'Saved Auth Target',
      platform_id: 'lab',
      platform_name: 'Lab',
      profile_revision: 'c'.repeat(64),
      policy_ref: 'local-lab-offline-review-v1',
      authorization_status: 'reviewed_for_offline_configuration' as const,
      endpoint: 'http://127.0.0.1:8080/api/invoke',
      protocol: 'http-json' as const,
      method: 'POST' as const,
      models: [],
      default_model: '',
      timeout_min: 1,
      timeout_max: 600,
      timeout_default: 60,
      credential_alias: null,
      credential_availability: 'unavailable',
      auth_source: 'session_memory' as const,
      session_auth: { ref_id: savedRef, auth_type: 'bearer' as const, header_name: 'Authorization' },
      request_mapping: 'http-json-template-v1' as const,
      response_parser: 'answer',
      http_config: {
        method: 'POST' as const,
        body_template: { prompt: '{{input}}' },
        headers: {},
        response: { text_path: 'answer' },
      },
      connection_probe: {
        status: 'supported' as const,
        reason: 'reviewed_exact_endpoint',
        active_probe_authorized: true,
        security_execution_authorized: false as const,
      },
      capabilities: ['http_json'],
      capability_basis: 'configured_claim_not_probed',
      limitations: [],
    };
    const setSpy = vi.spyOn(testingApi, 'setSessionCredential').mockResolvedValue({
      ref_id: pendingRef,
      scope_kind: 'draft',
      scope_id: savedTarget.id,
      bound_origin: 'http://127.0.0.1:8080',
      auth_type: 'bearer',
      header_name: 'Authorization',
      available: true,
      source: 'session_memory',
      generation: 'e'.repeat(32),
    });
    const clearSpy = vi.spyOn(testingApi, 'clearSessionCredential').mockResolvedValue({
      cleared: true,
      credential_availability: 'unavailable',
    });

    render(
      <TargetManager
        enabled={true}
        localSingleUser={true}
        target={savedTarget}
        existingProfiles={[savedTarget]}
        nonce={'N'.repeat(43)}
        onChanged={() => {}}
      />,
    );

    // Open Edit Target -> must accurately show "Saved session credential unavailable", NOT "active"!
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    expect(screen.getByText(/Saved session credential unavailable \(Authorization\)/i)).toBeTruthy();

    // Apply replacement Bearer token during Edit -> MUST use draft scope WITHOUT passing savedRef!
    const input = screen.getByLabelText(/Bearer Token \(session memory\)/i) as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'new-edit-bearer-token' } });
    fireEvent.click(screen.getByRole('button', { name: 'Update Session Credential' }));
    await waitFor(() => expect(setSpy).toHaveBeenCalledTimes(1));
    const callArg = setSpy.mock.calls[0][0];
    expect(callArg.scope_kind).toBe('draft');
    expect(callArg.scope_id).toBe(savedTarget.id);
    expect(callArg.ref_id).toBeUndefined();
    expect(await screen.findByText(/Pending session credential ready \(Authorization\)/i)).toBeTruthy();

    // Cancelling Edit releases ONLY the pending draft ref (never savedRef)!
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(clearSpy).toHaveBeenCalledWith(
      { ref_id: pendingRef, scope_kind: 'draft', scope_id: savedTarget.id },
      '',
      'N'.repeat(43),
    ));
    expect(clearSpy).not.toHaveBeenCalledWith(expect.objectContaining({ ref_id: savedRef }), expect.anything(), expect.anything());
  });

  it('R-07: SecurityScanWizard forwards session credential generation & target revision from preview and clears authorization on stale credential rejection', async () => {
    const { default: SecurityScanWizard } = await import('./SecurityScanWizard');
    const rev = 'f'.repeat(64);
    const genA = 'a'.repeat(32);

    vi.spyOn(testingApi, 'health').mockResolvedValue({
      nonce: 'N'.repeat(43),
      evaluationModes: ['rule_only'],
      managementEnabled: true,
      controlledRunsEnabled: true,
      localSingleUser: true,
      offlineBatchEnabled: false,
      asi01BatchEnabled: false,
      asi01TextTargets: [],
      webLabBatchEnabled: false,
      toolbotLabBatchEnabled: false,
      customImportedBatchEnabled: false,
      importedLiveLocalEnabled: false,
      importedLiveLocalMocked: false,
      judgeSetupReason: 'judge_configuration_missing',
      mcpActionSetupReason: 'catalog_missing',
      piJudgeReady: false,
      genericRunnerEnabled: true,
    });
    vi.spyOn(testingApi, 'targets').mockResolvedValue({
      targets: [
        {
          id: 'r07-ui-target',
          name: 'R07 UI Target',
          profile_revision: rev,
          policy_ref: 'local-lab-offline-review-v1',
          authorization_status: 'reviewed_for_offline_configuration',
          endpoint: 'http://127.0.0.1:8096/api/runs',
          protocol: 'http-json',
          method: 'POST',
          models: [],
          default_model: '',
          timeout_min: 1,
          timeout_max: 600,
          timeout_default: 30,
          credential_alias: null,
          credential_availability: 'available',
          auth_source: 'session_memory',
          session_auth: { ref_id: 'sess_' + '12'.repeat(12), auth_type: 'bearer', header_name: 'Authorization' },
          request_mapping: 'http-json-template-v1',
          response_parser: 'answer',
          connection_probe: { status: 'supported', reason: 'reviewed_exact_endpoint', active_probe_authorized: true, security_execution_authorized: false },
          capabilities: ['http_json'],
          capability_basis: 'configured_claim_not_probed',
          limitations: [],
        },
      ],
      protocols: [],
    });
    vi.spyOn(testingApi, 'listDatasets').mockResolvedValue([
      {
        dataset_id: 'd'.repeat(32),
        name: 'asi01.json',
        schema_version: '1.0.0',
        source_tool: 'canonical_stored_json',
        imported_at: '2026-11-25T00:00:00Z',
        file_sha256: '1'.repeat(64),
        total_testcases: 1,
        has_stored_responses: false,
      },
    ]);
    vi.spyOn(testingApi, 'getDataset').mockResolvedValue({
      dataset_id: 'd'.repeat(32),
      name: 'asi01.json',
      schema_version: '1.0.0',
      source_tool: 'canonical_stored_json',
      imported_at: '2026-11-25T00:00:00Z',
      file_sha256: '1'.repeat(64),
      total_testcases: 1,
      has_stored_responses: false,
      source_metadata: {},
      testcases: [
        {
          testcase_id: 'TC-1',
          internal_id: 'import-' + '1'.repeat(24),
          description: null,
          plugin_id: null,
          strategy_id: null,
          prompt: 'Ignore rules',
          prompt_sha256: '2'.repeat(64),
          assertions: [],
          metadata: {},
          options: {},
          extra: {},
          index: 0,
        },
      ],
    });
    vi.spyOn(testingApi, 'listGenericRuns').mockResolvedValue([]);
    vi.spyOn(testingApi, 'previewGenericRun').mockResolvedValue({
      workflow_schema_version: '1.0.0',
      mode: 'live',
      target_id: 'r07-ui-target',
      target_name: 'R07 UI Target',
      target_revision_sha256: rev,
      auth_source: 'session_memory',
      session_credential_generation: genA,
      session_auth_type: 'bearer',
      session_auth_header: 'Authorization',
      dataset_id: 'd'.repeat(32),
      dataset_name: 'asi01.json',
      asi_category: 'auto',
      use_judge: false,
      pi_judge_ready: false,
      capability_states: { response_behavior: 'supported' },
      evidence_source_count: 0,
      ready_count: 1,
      blocked_count: 0,
      unsupported_count: 0,
      policy_id: null,
      policy_revision_sha256: null,
      policy_review_status: 'not_required',
      blocker: null,
      items: [{ case_id: 'TC-1', category: 'goal_hijacking', status: 'ready', reason: null, prompt_preview: 'Ignore rules' }],
    });
    const startSpy = vi.spyOn(testingApi, 'startGenericRun').mockRejectedValue(
      new Error('Workflow API [generic_session_credential_stale]: The session credential changed or was cleared after scan preview.'),
    );

    render(<SecurityScanWizard />);
    const previewBtn = await screen.findByRole('button', { name: /Continue to Scan Preview/i });
    await waitFor(() => expect((previewBtn as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(previewBtn);

    const authCheckbox = await screen.findByRole('checkbox', { name: /I authorize SecAgent to run this/i });
    fireEvent.click(authCheckbox);
    const startBtn = screen.getByRole('button', { name: 'Start Scan' });
    fireEvent.click(startBtn);

    await waitFor(() => expect(startSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        target_id: 'r07-ui-target',
        expected_target_revision: rev,
        expected_session_credential_generation: genA,
      }),
      '',
      'N'.repeat(43),
    ));
    // Stale credential rejection clears preview & forces fresh preview/re-confirmation!
    expect(await screen.findByText(/generic_session_credential_stale/i)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Start Scan' })).toBeNull();
  });
});
