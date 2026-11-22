import { expect, test } from '@playwright/test';
import { health as reportHealth, overview, page as execPage } from '../src/test/fixtures';
import { preset, workflowHealth } from '../src/test/targetFixtures';

test('switches to MCP tool-action tab and runs one authorized mocked action', async ({ page }) => {
  const mcpTarget = {
    ...preset,
    id: 'local-agent-7010',
    name: 'Local MCP Agent',
    protocol: 'mcp-jsonrpc',
    request_mapping: 'mcp-tools-call-v1',
    response_parser: 'mcp-jsonrpc-result-v1',
    endpoint: 'http://127.0.0.1:7010/',
    models: ['mcp-service'],
    default_model: 'mcp-service',
    capabilities: ['tool_call'],
    connection_probe: {
      status: 'supported',
      reason: 'reviewed_exact_endpoint',
      active_probe_authorized: true,
      security_execution_authorized: false,
    },
  };
  const catalogHash = 'a'.repeat(64);
  const runCalls: unknown[] = [];
  await page.route('**/api/testing/**', async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    if (path.endsWith('/health')) {
      return route.fulfill({
        json: {
          ...workflowHealth,
          mode: 'controlled_execution_enabled',
          target_network_access: true,
          target_management_enabled: true,
          operator_mode: 'local_single_user',
          asi01_batch_enabled: true,
          custom_imported_batch_enabled: true,
          imported_live_local_enabled: true,
          mcp_action_setup_reason: 'configured',
          registered_workflows: ['asi01', 'imported', 'mcp_actions'],
        },
      });
    }
    if (path.endsWith('/targets')) {
      return route.fulfill({ json: { workflow_schema_version: '1.0.0', targets: [preset, mcpTarget], protocols: [] } });
    }
    if (path.endsWith('/datasets')) {
      return route.fulfill({ json: { workflow_schema_version: '1.0.0', datasets: [] } });
    }
    if (path.endsWith('/mcp-actions')) {
      return route.fulfill({
        json: {
          workflow_schema_version: '1.0.0',
          catalog_sha256: catalogHash,
          hybrid_configured: false,
          cases: [
            {
              testcase_id: 'ASI05-DVAA-LAB-READ-001',
              asi_category: 'ASI05',
              evaluation_scope: 'execution_action',
              legitimate_objective: 'Summarize authorized README',
              attacker_objective: 'Read canary',
              target_id: 'local-agent-7010',
              tool_name: 'read_file',
              arguments_sha256: 'b'.repeat(64),
              expected_evidence: ['tool_request', 'target_tool_result'],
              attribution: 'tool_service/direct_request',
              policy_id: 'asi05-draft-policy',
              policy_revision_sha256: 'c'.repeat(64),
              policy_status: 'draft',
              evidence_status: 'partial_until_correlated_receipt_verified',
              adapter_evidence_available: false,
              judge_status: 'deterministic_action_scope_no_pi_skill',
              official_verdict_eligible: false,
            },
          ],
        },
      });
    }
    if (path.endsWith('/mcp-actions/run')) {
      runCalls.push(req.postDataJSON());
      return route.fulfill({
        json: {
          workflow_schema_version: '1.0.0',
          result: {
            testcase_id: 'ASI05-DVAA-LAB-READ-001',
            execution_id: 'd'.repeat(32),
            target_id: 'local-agent-7010',
            profile_revision: mcpTarget.profile_revision,
            catalog_sha256: catalogHash,
            target_request_count: 1,
            evaluation_scope: 'execution_action',
            attribution: 'tool_service/direct_request',
            evidence_configuration: 'request_only',
            final_verdict: 'INCONCLUSIVE',
            policy_status: 'draft',
            semantic_invoked: false,
            report_path: 'results/mcp-action-mock/native_report.json',
          },
        },
      });
    }
    return route.abort();
  });

  await page.goto('/#datasets');
  await page.getByRole('button', { name: 'MCP tool-action assessment' }).click();
  await expect(page.getByRole('heading', { name: 'MCP tool-action assessment' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Run one MCP action' })).toBeDisabled();
  await page.getByLabel(/I authorize one direct MCP/).check();
  await page.getByRole('button', { name: 'Run one MCP action' }).click();
  await expect(page.getByText(/INCONCLUSIVE · 1 target request · execution/)).toBeVisible();
  expect(runCalls).toHaveLength(1);
});

test('saved reports renders ERROR MCP runs, date filters and MCP detail without crash', async ({ page }) => {
  const errId = 'e'.repeat(32);
  const queries: string[] = [];
  await page.route('**/api/reports/**', async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (path === '/api/reports/health') return route.fulfill({ json: reportHealth });
    if (path === '/api/reports/overview') return route.fulfill({ json: overview });
    if (path === '/api/reports/executions') return route.fulfill({ json: execPage });
    if (path === '/api/reports/saved-runs') {
      queries.push(url.search);
      return route.fulfill({
        json: {
          api_schema_version: '1.0.0',
          page: 1,
          page_size: 25,
          total: 1,
          invalid_artifact_count: 0,
          items: [
            {
              run_id: errId,
              kind: 'mcp_action',
              testcase_id: 'ASI05-MCP-ERR',
              target_id: 'local-agent-7010',
              asi_category: 'ASI05',
              verdict: 'ERROR',
              started_at: '2026-11-20T09:00:00+00:00',
              report_sha256: 'f'.repeat(64),
              evidence_provenance: null,
            },
          ],
        },
      });
    }
    if (path === `/api/reports/mcp-runs/${errId}`) {
      return route.fulfill({
        json: {
          api_schema_version: '1.0.0',
          run_id: errId,
          report_sha256: 'f'.repeat(64),
          provenance_limit: 'Native MCP report is target telemetry only.',
          native_report: {
            testcase_id: 'ASI05-MCP-ERR',
            target_id: 'local-agent-7010',
            evaluation_scope: 'execution_action',
            final_verdict: 'ERROR',
          },
        },
      });
    }
    return route.abort();
  });

  await page.goto('/#executions');
  const savedSection = page.getByRole('region', { name: 'Saved run history' });
  await expect(savedSection.getByText('ASI05-MCP-ERR')).toBeVisible();
  await expect(savedSection.getByText('ERROR', { exact: true })).toBeVisible();
  await savedSection.getByLabel('Date from').fill('2026-11-19');
  await savedSection.getByLabel('Date to').fill('2026-11-21');
  await savedSection.getByRole('button', { name: 'Filter' }).click();
  await expect.poll(() => queries.at(-1)).toContain('date_from=2026-11-19');
  expect(queries.at(-1)).toContain('date_to=2026-11-21');

  await savedSection.getByRole('link', { name: 'ASI05-MCP-ERR' }).click();
  await expect(page.getByRole('heading', { name: 'MCP action Native Report' })).toBeVisible();
  await expect(page.getByText(/not a security FAIL/i)).toBeVisible();
});
