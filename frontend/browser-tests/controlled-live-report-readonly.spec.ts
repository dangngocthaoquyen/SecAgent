import { expect, test } from '@playwright/test';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createServer } from 'node:net';
import { delimiter, resolve } from 'node:path';

// Opt-in read-only check against an existing report. Never starts a target or workflow API.
test('opens an existing controlled report through a fresh real Reporting API', async ({ page }) => {
  test.setTimeout(45000);
  const manifest = process.env.SECAGENT_EXISTING_REPORT_MANIFEST;
  const runId = process.env.SECAGENT_EXISTING_REPORT_RUN_ID;
  test.skip(!manifest || !existsSync(manifest) || !runId, 'Existing report selection is required.');
  expect(runId).toMatch(/^[a-f0-9]{32}$/);
  const port = Number(process.env.SECAGENT_REPORTING_PROXY_PORT || '8096');
  const available = await new Promise<boolean>(done => {
    const server = createServer();
    server.once('error', () => done(false));
    server.listen(port, '127.0.0.1', () => server.close(() => done(true)));
  });
  test.skip(!available, 'Isolated reporting port is occupied.');
  const root = resolve(process.cwd(), '..');
  const env = { ...process.env, PYTHONPATH: [resolve(root, 'backend/src'), root].join(delimiter) };
  const reporting: ChildProcessWithoutNullStreams = spawn('python', [
    '-u', '-m', 'reporting.api', '--manifest', manifest!, '--port', String(port),
  ], { cwd: root, windowsHide: true, env });
  try {
    let ready = false;
    for (let i = 0; i < 80; i++) {
      try {
        const health = await page.request.get('/api/reports/health');
        if (health.ok()) { ready = true; break; }
      } catch { /* Reporting API is starting. */ }
      await new Promise(done => setTimeout(done, 250));
    }
    expect(ready).toBe(true);
    const response = await page.request.get(`/api/reports/runs/${runId}`);
    expect(response.status()).toBe(200);
    const report = await response.json();
    expect(report.run_id).toBe(runId);
    expect(report.target_request_count).toBe(2);
    expect(report.execution.identity.testcase_id).toBe('GH-WEB-001');
    expect(report.execution.security.verdict).toBe('FAIL');
    expect(report.execution.source.reported_provenance).toBe('restricted_dvaa_lab');
    await page.goto(`/#run/${runId}`);
    await expect(page.getByRole('heading', { name: 'Why this verdict was recorded' })).toBeVisible();
    await expect(page.getByText('Recorded target requests')).toBeVisible();
    await expect(page.getByText('restricted_dvaa_lab')).toBeVisible();
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Why this verdict was recorded' })).toBeVisible();
  } finally {
    if (reporting.exitCode === null) {
      reporting.kill();
      await Promise.race([
        new Promise<void>(done => reporting.once('exit', () => done())),
        new Promise<void>(done => setTimeout(done, 5000)),
      ]);
    }
  }
});
