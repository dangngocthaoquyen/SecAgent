import {expect, test} from '@playwright/test';
import {spawn, type ChildProcessWithoutNullStreams} from 'node:child_process';
import {mkdtempSync, mkdirSync, writeFileSync, readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {delimiter, join, resolve} from 'node:path';

const root = resolve(process.cwd(), '..');
const workflowPort = Number(process.env.SECAGENT_WORKFLOW_PROXY_PORT || '8093');
const reportingPort = Number(process.env.SECAGENT_REPORTING_PROXY_PORT || '8094');
const token = 'offline-browser-test-operator-secret-123456';
const CODEBOT_JSON = 'E:\\KiemLaiSS1\\testcases_dvaa_codebot_asi02.json';

async function free(port: number) {
  return new Promise<boolean>(done => {
    const server = createServer();
    server.once('error', () => done(false));
    server.listen(port, '127.0.0.1', () => server.close(() => done(true)));
  });
}

async function stop(child:ChildProcessWithoutNullStreams|undefined){
 if(!child||child.exitCode!==null)return;
 child.kill();await new Promise<void>(done=>child.once('exit',()=>done()));
}

test('operator imports CodeBot ASI02 dataset and executes generic batch offline', async ({page}) => {
  test.setTimeout(240000);
  if (process.env.SECAGENT_LOCAL_PROXY_TOKEN !== token) test.skip(true, 'Isolated proxy credential required.');
  if (!(await free(workflowPort)) || !(await free(reportingPort))) test.skip(true, 'Isolated API port occupied.');

  const state = mkdtempSync(join(tmpdir(), 'secagent-custom-import-browser-'));
  const runs = join(state, 'results', 'runs');
  mkdirSync(runs, {recursive: true});
  const manifest = join(state, 'reporting.json');
  writeFileSync(manifest, JSON.stringify({
    dataset_schema_version: '1.0.0',
    allowed_roots: {controlled: runs},
    reports: [],
    verification_jobs: [],
    controlled_runs_root: 'controlled'
  }));

  const env = {...process.env, PYTHONPATH: [join(root, 'backend/src'), root].join(delimiter)};
  let workflow: ChildProcessWithoutNullStreams | undefined;
  let reporting: ChildProcessWithoutNullStreams | undefined;

  try {
    reporting = spawn('python', ['-u', '-m', 'reporting.api', '--manifest', manifest, '--port', String(reportingPort)],
      {cwd: root, windowsHide: true, env});
    workflow = spawn('python', ['-u', join(root, 'backend/tests/serve_generic_imported_batch_offline.py'),
      '--state-dir', state, '--port', String(workflowPort)], {cwd: root, windowsHide: true, env});
    workflow.stderr.on('data', () => {});
    workflow.stdout.on('data', () => {});

    await expect.poll(async () => {
      try {
        const response = await page.request.get('/api/testing/health');
        if (!response.ok()) return false;
        const data = await response.json();
        return data.custom_imported_batch_enabled === true;
      } catch {
        return false;
      }
    }, {timeout: 30000}).toBe(true);

    // Navigate to Datasets library
    await page.goto('/#datasets');
    await expect(page.getByRole('heading', {name: 'Testcase Datasets'})).toBeVisible();

    // Upload real CodeBot JSON dataset
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles(CODEBOT_JSON);

    // Verify validation preview displays dataset properties
    await expect(page.getByRole('heading', {name: /Validation Preview:/})).toBeVisible();
    await expect(page.getByText(/Cases: 30/)).toBeVisible();
    await expect(page.locator('.preview-box strong', {hasText: 'promptfoo'})).toBeVisible();

    // Confirm import
    await page.getByRole('button', {name: 'Confirm & Import to Library'}).click();

    // Verify dataset is listed in table and case inspection opens
    await expect(page.getByRole('heading', {name: /30 testcases/})).toBeVisible();
    await expect(page.getByText('30 of 30 selected')).toBeVisible();

    const sourceBytes=readFileSync(CODEBOT_JSON);
    const original=JSON.parse(sourceBytes.toString('utf8'));
    const originalHash=createHash('sha256').update(sourceBytes).digest('hex');
    let health=await (await page.request.get('/api/testing/health')).json();
    const library=await (await page.request.get('/api/testing/datasets',{headers:{'X-SecAgent-Validation':health.validation_nonce}})).json();
    expect(library.datasets).toHaveLength(1);
    expect(library.datasets[0].file_sha256).toBe(originalHash);
    const datasetId=library.datasets[0].dataset_id;
    // Reimport through the actual upload UI: byte identity must deduplicate.
    await fileInput.setInputFiles([]);
    await fileInput.setInputFiles(CODEBOT_JSON);
    await page.getByRole('button',{name:'Confirm & Import to Library'}).click();
    await expect(page.getByText('Available Datasets (1)')).toBeVisible();
    const batches:string[]=[];
    const reportIds:string[]=[];
    const expectedPrompts:string[]=[];
    for(const count of [1,2,30,30]){
      await page.goto('/#datasets');
      if(!await page.getByRole('button',{name:'Clear Selection'}).isVisible())
        await page.getByRole('button',{name:'Inspect & Select'}).click();
      await page.getByRole('button',{name:'Clear Selection'}).click();
      if(count===30)await page.getByRole('button',{name:'Select All Cases'}).click();
      else for(let i=1;i<=count;i++)await page.getByLabel(`Select TC${String(i).padStart(4,'0')}`).check();
      await expect(page.getByText(`Ready: ${count} / Blocked: 0 / Unsupported: 0.`)).toBeVisible();
      await page.getByRole('button',{name:'Run Selected Tests'}).click();
      await expect(page).toHaveURL(/#batch\/[a-f0-9]{32}$/);
      await expect(page.getByRole('heading',{name:'Batch completed'})).toBeVisible({timeout:60000});
      const id=page.url().split('#batch/')[1]; batches.push(id);
      health=await (await page.request.get('/api/testing/health')).json();
      const headers={'X-SecAgent-Validation':health.validation_nonce};
      const status=await (await page.request.get(`/api/testing/batches/${id}`,{headers})).json();
      expect(status.target_request_count).toBe(count);
      expect(status.request_budget_consumed).toBe(count);
      const results=await (await page.request.get(`/api/testing/batches/${id}/results`,{headers})).json();
      expect(results.results).toHaveLength(count);
      expect(results.snapshot.imported_provenance.dataset_id).toBe(datasetId);
      for(let i=0;i<count;i++){
        const row=results.results[i];
        expect(row.verdict).toBe('INCONCLUSIVE');
        expect(row.request_count).toBe(1);
        const saved=await page.request.get(`/api/reports/runs/${row.report_run_id}`);
        expect(saved.status()).toBe(200);
        const report=await saved.json();
        expect(report.execution.imported_provenance.source_testcase_id).toBe(original.testcases[i].testcase_id);
        expect(report.execution.imported_provenance.dataset_revision_sha256).toBe(originalHash);
        expect(report.execution.imported_provenance.prompt_sha256).toBe(createHash('sha256').update(original.testcases[i].vars.prompt).digest('hex'));
        expect(report.execution.security.verdict).toBe('INCONCLUSIVE');
        expect(report.target_request_count).toBe(1);
        reportIds.push(row.report_run_id);
        expectedPrompts.push(original.testcases[i].vars.prompt);
      }
      await page.getByRole('link',{name:'View Report'}).first().click();
      await expect(page.getByRole('heading',{name:'Imported testcase provenance'})).toBeVisible();
      await page.goto(`/#batch/${id}`); await page.reload();
      await expect(page.getByRole('link',{name:'View Report'})).toHaveCount(count);
    }
    const dispatched=readFileSync(join(state,'requests.jsonl'),'utf8').trim().split('\n').map(line=>JSON.parse(line));
    expect(dispatched.map(row=>row.body.messages[0].content)).toEqual(expectedPrompts);
    expect(dispatched).toHaveLength(63);
    // Restart the actual workflow process, then reopen persistent library/batch/reports.
    await stop(workflow);
    workflow=spawn('python',['-u',join(root,'backend/tests/serve_generic_imported_batch_offline.py'),
      '--state-dir',state,'--port',String(workflowPort)],{cwd:root,windowsHide:true,env});
    workflow.stderr.on('data',()=>{}); workflow.stdout.on('data',()=>{});
    await expect.poll(async()=>{try{
      const h=await (await page.request.get('/api/testing/health')).json();
      return h.validation_nonce!==health.validation_nonce&&h.custom_imported_batch_enabled;
    }catch{return false;}},{timeout:30000}).toBe(true);
    await page.goto('/#datasets'); await page.reload();
    await expect(page.getByText('Available Datasets (1)')).toBeVisible();
    await page.goto(`/#batch/${batches.at(-1)}`);
    await expect(page.getByRole('heading',{name:'Batch completed'})).toBeVisible();
    for(const run of reportIds)expect((await page.request.get(`/api/reports/runs/${run}`)).status()).toBe(200);
    console.log(`B4.7 acceptance: 1,2,30,30 cases; 63 native reports; original SHA256 ${originalHash}; artifacts ${state}`);
  } finally {
    await stop(workflow);
    await stop(reporting);
  }
});
