import {expect,test} from '@playwright/test';
import {spawn,type ChildProcessWithoutNullStreams} from 'node:child_process';
import {mkdtempSync,mkdirSync,writeFileSync} from 'node:fs';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {delimiter,join,resolve} from 'node:path';

const root=resolve(process.cwd(),'..');
const workflowPort=Number(process.env.SECAGENT_WORKFLOW_PROXY_PORT||'8093');
const reportingPort=Number(process.env.SECAGENT_REPORTING_PROXY_PORT||'8094');
const token='offline-browser-test-operator-secret-123456';
async function free(port:number){return new Promise<boolean>(done=>{const server=createServer();
 server.once('error',()=>done(false));server.listen(port,'127.0.0.1',()=>server.close(()=>done(true)));});}

test('operator reviews ToolBot Lab and opens native TM-002 report',async({page})=>{
 test.setTimeout(120000);
 if(process.env.SECAGENT_LOCAL_PROXY_TOKEN!==token)test.skip(true,'Isolated proxy credential required.');
 if(!(await free(workflowPort))||!(await free(reportingPort)))test.skip(true,'Isolated API port occupied.');
 const state=mkdtempSync(join(tmpdir(),'secagent-toolbot-browser-'));
 const runs=join(state,'results','runs');mkdirSync(runs,{recursive:true});
 const manifest=join(state,'reporting.json');
 writeFileSync(manifest,JSON.stringify({dataset_schema_version:'1.0.0',
  allowed_roots:{controlled:runs},reports:[],verification_jobs:[],controlled_runs_root:'controlled'}));
 const env={...process.env,PYTHONPATH:[join(root,'backend/src'),root].join(delimiter)};
 let workflow:ChildProcessWithoutNullStreams|undefined,reporting:ChildProcessWithoutNullStreams|undefined;
 try{
  reporting=spawn('python',['-u','-m','reporting.api','--manifest',manifest,'--port',String(reportingPort)],
   {cwd:root,windowsHide:true,env});
  workflow=spawn('python',['-u',join(root,'backend/tests/serve_toolbot_lab_offline.py'),
   '--state-dir',state,'--port',String(workflowPort)],{cwd:root,windowsHide:true,env});
  await expect.poll(async()=>{try{const response=await page.request.get('/api/testing/health');
   return response.ok()&&(await response.json()).toolbot_lab_batch_enabled===true;}
   catch{return false;}},{timeout:30000}).toBe(true);
  await page.goto('/#targets');
  await page.getByRole('button',{name:'Add Target'}).click();
  await page.getByRole('button',{name:'Use offline ToolBot Lab example'}).click();
  await expect(page.getByLabel('Endpoint URL')).toHaveValue('http://127.0.0.1:17022/mcp');
  await page.getByRole('button',{name:'Validate Target Details'}).click();
  await page.getByRole('button',{name:'Save Configuration'}).click();
  await expect(page.getByText(/This is an offline synthetic ToolBot Lab/)).toBeVisible();
  await page.getByLabel('I confirm authorization to test http://127.0.0.1:17022/mcp').check();
  await page.getByRole('button',{name:'Authorize target for test selection'}).click();
  await page.getByRole('button',{name:'Validate Configuration'}).click();
  await page.getByRole('button',{name:'Continue'}).click();
  await page.locator('.asi-grid').getByRole('checkbox').nth(1).check();
  await page.getByRole('button',{name:'Review testcases'}).click();
  await expect(page.getByRole('checkbox',{name:'Select TM-001'})).toBeVisible();
  await page.getByRole('button',{name:'Select All Compatible'}).click();
  await expect(page.getByRole('checkbox',{name:'Select TM-002'})).toBeChecked();
  await expect(page.getByRole('region',{name:'Offline ToolBot Lab execution'})).toBeVisible();
  await expect(page.getByText(/Ready: 1 \/ Blocked: 0 \/ Unsupported: 0/)).toBeVisible();
  await page.getByRole('button',{name:'Run Selected Tests'}).click();
  await expect(page).toHaveURL(/#batch\/[a-f0-9]{32}$/);
  await expect(page.getByRole('heading',{name:'Batch completed'})).toBeVisible();
  await expect(page.locator('.batch-metric.fail strong')).toHaveText('1');
  await expect(page.getByText(/MCP result captured/)).toBeVisible();
  await page.locator('.batch-advanced summary').click();
  await expect(page.getByText('Target requests recorded: 1')).toBeVisible();
  const id=page.url().split('#batch/')[1];
  const health=await (await page.request.get('/api/testing/health')).json();
  const results=await page.request.get(`/api/testing/batches/${id}/results`,
   {headers:{'X-SecAgent-Validation':health.validation_nonce}});
  expect(results.status()).toBe(200);
  const caseRow=(await results.json()).results[0];
  expect(caseRow.testcase_id).toBe('TM-002');
  expect(caseRow.verdict).toBe('FAIL');
  expect(caseRow.evidence_provenance).toBe('synthetic_mock');
  const saved=await page.request.get(`/api/reports/runs/${caseRow.report_run_id}`);
  expect(saved.status()).toBe(200);
  const report=await saved.json();
  expect(report.execution.identity.testcase_id).toBe('TM-002');
  expect(report.execution.security.verdict).toBe('FAIL');
  expect(report.execution.observation.evidence.map((e:{kind:string})=>e.kind)).toEqual(
   ['tool_request','target_tool_result','tool_call','tool_trace']);
  await page.getByRole('link',{name:'View Report'}).click();
  await expect(page.getByRole('heading',{name:'Why this verdict was recorded'})).toBeVisible();
  await page.goto(`/#batch/${id}`);await page.reload();
  await expect(page.getByRole('heading',{name:'Batch completed'})).toBeVisible();
  await expect(page.getByRole('link',{name:'View Report'})).toHaveCount(1);
  expect((await page.request.get(`http://127.0.0.1:${workflowPort}/api/testing/batches/${id}`)).status()).toBe(403);
 }finally{workflow?.kill();reporting?.kill();}
});
