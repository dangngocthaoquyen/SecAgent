import {expect,test} from '@playwright/test';
import {spawn,type ChildProcessWithoutNullStreams} from 'node:child_process';
import {mkdtempSync,mkdirSync,readdirSync,writeFileSync} from 'node:fs';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {delimiter,join,resolve} from 'node:path';

const root=resolve(process.cwd(),'..');
const workflowPort=Number(process.env.SECAGENT_WORKFLOW_PROXY_PORT||'8093');
const reportingPort=Number(process.env.SECAGENT_REPORTING_PROXY_PORT||'8094');
const token='offline-browser-test-operator-secret-123456';
async function free(port:number){return new Promise<boolean>(done=>{const server=createServer();
 server.once('error',()=>done(false));server.listen(port,'127.0.0.1',()=>server.close(()=>done(true)));});}

test('real browser runs and restores a synthetic batch through real APIs',async({page})=>{
 test.setTimeout(120000);
 if(process.env.SECAGENT_LOCAL_PROXY_TOKEN!==token)test.skip(true,'Isolated proxy credential required.');
 if(!(await free(workflowPort))||!(await free(reportingPort)))test.skip(true,'Isolated API port occupied.');
 const state=mkdtempSync(join(tmpdir(),'secagent-batch-browser-'));
 const runs=join(state,'results','runs');mkdirSync(runs,{recursive:true});
 const manifest=join(state,'reporting.json');
 writeFileSync(manifest,JSON.stringify({dataset_schema_version:'1.0.0',allowed_roots:{controlled:runs},
  reports:[],verification_jobs:[],controlled_runs_root:'controlled'}));
 const env={...process.env,PYTHONPATH:[join(root,'backend/src'),root].join(delimiter)};
 let workflow:ChildProcessWithoutNullStreams|undefined,reporting:ChildProcessWithoutNullStreams|undefined;
 async function selectCases(ids:string[]){
  await page.goto('/#targets');
  await page.getByRole('button',{name:'Validate Configuration'}).click();
  await page.getByRole('button',{name:'Continue'}).click();
  await page.locator('.asi-grid').getByRole('checkbox').first().check();
  await page.getByRole('button',{name:'Review testcases'}).click();
  for(const id of ids)await page.getByRole('checkbox',{name:`Select ${id}`}).check();
 }
 try{
  reporting=spawn('python',['-u','-m','reporting.api','--manifest',manifest,'--port',String(reportingPort)],
   {cwd:root,windowsHide:true,env});
  workflow=spawn('python',['-u',join(root,'backend/tests/serve_batch_offline.py'),
   '--state-dir',state,'--port',String(workflowPort)],{cwd:root,windowsHide:true,env});
  let ready=false;
  for(let i=0;i<80;i++){
   try{const w=await page.request.get('/api/testing/health');const r=await page.request.get('/api/reports/health');
    if(w.ok()&&r.ok()&&(await w.json()).offline_batch_enabled===true){ready=true;break;}}
   catch{/* isolated services are starting */}
   await new Promise(done=>setTimeout(done,250));
  }
  expect(ready).toBe(true);
  await selectCases(['CASE-0','CASE-1','CASE-2','CASE-3','CASE-4','UNKNOWN']);
  await expect(page.getByText(/Ready: 4 \/ Blocked: 1 \/ Unsupported: 1/)).toBeVisible();
  await expect(page.getByText(/Offline synthetic batch/)).toBeVisible();
  await page.getByRole('button',{name:'Run Selected Tests'}).click();
  await expect(page).toHaveURL(/#batch\/[a-f0-9]{32}$/);
  const firstId=page.url().split('#batch/')[1];
  await expect(page.getByRole('heading',{name:'Batch running'})).toBeVisible();
  await expect(page.locator('.batch-active-panel h2')).toHaveText('CASE-0');
  await expect(page.locator('.batch-stage')).toContainText('sending target request');
  await expect(page.getByRole('heading',{name:'Batch partially completed'})).toBeVisible();
  await expect(page.locator('.batch-progress-number strong')).toHaveText('100%');
  await expect(page.locator('.batch-metric.pass strong')).toHaveText('1');
  await expect(page.locator('.batch-metric.fail strong')).toHaveText('1');
  await expect(page.locator('.batch-metric.inconclusive strong')).toHaveText('1');
  await expect(page.locator('.batch-metric.error strong')).toHaveText('1');
  await expect(page.locator('.batch-metric.blocked strong')).toHaveText('1');
  expect(await page.getByRole('link',{name:'View Report'}).count()).toBe(4);
  expect(readdirSync(join(runs,'batch-runs')).filter(name=>name.startsWith('submission-'))).toHaveLength(1);
  const firstReport=page.getByRole('link',{name:'View Report'}).first();
  await expect(firstReport).toHaveAttribute('href',/#run\/[a-f0-9]{32}/);
  await firstReport.click();
  await expect(page.getByRole('heading',{name:'Why this verdict was recorded'})).toBeVisible();
  await page.goto(`/#batch/${firstId}`);
  await page.reload();
  await expect(page.getByRole('heading',{name:'Batch partially completed'})).toBeVisible();
  await expect(page.locator('.batch-progress-number strong')).toHaveText('100%');
  const unauthorized=await page.request.get(`http://127.0.0.1:${workflowPort}/api/testing/batches/${firstId}`);
  expect(unauthorized.status()).toBe(403);
  const unauthorizedCancel=await page.request.post(`http://127.0.0.1:${workflowPort}/api/testing/batches/${firstId}/cancel`,
   {data:{},headers:{Origin:`http://127.0.0.1:${workflowPort}`}});
  expect(unauthorizedCancel.status()).toBe(403);
  await page.goto('/#batch/invalid');
  await expect(page.getByRole('heading',{name:'Invalid batch reference'})).toBeVisible();
  await page.goto('/#batch/'+'f'.repeat(32));
  await expect(page.getByText(/Batch not found/)).toBeVisible();
  await page.goto('/#batch/'+'e'.repeat(32));
  await expect(page.getByRole('heading',{name:'Batch interrupted'})).toBeVisible();
  await expect(page.getByText(/Completed records remain saved/)).toBeVisible();

  await selectCases(['CASE-6','CASE-7','CASE-8']);
  await expect(page.getByText(/Ready: 3 \/ Blocked: 0 \/ Unsupported: 0/)).toBeVisible();
  await page.getByRole('button',{name:'Run Selected Tests'}).click();
  await expect(page).toHaveURL(/#batch\/[a-f0-9]{32}$/);
  await expect(page.locator('.batch-active-panel h2')).toHaveText('CASE-6');
  await page.getByRole('button',{name:'Cancel remaining tests'}).click();
  await expect(page.getByText(/No active HTTP request was cancelled/)).toBeVisible();
  await expect(page.getByRole('heading',{name:'Batch cancelled'})).toBeVisible();
  await expect(page.getByText(/33% processed; batch is terminal/)).toBeVisible();
  await expect(page.getByText(/Pending: 0. Cancelled before execution: 2/)).toBeVisible();
  expect(await page.getByRole('link',{name:'View Report'}).count()).toBe(1);
  expect(readdirSync(join(runs,'batch-runs')).filter(name=>name.startsWith('submission-'))).toHaveLength(2);
 }finally{workflow?.kill();reporting?.kill();}
});
