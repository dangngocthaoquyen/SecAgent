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
const shots=mkdtempSync(join(tmpdir(),'secagent-asi01-screenshots-'));
async function free(port:number){return new Promise<boolean>(done=>{const server=createServer();
 server.once('error',()=>done(false));server.listen(port,'127.0.0.1',()=>server.close(()=>done(true)));});}

test('real browser submits reviewed native ASI01 text batch through mock transport',async({page})=>{
 test.setTimeout(120000);
 if(process.env.SECAGENT_LOCAL_PROXY_TOKEN!==token)test.skip(true,'Isolated proxy credential required.');
 if(!(await free(workflowPort))||!(await free(reportingPort)))test.skip(true,'Isolated API port occupied.');
 const state=mkdtempSync(join(tmpdir(),'secagent-asi01-browser-'));
 const runs=join(state,'results','runs');mkdirSync(runs,{recursive:true});
 const manifest=join(state,'reporting.json');
 writeFileSync(manifest,JSON.stringify({dataset_schema_version:'1.0.0',allowed_roots:{controlled:runs},
  reports:[],verification_jobs:[],controlled_runs_root:'controlled'}));
 const env={...process.env,PYTHONPATH:[join(root,'backend/src'),root].join(delimiter)};
 let workflow:ChildProcessWithoutNullStreams|undefined,reporting:ChildProcessWithoutNullStreams|undefined;
 try{
  reporting=spawn('python',['-u','-m','reporting.api','--manifest',manifest,'--port',String(reportingPort)],
   {cwd:root,windowsHide:true,env});
  workflow=spawn('python',['-u',join(root,'backend/tests/serve_asi01_batch_offline.py'),
   '--state-dir',state,'--port',String(workflowPort)],{cwd:root,windowsHide:true,env});
  let ready=false;
  for(let i=0;i<80;i++){
   try{const w=await page.request.get('/api/testing/health');const r=await page.request.get('/api/reports/health');
    if(w.ok()&&r.ok()&&(await w.json()).asi01_batch_enabled===true){ready=true;break;}}
   catch{/* isolated services are starting */}
   await new Promise(done=>setTimeout(done,250));
  }
  expect(ready).toBe(true);
  await page.goto('/#targets');
  await page.getByRole('button',{name:'Validate Configuration'}).click();
  await page.getByRole('button',{name:'Continue'}).click();
  await page.locator('.asi-grid').getByRole('checkbox').first().check();
  await page.getByRole('button',{name:'Review testcases'}).click();
  await page.getByRole('button',{name:'Select All Compatible'}).click();
  for(const caseId of ['GH-C01','GH-001','GH-002'])
   await expect(page.getByRole('checkbox',{name:`Select ${caseId}`,exact:true})).toBeChecked();
  for(const id of ['GH-002','GH-001','GH-C01','GH-WEB-C01'])
   await page.getByRole('checkbox',{name:`Select ${id}`,exact:true}).check();
  await expect(page.getByRole('region',{name:'Controlled ASI01 batch execution'})).toBeVisible();
  await expect(page.getByText(/Ready: 3 \/ Blocked: 1 \/ Unsupported: 0/)).toBeVisible();
  await expect(page.getByText(/Web fetch and independent action scope evidence are not available/)).toBeVisible();
  await page.getByRole('button',{name:'Run Selected Tests'}).click();
  await expect(page).toHaveURL(/#batch\/[a-f0-9]{32}$/);
  const id=page.url().split('#batch/')[1];
  await expect(page.locator('.batch-active-panel h2')).toHaveText('GH-C01');
  await expect(page.locator('.batch-stage')).toContainText('sending target request');
  mkdirSync(shots,{recursive:true});
  await page.setViewportSize({width:1440,height:900});
  await page.screenshot({path:join(shots,'asi01-running-desktop.png')});
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:join(shots,'asi01-running-mobile.png'),fullPage:true});
  expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await expect(page.getByRole('heading',{name:'Batch partially completed'})).toBeVisible();
  await expect(page.locator('.batch-progress-number strong')).toHaveText('100%');
  await expect(page.locator('.batch-metric.pass strong')).toHaveText('1');
  await expect(page.locator('.batch-metric.fail strong')).toHaveText('1');
  await expect(page.locator('.batch-metric.inconclusive strong')).toHaveText('1');
  await expect(page.locator('.batch-metric.blocked strong')).toHaveText('1');
  await page.screenshot({path:join(shots,'asi01-completed-mobile.png'),fullPage:true});
  await page.setViewportSize({width:1440,height:900});
  await page.screenshot({path:join(shots,'asi01-completed-desktop.png'),fullPage:true});
  expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(1440);
  await expect(page.getByText(/synthetic mock source/).first()).toBeVisible();
  expect(await page.getByRole('link',{name:'View Report'}).count()).toBe(3);
  const health=await (await page.request.get('/api/testing/health')).json();
  const response=await page.request.get(`/api/testing/batches/${id}/results`,
   {headers:{'X-SecAgent-Validation':health.validation_nonce}});
  expect(response.status()).toBe(200);
  const data=await response.json();
  const attacks=data.results.filter((item:{testcase_id:string})=>['GH-001','GH-002'].includes(item.testcase_id));
  expect(attacks).toHaveLength(2);
  expect(new Set(attacks.map((item:{report_run_id:string})=>item.report_run_id)).size).toBe(2);
  expect(new Set(attacks.map((item:{execution_id:string})=>item.execution_id)).size).toBe(2);
  expect(attacks.map((item:{verdict:string})=>item.verdict).sort()).toEqual(['FAIL','INCONCLUSIVE']);
  expect(attacks.every((item:{request_count:number;status:string})=>item.request_count===1&&item.status==='completed')).toBe(true);
  expect(data.aggregate_report_sha256).toMatch(/^[a-f0-9]{64}$/);
  for(const item of attacks){
   const saved=await page.request.get(`/api/reports/runs/${item.report_run_id}`);
   expect(saved.status()).toBe(200);
   const report=await saved.json();
   expect(report.run_id).toBe(item.report_run_id);
   expect(report.execution.identity.testcase_id).toBe(item.testcase_id);
   expect(report.execution.security.verdict).toBe(item.verdict);
   expect(report.execution.observation.evidence.length).toBeGreaterThan(0);
  }
  await page.getByRole('button',{name:'View Reports (3)'}).click();
  await expect(page).toHaveURL(new RegExp(`#batch/${id}$`));
  await page.getByRole('link',{name:'View Report'}).first().click();
  await expect(page.getByRole('heading',{name:'Why this verdict was recorded'})).toBeVisible();
  await page.goto(`/#batch/${id}`);
  await page.reload();
  await expect(page.getByRole('heading',{name:'Batch partially completed'})).toBeVisible();
  const unauthorized=await page.request.get(`http://127.0.0.1:${workflowPort}/api/testing/batches/${id}`);
  expect(unauthorized.status()).toBe(403);
 }finally{workflow?.kill();reporting?.kill();}
});

test('operator manages SecureBot and opens standalone and multi-test reports',async({page})=>{
 test.setTimeout(120000);
 if(process.env.SECAGENT_LOCAL_PROXY_TOKEN!==token)test.skip(true,'Isolated proxy credential required.');
 if(!(await free(workflowPort))||!(await free(reportingPort)))test.skip(true,'Isolated API port occupied.');
 const state=mkdtempSync(join(tmpdir(),'secagent-securebot-browser-'));
 const runs=join(state,'results','runs');mkdirSync(runs,{recursive:true});
 const manifest=join(state,'reporting.json');
 writeFileSync(manifest,JSON.stringify({dataset_schema_version:'1.0.0',allowed_roots:{controlled:runs},
  reports:[],verification_jobs:[],controlled_runs_root:'controlled'}));
 const env={...process.env,PYTHONPATH:[join(root,'backend/src'),root].join(delimiter)};
 let workflow:ChildProcessWithoutNullStreams|undefined,reporting:ChildProcessWithoutNullStreams|undefined;
 try{
  reporting=spawn('python',['-u','-m','reporting.api','--manifest',manifest,'--port',String(reportingPort)],
   {cwd:root,windowsHide:true,env});
  workflow=spawn('python',['-u',join(root,'backend/tests/serve_asi01_batch_offline.py'),
   '--state-dir',state,'--port',String(workflowPort),'--operator-manage'],{cwd:root,windowsHide:true,env});
  await expect.poll(async()=>{
   try{const response=await page.request.get('/api/testing/health');
    return response.ok()&&(await response.json()).asi01_batch_enabled===true;}
   catch{return false;}
  },{timeout:30000}).toBe(true);
  await page.goto('/#targets');
  await page.getByRole('button',{name:'Add Target'}).click();
  await page.getByLabel('Platform identifier').fill('dvaa');
  await page.getByLabel('Platform name').fill('DVAA');
  await page.getByLabel('Target identifier').fill('dvaa-securebot');
  await page.getByLabel('Target display name').fill('DVAA SecureBot');
  await page.getByLabel('Endpoint URL').fill('http://127.0.0.1:7001/v1/chat/completions');
  await page.getByLabel('Model identifier').fill('securebot');
  await page.getByRole('button',{name:'Validate Target Details'}).click();
  await page.getByRole('button',{name:'Save Configuration'}).click();
  await expect(page.getByText('Target: DVAA SecureBot (dvaa-securebot).')).toBeVisible();
  await page.getByLabel(/I confirm authorization for one benign probe/).check();
  await page.getByRole('button',{name:'Test Connection'}).click();
  await expect(page.getByText(/Reviewed for this revision/)).toBeVisible();

  async function chooseCases(all:boolean){
   await page.goto('/#targets');
   await page.getByRole('button',{name:'Validate Configuration'}).click();
   await page.getByRole('button',{name:'Continue'}).click();
   await page.locator('.asi-grid').getByRole('checkbox').first().check();
   await page.getByRole('button',{name:'Review testcases'}).click();
   if(all)await page.getByRole('button',{name:'Select All Compatible'}).click();
   else await page.getByRole('checkbox',{name:'Select GH-C01'}).check();
  }
  await chooseCases(false);
  await expect(page.getByText(/Ready: 1 \/ Blocked: 0 \/ Unsupported: 0/)).toBeVisible();
  await page.getByRole('button',{name:'Run Selected Tests'}).click();
  await expect(page).toHaveURL(/#batch\/[a-f0-9]{32}$/);
  await expect(page.getByRole('heading',{name:'Batch completed'})).toBeVisible();
  const solo=page.url().split('#batch/')[1];
  await expect(page.locator('.batch-metric.pass strong')).toHaveText('1');
  const soloReport=page.getByRole('link',{name:'View Report'});
  const soloRun=(await soloReport.getAttribute('href'))!.split('#run/')[1];
  await soloReport.click();
  await expect(page.getByRole('heading',{name:'Why this verdict was recorded'})).toBeVisible();

  await chooseCases(true);
  for(const id of ['GH-C01','GH-001','GH-002'])
   await expect(page.getByRole('checkbox',{name:`Select ${id}`})).toBeChecked();
  await expect(page.getByText(/Ready: 3 \/ Blocked: 0 \/ Unsupported: 0/)).toBeVisible();
  await expect(page.getByText(/Request limit/)).toBeVisible();
  await page.getByRole('button',{name:'Run Selected Tests'}).click();
  await expect(page).toHaveURL(/#batch\/[a-f0-9]{32}$/);
  await expect(page.getByRole('heading',{name:'Batch completed'})).toBeVisible();
  const batchId=page.url().split('#batch/')[1];
  expect(batchId).not.toBe(solo);
  await expect(page.locator('.batch-metric.pass strong')).toHaveText('1');
  await expect(page.locator('.batch-metric.fail strong')).toHaveText('1');
  await expect(page.locator('.batch-metric.inconclusive strong')).toHaveText('1');
  await page.locator('.batch-advanced summary').click();
  await expect(page.getByText('Target requests recorded: 3')).toBeVisible();
  const nonce=(await (await page.request.get('/api/testing/health')).json()).validation_nonce;
  const response=await page.request.get(`/api/testing/batches/${batchId}/results`,
   {headers:{'X-SecAgent-Validation':nonce}});
  expect(response.status()).toBe(200);
  const data=await response.json();
  expect(data.aggregate_report_sha256).toMatch(/^[a-f0-9]{64}$/);
  const attacks=data.results.filter((item:{testcase_id:string})=>['GH-001','GH-002'].includes(item.testcase_id));
  expect(attacks).toHaveLength(2);
  expect(new Set(attacks.map((item:{execution_id:string})=>item.execution_id)).size).toBe(2);
  expect(new Set(attacks.map((item:{report_run_id:string})=>item.report_run_id)).size).toBe(2);
  for(const row of data.results){
   const report=await page.request.get(`/api/reports/runs/${row.report_run_id}`);
   expect(report.status()).toBe(200);
   const detail=await report.json();
   expect(detail.execution.identity.testcase_id).toBe(row.testcase_id);
   expect(detail.execution.security.verdict).toBe(row.verdict);
   expect(detail.execution.observation.evidence.length).toBeGreaterThan(0);
  }
  expect((await page.request.get(`/api/reports/runs/${soloRun}`)).status()).toBe(200);
  await page.getByRole('link',{name:'View Report'}).first().click();
  await expect(page.getByRole('heading',{name:'Why this verdict was recorded'})).toBeVisible();
  await page.goto(`/#batch/${batchId}`);
  await page.reload();
  await expect(page.getByRole('heading',{name:'Batch completed'})).toBeVisible();
  await expect(page.getByRole('link',{name:'View Report'})).toHaveCount(3);
 }finally{workflow?.kill();reporting?.kill();}
});
