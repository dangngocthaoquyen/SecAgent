import {expect,test,type Page} from '@playwright/test';
import {spawn,type ChildProcessWithoutNullStreams} from 'node:child_process';
import {mkdtempSync,mkdirSync,writeFileSync} from 'node:fs';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {delimiter,join,resolve} from 'node:path';

const root=resolve(process.cwd(),'..');
const workflowPort=Number(process.env.SECAGENT_WORKFLOW_PROXY_PORT||'8095');
const reportingPort=Number(process.env.SECAGENT_REPORTING_PROXY_PORT||'8096');
const token='researchbot-web-batch-operator-'+'x'.repeat(32);
async function free(port:number){return new Promise<boolean>(done=>{const server=createServer();
 server.once('error',()=>done(false));server.listen(port,'127.0.0.1',()=>server.close(()=>done(true)));});}
async function stop(child:ChildProcessWithoutNullStreams|undefined){if(!child)return;
 if(child.exitCode!==null)return;child.kill();await Promise.race([
  new Promise<void>(done=>child.once('exit',()=>done())),new Promise<void>(done=>setTimeout(done,5000))]);}
async function selectWebCase(page:Page){
 await page.goto('/#targets');
 await page.getByRole('button',{name:'Validate Configuration'}).click();
 await page.getByRole('button',{name:'Continue'}).click();
 await page.locator('.asi-grid').getByRole('checkbox').first().check();
 await page.getByRole('button',{name:'Review testcases'}).click();
 await page.getByRole('checkbox',{name:'Select GH-WEB-001'}).check();
 await expect(page.getByText(/Ready: 1 \/ Blocked: 0 \/ Unsupported: 0/)).toBeVisible();
}

test('browser launches the restricted Web contract through real offline APIs',async({page})=>{
 test.setTimeout(180000);
 if(process.env.SECAGENT_LOCAL_PROXY_TOKEN!==token)test.skip(true,'Isolated Web Lab proxy credential required.');
 if(!(await free(workflowPort))||!(await free(reportingPort)))test.skip(true,'Isolated API port occupied.');
 const state=mkdtempSync(join(tmpdir(),'secagent-web-lab-browser-'));
 const runs=join(state,'results','runs');mkdirSync(runs,{recursive:true});
 const manifest=join(state,'reporting.json');
 writeFileSync(manifest,JSON.stringify({dataset_schema_version:'1.0.0',
  allowed_roots:{controlled:runs},reports:[],verification_jobs:[],controlled_runs_root:'controlled'}));
 const env={...process.env,PYTHONPATH:[join(root,'backend/src'),root].join(delimiter)};
 let workflow:ChildProcessWithoutNullStreams|undefined,reporting:ChildProcessWithoutNullStreams|undefined;
 try{
  reporting=spawn('python',['-u','-m','reporting.api','--manifest',manifest,'--port',String(reportingPort)],
   {cwd:root,windowsHide:true,env});
  workflow=spawn('python',['-u',join(root,'backend/tests/serve_researchbot_web_batch_offline.py'),
   '--state-dir',state,'--port',String(workflowPort)],{cwd:root,windowsHide:true,env});
  let ready=false;
  for(let i=0;i<80;i++){
   try{const w=await page.request.get('/api/testing/health');const r=await page.request.get('/api/reports/health');
    if(w.ok()&&r.ok()&&(await w.json()).web_lab_batch_enabled===true){ready=true;break;}}
   catch{/* isolated services are starting */}
   await new Promise(done=>setTimeout(done,250));
  }
  expect(ready).toBe(true);
  await page.goto('/#targets');
  await page.getByRole('button',{name:'Validate Configuration'}).click();
  await page.getByRole('button',{name:'Continue'}).click();
  await page.locator('.asi-grid').getByRole('checkbox').first().check();
  await page.getByRole('button',{name:'Review testcases'}).click();
  await expect(page.getByText(/guarded Web Lab permits GH-WEB-001 only/)).toBeVisible();
  await page.getByRole('checkbox',{name:'Select GH-WEB-001'}).check();
  await expect(page.getByText(/Request limit/)).toBeVisible();
  await expect(page.getByText(/Ready: 1 \/ Blocked: 0 \/ Unsupported: 0/)).toBeVisible();
  await page.getByRole('button',{name:'Run Selected Tests'}).click();
  await expect(page).toHaveURL(/#batch\/[a-f0-9]{32}$/);
  const batchId=page.url().split('#batch/')[1];
  await expect(page.getByRole('heading',{name:'Batch completed'})).toBeVisible();
  await expect(page.locator('.batch-metric.fail strong')).toHaveText('1');
  await expect(page.getByText(/Processed 1 \/ 1 case records/)).toBeVisible();
  await page.locator('.batch-advanced summary').click();
  await expect(page.getByText(/Budget consumed: 2/)).toBeVisible();
  const nonce=(await (await page.request.get('/api/testing/health')).json()).validation_nonce;
  const events=await page.request.get(`/api/testing/batches/${batchId}/events`,
   {headers:{'X-SecAgent-Validation':nonce}});
  expect(events.ok()).toBe(true);
  expect((await events.json()).events.map((event:{stage:string})=>event.stage)).toContain('verifying_web_capability');
  const report=page.getByRole('link',{name:'View Report'});
  await expect(report).toHaveAttribute('href',/#run\/[a-f0-9]{32}/);
  const firstRun=(await report.getAttribute('href'))!.split('#run/')[1];
  await report.click();
  await expect(page.getByRole('heading',{name:'Why this verdict was recorded'})).toBeVisible();
  await expect(page.getByText('Recorded target requests')).toBeVisible();
  await expect(page.getByText('synthetic_mock')).toBeVisible();
  await page.reload();
  await expect(page.getByRole('heading',{name:'Why this verdict was recorded'})).toBeVisible();
  await page.goto(`/#batch/${batchId}`);
  await page.reload();
  await expect(page.getByRole('heading',{name:'Batch completed'})).toBeVisible();
  await expect(page.locator('.batch-metric.fail strong')).toHaveText('1');
  await selectWebCase(page);
  await page.getByRole('button',{name:'Run Selected Tests'}).click();
  await expect(page).toHaveURL(/#batch\/[a-f0-9]{32}$/);
  const secondBatch=page.url().split('#batch/')[1];
  expect(secondBatch).not.toBe(batchId);
  await expect(page.getByRole('heading',{name:'Batch completed'})).toBeVisible();
  const secondRun=(await page.getByRole('link',{name:'View Report'}).getAttribute('href'))!.split('#run/')[1];
  expect(secondRun).not.toBe(firstRun);
  for(const runId of [firstRun,secondRun]){
   const saved=await page.request.get(`/api/reports/runs/${runId}`);
   expect(saved.status()).toBe(200);
   const data=await saved.json();
   expect(data.run_id).toBe(runId);
   expect(data.target_request_count).toBe(2);
   expect(data.execution.identity.testcase_id).toBe('GH-WEB-001');
   expect(data.execution.security.verdict).toBe('FAIL');
  }
  await page.getByRole('link',{name:'View Report'}).click();
  await expect(page.getByRole('heading',{name:'Why this verdict was recorded'})).toBeVisible();
  const direct=await page.request.get(`http://127.0.0.1:${workflowPort}/api/testing/batches/${batchId}`);
  expect(direct.status()).toBe(403);
 }finally{await stop(workflow);await stop(reporting);}
});

test('browser keeps failed preflight, missing callback and cancellation separate',async({page})=>{
 test.setTimeout(180000);
 if(process.env.SECAGENT_LOCAL_PROXY_TOKEN!==token)test.skip(true,'Isolated Web Lab proxy credential required.');
 for(const scenario of ['no_fetch','missing_callback','slow_preflight'] as const){
  if(!(await free(workflowPort))||!(await free(reportingPort)))throw Error('Isolated API port occupied.');
  const state=mkdtempSync(join(tmpdir(),`secagent-web-${scenario}-`));
  const runs=join(state,'results','runs');mkdirSync(runs,{recursive:true});
  const manifest=join(state,'reporting.json');
  writeFileSync(manifest,JSON.stringify({dataset_schema_version:'1.0.0',
   allowed_roots:{controlled:runs},reports:[],verification_jobs:[],controlled_runs_root:'controlled'}));
  const env={...process.env,PYTHONPATH:[join(root,'backend/src'),root].join(delimiter)};
  let workflow:ChildProcessWithoutNullStreams|undefined,reporting:ChildProcessWithoutNullStreams|undefined;
  try{
   reporting=spawn('python',['-u','-m','reporting.api','--manifest',manifest,'--port',String(reportingPort)],
    {cwd:root,windowsHide:true,env});
   workflow=spawn('python',['-u',join(root,'backend/tests/serve_researchbot_web_batch_offline.py'),
    '--state-dir',state,'--port',String(workflowPort),'--scenario',scenario],
    {cwd:root,windowsHide:true,env});
   let ready=false;
   for(let i=0;i<80;i++){
    try{const h=await page.request.get('/api/testing/health');
     if(h.ok()&&(await h.json()).web_lab_batch_enabled===true){ready=true;break;}}
    catch{/* isolated service is starting */}
    await new Promise(done=>setTimeout(done,250));
   }
   expect(ready).toBe(true);
   await selectWebCase(page);
   await page.getByRole('button',{name:'Run Selected Tests'}).click();
   await expect(page).toHaveURL(/#batch\/[a-f0-9]{32}$/);
   if(scenario==='slow_preflight'){
    await expect(page.getByRole('heading',{name:'Batch running'})).toBeVisible();
    await expect(page.locator('.batch-stage')).toContainText('sending target request');
    await page.getByRole('button',{name:'Cancel remaining tests'}).click();
    await expect(page.getByRole('heading',{name:'Batch cancelled'})).toBeVisible();
    await expect(page.getByText(/No active HTTP request was cancelled/)).toBeVisible();
    await page.locator('.batch-advanced summary').click();
    await expect(page.getByText(/Budget consumed: 1/)).toBeVisible();
   }else if(scenario==='no_fetch'){
    await expect(page.getByRole('heading',{name:'Batch partially completed'})).toBeVisible();
    await expect(page.getByText(/fresh page fetch was not independently verified/)).toBeVisible();
    await page.locator('.batch-advanced summary').click();
    await expect(page.getByText(/Budget consumed: 1/)).toBeVisible();
    expect(await page.getByRole('link',{name:'View Report'}).count()).toBe(0);
   }else{
    await expect(page.getByRole('heading',{name:'Batch completed'})).toBeVisible();
    await expect(page.locator('.batch-metric.inconclusive strong')).toHaveText('1');
    await page.locator('.batch-advanced summary').click();
    await expect(page.getByText(/Budget consumed: 2/)).toBeVisible();
    await expect(page.getByRole('link',{name:'View Report'})).toBeVisible();
   }
  }finally{await stop(workflow);await stop(reporting);}
 }
});

test('browser-managed Web Lab target fixes the operator endpoint mismatch before execution',async({page})=>{
 test.setTimeout(120000);
 if(process.env.SECAGENT_LOCAL_PROXY_TOKEN!==token)test.skip(true,'Isolated Web Lab proxy credential required.');
 if(!(await free(workflowPort))||!(await free(reportingPort)))test.skip(true,'Isolated API port occupied.');
 const state=mkdtempSync(join(tmpdir(),'secagent-web-managed-browser-'));
 const runs=join(state,'results','runs');mkdirSync(runs,{recursive:true});
 const manifest=join(state,'reporting.json');
 writeFileSync(manifest,JSON.stringify({dataset_schema_version:'1.0.0',
  allowed_roots:{controlled:runs},reports:[],verification_jobs:[],controlled_runs_root:'controlled'}));
 const env={...process.env,PYTHONPATH:[join(root,'backend/src'),root].join(delimiter)};
 let workflow:ChildProcessWithoutNullStreams|undefined,reporting:ChildProcessWithoutNullStreams|undefined;
 try{
  reporting=spawn('python',['-u','-m','reporting.api','--manifest',manifest,'--port',String(reportingPort)],
   {cwd:root,windowsHide:true,env});
  workflow=spawn('python',['-u',join(root,'backend/tests/serve_researchbot_web_batch_offline.py'),
   '--state-dir',state,'--port',String(workflowPort),'--browser-managed-target'],
   {cwd:root,windowsHide:true,env});
  let ready=false;
  for(let i=0;i<80;i++){
   try{const h=await page.request.get('/api/testing/health');
    if(h.ok()&&(await h.json()).web_lab_batch_enabled===true){ready=true;break;}}
   catch{/* isolated API is starting */}
   await new Promise(done=>setTimeout(done,250));
  }
  expect(ready).toBe(true);
  const origin=`http://127.0.0.1:${process.env.SECAGENT_FRONTEND_PORT||'5185'}`;
  const nonce=(await (await page.request.get('/api/testing/health')).json()).validation_nonce;
  async function preview(){
   const targets=(await (await page.request.get('/api/testing/targets')).json()).targets;
   const row=targets.find((item:{id:string})=>item.id==='dvaa-researchbot-web-lab');
   expect(row).toBeTruthy();
   const target={target_id:row.id,profile_revision:row.profile_revision,
    policy_ref:row.policy_ref,endpoint:row.endpoint,protocol:row.protocol,
    method:row.method,request_mapping:row.request_mapping,response_parser:row.response_parser,
    credential_alias:row.credential_alias,model:row.default_model,timeout_seconds:row.timeout_default};
   return page.request.post('/api/testing/batches/preview',{data:{target,
    testcase_ids:['GH-WEB-001'],total_request_budget:2,evaluation_mode:'rule_only'},
    headers:{Origin:origin,'X-SecAgent-Validation':nonce}});
  }
  await page.goto('/#targets');
  await page.getByRole('button',{name:'Add Target'}).click();
  await page.getByLabel('Platform identifier').fill('dvaa');
  await page.getByLabel('Platform name').fill('DVAA');
  await page.getByLabel('Target identifier').fill('dvaa-researchbot-web-lab');
  await page.getByLabel('Target display name').fill('Restricted ResearchBot Web Lab');
  await page.getByLabel('Endpoint URL').fill('http://127.0.0.1:7015/v1/chat/completions');
  await page.getByLabel('Model identifier').fill('researchbot');
  await page.getByLabel('Timeout (seconds)').fill('3');
  await page.getByRole('button',{name:'Validate Target Details'}).click();
  await page.getByRole('button',{name:'Save Configuration'}).click();
  await expect(page.getByText(/The restricted Web Lab starts only for an assessment/)).toBeVisible();
  expect(await page.getByRole('button',{name:'Test Connection'}).count()).toBe(0);
  const unreviewed=await preview();
  expect(unreviewed.status()).toBe(409);
  expect((await unreviewed.json()).error.code).toBe('web_lab_target_not_reviewed');
  await page.getByLabel(/I confirm authorization to test/).check();
  await page.getByRole('button',{name:'Authorize target for test selection'}).click();
  await expect(page.getByText(/Reviewed for this revision/)).toBeVisible();
  const wrong=await preview();
  expect(wrong.status()).toBe(409);
  expect((await wrong.json()).error.code).toBe('web_lab_endpoint_mismatch');
  expect((await wrong.json()).error.message).toContain('127.0.0.1:17016');
  await page.getByRole('button',{name:'Validate Configuration'}).click();
  await page.getByRole('button',{name:'Continue'}).click();
  await page.locator('.asi-grid').getByRole('checkbox').first().check();
  await page.getByRole('button',{name:'Review testcases'}).click();
  await expect(page.getByRole('checkbox',{name:'Select GH-WEB-001'})).toBeEnabled();
  await expect(page.locator('tr').filter({has:page.getByRole('checkbox',{name:'Select GH-WEB-001'})}))
   .toContainText('This Web Lab target needs endpoint http://127.0.0.1:17016');
  await page.goto('/#targets');
  await page.getByRole('button',{name:'Edit Target'}).click();
  await page.getByLabel('Endpoint URL').fill('http://127.0.0.1:17016/v1/chat/completions');
  await page.getByRole('button',{name:'Validate Target Details'}).click();
  await page.getByRole('button',{name:'Save Configuration'}).click();
  const changed=await preview();
  expect(changed.status()).toBe(409);
  expect((await changed.json()).error.code).toBe('web_lab_target_not_reviewed');
  await page.getByLabel(/I confirm authorization to test/).check();
  await page.getByRole('button',{name:'Authorize target for test selection'}).click();
  await expect(page.getByText(/Reviewed for this revision/)).toBeVisible();
  const valid=await preview();
  expect(valid.status()).toBe(200);
  const plan=await valid.json();
  expect(plan.plan_id).toMatch(/^[a-f0-9]{64}$/);
  expect(plan.target_request_budget).toBe(2);
  expect(plan.items[0].status).toBe('ready');
  await selectWebCase(page);
  await expect(page.getByRole('button',{name:'Run Selected Tests'})).toBeEnabled();
  await page.getByRole('button',{name:'Run Selected Tests'}).click();
  await expect(page).toHaveURL(/#batch\/[a-f0-9]{32}$/);
  await expect(page.getByRole('heading',{name:'Batch completed'})).toBeVisible();
  await page.getByRole('link',{name:'View Report'}).click();
  await expect(page.getByRole('heading',{name:'Why this verdict was recorded'})).toBeVisible();
 }finally{await stop(workflow);await stop(reporting);}
});
