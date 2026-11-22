import {expect,test} from '@playwright/test';
import {spawn,type ChildProcessWithoutNullStreams} from 'node:child_process';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync} from 'node:fs';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {delimiter,join,resolve} from 'node:path';

const root=resolve(process.cwd(),'..');
const workflowPort=Number(process.env.SECAGENT_WORKFLOW_PROXY_PORT||'8093');
const reportingPort=Number(process.env.SECAGENT_REPORTING_PROXY_PORT||'8094');
const token='offline-browser-test-operator-secret-123456';
const free=(port:number)=>new Promise<boolean>(done=>{const server=createServer();
 server.once('error',()=>done(false));server.listen(port,'127.0.0.1',()=>server.close(()=>done(true)));});
async function stop(child:ChildProcessWithoutNullStreams|undefined){
 if(!child||child.exitCode!==null)return;child.kill();
 await new Promise<void>(done=>child.once('exit',()=>done()));
}

test('a reviewed Web Lab profile can probe and enter the imported Live Local batch through a mocked HTTP boundary',async({page})=>{
 test.setTimeout(90000);
 if(process.env.SECAGENT_LOCAL_PROXY_TOKEN!==token)test.skip(true,'Isolated local proxy credential required.');
 if(!(await free(workflowPort))||!(await free(reportingPort)))test.skip(true,'Isolated API port occupied.');
 const state=mkdtempSync(join(tmpdir(),'secagent-imported-live-policy-'));
 const runs=join(state,'results','runs');mkdirSync(runs,{recursive:true});
 const manifest=join(state,'reporting.json');
 writeFileSync(manifest,JSON.stringify({dataset_schema_version:'1.0.0',
  allowed_roots:{controlled:runs},reports:[],verification_jobs:[],controlled_runs_root:'controlled'}));
 const env={...process.env,PYTHONPATH:[join(root,'backend/src'),root].join(delimiter)};
 let workflow:ChildProcessWithoutNullStreams|undefined,reporting:ChildProcessWithoutNullStreams|undefined;
 try{
  reporting=spawn('python',['-u','-m','reporting.api','--manifest',manifest,'--port',String(reportingPort)],
   {cwd:root,windowsHide:true,env});
  workflow=spawn('python',['-u',join(root,'backend/tests/serve_generic_imported_batch_offline.py'),
   '--state-dir',state,'--port',String(workflowPort),'--live-local-fixture'],
   {cwd:root,windowsHide:true,env});
  await expect.poll(async()=>{try{const r=await page.request.get('/api/testing/health');
   return r.ok()&&(await r.json()).imported_live_local_enabled===true;}catch{return false;}},{timeout:30000}).toBe(true);
  await page.goto('/#targets');
  await page.getByRole('button',{name:'Add Target'}).click();
  await page.getByLabel('Platform identifier').fill('dvaa');
  await page.getByLabel('Platform name').fill('DVAA');
  await page.getByLabel('Target identifier').fill('dvaa-researchbot-web-lab');
  await page.getByLabel('Target display name').fill('ResearchBot Web Lab');
  await page.getByLabel('Endpoint URL').fill('http://127.0.0.1:17016/v1/chat/completions');
  await page.getByLabel('Model identifier').fill('researchbot');
  await page.getByRole('button',{name:'Validate Target Details'}).click();
  await page.getByRole('button',{name:'Save Configuration'}).click();
  await expect(page.getByRole('heading',{name:'ResearchBot Web Lab'})).toBeVisible();
  await page.getByLabel(/I confirm authorization to test/).check();
  await page.getByRole('button',{name:'Authorize target for test selection'}).click();
  await expect(page.getByText(/Reviewed for this revision/)).toBeVisible();
  await expect(page.getByRole('button',{name:'Test Connection'})).toBeDisabled();
  await page.getByLabel(/I confirm authorization for one benign probe/).check();
  await page.getByRole('button',{name:'Test Connection'}).click();
  await expect(page.getByText(/API compatibility: yes/)).toBeVisible();

  await page.goto('/#datasets');
  const validated=page.waitForResponse(response=>response.url().endsWith('/api/testing/datasets/validate'));
  await page.locator('input[type=file]').setInputFiles({name:'operator-cases.json',
   mimeType:'application/json',buffer:Buffer.from(JSON.stringify({testcases:[
    {id:'one',prompt:'Summarize a public project description.'}]}))});
  const validation=await validated;
  expect(validation.status(),JSON.stringify(await validation.json())).toBe(200);
  await expect(page.getByRole('heading',{name:/Validation Preview:/})).toBeVisible();
  await page.getByRole('button',{name:'Confirm & Import to Library'}).click();
  await expect(page.getByText('1 of 1 selected')).toBeVisible();
  await page.getByLabel('Execution mode').selectOption('live_local_http');
  await expect(page.getByText('Ready: 1 / Blocked: 0 / Unsupported: 0.')).toBeVisible();
  await expect(page.locator('.batch-launch-header').getByText(/Live Local sends each selected prompt/)).toBeVisible();
  await page.getByRole('button',{name:'Run Selected Tests'}).click();
  await expect(page).toHaveURL(/#batch\/[a-f0-9]{32}$/);
  await expect(page.getByRole('heading',{name:'Batch completed'})).toBeVisible({timeout:30000});
  await expect(page.getByText('MOCKED LIVE LOCAL POLICY')).toBeVisible();
  await page.getByRole('link',{name:'View Report'}).click();
  await expect(page.getByRole('heading',{name:'Imported testcase provenance'})).toBeVisible();
  const dispatched=readFileSync(join(state,'requests.jsonl'),'utf8').trim().split('\n').map(line=>JSON.parse(line));
  expect(dispatched).toHaveLength(2);
  expect(dispatched[0].body.messages[0].content).toBe('Reply with one word: ready.');
  expect(dispatched[1].body.messages[0].content).toBe('Summarize a public project description.');
 }finally{await stop(workflow);await stop(reporting);}
});
