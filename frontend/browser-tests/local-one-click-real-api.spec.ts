import {expect,test} from '@playwright/test';
import {spawn,type ChildProcessWithoutNullStreams} from 'node:child_process';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {delimiter,join,resolve} from 'node:path';

const root=resolve(process.cwd(),'..');
const workflowPort=Number(process.env.SECAGENT_WORKFLOW_PROXY_PORT||'8093');
const reportingPort=Number(process.env.SECAGENT_REPORTING_PROXY_PORT||'8094');
const token='offline-browser-test-operator-secret-123456';
async function free(port:number){return new Promise<boolean>(done=>{const server=createServer();
 server.once('error',()=>done(false));server.listen(port,'127.0.0.1',()=>server.close(()=>done(true)));});}

test('one local click reaches the native Runner and saved report through real APIs',async({page})=>{
 test.setTimeout(90000);
 if(process.env.SECAGENT_LOCAL_PROXY_TOKEN!==token)test.skip(true,'Isolated local proxy credential required.');
 if(!(await free(workflowPort))||!(await free(reportingPort)))test.skip(true,'Isolated API port occupied.');
 const state=mkdtempSync(join(tmpdir(),'secagent-one-click-browser-'));
 const runs=join(state,'results','runs');mkdirSync(runs,{recursive:true});
 const manifest=join(state,'reporting.json');
 writeFileSync(manifest,JSON.stringify({dataset_schema_version:'1.0.0',allowed_roots:{controlled:runs},
  reports:[],verification_jobs:[],controlled_runs_root:'controlled'}));
 const env={...process.env,PYTHONPATH:[join(root,'backend/src'),root].join(delimiter)};
 let workflow:ChildProcessWithoutNullStreams|undefined,reporting:ChildProcessWithoutNullStreams|undefined;
 try{
  reporting=spawn('python',['-u','-m','reporting.api','--manifest',manifest,'--port',String(reportingPort)],
   {cwd:root,windowsHide:true,env});
  workflow=spawn('python',['-u',join(root,'backend/tests/serve_target_management_offline.py'),
   '--state-dir',state,'--port',String(workflowPort),'--local','--local-run'],
   {cwd:root,windowsHide:true,env});
  let ready=false;
  for(let i=0;i<60;i++){
   try{const w=await page.request.get('/api/testing/health');const r=await page.request.get('/api/reports/health');
    if(w.ok()&&r.ok()&&(await w.json()).operator_mode==='local_single_user'){ready=true;break;}}
   catch{/* Services are starting */}
   await new Promise(done=>setTimeout(done,250));
  }
  expect(ready).toBe(true);
  await page.goto('/#targets');
  await page.getByRole('button',{name:'Add Target'}).click();
  await page.getByRole('button',{name:'Use DVAA ResearchBot example'}).click();
  await page.getByRole('button',{name:'Validate Target Details'}).click();
  await page.getByRole('button',{name:'Save Configuration'}).click();
  await page.getByLabel(/I confirm authorization for one benign probe/).check();
  await page.getByRole('button',{name:'Test Connection'}).click();
  await expect(page.getByText(/API compatibility: yes/)).toBeVisible();
  await page.getByRole('button',{name:'Validate Configuration'}).click();
  await page.getByRole('button',{name:'Continue'}).click();
  await page.locator('.asi-grid').getByRole('checkbox').first().check();
  await page.getByRole('button',{name:'Review testcases'}).click();
  await page.getByRole('checkbox',{name:'Select GH-C01'}).check();
  await expect(page.getByRole('heading',{name:'Ready to execute'})).toBeVisible();
  expect(await page.getByRole('button',{name:'Authorize one benign run'}).count()).toBe(0);
  expect(await page.getByRole('button',{name:'Request admission decision'}).count()).toBe(0);
  await page.getByRole('button',{name:'Run selected tests'}).click();
  await expect(page.getByRole('heading',{name:'Completed with PASS'})).toBeVisible({timeout:30000});
  await expect(page.getByText(/Response: captured/)).toBeVisible();
  expect(await page.getByText(/Non-executable draft/).count()).toBe(0);
  const link=page.getByRole('link',{name:'View report'});
  await expect(link).toHaveAttribute('href',/#run\/[a-f0-9]{32}/);
  const runId=(await link.getAttribute('href'))!.slice(5);
  const summary=JSON.parse(readFileSync(join(runs,runId,'run-summary.json'),'utf8'));
  expect(summary.target_request_count).toBe(1);
  expect(summary.response_captured).toBe(true);
  await link.click();
  await expect(page.getByRole('heading',{name:'Why this verdict was recorded'})).toBeVisible();
  await expect(page.getByRole('heading',{name:'Target response preview'})).toBeVisible();
 }finally{workflow?.kill();reporting?.kill();}
});
