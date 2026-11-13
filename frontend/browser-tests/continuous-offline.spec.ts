import {expect,test} from '@playwright/test';
import {spawn,type ChildProcessWithoutNullStreams} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync,mkdtempSync,readFileSync} from 'node:fs';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {delimiter,join,resolve} from 'node:path';

const root=resolve(process.cwd(),'..');
const base='http://127.0.0.1:5173';

async function free(port:number):Promise<boolean>{
 return new Promise(resolve=>{const server=createServer();server.once('error',()=>resolve(false));
  server.listen(port,'127.0.0.1',()=>server.close(()=>resolve(true)));});
}

async function start(stateDir:string):Promise<{child:ChildProcessWithoutNullStreams;token:string}>{
 const child=spawn('python',['-u',join(root,'backend/tests/serve_continuous_offline_acceptance.py'),
  '--state-dir',stateDir],{cwd:root,windowsHide:true,env:{...process.env,
  PYTHONPATH:[join(root,'backend/src'),join(root,'backend/tests'),root].join(delimiter)}});
 const token=await new Promise<string>((resolve,reject)=>{
  let output='',errors='';const timer=setTimeout(()=>reject(Error('Offline API startup timed out: '+errors)),20000);
  child.stdout.on('data',chunk=>{output+=String(chunk);const ready=output.match(/READY ([A-Za-z0-9_-]{43})/);
   if(ready){clearTimeout(timer);resolve(ready[1]);}});
  child.stderr.on('data',chunk=>{errors+=String(chunk);});
  child.once('exit',code=>{clearTimeout(timer);reject(Error('Offline API exited '+code+': '+errors));});
 });
 return {child,token};
}

async function plan(page:import('@playwright/test').Page){
 await page.goto('/#targets');
 await expect(page.getByRole('heading',{name:'Synthetic ResearchBot'})).toBeVisible();
 await page.getByRole('button',{name:'Validate Configuration'}).click();
 await expect(page.getByText('Configuration valid',{exact:true})).toBeVisible();
 await page.getByRole('button',{name:'Continue',exact:true}).click();
 await page.getByText('Agent Goal Hijacking',{exact:true}).click();
 await page.getByRole('button',{name:'Review testcases'}).click();
 await page.getByLabel('Select GH-C01').check();
 await page.getByRole('button',{name:'Preview Test Plan'}).click();
 await expect(page.getByRole('heading',{name:'Test plan preview',level:2})).toBeVisible();
}

test('browser submits rule-only and hybrid through real APIs and opens persisted reports',async({page})=>{
 test.setTimeout(120000);
 if(!(await free(8091))||!(await free(8092)))test.skip(true,'Stock loopback API ports are occupied; existing services are left untouched.');
 const stateDir=join(mkdtempSync(join(tmpdir(),'secagent-continuous-offline-')),'state');
 let child:ChildProcessWithoutNullStreams|undefined;
 try{
  const started=await start(stateDir);child=started.child;
  const controlPath=join(stateDir,'control.json');
  expect(existsSync(controlPath)).toBe(true);
  const control=JSON.parse(readFileSync(controlPath,'utf8'));
  expect(control.target_id).toBe('synthetic-researchbot');
  expect(existsSync(control.reporting_manifest)).toBe(true);
  const healthResponse=await page.request.get(base+'/api/testing/health');
  expect(healthResponse.status()).toBe(200);
  const health=await healthResponse.json();
  expect(health.evaluation_modes).toEqual(['rule_only','hybrid']);
  const headers={'Origin':base,'X-SecAgent-Validation':health.validation_nonce,
   'X-SecAgent-Operator':started.token};

  await plan(page);
  await expect(page.getByLabel('Evaluation mode')).toHaveValue('rule_only');
  const previewRequest=page.waitForRequest(r=>r.url().endsWith('/api/testing/readiness/preview'));
  await page.getByRole('button',{name:'Check run readiness'}).click();
  const selection=(await previewRequest).postDataJSON();
  await expect(page.getByText('Ready: 1 / Blocked: 0')).toBeVisible();
  await page.getByRole('button',{name:'Request admission decision'}).click();
  await expect(page.getByRole('button',{name:'Run one authorized test'})).toBeVisible();
  const stale=await page.request.post(base+'/api/testing/runs',{headers,
   data:{...selection,expected_plan_id:'0'.repeat(64)}});
  expect(stale.status()).toBe(409);
  const unauthorized=await page.request.post(base+'/api/testing/runs',{
   headers:{...headers,'X-SecAgent-Operator':'invalid-token'},data:selection});
  expect(unauthorized.status()).toBe(403);
  await page.getByLabel('Operator execution secret').fill(started.token);
  const ruleResponse=page.waitForResponse(r=>r.url().endsWith('/api/testing/runs'));
  await page.getByRole('button',{name:'Run one authorized test'}).click();
  const ruleRun=await (await ruleResponse).json();
  expect(ruleRun).toMatchObject({execution_status:'completed',evaluation_mode:'rule_only',
   historical_verdict:'PASS',report_persisted:true,target_request_count:1});
  const ruleLink=page.getByRole('link',{name:'Open saved report'});
  await expect(ruleLink).toHaveAttribute('href','#run/'+ruleRun.run_id);
  const ruleReportResponse=page.waitForResponse(r=>r.url().endsWith('/api/reports/runs/'+ruleRun.run_id));
  await ruleLink.click();
  const ruleDetail=await (await ruleReportResponse).json();
  await expect(page.getByRole('heading',{name:'GH-C01'})).toBeVisible();
  await expect(page.locator('.page-title .badge')).toHaveText('PASS');
  await expect(page.locator('.judge-panel').getByText('not_requested',{exact:true})).toBeVisible();
  expect(ruleDetail.execution.security.verdict).toBe('PASS');
  expect(ruleDetail.execution.judge.invocation_state).toBe('not_requested');

  await plan(page);
  await page.getByLabel('Evaluation mode').selectOption('hybrid');
  await page.getByRole('button',{name:'Check run readiness'}).click();
  await expect(page.getByText('Ready: 1 / Blocked: 0')).toBeVisible();
  await page.getByRole('button',{name:'Request admission decision'}).click();
  await expect(page.getByRole('button',{name:'Run one authorized test'})).toBeVisible();
  await page.getByLabel('Operator execution secret').fill(started.token);
  const hybridResponse=page.waitForResponse(r=>r.url().endsWith('/api/testing/runs'));
  await page.getByRole('button',{name:'Run one authorized test'}).click();
  const hybridRun=await (await hybridResponse).json();
  expect(hybridRun).toMatchObject({execution_status:'completed',evaluation_mode:'hybrid',
   historical_verdict:'INCONCLUSIVE',report_persisted:true,target_request_count:1});
  const hybridLink=page.getByRole('link',{name:'Open saved report'});
  await expect(hybridLink).toHaveAttribute('href','#run/'+hybridRun.run_id);
  const hybridReportResponse=page.waitForResponse(r=>r.url().endsWith('/api/reports/runs/'+hybridRun.run_id));
  await hybridLink.click();
  const hybridApiResponse=await hybridReportResponse;
  expect(hybridApiResponse.status()).toBe(200);
  const hybridDetail=(await hybridApiResponse.json()).execution;
  await expect(page.getByRole('heading',{name:'GH-C01'})).toBeVisible();
  await expect(page.locator('.page-title .badge')).toHaveText('INCONCLUSIVE');
  await expect(page.getByRole('heading',{name:'Production Judge · original execution'})).toBeVisible();
  await expect(page.locator('.judge-panel').getByText('result_available',{exact:true})).toBeVisible();
  await expect(page.locator('.judge-panel').getByText('PASS',{exact:true})).toBeVisible();
  await expect(page.locator('.judge-panel').getByText('Canned offline recommendation, not an accuracy measurement.')).toBeVisible();
  await expect(page.getByText('Synthetic response needs review.',{exact:true}).first()).toBeVisible();
  expect(hybridDetail.security.verdict).toBe('INCONCLUSIVE');
  expect(hybridDetail.observation.response_preview).toBe('Synthetic response needs review.');
  expect(hybridDetail.observation.response_completeness.state).toBe('unknown');
  expect(hybridDetail.observation.evidence).toEqual([]);
  expect(hybridDetail.judge).toMatchObject({invocation_state:'result_available',
   classification:'ORIGINAL_GOAL',recommendation:'PASS'});
  expect(hybridDetail.judge.downgrade_reason).toMatch(/complete response observation/);
  const summary=JSON.parse(readFileSync(join(stateDir,'runs',hybridRun.run_id,'run-summary.json'),'utf8'));
  const raw=readFileSync(join(stateDir,'runs',hybridRun.run_id,summary.report_file));
  const native=JSON.parse(raw.toString('utf8'));
  expect(createHash('sha256').update(raw).digest('hex')).toBe(hybridRun.report_sha256);
  expect(native.evaluation).toMatchObject({evaluation_mode:'hybrid',final_verdict:'INCONCLUSIVE'});
  expect(native.evaluation.judge_budget.used).toBe(1);
  expect(native.evaluation.judge.recommendation).toBe('PASS');
  expect(hybridDetail.source.file_byte_sha256).toBe(hybridRun.report_sha256);
  expect((await page.request.get(base+'/api/reports/runs/'+'f'.repeat(32))).status()).toBe(404);
  await page.goto('/#run/'+'f'.repeat(32));
  await expect(page.getByText(/Saved report unavailable in the selected reporting dataset/)).toBeVisible();
 }finally{child?.kill();}
});
