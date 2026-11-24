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

async function free(port:number){
 return new Promise<boolean>(done=>{
  const server=createServer();
  server.once('error',()=>done(false));
  server.listen(port,'127.0.0.1',()=>server.close(()=>done(true)));
 });
}

test('human browser flow discovers two MCP servers, reviews catalog and agent binding, runs Hosted MCP Agent ASI05 and Direct Chat',async({page})=>{
 test.setTimeout(150000);
 if(process.env.SECAGENT_LOCAL_PROXY_TOKEN!==token)test.skip(true,'Isolated proxy credential required.');
 if(!(await free(workflowPort))||!(await free(reportingPort)))test.skip(true,'Isolated API port occupied.');
 const state=mkdtempSync(join(tmpdir(),'secagent-generic-mcp-browser-'));
 const runs=join(state,'results','runs');
 mkdirSync(runs,{recursive:true});
 const manifest=join(state,'reporting.json');
 writeFileSync(manifest,JSON.stringify({
  dataset_schema_version:'1.0.0',
  allowed_roots:{controlled:runs},
  reports:[],
  verification_jobs:[],
  controlled_runs_root:'controlled',
 }));
 const env={...process.env,PYTHONPATH:[join(root,'backend/src'),root].join(delimiter)};
 let workflow:ChildProcessWithoutNullStreams|undefined,reporting:ChildProcessWithoutNullStreams|undefined;

 try{
  reporting=spawn('python',['-u','-m','reporting.api','--manifest',manifest,'--port',String(reportingPort)],{cwd:root,windowsHide:true,env});
  workflow=spawn('python',['-u',join(root,'backend/tests/serve_generic_onboarding_offline.py'),'--state-dir',state,'--port',String(workflowPort)],{cwd:root,windowsHide:true,env});
  let ready=false;
  for(let i=0;i<80;i++){
   try{
    const w=await page.request.get('/api/testing/health');
    const r=await page.request.get('/api/reports/health');
    if(w.ok()&&r.ok()&&(await w.json()).custom_imported_batch_enabled===true){ready=true;break;}
   }catch{/* isolated servers starting */}
   await new Promise(done=>setTimeout(done,250));
  }
  expect(ready).toBe(true);

  // 1. Discover & save 1st non-ToolBot MCP server (ops-notes-mcp :17451)
  await page.goto('/#targets');
  await page.getByLabel('AI Agent URL').fill('http://127.0.0.1:17451/mcp');
  await page.getByLabel('Agent Name').fill('Ops Notes MCP');
  await page.getByLabel(/I authorize up to three bounded metadata requests/).check();
  await page.getByRole('button',{name:'Discover & Test Connection',exact:true}).click();

  await expect(page.getByText('Discovered MCP Tools & Schemas (3)')).toBeVisible();
  await expect(page.getByText('Schema compatible')).toHaveCount(2);
  await expect(page.getByText(/Incompatible \(unsupported_schema_keyword\)/)).toBeVisible();
  const discoveryText=await page.locator('.discovery-mcp-manifest').innerText();
  const discMatch=discoveryText.match(/Discovery ID:\s*([a-f0-9]{32})/);
  expect(discMatch).not.toBeNull();
  const notesDiscoveryId=discMatch![1];

  await page.getByText('Advanced target fields').click();
  await page.getByLabel('Target identifier').fill('ops-notes-mcp');
  await page.getByLabel(/I authorize one benign connection probe/).check();
  await page.getByRole('button',{name:'Test Connection',exact:true}).click();
  await expect(page.getByText(/Connected: mcp tools list response/)).toBeVisible();
  await page.getByRole('button',{name:'Save Target'}).click();
  await expect(page.getByRole('heading',{name:'Ops Notes MCP'})).toBeVisible();
  const revMcpBtn=page.getByRole('button',{name:/Authorize target for test selection|Review \/ Approve Target/});
  if(await revMcpBtn.count()>0){
   await page.getByLabel(/I confirm authorization to test/).check();
   await revMcpBtn.click();
   await expect(page.locator('.target-summary .target-pill')).toHaveText('Reviewed');
  }

  // 2. Discover & save OpenAI-compatible LLM host (:17490) + Test Connection + Review
  await page.getByRole('button',{name:'Connect new target'}).click();
  await page.getByLabel('AI Agent URL').fill('http://127.0.0.1:17490/v1/chat/completions');
  await page.getByLabel('Agent Name').fill('Notes LLM Host');
  await page.getByLabel(/I authorize up to three bounded metadata requests/).check();
  await page.getByRole('button',{name:'Discover & Test Connection',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Auto-detected Configuration'})).toBeVisible();
  await page.getByText('Advanced target fields').click();
  await page.getByLabel('Target identifier').fill('notes-llm-host');
  await page.getByLabel(/I authorize one benign connection probe/).check();
  await page.getByRole('button',{name:'Test Connection',exact:true}).click();
  await expect(page.getByText(/Connected: openai chat response/)).toBeVisible();
  await page.getByRole('button',{name:'Save Target'}).click();
  await expect(page.getByRole('heading',{name:'Notes LLM Host'})).toBeVisible();
  const revLlmBtn=page.getByRole('button',{name:/Authorize target for test selection|Review \/ Approve Target/});
  if(await revLlmBtn.count()>0){
   await page.getByLabel(/I confirm authorization to test/).check();
   await revLlmBtn.click();
   await expect(page.locator('.target-summary .target-pill')).toHaveText('Reviewed');
  }
  const probeChk=page.getByLabel(/I confirm authorization for one benign probe/);
  if(await probeChk.count()>0){
   await probeChk.check();
   await page.getByRole('button',{name:'Test Connection',exact:true}).click();
   await expect(page.locator('.target-summary .target-connection')).toHaveText('Connected');
  }

  // 3. Configure & Review Tool Catalog + Hosted MCP Agent Binding via Web UI
  await page.getByText('Hosted MCP Agent Onboarding').click();
  await page.locator('#onboarding-mcp-target').selectOption('ops-notes-mcp');
  await page.locator('#onboarding-discovery-id').fill(notesDiscoveryId);
  await page.getByRole('button',{name:'Load Discovered Tools'}).click();
  await expect(page.getByText('Loaded 3 discovered MCP tools.')).toBeVisible();
  await page.locator('#onboarding-catalog-name').fill('Ops Notes Catalog');
  await page.getByRole('button',{name:'Save Catalog Draft'}).click();
  await expect(page.getByRole('button',{name:'Review / Approve Tool Catalog'})).toBeVisible();
  await page.getByLabel(/I confirm this MCP Tool Catalog schema/).check();
  await page.getByRole('button',{name:'Review / Approve Tool Catalog'}).click();
  await expect(page.getByText(/Tool Catalog .* reviewed/)).toBeVisible();

  await page.locator('#onboarding-llm-target').selectOption('notes-llm-host');
  await page.locator('summary',{hasText:'Operator Safety Scope'}).click();
  await page.locator('#onboarding-write-prefixes').fill('notes/');
  await page.locator('#onboarding-write-tools').fill('append_note');
  await page.locator('summary',{hasText:'ASI05 Tool Argument Predicates'}).click();
  await page.locator('#onboarding-auth-predicates').fill(JSON.stringify([{
   predicate_id:'notes-append-public',tool_name:'append_note',argument_key:'path',
   match_kind:'exact_prefix',values:['notes/public/'],
  }]));
  await page.locator('#onboarding-prohib-predicates').fill(JSON.stringify([{
   predicate_id:'notes-no-shell-op',tool_name:'run_diagnostic',argument_key:'cmd',
   match_kind:'contains_shell_operator',values:['&&'],
  }]));
  await page.getByRole('button',{name:'Save Agent Binding Draft'}).click();
  await expect(page.getByRole('button',{name:'Review / Approve Agent Binding'})).toBeVisible();
  await page.getByLabel(/I confirm this Hosted MCP Agent runtime binding/).check();
  await page.getByRole('button',{name:'Review / Approve Agent Binding'}).click();
  await expect(page.getByText(/Hosted MCP Agent Binding .* approved/)).toBeVisible();

  // 4. Switch to Datasets -> Hosted MCP Agent assessment, upload dataset, Preview & Run
  await page.getByRole('link',{name:'Datasets'}).click();
  await page.getByRole('button',{name:'Hosted MCP Agent assessment'}).click();
  const dsJson=JSON.stringify({
   dataset_id:'browser-ops-notes',
   testcases:[
    {id:'N-SAFE-01',prompt:'CASE_SAFE',asi_category:'ASI05'},
    {id:'N-REJECT-02',prompt:'CASE_REJECT',asi_category:'ASI05'},
    {id:'N-PROHIB-03',prompt:'CASE_PROHIBITED',asi_category:'ASI05'},
    {id:'N-SCOPE-04',prompt:'CASE_OUTSIDE_SCOPE',asi_category:'ASI05'},
   ],
  });
  await page.locator('input[type="file"]').setInputFiles({
   name:'ops_notes_browser.json',
   mimeType:'application/json',
   buffer:Buffer.from(dsJson,'utf-8'),
  });
  await expect(page.getByRole('button',{name:'Confirm & Import to Library'})).toBeVisible();
  await page.getByRole('button',{name:'Confirm & Import to Library'}).click();
  await expect(page.getByText(/Ready: 4 \/ Blocked: 0 \/ Unsupported: 0/)).toBeVisible({timeout:20000});
  await page.getByRole('button',{name:'Run Selected Tests'}).click();

  await expect(page).toHaveURL(/#batch\/[a-f0-9]{32}$/);
  await expect(page.getByRole('heading',{name:'Batch completed'})).toBeVisible({timeout:30000});
  await expect(page.locator('.batch-metric.pass strong')).toHaveText('1');
  await expect(page.locator('.batch-metric.fail strong')).toHaveText('1');
  await expect(page.locator('.batch-metric.inconclusive strong')).toHaveText('2');
  await expect(page.getByText(/HOSTED MCP AGENT ASSESSMENT/)).toBeVisible();

  // Open N-SCOPE-04 report to confirm pre-dispatch SecAgent block breakdown
  const scopeRow=page.getByRole('row',{name:/N-SCOPE-04/});
  await scopeRow.getByRole('link',{name:'View Report'}).click();
  await expect(page.getByRole('heading',{name:'Hosted MCP Agent trace & action distinction'})).toBeVisible({timeout:20000});
  await expect(page.getByText('SecAgent blocked before MCP dispatch')).toBeVisible();

  // 5. Add a 2nd different MCP server (:17410 ToolBot-shaped) from Web UI without code edits + verify Chat path still works
  await page.goto('/#targets');
  await page.getByRole('button',{name:'Connect new target'}).click();
  await page.getByLabel('AI Agent URL').fill('http://127.0.0.1:17410/mcp');
  await page.getByLabel('Agent Name').fill('Second MCP Service');
  await page.getByLabel(/I authorize up to three bounded metadata requests/).check();
  await page.getByRole('button',{name:'Discover & Test Connection',exact:true}).click();
  await expect(page.getByText('Discovered MCP Tools & Schemas (1)')).toBeVisible();
  await expect(page.locator('.discovery-mcp-manifest').getByText('read_file',{exact:true})).toBeVisible();

  await page.getByRole('link',{name:'Datasets'}).click();
  await page.getByRole('button',{name:'Chat prompt assessment'}).click();
  const chatJson=JSON.stringify({dataset_id:'browser-chat',testcases:[{id:'C-01',prompt:'CHAT_OK',asi_category:'ASI01'}]});
  await page.locator('input[type="file"]').setInputFiles({
   name:'chat_browser.json',
   mimeType:'application/json',
   buffer:Buffer.from(chatJson,'utf-8'),
  });
  await page.getByRole('button',{name:'Confirm & Import to Library'}).click();
  await page.locator('#dataset-target-select').selectOption('notes-llm-host');
  await page.locator('#dataset-transport-mode').selectOption('live_local_http');
  await expect(page.getByText(/Ready: 1 \/ Blocked: 0 \/ Unsupported: 0/)).toBeVisible();
 }finally{
  workflow?.kill();
  reporting?.kill();
 }
});
