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

test('New Security Scan wizard supports Hosted MCP Agent, second MCP server, Direct Chat Agent and Advanced Settings without manual IDs',async({page})=>{
 test.setTimeout(150000);
 if(process.env.SECAGENT_LOCAL_PROXY_TOKEN!==token)test.skip(true,'Isolated proxy credential required.');
 if(!(await free(workflowPort))||!(await free(reportingPort)))test.skip(true,'Isolated API port occupied.');
 const state=mkdtempSync(join(tmpdir(),'secagent-scan-wizard-browser-'));
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

  // Journey 1: Existing AI Agent (Chat API) via simple New Security Scan (no Tool Catalog / Agent Binding)
  await page.goto('/#scan');
  await expect(page.getByRole('heading',{name:'New Security Scan'})).toBeVisible();
  await page.getByLabel('Target Name').fill('Simple Chat Agent');
  await page.getByLabel('Target Endpoint URL').fill('http://127.0.0.1:17490/v1/chat/completions');
  await page.getByLabel(/I authorize SecAgent to run bounded loopback metadata discovery/).check();
  await page.getByRole('button',{name:'Connect & Continue'}).click();

  await expect(page.getByRole('heading',{name:'2 · AI Agent Configuration'})).toBeVisible();
  await page.getByLabel(/I authorize SecAgent to test this exact endpoint/).check();
  await page.getByRole('button',{name:'Authorize & Continue'}).click();

  await expect(page.getByRole('heading',{name:'3 · Testcases & Security Policies'})).toBeVisible();
  const chatDsJson=JSON.stringify({dataset_id:'wizard-chat-ds',testcases:[{id:'CHAT-WIZ-01',prompt:'Hello CHAT_OK',asi_category:'ASI01'}]});
  await page.locator('input[type="file"]').setInputFiles({name:'wizard_chat.json',mimeType:'application/json',buffer:Buffer.from(chatDsJson,'utf-8')});
  await expect(page.getByText('CHAT-WIZ-01')).toBeVisible();
  await page.getByRole('button',{name:'Review Scan Plan'}).click();

  await expect(page.getByRole('heading',{name:'4 · Review Scan Plan & Start'})).toBeVisible();
  await expect(page.getByText(/Existing AI Agent Direct Chat/)).toBeVisible();
  await page.getByLabel(/I authorize SecAgent to run this exact security scan/).check();
  await page.getByRole('button',{name:'Start Scan'}).click();
  await expect(page.getByRole('heading',{name:'Batch completed'})).toBeVisible({timeout:25000});

  // Journey 2: Hosted MCP Agent (LLM Agent + MCP Server) without manual IDs or JSON editing
  await page.getByRole('button',{name:'Start Another Security Scan'}).click();
  await page.getByRole('button',{name:'LLM Agent + MCP Server'}).click();
  await page.getByLabel('Target Name').fill('Ops Notes MCP');
  await page.getByLabel('MCP Server URL').fill('http://127.0.0.1:17451/mcp');
  await page.getByLabel(/I authorize SecAgent to run bounded loopback metadata discovery/).check();
  await page.getByRole('button',{name:'Connect & Continue'}).click();

  await expect(page.getByRole('heading',{name:'2 · MCP Capabilities & LLM Pairing'})).toBeVisible();
  await expect(page.getByLabel('Discovered MCP tools summary').getByText('append_note',{exact:true})).toBeVisible();
  await expect(page.getByText(/Unsupported \(unsupported_schema_keyword\)/)).toBeVisible();
  // Select previously saved LLM provider from dropdown (no DVAA ResearchBot substitution)
  await page.locator('#scan-llm-provider').selectOption('simple-chat-agent');

  // Set safety scope & predicates inside Advanced Settings only to verify Advanced Settings work seamlessly
  await page.locator('summary',{hasText:'Advanced Settings'}).click();
  await page.getByPlaceholder('notes/').fill('notes/');
  await page.getByPlaceholder('append_note').fill('append_note');
  await page.locator('summary',{hasText:'Advanced Settings'}).click();

  await page.getByLabel(/I confirm this MCP Server, exposed tools, LLM Provider, and Agent Binding/).check();
  await page.getByRole('button',{name:'Approve & Continue to Testcases'}).click();

  await expect(page.getByRole('heading',{name:'3 · Testcases & Security Policies'})).toBeVisible();
  const mcpDsJson=JSON.stringify({
   dataset_id:'wizard-notes-ds',
   testcases:[
    {id:'WIZ-SAFE-01',prompt:'Run CASE_SAFE',asi_category:'ASI05'},
    {id:'WIZ-SCOPE-02',prompt:'Run CASE_OUTSIDE_SCOPE',asi_category:'ASI05'},
   ],
  });
  await page.locator('input[type="file"]').setInputFiles({name:'wizard_notes.json',mimeType:'application/json',buffer:Buffer.from(mcpDsJson,'utf-8')});
  await expect(page.getByText('WIZ-SAFE-01')).toBeVisible();
  await page.getByRole('button',{name:'Review Scan Plan'}).click();

  await expect(page.getByRole('heading',{name:'4 · Review Scan Plan & Start'})).toBeVisible();
  await expect(page.getByText(/Hosted MCP Agent Runtime/)).toBeVisible();
  await expect(page.getByText(/14 requests/)).toBeVisible();
  await page.getByLabel(/I authorize SecAgent to run this exact security scan/).check();
  await page.getByRole('button',{name:'Start Scan'}).click();

  await expect(page.getByRole('heading',{name:'Batch completed'})).toBeVisible({timeout:30000});
  await expect(page.getByText(/HOSTED MCP AGENT ASSESSMENT/)).toBeVisible();
  // Verify distinct evidence boundary rendered directly in results
  await expect(page.getByText(/SecAgent blocked before dispatch.*NOT target defense/i)).toBeVisible({timeout:15000});
  await expect(page.getByText(/Host OS effect: Unverified/).first()).toBeVisible();

  // Open Native Report
  await page.getByRole('link',{name:'View Report'}).first().click();
  await expect(page.getByRole('heading',{name:'Hosted MCP Agent trace & action distinction'})).toBeVisible({timeout:20000});

  // Journey 3: Second different MCP Server (:17410) via New Security Scan without source edits + Advanced Settings link works
  await page.goto('/#scan');
  await page.getByRole('button',{name:'LLM Agent + MCP Server'}).click();
  await page.getByLabel('Target Name').fill('Second Generic MCP');
  await page.getByLabel('MCP Server URL').fill('http://127.0.0.1:17410/mcp');
  await page.getByLabel(/I authorize SecAgent to run bounded loopback metadata discovery/).check();
  await page.getByRole('button',{name:'Connect & Continue'}).click();
  await expect(page.getByRole('heading',{name:'2 · MCP Capabilities & LLM Pairing'})).toBeVisible();
  await expect(page.getByLabel('Discovered MCP tools summary').getByText('read_file',{exact:true})).toBeVisible();

  await page.getByRole('link',{name:'Advanced Settings (Targets)'}).click();
  await expect(page.getByRole('heading',{name:'Connect AI Agent'})).toBeVisible();
 }finally{
  workflow?.kill();
  reporting?.kill();
 }
});
