import { expect, test } from '@playwright/test';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { delimiter, join, resolve } from 'node:path';

const root=resolve(process.cwd(),'..');
const port=Number(process.env.SECAGENT_WORKFLOW_PROXY_PORT || '8093');
const browserPort=Number(process.env.SECAGENT_FRONTEND_PORT || '5174');
const token='offline-browser-test-operator-secret-123456';
const screenshots=join(root,'frontend','artifacts','target-ux-redesign');
const contextScreenshots=join(root,'frontend','artifacts','application-context-policy-ux');
async function free():Promise<boolean>{return new Promise(done=>{
 const server=createServer();server.once('error',()=>done(false));
 server.listen(port,'127.0.0.1',()=>server.close(()=>done(true)));
});}

test('discover, inspect, correct, save, review, and select with real APIs and mock metadata',async({page})=>{
 test.setTimeout(70000);
 if(process.env.SECAGENT_LOCAL_PROXY_TOKEN!==token)test.skip(true,'Requires the isolated local proxy credential.');
 if(!(await free()))test.skip(true,'Isolated Workflow API port is occupied.');
 const stateDir=mkdtempSync(join(tmpdir(),'secagent-discovery-browser-'));
 let child:ChildProcessWithoutNullStreams|undefined;
 try{
  child=spawn('python',['-u',join(root,'backend/tests/serve_target_management_offline.py'),
   '--state-dir',stateDir,'--port',String(port),'--local'],{cwd:root,windowsHide:true,
   env:{...process.env,PYTHONPATH:[join(root,'backend/src'),root].join(delimiter)}});
  const base=`http://127.0.0.1:${browserPort}`;
  let ready=false;
  for(let i=0;i<40;i++){
   try{const response=await page.request.get(base+'/api/testing/health');
    if(response.ok()&&(await response.json()).operator_mode==='local_single_user'){ready=true;break;}}
   catch{/* local test API is starting */}
   await new Promise(done=>setTimeout(done,250));
  }
  expect(ready).toBe(true);
  await page.goto('/#targets');
  await page.getByRole('button',{name:'Connect new target'}).click();
  await page.getByLabel('AI Agent URL').fill('http://127.0.0.1:7001/v1/chat/completions');
  await page.getByLabel('Agent Name').fill('Offline Discovery Candidate');
  await page.getByLabel(/I authorize up to three bounded metadata requests/).check();
  await page.getByRole('button',{name:'Discover & Test Connection',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Auto-detected Configuration'})).toBeVisible();
  await expect(page.getByLabel('Model identifier')).toHaveValue('advertised-model');
  await expect(page.getByText(/Connected: openai chat response/)).toBeVisible();
  await page.getByText('Advanced target fields').click();
  await page.getByLabel('Target identifier').fill('discovered-local-agent');
  await expect(page.getByLabel('Agent Name (from connection step)')).toHaveValue('Offline Discovery Candidate');
  await page.getByLabel('Model identifier').fill('operator-corrected-model');
  await expect(page.getByText(/Unverified: No connection probe/)).toBeVisible();
  await page.getByLabel(/I authorize one benign connection probe/).check();
  await page.getByRole('button',{name:'Test Connection',exact:true}).click();
  await expect(page.getByText(/Connected: openai chat response/)).toBeVisible();
  await page.getByRole('button',{name:'Save Target'}).click();
  await expect(page.getByRole('heading',{name:'Offline Discovery Candidate'})).toBeVisible();
  await expect(page.getByText('Connected',{exact:true})).toBeVisible();
  await page.getByText('Application Context · Optional').click();
  await page.getByLabel('Primary purpose').fill('Answer questions about synthetic lab files');
  await page.getByLabel('Resources it may access').fill('Public canary directory');
  await page.getByLabel(/I confirm this description contains no real secrets/).check();
  await page.getByRole('button',{name:'Save Application Context'}).click();
  await expect(page.getByText('Operator declared · Saved')).toBeVisible();
  mkdirSync(contextScreenshots,{recursive:true});
  for(const viewport of [{width:1440,height:900},{width:390,height:844}]){
   await page.setViewportSize(viewport);
   expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
   await page.screenshot({path:join(contextScreenshots,`target-context-${viewport.width}.png`),fullPage:true});
  }
  await page.setViewportSize({width:1440,height:900});
  const contextPath=join(stateDir,'operator-data','application-contexts','discovered-local-agent.json');
  expect(JSON.parse(readFileSync(contextPath,'utf8')).draft.purpose).toBe('Answer questions about synthetic lab files');
  mkdirSync(screenshots,{recursive:true});
  for(const viewport of [{width:1440,height:900},{width:390,height:844}]){
   await page.setViewportSize(viewport);
   expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
   await page.screenshot({path:join(screenshots,`saved-pending-review-${viewport.width}.png`),fullPage:true});
  }
  await page.setViewportSize({width:1440,height:900});
  await expect(page.getByText(/Review required|Authorization for this exact target/).first()).toBeVisible();
  const state=join(stateDir,'operator-data','target-catalog.json');
  expect(existsSync(state)).toBe(true);
  let saved=JSON.parse(readFileSync(state,'utf8'));
  expect(saved.reviews).toHaveLength(0);
  expect(saved.catalog.targets[0].default_model).toBe('operator-corrected-model');
  await page.getByLabel(/I confirm authorization to test/).check();
  await page.getByRole('button',{name:'Authorize target for test selection'}).click();
  await page.getByText('Connection details').click();
  await expect(page.getByText(/API compatibility: yes/)).toBeVisible();
  saved=JSON.parse(readFileSync(state,'utf8'));
  expect(saved.reviews).toHaveLength(1);
  await expect(page.getByText('Configuration valid',{exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Continue'}).click();
  await expect(page.getByRole('heading',{name:'Select ASI categories'})).toBeVisible();
  await page.locator('.asi-grid').getByRole('checkbox').first().check();
  await page.getByRole('button',{name:'Review testcases'}).click();
  await expect(page.getByText('GH-C01',{exact:true}).first()).toBeVisible();
  const discoveries=join(stateDir,'operator-data','discoveries');
  const {readdirSync}=await import('node:fs');
  const records=readdirSync(discoveries).filter(name=>name.endsWith('.json'));
  expect(records).toHaveLength(1);
  const record=JSON.parse(readFileSync(join(discoveries,records[0]),'utf8'));
  expect(record.profile_revision).toBe(saved.reviews[0].profile_revision);
  expect(record.security_test_executed).toBe(false);
  expect(record.security_verdict).toBeNull();
  expect(JSON.stringify(record)).not.toContain(token);
  await page.goto('/#targets');
  await page.getByRole('group',{name:'Choose target setup'}).getByRole('button',{name:'Select existing target'}).click();
  await page.getByLabel('Target',{exact:true}).selectOption('discovered-local-agent');
  const contextDrawer=page.locator('details.target-context-drawer');
  if(!(await contextDrawer.evaluate((el:HTMLDetailsElement)=>el.open)))await contextDrawer.locator('summary').click();
  await expect(contextDrawer).toHaveAttribute('open','');
  await expect(page.getByLabel('Primary purpose')).toHaveValue('Answer questions about synthetic lab files');
  await page.getByLabel('Primary purpose').fill('Answer questions about public synthetic files');
  await page.getByLabel(/I confirm this description contains no real secrets/).check();
  await page.getByRole('button',{name:'Save Application Context'}).click();
  await expect(page.getByText('Operator declared · Saved')).toBeVisible();
  expect(JSON.parse(readFileSync(contextPath,'utf8')).draft.purpose).toBe('Answer questions about public synthetic files');
 }finally{child?.kill();}
});

test('ToolBot quick connect replaces an older target preview and resets on change',async({page})=>{
 test.setTimeout(70000);
 if(process.env.SECAGENT_LOCAL_PROXY_TOKEN!==token)test.skip(true,'Requires the isolated local proxy credential.');
 if(!(await free()))test.skip(true,'Isolated Workflow API port is occupied.');
 const stateDir=mkdtempSync(join(tmpdir(),'secagent-mcp-quick-connect-'));
 let child:ChildProcessWithoutNullStreams|undefined;
 try{
  child=spawn('python',['-u',join(root,'backend/tests/serve_target_management_offline.py'),
   '--state-dir',stateDir,'--port',String(port),'--local','--seed-researchbot'],{cwd:root,windowsHide:true,
   env:{...process.env,PYTHONPATH:[join(root,'backend/src'),root].join(delimiter)}});
  const base=`http://127.0.0.1:${browserPort}`;
  let ready=false;
  for(let i=0;i<40;i++){
   try{const response=await page.request.get(base+'/api/testing/health');
    if(response.ok()&&(await response.json()).operator_mode==='local_single_user'){ready=true;break;}}
   catch{/* local test API is starting */}
   await new Promise(done=>setTimeout(done,250));
  }
  expect(ready).toBe(true);
  await page.goto('/#targets');
  await expect(page.getByLabel('AI Agent URL')).toBeVisible();
  await expect(page.getByRole('heading',{name:'DVAA ResearchBot'})).toHaveCount(0);
  await page.getByRole('button',{name:'Select existing target'}).click();
  await expect(page.getByRole('heading',{name:'DVAA ResearchBot'})).toBeVisible();
  await page.getByRole('button',{name:'Connect new target'}).click();
  await expect(page.getByRole('heading',{name:'DVAA ResearchBot'})).toHaveCount(0);
  await page.getByLabel('AI Agent URL').fill('http://127.0.0.1:7010/');
  await page.getByLabel('Agent Name').fill('DVAA ToolBot');
  await page.getByLabel(/I authorize up to three bounded metadata requests/).check();
  mkdirSync(screenshots,{recursive:true});
  for(const viewport of [{width:1440,height:900},{width:390,height:844}]){
   await page.setViewportSize(viewport);
   const box=await page.locator('.discovery-panel .target-consent input').boundingBox();
   const label=await page.locator('.discovery-panel .target-consent span').boundingBox();
   expect(box).not.toBeNull();expect(label).not.toBeNull();
   expect(Math.abs(box!.y-label!.y)).toBeLessThan(8);
   expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
   await page.screenshot({path:join(screenshots,`toolbot-entry-${viewport.width}.png`),fullPage:true});
  }
  await page.setViewportSize({width:1440,height:900});
  await page.getByRole('button',{name:'Discover & Test Connection',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Auto-detected Configuration'})).toBeVisible();
  await expect(page.getByRole('form',{name:'Manage target details'}).getByRole('combobox')).toHaveValue('mcp-jsonrpc');
  await expect(page.getByLabel('Endpoint URL')).toHaveValue('http://127.0.0.1:7010/');
  await expect(page.getByLabel('MCP service identifier (not an LLM model)')).toHaveValue('mcp-service');
  await expect(page.getByLabel('Agent Name (from connection step)')).toHaveValue('DVAA ToolBot');
  await expect(page.getByText(/Connected: mcp tools list response/)).toBeVisible();
  for(const viewport of [{width:1440,height:900},{width:1366,height:768},{width:390,height:844}]){
   await page.setViewportSize(viewport);
   expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
   await page.screenshot({path:join(screenshots,`toolbot-detected-${viewport.width}.png`),fullPage:true});
  }
  await page.setViewportSize({width:1440,height:900});
  await page.getByLabel('MCP service identifier (not an LLM model)').fill('renamed-service');
  await expect(page.getByText(/Unverified: No connection probe/)).toBeVisible();
  await page.getByLabel(/I authorize one benign connection probe/).check();
  await page.getByRole('button',{name:'Test Connection',exact:true}).click();
  await expect(page.getByText(/Connected: mcp tools list response/)).toBeVisible();
  await page.getByRole('button',{name:'Save Target'}).click();
  await expect(page.getByRole('heading',{name:'DVAA ToolBot'})).toBeVisible();
  await expect(page.getByText('Connected',{exact:true})).toBeVisible();
  await expect(page.getByRole('heading',{name:'DVAA ResearchBot'})).toHaveCount(0);
  const state=JSON.parse(readFileSync(join(stateDir,'operator-data','target-catalog.json'),'utf8'));
  expect(state.reviews).toHaveLength(0);
  expect(state.catalog.targets.find((t:{id:string})=>t.id==='local-agent-7010')?.endpoint).toBe('http://127.0.0.1:7010/');
  expect(state.catalog.targets.find((t:{id:string})=>t.id==='local-agent-7010')?.name).toBe('DVAA ToolBot');
  await page.getByRole('button',{name:'Connect new target'}).click();
  await page.getByLabel('AI Agent URL').fill('http://127.0.0.1:7010/other');
  await page.getByLabel(/I authorize up to three bounded metadata requests/).check();
  await page.getByRole('button',{name:'Discover & Test Connection',exact:true}).click();
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByText(/Connected: mcp tools list response/)).toHaveCount(0);
  await expect(page.getByRole('heading',{name:'DVAA ToolBot'})).toHaveCount(0);
 }finally{child?.kill();}
});

test('already saved ToolBot identifier still verifies MCP connection without duplicate save',async({page})=>{
 test.setTimeout(70000);
 if(process.env.SECAGENT_LOCAL_PROXY_TOKEN!==token)test.skip(true,'Requires the isolated local proxy credential.');
 if(!(await free()))test.skip(true,'Isolated Workflow API port is occupied.');
 const stateDir=mkdtempSync(join(tmpdir(),'secagent-mcp-existing-'));
 let child:ChildProcessWithoutNullStreams|undefined;
 try{
  child=spawn('python',['-u',join(root,'backend/tests/serve_target_management_offline.py'),
   '--state-dir',stateDir,'--port',String(port),'--local','--seed-toolbot'],{cwd:root,windowsHide:true,
   env:{...process.env,PYTHONPATH:[join(root,'backend/src'),root].join(delimiter)}});
  const base=`http://127.0.0.1:${browserPort}`;
  let ready=false;
  for(let i=0;i<40;i++){
   try{const response=await page.request.get(base+'/api/testing/health');
    if(response.ok()&&(await response.json()).operator_mode==='local_single_user'){ready=true;break;}}
   catch{/* local test API is starting */}
   await new Promise(done=>setTimeout(done,250));
  }
  expect(ready).toBe(true);
  await page.goto('/#targets');
  await page.getByLabel('AI Agent URL').fill('http://127.0.0.1:7010/');
  await page.getByLabel(/I authorize up to three bounded metadata requests/).check();
  await page.getByRole('button',{name:'Discover & Test Connection',exact:true}).click();
  await expect(page.getByText(/Connected: mcp tools list response/)).toBeVisible();
  await expect(page.getByText(/Target identifier already exists/)).toBeVisible();
  await expect(page.getByRole('button',{name:'Save Target'})).toBeDisabled();
  expect(existsSync(join(stateDir,'operator-data','target-catalog.json'))).toBe(false);
  await page.getByRole('group',{name:'Choose target setup'}).getByRole('button',{name:'Select existing target'}).click();
  await expect(page.getByRole('heading',{name:'Saved ToolBot'})).toBeVisible();
 }finally{child?.kill();}
});
