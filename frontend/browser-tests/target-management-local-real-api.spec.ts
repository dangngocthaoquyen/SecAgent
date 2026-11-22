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

async function free():Promise<boolean>{return new Promise(done=>{
 const server=createServer();server.once('error',()=>done(false));
 server.listen(port,'127.0.0.1',()=>server.close(()=>done(true)));
});}

test('local frontend manages and confirms a target through the real API without a browser token',async({page})=>{
 test.setTimeout(60000);
 if(process.env.SECAGENT_LOCAL_PROXY_TOKEN!==token)test.skip(true,'Run with the isolated local proxy credential.');
 if(!(await free()))test.skip(true,'Isolated Workflow API port is occupied.');
 const stateDir=mkdtempSync(join(tmpdir(),'secagent-local-browser-'));
 let child:ChildProcessWithoutNullStreams|undefined;
 try{
  child=spawn('python',['-u',join(root,'backend/tests/serve_target_management_offline.py'),
   '--state-dir',stateDir,'--port',String(port),'--local'],{cwd:root,windowsHide:true,env:{...process.env,
    PYTHONPATH:[join(root,'backend/src'),root].join(delimiter)}});
  const base=`http://127.0.0.1:${browserPort}`;
  let ready=false;
  for(let i=0;i<40;i++){
   try{const response=await page.request.get(base+'/api/testing/health');if(response.ok()&&
     (await response.json()).operator_mode==='local_single_user'){ready=true;break;}}
   catch{/* API has not started */}
   await new Promise(done=>setTimeout(done,250));
  }
  expect(ready).toBe(true);
  const direct=await page.request.get(`http://127.0.0.1:${port}/api/testing/managed-targets`);
  expect(direct.status()).toBe(403);
  const cross=await page.request.get(base+'/api/testing/managed-targets',{
   headers:{Origin:'http://evil.example','Sec-Fetch-Site':'cross-site'}});
  expect(cross.status()).toBe(403);
  await page.goto('/#targets');
  expect(await page.getByLabel('Operator secret').count()).toBe(0);
  await page.getByRole('button',{name:'Select existing target'}).click();
  await page.getByRole('button',{name:'Add Target'}).click();
  await page.getByRole('button',{name:'Use DVAA ResearchBot example'}).click();
  await page.getByRole('button',{name:'Validate Target Details'}).click();
  await page.getByRole('button',{name:'Save Configuration'}).click();
  await expect(page.getByRole('heading',{name:'DVAA ResearchBot'})).toBeVisible();
  const probe=page.getByRole('button',{name:'Test Connection'});
  await expect(probe).toBeDisabled();
  await page.getByLabel(/I confirm authorization for one benign probe/).check();
  await probe.click();
  await expect(page.locator('.target-connection')).toHaveText('Connected');
  const shots=join(root,'frontend','artifacts','target-management-final');
  mkdirSync(shots,{recursive:true});
  await page.setViewportSize({width:1440,height:900});
  await page.screenshot({path:join(shots,'targets-1440.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.screenshot({path:join(shots,'targets-390.png'),fullPage:true});
  await page.locator('.target-list-row').filter({hasText:'DVAA ResearchBot'}).getByRole('button',{name:'Archive'}).click();
  const dialog=page.getByRole('dialog',{name:'Confirm target archive'});
  await expect(dialog).toContainText('http://127.0.0.1:7015/v1/chat/completions');
  await dialog.getByLabel('I confirm the exact targets above should be archived.').check();
  await dialog.getByRole('button',{name:'Archive targets'}).click();
  await expect(page.getByText('No active targets. Connect or restore a target.')).toBeVisible();
  const saved=join(stateDir,'operator-data','target-catalog.json');
  expect(existsSync(saved)).toBe(true);
  const state=JSON.parse(readFileSync(saved,'utf8'));
  expect(state.catalog.targets[0].reviewed).toBe(false);
  expect(state.reviews).toHaveLength(1);
  expect(state.archived).toHaveLength(1);
  expect(JSON.stringify(state)).not.toContain(token);
 }finally{child?.kill();}
});
