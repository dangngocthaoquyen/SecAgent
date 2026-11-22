import { expect, test } from '@playwright/test';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { delimiter, join, resolve } from 'node:path';

const root=resolve(process.cwd(),'..');
const port=Number(process.env.SECAGENT_WORKFLOW_PROXY_PORT || '8093');
const browserPort=Number(process.env.SECAGENT_FRONTEND_PORT || '5174');

async function free():Promise<boolean>{return new Promise(done=>{
 const server=createServer();server.once('error',()=>done(false));
 server.listen(port,'127.0.0.1',()=>server.close(()=>done(true)));
});}

test('real Workflow API and local proxy persist an operator-reviewed target',async({page})=>{
 test.setTimeout(60000);
 if(!(await free()))test.skip(true,'Isolated Workflow API port is occupied.');
 const stateDir=mkdtempSync(join(tmpdir(),'secagent-managed-browser-'));
 let child:ChildProcessWithoutNullStreams|undefined;
 try{
  child=spawn('python',['-u',join(root,'backend/tests/serve_target_management_offline.py'),
   '--state-dir',stateDir,'--port',String(port)],{cwd:root,windowsHide:true,env:{...process.env,
    PYTHONPATH:[join(root,'backend/src'),root].join(delimiter)}});
  const base=`http://127.0.0.1:${browserPort}`;
  let ready=false;
  for(let i=0;i<40;i++){
   try{const response=await page.request.get(base+'/api/testing/health');if(response.ok()){ready=true;break;}}
   catch{/* API has not started */}
   await new Promise(done=>setTimeout(done,250));
  }
  expect(ready).toBe(true);
  await page.goto('/#targets');
  await expect(page.getByText('No target presets selected')).toBeVisible();
  await page.getByLabel('Operator secret').fill('offline-browser-test-operator-secret-123456');
  await page.getByRole('button',{name:'Unlock target management'}).click();
  await page.getByRole('button',{name:'Add Target'}).click();
  await page.getByRole('button',{name:'Use DVAA ResearchBot example'}).click();
  await page.getByRole('button',{name:'Validate Target Details'}).click();
  await expect(page.getByRole('button',{name:'Save Configuration'})).toBeEnabled();
  await page.getByRole('button',{name:'Save Configuration'}).click();
  await expect(page.getByRole('heading',{name:'DVAA ResearchBot'})).toBeVisible();
  await expect(page.getByRole('button',{name:'Test Connection'})).toBeDisabled();
  await page.getByLabel(/I confirm authorization to test/).check();
  await page.getByRole('button',{name:'Review / Approve Target'}).click();
  await expect(page.getByRole('button',{name:'Test Connection'})).toBeEnabled();
  await page.getByRole('button',{name:'Test Connection'}).click();
  await expect(page.getByText(/API compatibility: yes/)).toBeVisible();
  await page.getByRole('button',{name:'Validate Configuration'}).click();
  await expect(page.getByText('Configuration valid',{exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Continue'}).click();
  await expect(page.getByRole('heading',{name:'Select ASI categories'})).toBeVisible();
  const state=join(stateDir,'operator-data','target-catalog.json');
  expect(existsSync(state)).toBe(true);
  const saved=JSON.parse(readFileSync(state,'utf8'));
  expect(saved.catalog.targets).toHaveLength(1);
  expect(saved.catalog.targets[0].id).toBe('dvaa-researchbot');
  expect(saved.catalog.targets[0].reviewed).toBe(false);
  expect(saved.reviews).toHaveLength(1);
  expect(saved.reviews[0].profile_revision).toMatch(/^[a-f0-9]{64}$/);
  expect(JSON.stringify(saved)).not.toContain('offline-browser-test-operator-secret-123456');
 }finally{
  child?.kill();
 }
});
