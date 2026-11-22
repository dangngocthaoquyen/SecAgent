import {expect,test} from '@playwright/test';
import {readFile} from 'node:fs/promises';
import {health,overview,page as executionPage,execution} from '../src/test/fixtures';
import {detail} from '../src/test/detailFixtures';

test('downloads the selected execution from both list and detail without execution calls',async({page})=>{
 const requests:string[]=[];
 await page.route('**/api/**',route=>{
  const request=route.request(),path=new URL(request.url()).pathname;requests.push(path);
  expect(request.method()).toBe('GET');
  if(path==='/api/reports/health')return route.fulfill({json:health});
  if(path==='/api/reports/overview')return route.fulfill({json:overview});
  if(path==='/api/reports/executions')return route.fulfill({json:executionPage});
  if(path.endsWith('/download')){
   expect(decodeURIComponent(path)).toBe(`/api/reports/executions/${execution.report_id}/download`);
   return route.fulfill({headers:{'Content-Type':'application/json','Content-Disposition':'attachment; filename="secagent-test-report.json"','X-SecAgent-Export-Schema':'1.0.0'},body:JSON.stringify({export_schema_version:'1.0.0',execution:detail.execution})});
  }
  if(decodeURIComponent(path)===`/api/reports/executions/${execution.report_id}`)return route.fulfill({json:detail});
  return route.abort();
 });
 await page.goto('/#executions');
 const first=page.getByRole('button',{name:'Download Report'}).first();await expect(first).toBeVisible();
 let pending=page.waitForEvent('download');await first.click();let download=await pending;
 expect(download.suggestedFilename()).toBe('secagent-test-report.json');
 expect(JSON.parse(await readFile((await download.path())!,'utf8')).export_schema_version).toBe('1.0.0');
 await page.goto(`/#execution/${execution.report_id}`);
 await expect(page.getByRole('link',{name:/Back to execution results/})).toBeVisible();
 pending=page.waitForEvent('download');await page.getByRole('button',{name:'Download Report'}).click();download=await pending;
 expect(download.suggestedFilename()).toBe('secagent-test-report.json');
 expect(requests.every(path=>path.startsWith('/api/reports/'))).toBe(true);
});

test('completed batch exposes one ZIP download next to View Reports',async({page})=>{
 const id='1'.repeat(32),base={workflow_schema_version:'1.0.0'};
 const status={...base,batch_run_id:id,status:'completed',total:1,processed:1,progress_percent:100,
  remaining_count:0,target_request_count:1,request_budget_consumed:1,request_count_unknown:false,
  active_testcase_id:null,active_testcase_name:null,active_asi_category:null,current_stage:null,snapshot_sha256:'a'.repeat(64),
  counts:{completed:1,error:0,blocked:0,unsupported:0,skipped:0,cancelled:0},verdict_counts:{PASS:1,FAIL:0,INCONCLUSIVE:0,ERROR:0}};
 let downloads=0;
 await page.route('**/api/**',route=>{
  const req=route.request(),path=new URL(req.url()).pathname;expect(req.method()).toBe('GET');
  if(path.endsWith('/health'))return route.fulfill({json:{...base,status:'ok',mode:'controlled_execution_enabled',target_network_access:true,
   validation_nonce:'n'.repeat(43),operator_mode:'authenticated',offline_batch_enabled:true,evaluation_modes:['rule_only']}});
  if(path.endsWith('/download')){expect(path).toBe(`/api/reports/batches/${id}/download`);downloads++;return route.fulfill({
   headers:{'Content-Type':'application/zip','Content-Disposition':`attachment; filename="secagent-batch-${id}.zip"`,'X-SecAgent-Export-Schema':'1.0.0'},
   body:Buffer.from('504b0506000000000000000000000000000000000000','hex')});}
  if(path.endsWith('/events'))return route.fulfill({json:{...base,batch_run_id:id,events:[]}});
  if(path.endsWith('/results'))return route.fulfill({json:{...base,batch_run_id:id,snapshot:{target_id:'fixture',profile_revision:'a'.repeat(64),policy_ref:'fixture',evaluation_mode:'rule_only',total_request_budget:1,
   cases:[{testcase_id:'TC0001',name:'Synthetic',asi_category:'ASI03',asset_sha256:'b'.repeat(64),input_sha256:'c'.repeat(64),request_budget:1}]},
   results:[{testcase_id:'TC0001',execution_id:'d'.repeat(32),status:'completed',verdict:'PASS',request_count:1,report_run_id:'e'.repeat(32),report_sha256:'f'.repeat(64),response_captured:true,response_complete:true,evidence_provenance:'synthetic_mock'}]}});
  if(path===`/api/testing/batches/${id}`)return route.fulfill({json:status});
  return route.abort();
 });
 await page.goto(`/#batch/${id}`);await expect(page.getByRole('button',{name:'View Reports (1)'})).toBeVisible();
 expect(downloads).toBe(0);
 const pending=page.waitForEvent('download');await page.getByRole('button',{name:'Download Full Report'}).click();
 expect((await pending).suggestedFilename()).toBe(`secagent-batch-${id}.zip`);expect(downloads).toBe(1);
});
