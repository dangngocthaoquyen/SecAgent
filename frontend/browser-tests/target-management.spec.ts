import { expect, test } from '@playwright/test';
import { preset, workflowHealth } from '../src/test/targetFixtures';

test('operator creates, reviews and probes ResearchBot before testcase selection',async({page})=>{
 let target: typeof preset | null=null;
 const calls:string[]=[];
 await page.route('**/api/testing/**',async route=>{
  const req=route.request(),path=new URL(req.url()).pathname;
  calls.push(path);
  const unreviewed={...preset,id:'dvaa-researchbot',name:'DVAA ResearchBot',platform_id:'dvaa',platform_name:'DVAA',
   authorization_status:'review_required',models:['researchbot'],default_model:'researchbot',
   connection_probe:{status:'unsupported',reason:'operator_review_required',active_probe_authorized:false,security_execution_authorized:false}};
  if(path.endsWith('/health'))return route.fulfill({json:{...workflowHealth,target_management_enabled:true}});
  if(path.endsWith('/targets'))return route.fulfill({json:{workflow_schema_version:'1.0.0',targets:target?[target]:[],protocols:[{id:'openai-chat',state:'offline_configuration_supported'}]}});
  if(path.endsWith('/managed-targets')&&req.method()==='GET')return route.fulfill({json:{workflow_schema_version:'1.0.0',targets:target?[target]:[],policy_ref:'lab-v1'}});
  if(path.endsWith('/managed-targets/validate'))return route.fulfill({json:{workflow_schema_version:'1.0.0',configuration_status:'valid',target_request_count:0,target_execution_performed:false}});
  if(path.endsWith('/managed-targets/create')){target=unreviewed as typeof preset;return route.fulfill({json:{workflow_schema_version:'1.0.0',profile:target}});}
  if(path.endsWith('/managed-targets/review')){target={...unreviewed,authorization_status:'reviewed_for_offline_configuration',
   connection_probe:{status:'supported',reason:'reviewed_exact_endpoint',active_probe_authorized:true,security_execution_authorized:false}} as typeof preset;
   return route.fulfill({json:{workflow_schema_version:'1.0.0',profile:target}});}
  if(path.endsWith('/connection-checks'))return route.fulfill({json:{workflow_schema_version:'1.0.0',connection_status:'succeeded',reason:'openai_chat_response',
   target_request_count:1,connection_reachable:true,runtime_protocol_compatible:true,http_status:200,security_test_executed:false,security_verdict:null}});
  if(path.endsWith('/target-drafts/validate'))return route.fulfill({json:{workflow_schema_version:'1.0.0',configuration_status:'valid',errors:[],
   target_id:'dvaa-researchbot',profile_revision:'a'.repeat(64),connection_reachable:null,runtime_protocol_compatible:null,target_execution_performed:false,security_verdict:null}});
  if(path.endsWith('/categories'))return route.fulfill({json:{workflow_schema_version:'1.0.0',items:[
   {id:'ASI01',name:'Agent Goal Hijacking'},{id:'ASI02',name:'Tool Misuse'},
   {id:'ASI03',name:'Identity and Privilege Abuse'},{id:'ASI05',name:'Unexpected Code Execution'}]}});
  return route.fulfill({status:404,json:{error:{code:'not_found'}}});
 });
 await page.goto('/#targets');
 await page.getByLabel('Operator secret').fill('synthetic-operator-secret');
 await page.getByRole('button',{name:'Unlock target management'}).click();
 await page.getByRole('button',{name:'Select existing target'}).click();
 await page.getByText('Add Target').click();
 await page.getByText('Use DVAA ResearchBot example').click();
 await expect(page.getByLabel('Endpoint URL')).toHaveValue('http://127.0.0.1:7015/v1/chat/completions');
 await page.getByText('Validate Target Details').click();
 await page.getByText('Save Configuration').click();
 await expect(page.getByRole('heading',{name:'DVAA ResearchBot'})).toBeVisible();
 await expect(page.getByText('Test Connection')).toBeDisabled();
 await page.getByLabel(/I confirm authorization to test/).check();
 await page.getByText('Review / Approve Target').click();
 await expect(page.getByText('Test Connection')).toBeDisabled();
 await page.getByLabel(/I confirm authorization for one benign probe/).check();
 await page.getByText('Test Connection').click();
 await expect(page.getByLabel('Selected target').getByText('Connected',{exact:true})).toBeVisible();
 await page.getByText('Connection details',{exact:true}).click();
 await expect(page.getByText(/API compatibility: yes/)).toBeVisible();
 await page.getByText('Advanced Settings',{exact:true}).click();
 await page.getByText('Validate Configuration',{exact:true}).click();
 await expect(page.getByText('Configuration valid',{exact:true})).toBeVisible();
 await page.getByText('Continue',{exact:true}).click();
 await expect(page.getByText('Agent Goal Hijacking',{exact:true})).toBeVisible();
 expect(calls).toContain('/api/testing/managed-targets/create');
 expect(calls).toContain('/api/testing/managed-targets/review');
 expect(calls).toContain('/api/testing/connection-checks');
 expect(calls).not.toContain('/api/testing/runs');
 await page.setViewportSize({width:390,height:844});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
});
