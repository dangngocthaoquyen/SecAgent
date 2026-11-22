import {expect, test} from '@playwright/test';
import {preset, valid, workflowHealth} from '../src/test/targetFixtures';

for(const viewport of [{width:1440,height:1000},{width:1366,height:768},{width:390,height:844}]){
 test(`target configuration remains bounded and readable at ${viewport.width}`,async({page},testInfo)=>{
  await page.setViewportSize(viewport);
  const targets=[{...preset,name:'Research assistant',connection_probe:{status:'supported',reason:'reviewed_exact_endpoint',active_probe_authorized:true,security_execution_authorized:false}},
   {...preset,id:'second',name:'Code assistant',default_model:'code-agent',models:['code-agent'],profile_revision:'b'.repeat(64),endpoint:'http://127.0.0.1:7200/v1/chat/completions',connection_probe:{status:'supported',reason:'reviewed_exact_endpoint',active_probe_authorized:true,security_execution_authorized:false}}];
  let probeCount=0;
  const unexpected:string[]=[];
  // Every API request is answered locally. No workflow proxy, Target or Judge is used.
  await page.route('**/api/**',async route=>{
   const req=route.request(),path=new URL(req.url()).pathname;
   if(path.endsWith('/health'))return route.fulfill({json:{...workflowHealth,target_management_enabled:true,operator_mode:'local_single_user',custom_imported_batch_enabled:true}});
   if(path.endsWith('/targets'))return route.fulfill({json:{workflow_schema_version:'1.0.0',targets,protocols:[]}});
   if(path.endsWith('/target-drafts/validate')){const draft=req.postDataJSON();return route.fulfill({json:{...valid,target_id:draft.target_id,profile_revision:draft.profile_revision}});}
   if(path.endsWith('/categories'))return route.fulfill({json:{workflow_schema_version:'1.0.0',items:[]}});
   if(path.endsWith('/managed-targets/archived'))return route.fulfill({json:{workflow_schema_version:'1.0.0',targets:[]}});
   if(path.includes('/application-contexts/target/'))return route.fulfill({json:{workflow_schema_version:'1.0.0',context:null,binding_status:'current'}});
   if(path.endsWith('/connection-checks')){
    probeCount++;expect(req.postDataJSON()).toMatchObject({target_id:'second',profile_revision:'b'.repeat(64)});
    return route.fulfill({json:{workflow_schema_version:'1.0.0',connection_status:'succeeded',reason:'openai_chat_response',target_request_count:1,connection_reachable:true,runtime_protocol_compatible:true,http_status:200,security_test_executed:false,security_verdict:null}});
   }
   unexpected.push(path);return route.abort();
  });
  await page.goto('/#targets');
  await page.getByRole('button',{name:'Select existing target'}).click();
  await expect(page.getByText('Configuration valid',{exact:true})).toBeVisible();
  await expect(page.getByLabel('Selected target').getByText('Not checked',{exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:'Test Connection'})).toBeDisabled();
  await expect(page.getByText('Profile revision',{exact:true})).not.toBeVisible();
  await expect(page.getByRole('button',{name:'Add Evidence Source'})).not.toBeVisible();
  expect(probeCount).toBe(0);
  const selector=await page.getByLabel('Selected target').boundingBox();
  const probe=await page.getByRole('button',{name:'Test Connection'}).boundingBox();
  expect(probe!.y-selector!.y).toBeLessThan(viewport.width<700?540:430);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.screenshot({path:testInfo.outputPath(`targets-${viewport.width}.png`),fullPage:true});
  await page.getByText('Evidence Sources',{exact:true}).click();
  await expect(page.getByRole('button',{name:'Add Evidence Source'})).toBeDisabled();
  await expect(page.getByText('Action verification not ready')).toBeVisible();
  expect(probeCount).toBe(0);
  await page.getByRole('button',{name:/Code assistant/}).click();
  await expect(page.getByRole('heading',{name:'Code assistant'})).toBeVisible();
  await expect(page.getByRole('button',{name:'Test Connection'})).toBeDisabled();
  await page.getByLabel(/I confirm authorization for one benign probe/).check();
  await page.getByRole('button',{name:'Test Connection'}).click();
  await expect(page.getByLabel('Selected target').getByText('Connected',{exact:true})).toBeVisible();
  expect(probeCount).toBe(1);
  await page.getByRole('button',{name:/Research assistant/}).click();
  await expect(page.getByLabel('Selected target').getByText('Not checked',{exact:true})).toBeVisible();
  await page.getByText('Advanced Settings',{exact:true}).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('combobox',{name:'Model',exact:true})).toBeVisible();
  expect(unexpected).toEqual([]);
 });
}
