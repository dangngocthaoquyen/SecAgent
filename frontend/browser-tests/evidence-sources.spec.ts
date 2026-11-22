import {expect,test} from '@playwright/test';
import {preset,valid,workflowHealth} from '../src/test/targetFixtures';

for(const width of [1440,1366])test(`evidence sources are optional and authorization-bound at ${width}`,async({page},testInfo)=>{
 await page.setViewportSize({width,height:width===1440?1000:768});
 let sources:Record<string,unknown>[]=[],collections=0;
 const unexpected:string[]=[];
 await page.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url()),path=url.pathname;
  if(url.hostname!=='127.0.0.1'){unexpected.push(req.url());return route.abort();}
  if(!path.startsWith('/api/'))return route.continue();
  if(path.endsWith('/health'))return route.fulfill({json:{...workflowHealth,evidence_sources_enabled:true,target_management_enabled:true,operator_mode:'local_single_user',custom_imported_batch_enabled:true}});
  if(path.endsWith('/targets'))return route.fulfill({json:{workflow_schema_version:'1.0.0',targets:[preset],protocols:[]}});
  if(path.endsWith('/managed-targets/archived'))return route.fulfill({json:{workflow_schema_version:'1.0.0',targets:[]}});
  if(path.includes('/application-contexts/target/'))return route.fulfill({json:{workflow_schema_version:'1.0.0',context:null,binding_status:'current'}});
  if(path.endsWith('/categories'))return route.fulfill({json:{workflow_schema_version:'1.0.0',items:[]}});
  if(path.endsWith('/target-drafts/validate'))return route.fulfill({json:valid});
  if(path.includes('/evidence-sources/target/'))return route.fulfill({json:{workflow_schema_version:'1.0.0',sources,allowed_endpoints:[{url:'http://127.0.0.1:7800/events',credential_ref:null}],action_verification_supported:false}});
  if(path.endsWith('/evidence-sources/save')){sources=[{...req.postDataJSON().profile,id:'a'.repeat(32),revision:'b'.repeat(64),schema_version:'1.0.0'}];return route.fulfill({json:{workflow_schema_version:'1.0.0',source:sources[0]}});}
  if(path.endsWith('/evidence-sources/collect')){collections++;expect(req.postDataJSON()).toEqual({source_id:'a'.repeat(32),expected_revision:'b'.repeat(64),authorization_confirmed:true});return route.fulfill({json:{workflow_schema_version:'1.0.0',capture:{id:'c'.repeat(32),source_id:'a'.repeat(32),source_revision:'b'.repeat(64),availability:'available',error:null,action_eligible:false,correlation_status:'uncorrelated',request_count:1,events:[{content:'I refuse.',reported_semantics:'detector_reported'}],external_judge_disclosure:'forbidden'}}});}
  unexpected.push(path);return route.abort();
 });
 await page.goto('/#targets');
 await page.getByRole('button',{name:'Select existing target'}).click();
 await expect(page.getByRole('heading',{name:preset.name})).toBeVisible();
 await expect(page.getByRole('button',{name:'Add Evidence Source'})).not.toBeVisible();
 expect(collections).toBe(0);
 await page.locator('details.target-evidence-drawer > summary').click();
 await page.locator('details.evidence-sources > summary').click();
 await page.getByRole('button',{name:'Add Evidence Source'}).click();
 await page.getByLabel('Source name',{exact:true}).fill('Research log');
 await page.getByRole('combobox',{name:'Allowlisted endpoint'}).selectOption('http://127.0.0.1:7800/events');
 await expect(page.getByLabel('Content field',{exact:true})).not.toBeVisible();
 await page.getByRole('button',{name:'Save Source'}).click();
 await expect(page.getByText('Research log',{exact:true})).toBeVisible();
 await expect(page.getByRole('button',{name:'Test Source'})).toBeDisabled();
 expect(collections).toBe(0);
 await page.getByLabel(/I authorize one read-only snapshot/).check();
 await page.getByRole('button',{name:'Test Source'}).click();
 await expect(page.getByText('At last snapshot',{exact:true})).toBeVisible();
 await expect(page.getByText('Uncorrelated',{exact:true})).toBeVisible();
 await expect(page.getByText('Not independently verified',{exact:true})).toBeVisible();
 expect(collections).toBe(1);expect(unexpected).toEqual([]);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await page.screenshot({path:testInfo.outputPath(`evidence-${width}.png`),fullPage:true});
});
