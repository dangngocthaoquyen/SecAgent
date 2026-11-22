import {expect,test} from '@playwright/test';
import {mkdirSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {preset,workflowHealth} from '../src/test/targetFixtures';

const screenshots=join(resolve(process.cwd(),'..'),'frontend','artifacts','application-context-policy-ux');
const datasetId='a'.repeat(32);
const summary={dataset_id:datasetId,name:'shell-injection-sample',schema_version:'1.0',source_tool:'promptfoo',
 platform:'DVAA',bot:'codebot',run_id:null,imported_at:'2026-11-20T00:00:00Z',file_sha256:'b'.repeat(64),total_testcases:1};
const dataset={...summary,source_metadata:{},testcases:[{testcase_id:'TC0001',internal_id:'import-'+'c'.repeat(24),
 description:null,plugin_id:'shell-injection',strategy_id:null,prompt:'Explain the safety boundary for a dummy command.',
 prompt_sha256:'d'.repeat(64),assertions:[],metadata:{},options:{},extra:{},index:0}]};

for(const width of [1440,390])test(`ASI05 imported policy stays scoped at ${width}px`,async({page})=>{
 await page.setViewportSize({width,height:width===390?844:900});
 const unexpected:string[]=[];
 await page.route('**/api/**',async route=>{
  const path=new URL(route.request().url()).pathname;
  if(path.endsWith('/health'))return route.fulfill({json:{...workflowHealth,custom_imported_batch_enabled:true,evaluation_modes:['rule_only','hybrid'],judge_configuration:'configured_unverified'}});
  if(path.endsWith('/targets'))return route.fulfill({json:{workflow_schema_version:'1.0.0',targets:[preset],protocols:[]}});
  if(path.endsWith('/datasets'))return route.fulfill({json:{workflow_schema_version:'1.0.0',datasets:[summary]}});
  if(path.endsWith(`/datasets/${datasetId}`))return route.fulfill({json:{workflow_schema_version:'1.0.0',dataset}});
  if(path.includes('/asi05-policies/target/'))return route.fulfill({json:{workflow_schema_version:'1.0.0',policy:null}});
  if(path.endsWith('/batches/preview'))return route.fulfill({json:{workflow_schema_version:'1.0.0',plan_id:'e'.repeat(64),total:1,ready_count:0,transport_mode:'offline_mock',items:[{testcase_id:'TC0001',name:'Synthetic imported case',asi_category:'ASI05',status:'blocked',reason:'asi05_policy_not_reviewed',asset_sha256:'f'.repeat(64),input_sha256:'d'.repeat(64)}]}});
  unexpected.push(path);return route.abort();
 });
 await page.goto('/#datasets');
 await page.getByRole('button',{name:'Inspect & Select'}).click();
 await expect(page.getByText('shell-injection',{exact:true})).toBeVisible();
 await expect(page.getByRole('button',{name:'Review response claim'})).toHaveCount(0);
 await page.getByRole('combobox',{name:'ASI',exact:true}).selectOption('ASI05');
 await expect(page.getByRole('heading',{name:/ASI05 response policy/})).toBeVisible();
 await expect(page.getByRole('heading',{name:/ASI03 identity policy/})).toHaveCount(0);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 mkdirSync(screenshots,{recursive:true});
 await page.screenshot({path:join(screenshots,`dataset-asi05-${width}.png`),fullPage:true});
 await page.getByRole('combobox',{name:'Evaluation scope'}).selectOption('execution_action');
 await expect(page.getByText(/Not available for official evaluation/)).toBeVisible();
 await expect(page.getByRole('heading',{name:/ASI05 response policy/})).toHaveCount(0);
 expect(unexpected).toEqual([]);
});
