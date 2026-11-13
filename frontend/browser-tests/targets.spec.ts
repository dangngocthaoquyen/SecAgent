import { expect,test } from '@playwright/test';
import {categories,planPreview} from '../src/test/planFixtures';
import { catalog,workflowHealth,valid } from '../src/test/targetFixtures';
import { health,overview,page as rows } from '../src/test/fixtures';
test('offline Targets selection and validation on desktop and mobile; reporting navigation retained',async({page})=>{
 await page.route('**/api/testing/**',async route=>{
 const path=new URL(route.request().url()).pathname;
 await route.fulfill({json:path.endsWith('/readiness/preview')?{workflow_schema_version:'1.0.0',plan_id:'a'.repeat(64),ready_count:0,blocked_count:1,blockers:[],items:[{testcase_id:'SYNTHETIC-01',blockers:['reviewed_runtime_binding_missing']}],decision:'blocked',admitted:false,execution_status:'not_started',dispatch_available:false}:path.endsWith('/categories')?categories:path.endsWith('/preview')?planPreview:path.endsWith('/health')?workflowHealth:path.endsWith('/targets')?catalog:valid});
 });
 await page.route('**/api/reports/**',async route=>{const path=new URL(route.request().url()).pathname;await route.fulfill({json:path.endsWith('/health')?health:path.endsWith('/overview')?overview:rows});});
 await page.goto('/#targets');
 await expect(page.getByRole('heading',{name:'Reviewed lab'})).toBeVisible();
 await page.getByRole('button',{name:'Validate Configuration'}).click();
 await expect(page.getByText('Configuration valid',{exact:true})).toBeVisible();
 await page.getByRole('button',{name:'Continue',exact:true}).click();
 await page.getByText('Agent Goal Hijacking',{exact:true}).click();
 await page.getByRole('button',{name:'Review testcases'}).click();
 await page.getByLabel('Select SYNTHETIC-01').check();
 await page.getByRole('button',{name:'Preview Test Plan'}).click();
 await expect(page.getByRole('heading',{name:'Test plan preview',level:2})).toBeVisible();
 await page.getByRole('button',{name:'Check run readiness'}).click();
 await expect(page.getByText('Ready: 0 / Blocked: 1')).toBeVisible();
 await page.setViewportSize({width:390,height:844});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await page.getByRole('button',{name:'Back to selection'}).click();
 await page.getByRole('button',{name:'Back to Target'}).click();
 await page.getByRole('button',{name:'Continue',exact:true}).click();
 await expect(page.getByText('1 of 4 categories selected')).toBeVisible();
 await page.getByRole('button',{name:'Back to Target'}).click();
 await expect(page.getByRole('button',{name:/Test Connection/})).toBeDisabled();
 await page.getByLabel('Target',{exact:true}).selectOption('lab-two');
 await expect(page.getByText('Requires approval',{exact:true})).toBeVisible();
 await page.setViewportSize({width:390,height:844});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await page.getByRole('link',{name:'Evaluation Overview'}).click();
 await expect(page.getByRole('heading',{name:'Evaluation overview'})).toBeVisible();
});

test('groups synthetic agents by platform without implying connection or execution',async({page})=>{
 const other={...catalog.targets[0],id:'lab-three',name:'Other platform agent',
  platform_id:'other-platform',platform_name:'Other Platform',models:['other-model'],
  default_model:'other-model',timeout_default:12};
 await page.route('**/api/testing/**',async route=>{
  const path=new URL(route.request().url()).pathname;
  await route.fulfill({json:path.endsWith('/health')?workflowHealth:
   path.endsWith('/targets')?{...catalog,targets:[...catalog.targets,other]}:valid});
 });
 await page.goto('/#targets');
 await page.getByLabel('Platform').selectOption('other-platform');
 await expect(page.getByRole('heading',{name:'Other platform agent'})).toBeVisible();
 await expect(page.getByLabel('Target').locator('option')).toHaveCount(1);
 await expect(page.getByLabel('Model')).toHaveValue('other-model');
 await expect(page.getByLabel('Timeout (seconds)')).toHaveValue('12');
 await expect(page.getByText('Configuration not validated')).toBeVisible();
 await expect(page.getByRole('button',{name:'Test Connection'})).toBeDisabled();
 await expect(page.getByRole('button',{name:'Continue'})).toBeDisabled();
 await page.setViewportSize({width:390,height:844});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
});

test('shows backend-authorized Judge choice while keeping the synthetic plan blocked',async({page})=>{
 await page.route('**/api/testing/**',async route=>{
  const path=new URL(route.request().url()).pathname;
  await route.fulfill({json:path.endsWith('/readiness/preview')?{
   workflow_schema_version:'1.0.0',plan_id:'a'.repeat(64),ready_count:0,blocked_count:1,
   blockers:['operator_authorization_missing'],items:[{testcase_id:'SYNTHETIC-01',blockers:['operator_authorization_missing']}],
   decision:'blocked',admitted:false,execution_status:'not_started',dispatch_available:false,
   evaluation_mode:'hybrid',max_judge_calls:1,judge_configuration:'configured_unverified'}:
   path.endsWith('/categories')?categories:path.endsWith('/preview')?planPreview:
   path.endsWith('/health')?{...workflowHealth,evaluation_modes:['rule_only','hybrid'],
    judge_configuration:'configured_unverified'}:path.endsWith('/targets')?catalog:valid});
 });
 await page.route('**/api/reports/**',async route=>{const path=new URL(route.request().url()).pathname;
  await route.fulfill({json:path.endsWith('/health')?health:path.endsWith('/overview')?overview:rows});});
 await page.goto('/#targets');
 await page.getByRole('button',{name:'Validate Configuration'}).click();
 await page.getByRole('button',{name:'Continue',exact:true}).click();
 await page.getByText('Agent Goal Hijacking',{exact:true}).click();
 await page.getByRole('button',{name:'Review testcases'}).click();
 await page.getByLabel('Select SYNTHETIC-01').check();
 await page.getByRole('button',{name:'Preview Test Plan'}).click();
 await page.getByLabel('Evaluation mode').selectOption('hybrid');
 await page.getByRole('button',{name:'Check run readiness'}).click();
 await expect(page.getByText('Ready: 0 / Blocked: 1')).toBeVisible();
 await expect(page.getByRole('button',{name:'Run one authorized test'})).toHaveCount(0);
});
