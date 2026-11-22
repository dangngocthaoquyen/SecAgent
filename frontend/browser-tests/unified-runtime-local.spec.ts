import {expect,test} from '@playwright/test';

test('one local session switches targets and ASI scopes and opens persisted history',async({page})=>{
 test.setTimeout(60000);
 const executionRequests:string[]=[];
 page.on('request',request=>{if(request.method()==='POST'&&/\/api\/testing\/(?:batches|mcp-actions\/run)$/.test(request.url()))executionRequests.push(request.url());});
 const health=await (await page.request.get('/api/testing/health')).json();
 test.skip(!health.registered_workflows?.includes('asi01')||!health.registered_workflows?.includes('imported'),
  'Unified local runtime is not active on this port.');
 await page.goto('/#datasets');
 await page.getByRole('row',{name:/testcases_dvaa_codebot_asi05\.json/}).getByRole('button',{name:'Inspect & Select'}).click();
 const target=page.locator('#dataset-target-select');
 await expect(target).toBeVisible();
 const options=await target.locator('option').evaluateAll(nodes=>nodes.map(n=>(n as HTMLOptionElement).value));
 expect(options.length).toBeGreaterThan(1);
 expect(options).toContain('dvaa-codebot');
 expect(options).toContain('local-agent-7010');
 await target.selectOption('local-agent-7010');
 await target.selectOption('dvaa-codebot');
 await expect(target).toHaveValue('dvaa-codebot');
 await page.locator('#dataset-evaluation-category').selectOption('ASI05');
 await expect(page.locator('#dataset-evaluation-scope')).toHaveValue('response_command_artifact');
 await page.locator('#dataset-evaluation-scope').selectOption('execution_action');
 await expect(page.getByText('The imported chat workflow has no reviewed execution policy binding', {exact:false})).toBeVisible();
 await page.locator('#dataset-evaluation-scope').selectOption('response_command_artifact');
 await page.locator('#dataset-evaluation-category').selectOption('ASI02');
 await expect(page.getByText('Imported prompts do not provide tool invocation', {exact:false})).toBeVisible();
 await page.locator('#dataset-evaluation-category').selectOption('ASI03');
 await expect(page.locator('#dataset-evaluation-scope')).toHaveValue('identity_claim_response');
 await page.getByRole('button',{name:'MCP tool-action assessment'}).click();
 await expect(page.getByRole('heading',{name:'MCP tool-action assessment'})).toBeVisible();
 await expect(page.getByRole('combobox',{name:'Testcase'})).toHaveValue('ASI05-DVAA-LAB-READ-001');
 await expect(page.getByText('draft', {exact:false})).toBeVisible();
 expect(executionRequests).toEqual([]);
 await page.getByRole('link',{name:'Execution Results'}).click();
 await expect(page.getByRole('heading',{name:'Saved Native Reports'})).toBeVisible({timeout:30000});
 await expect(page.getByText(/saved reports/)).toBeVisible({timeout:30000});
});
