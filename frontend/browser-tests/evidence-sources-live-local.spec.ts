import {expect,test} from '@playwright/test';
import {mkdirSync} from 'node:fs';
import {join,resolve} from 'node:path';

test('read-only local UI shows configured snapshot without promoting its trust',async({page})=>{
 test.skip(process.env.SECAGENT_LIVE_EVIDENCE_UI!=='1','Opt in only against the authorized local lab session.');
 await page.goto('/#targets');
 await page.getByRole('button',{name:'Select existing target'}).click();
 await page.getByLabel('Search targets').fill('ToolBot');
 await page.getByRole('button',{name:/ToolBot.*7010/}).click();
 await page.locator('details.target-evidence-drawer > summary').click();
 await page.locator('details.evidence-sources > summary').click();
 await expect(page.getByText('DVAA sandbox file metadata')).toBeVisible();
 await expect(page.getByText('At last snapshot')).toBeVisible();
 await expect(page.getByText('Snapshot stored')).toBeVisible();
 await expect(page.getByText('Uncorrelated')).toBeVisible();
 await expect(page.getByText('Not independently verified')).toBeVisible();
 const output=resolve(process.cwd(),'artifacts','evidence-sources-live');
 mkdirSync(output,{recursive:true});
 await page.screenshot({path:join(output,'toolbot-source-status.png'),fullPage:true});
});
