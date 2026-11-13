import {fireEvent,render,screen} from '@testing-library/react';
import {it,expect,vi} from 'vitest';
import PlanWizard from './PlanWizard';
import {categories,planPreview} from './test/planFixtures';
import {preset} from './test/targetFixtures';
import {draftFor} from './testingApi';
function mount(data=planPreview){const spy=vi.spyOn(globalThis,'fetch').mockImplementation(async url=>new Response(JSON.stringify(String(url).endsWith('categories')?categories:data)));render(<PlanWizard target={draftFor(preset,'researchbot',30)} nonce={'n'.repeat(43)} onBack={()=>{}}/>);return spy;}
it('selects categories, individual testcases and previews without execution',async()=>{
 const spy=mount();await screen.findByText('Agent Goal Hijacking');fireEvent.click(screen.getByText('Select All'));expect(screen.getByText('4 of 4 categories selected')).toBeInTheDocument();
 fireEvent.click(screen.getByText('Clear All'));expect(screen.getByText('Review testcases')).toBeDisabled();
 fireEvent.click(screen.getByText('Agent Goal Hijacking'));fireEvent.click(screen.getByText('Review testcases'));
 await screen.findByLabelText('Select SYNTHETIC-01');fireEvent.click(screen.getByLabelText('Select SYNTHETIC-01'));fireEvent.click(screen.getByText('Preview Test Plan'));
 await screen.findByRole('heading',{name:'Test plan preview',level:2});expect(screen.getByText(/Execution has not started/)).toBeInTheDocument();
 expect(spy.mock.calls.every(([url])=>String(url).startsWith('/api/testing/'))).toBe(true);
 fireEvent.click(screen.getByText('Back to selection'));expect(screen.getByLabelText('Select SYNTHETIC-01')).toBeChecked();expect(screen.getByText('1 of 4 categories selected')).toBeInTheDocument();
});
it.each(Array.from({length:15},(_,i)=>i+1))('accepts category subset %s',async mask=>{mount();await screen.findByText('Agent Goal Hijacking');categories.items.forEach((c,i)=>{if(mask&(1<<i))fireEvent.click(screen.getByText(c.name));});expect(screen.getByText('Review testcases')).toBeEnabled();});
it('shows empty matching catalog',async()=>{mount({...planPreview,items:[]});await screen.findByText('Select All');fireEvent.click(screen.getByText('Select All'));await screen.findByText('Agent Goal Hijacking');fireEvent.click(screen.getByText('Select All'));fireEvent.click(screen.getByText('Review testcases'));await screen.findByText('No testcases match this selection.');});
it('handles loading and unavailable service',async()=>{vi.spyOn(globalThis,'fetch').mockRejectedValue(Error('secret'));render(<PlanWizard target={draftFor(preset,'researchbot',30)} nonce="nonce" onBack={()=>{}}/>);expect(screen.getByText('Loading categories...')).toBeInTheDocument();await screen.findByRole('alert');expect(document.body.textContent).not.toContain('secret');});
it('blocks unsupported cases while permitting provisional unknown selection',async()=>{
 mount({...planPreview,items:[{...planPreview.items[0],id:'BLOCKED',compatibility:'unsupported'},{...planPreview.items[0],id:'UNKNOWN',compatibility:'unknown'}]});
 await screen.findByText('Agent Goal Hijacking');fireEvent.click(screen.getByText('Select All'));fireEvent.click(screen.getByText('Review testcases'));
 expect(await screen.findByLabelText('Select BLOCKED')).toBeDisabled();expect(screen.getByLabelText('Select UNKNOWN')).toBeEnabled();
});
it('rejects an executable response instead of showing readiness',async()=>{
 mount({...planPreview,executable:true});await screen.findByText('Agent Goal Hijacking');fireEvent.click(screen.getByText('Select All'));fireEvent.click(screen.getByText('Review testcases'));await screen.findByRole('alert');expect(screen.queryByText('Preview Test Plan')).not.toBeInTheDocument();
});
