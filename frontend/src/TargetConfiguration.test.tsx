import { fireEvent,render,screen,waitFor } from '@testing-library/react';
import { expect,it,vi } from 'vitest';
import TargetConfiguration from './TargetConfiguration';
import App from './App';
import { parseTargets,parseValidation } from './testingApi';
import { catalog,valid,workflowHealth } from './test/targetFixtures';
import { health,overview,page } from './test/fixtures';
function mock(data:unknown=catalog,result:unknown=valid){return vi.spyOn(globalThis,'fetch').mockImplementation(async(url)=>new Response(JSON.stringify(String(url).startsWith('/api/reports/')?(String(url).endsWith('/health')?health:String(url).endsWith('/overview')?overview:page):String(url).endsWith('/health')?workflowHealth:String(url).endsWith('/targets')?data:result)));}
it('loads catalog and validates only via offline POST; changing options invalidates result',async()=>{
 const fetcher=mock();render(<TargetConfiguration/>);
 await screen.findByRole('heading',{name:'Reviewed lab'});
 expect(screen.getByLabelText('Platform')).toHaveValue('synthetic-lab');
 expect(screen.getByLabelText('Target').querySelectorAll('option')).toHaveLength(2);
 expect(screen.getByText(catalog.targets[0].endpoint)).toBeInTheDocument();
 fireEvent.click(screen.getByRole('button',{name:'Validate Configuration'}));
 await screen.findByText('Configuration valid');
 const call=fetcher.mock.calls.find(([url])=>String(url).endsWith('/validate'))!;
 expect(call[1]?.method).toBe('POST');expect(call[1]?.headers).toHaveProperty('X-SecAgent-Validation',workflowHealth.validation_nonce);
 expect(JSON.parse(String(call[1]?.body))).toMatchObject({target_id:'lab-one',timeout_seconds:30});
 expect(fetcher.mock.calls.every(([url])=>String(url).startsWith('/api/testing/'))).toBe(true);
 fireEvent.change(screen.getByLabelText('Model'),{target:{value:'alternate'}});
 expect(screen.getByText('Configuration not validated')).toBeInTheDocument();
 expect(screen.getByRole('button',{name:/Test Connection/})).toBeDisabled();
 expect(screen.queryByRole('button',{name:/Run Security Test/})).not.toBeInTheDocument();
});
it('switches platform and uses that agent’s own model and timeout without carrying validation',async()=>{
 const other={...catalog.targets[0],id:'lab-three',name:'Other platform agent',
  platform_id:'other-platform',platform_name:'Other Platform',models:['other-model'],
  default_model:'other-model',timeout_default:12};
 mock({...catalog,targets:[...catalog.targets,other]});render(<TargetConfiguration/>);
 await screen.findByLabelText('Platform');
 fireEvent.click(screen.getByText('Validate Configuration'));
 await screen.findByText('Configuration valid');
 fireEvent.change(screen.getByLabelText('Platform'),{target:{value:'other-platform'}});
 expect(screen.getByRole('heading',{name:'Other platform agent'})).toBeInTheDocument();
 expect(screen.getByLabelText('Target').querySelectorAll('option')).toHaveLength(1);
 expect(screen.getByLabelText('Model')).toHaveValue('other-model');
 expect(screen.getByLabelText('Timeout (seconds)')).toHaveValue(12);
 expect(screen.getByText('Configuration not validated')).toBeInTheDocument();
 expect(screen.getByRole('button',{name:'Continue'})).toBeDisabled();
});
it('keeps a one-profile legacy catalog usable without platform metadata',async()=>{
 const legacy={...catalog.targets[0]};delete legacy.platform_id;delete legacy.platform_name;
 mock({...catalog,targets:[legacy]});render(<TargetConfiguration/>);
 await screen.findByLabelText('Platform');
 expect(screen.getByLabelText('Platform')).toHaveValue('__legacy_platform__');
 expect(screen.getByRole('option',{name:'Configured targets'})).toBeInTheDocument();
 expect(screen.getByLabelText('Target').querySelectorAll('option')).toHaveLength(1);
 fireEvent.click(screen.getByText('Validate Configuration'));
 await screen.findByText('Configuration valid');
});
it('resets model and timeout when selecting another agent on the same platform',async()=>{
 const second={...catalog.targets[1],models:['second-model'],default_model:'second-model',timeout_default:18};
 mock({...catalog,targets:[catalog.targets[0],second]});render(<TargetConfiguration/>);
 await screen.findByLabelText('Target');
 fireEvent.change(screen.getByLabelText('Target'),{target:{value:'lab-two'}});
 expect(screen.getByLabelText('Model')).toHaveValue('second-model');
 expect(screen.getByLabelText('Timeout (seconds)')).toHaveValue(18);
 expect(screen.getByText('Requires approval')).toBeInTheDocument();
});
it('selects a review-required preset without claiming connectivity',async()=>{
 mock(catalog,{...valid,target_id:'lab-two',configuration_status:'invalid',errors:['operator_review_required']});render(<TargetConfiguration/>);
 await screen.findByLabelText('Target');fireEvent.change(screen.getByLabelText('Target'),{target:{value:'lab-two'}});
 expect(screen.getByText('Requires approval')).toBeInTheDocument();
 fireEvent.click(screen.getByText('Validate Configuration'));await screen.findByText('Operator approval required');
 expect(screen.getByText(/Connection not checked/)).toBeInTheDocument();
});
it.each(['unauthorized_endpoint','stale_profile_revision','credential_unavailable'])('shows offline invalid reason %s',async(code)=>{
 mock(catalog,{...valid,configuration_status:'invalid',errors:[code]});render(<TargetConfiguration/>);await screen.findByLabelText('Target');
 fireEvent.click(screen.getByText('Validate Configuration'));await screen.findByText('Configuration invalid');expect(screen.getByText(code.replaceAll('_',' '))).toBeInTheDocument();
});
it('handles empty catalog',async()=>{mock({...catalog,targets:[]});render(<TargetConfiguration/>);await screen.findByText('No target presets selected');expect(screen.queryByText('Validate Configuration')).not.toBeInTheDocument();});
it('handles API unavailable without rendering raw errors',async()=>{vi.spyOn(globalThis,'fetch').mockRejectedValue(Error('secret-token'));render(<TargetConfiguration/>);await screen.findByRole('alert');expect(document.body.textContent).not.toContain('secret-token');});
it('keeps reporting navigation operational',async()=>{mock();location.hash='#targets';render(<App/>);await screen.findByLabelText('Target');fireEvent.click(screen.getByRole('link',{name:'Evaluation Overview'}));await screen.findByRole('heading',{name:'Evaluation overview'});fireEvent.click(screen.getByRole('link',{name:'Targets'}));await screen.findByLabelText('Target');});
it('does not allow stale validation to survive a target change',async()=>{mock();render(<TargetConfiguration/>);await screen.findByLabelText('Target');fireEvent.click(screen.getByText('Validate Configuration'));await screen.findByText('Configuration valid');fireEvent.change(screen.getByLabelText('Target'),{target:{value:'lab-two'}});await waitFor(()=>expect(screen.queryByText('Configuration valid')).not.toBeInTheDocument());});
it.each(['http://user:secret@127.0.0.1/path','http://127.0.0.1/path?token=secret','http://127.0.0.1/path#secret'])('rejects sensitive endpoint %s',endpoint=>expect(()=>parseTargets({...catalog,targets:[{...catalog.targets[0],endpoint}]})).toThrow());
it('rejects unsupported selectable protocols and fabricated execution',()=>{expect(()=>parseTargets({...catalog,targets:[{...catalog.targets[0],protocol:'a2a'}]})).toThrow();expect(()=>parseValidation({...valid,target_execution_performed:true})).toThrow();});
it('keeps advanced metadata collapsed and refuses to invent a probe',async()=>{
 const fetcher=mock();render(<TargetConfiguration/>);await screen.findByLabelText('Target');
 const details=screen.getByText('Advanced Settings').closest('details')!;
 expect(details.open).toBe(false);
 expect(screen.queryByText(/Approved endpoint/)).not.toBeInTheDocument();
 expect(screen.getByRole('button',{name:'Continue'})).toBeDisabled();
 expect(screen.getByRole('button',{name:'Test Connection'})).toBeDisabled();
 expect(screen.getByText('Probe unsupported')).toBeInTheDocument();
 expect(fetcher.mock.calls.every(([url])=>!String(url).includes('connection-checks'))).toBe(true);
 fireEvent.click(screen.getByText('Advanced Settings'));expect(details.open).toBe(true);
});
it('fails closed if a catalog claims unimplemented active authorization',()=>{
 expect(()=>parseTargets({...catalog,targets:[{...catalog.targets[0],connection_probe:{status:'supported',active_probe_authorized:true}}]})).toThrow();
});
it('rejects ambiguous or contradictory platform metadata from the API',()=>{
 expect(()=>parseTargets({...catalog,targets:[{...catalog.targets[0],platform_name:null}]})).toThrow();
 expect(()=>parseTargets({...catalog,targets:[catalog.targets[0],{...catalog.targets[1],platform_name:'Other Name'}]})).toThrow();
 expect(()=>parseTargets({...catalog,targets:[catalog.targets[0],{...catalog.targets[0]}]})).toThrow();
});
