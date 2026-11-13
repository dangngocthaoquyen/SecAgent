import {render,screen,fireEvent} from '@testing-library/react';
import {it,expect,vi} from 'vitest';
import Readiness from './Readiness';
import {preset} from './test/targetFixtures';
import {draftFor} from './testingApi';
const response={workflow_schema_version:'1.0.0',plan_id:'a'.repeat(64),ready_count:0,blocked_count:1,blockers:[],items:[{testcase_id:'GH-WEB-001',blockers:['fresh_collector_binding_missing']}],decision:'blocked',admitted:false,execution_status:'not_started',dispatch_available:false};
function mount(evaluationModes:('rule_only'|'hybrid')[]=['rule_only']){render(<Readiness target={draftFor(preset,'researchbot',30)} ids={['GH-WEB-001']} categories={['ASI01']} nonce={'n'.repeat(43)} evaluationModes={evaluationModes}/>);}
it('checks readiness only on request and submits explicit identity for admission',async()=>{
 const spy=vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response(JSON.stringify(response)));
 mount();expect(spy).not.toHaveBeenCalled();fireEvent.click(screen.getByText('Check run readiness'));await screen.findByText('Ready: 0 / Blocked: 1');
 expect(screen.getByText('fresh collector binding missing')).toBeInTheDocument();
 spy.mockResolvedValue(new Response(JSON.stringify(response)));
 fireEvent.click(screen.getByText('Request admission decision'));await screen.findByText('Ready: 0 / Blocked: 1');
 expect(JSON.parse(String(spy.mock.calls[1][1]?.body)).expected_plan_id).toBe('a'.repeat(64));
 expect(screen.queryByRole('button',{name:'Run'})).not.toBeInTheDocument();
});
it('does not display dispatch as available from a malformed response',async()=>{
 vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response(JSON.stringify({...response,dispatch_available:true})));
 mount();fireEvent.click(screen.getByText('Check run readiness'));await screen.findByRole('alert');
});
it('shows lab setup as blocked without enabling a live web run',async()=>{
 vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response(JSON.stringify({...response,
  lab_preflight_status:'not_checked'})));
 mount();fireEvent.click(screen.getByText('Check run readiness'));
 await screen.findByText(/Requires lab setup. Lab preflight has not been checked/);
 expect(screen.queryByRole('button',{name:'Run one authorized test'})).not.toBeInTheDocument();
});
it('rejects a claimed live run when lab preflight is still unchecked',async()=>{
 vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response(JSON.stringify({...response,
  ready_count:1,blocked_count:0,items:[{testcase_id:'GH-WEB-001',blockers:[]}],
  decision:'admitted',admitted:true,dispatch_available:true,lab_preflight_status:'not_checked'})));
 mount();fireEvent.click(screen.getByText('Check run readiness'));
 await screen.findByRole('alert');
 expect(screen.queryByRole('button',{name:'Run one authorized test'})).not.toBeInTheDocument();
});
it('runs once only after backend admission and uses an ephemeral operator secret',async()=>{
 const admitted={...response,ready_count:1,blocked_count:0,items:[{testcase_id:'GH-WEB-001',blockers:[]}],decision:'admitted',admitted:true,dispatch_available:true};
 const run={workflow_schema_version:'1.0.0',run_id:'c'.repeat(32),execution_status:'completed',target_request_count:1,report_persisted:true,evidence_captured:false,artifact_provenance:'target_observation',reporting_snapshot_contains_run:false,historical_verdict:'PASS',reporting_run_reference:'c'.repeat(32),reporting_view:'run/'+'c'.repeat(32)};
 const spy=vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify(admitted))).mockResolvedValueOnce(new Response(JSON.stringify(run)));
 mount();expect(screen.queryByRole('button',{name:'Run one authorized test'})).not.toBeInTheDocument();
 fireEvent.click(screen.getByText('Check run readiness'));await screen.findByRole('button',{name:'Run one authorized test'});
 fireEvent.change(screen.getByLabelText('Operator execution secret'),{target:{value:'synthetic-operator-secret'}});
 fireEvent.click(screen.getByRole('button',{name:'Run one authorized test'}));await screen.findByText(/Native report saved locally/);
 expect(spy.mock.calls[1][0]).toBe('/api/testing/runs');
 expect(spy.mock.calls[1][1]?.headers).toHaveProperty('X-SecAgent-Operator','synthetic-operator-secret');
 expect(screen.getByText(/startup snapshot does not contain this run/)).toBeInTheDocument();
 expect(screen.getByText(/Evidence unavailable/)).toBeInTheDocument();
 expect(screen.getByText(/Evidence source: target observation/)).toBeInTheDocument();
 expect(screen.getByRole('link',{name:'Open saved report'})).toHaveAttribute('href','#run/'+'c'.repeat(32));
 expect(screen.queryByRole('button',{name:'Run one authorized test'})).not.toBeInTheDocument();
});

it.each([
 ['missing reference',{},true,'completed'],
 ['unmatched reference',{reporting_run_reference:'d'.repeat(32),reporting_view:'run/'+'d'.repeat(32)},true,'completed'],
 ['path-shaped view',{reporting_run_reference:'c'.repeat(32),reporting_view:'../../private'},true,'completed'],
 ['persistence failed',{reporting_run_reference:'c'.repeat(32),reporting_view:'run/'+'c'.repeat(32)},false,'completed'],
 ['execution failed',{reporting_run_reference:'c'.repeat(32),reporting_view:'run/'+'c'.repeat(32)},true,'failed'],
] as const)('does not link a %s run',async(_label,fields,persisted,status)=>{
 const admitted={...response,ready_count:1,blocked_count:0,items:[{testcase_id:'GH-WEB-001',blockers:[]}],decision:'admitted',admitted:true,dispatch_available:true};
 const run={workflow_schema_version:'1.0.0',run_id:'c'.repeat(32),execution_status:status,target_request_count:0,report_persisted:persisted,evidence_captured:false,artifact_provenance:'synthetic_mock',reporting_snapshot_contains_run:false,...fields};
 vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify(admitted))).mockResolvedValueOnce(new Response(JSON.stringify(run)));
 mount();fireEvent.click(screen.getByText('Check run readiness'));
 fireEvent.change(await screen.findByLabelText('Operator execution secret'),{target:{value:'synthetic-operator-secret'}});
 fireEvent.click(screen.getByRole('button',{name:'Run one authorized test'}));
 await screen.findByText(/Run c{32}:/);
 expect(screen.queryByRole('link',{name:'Open saved report'})).not.toBeInTheDocument();
});

it('offers hybrid only when advertised and binds selection to admission and run',async()=>{
 const admitted={...response,ready_count:1,blocked_count:0,items:[{testcase_id:'GH-WEB-001',blockers:[]}],
  decision:'admitted',admitted:true,dispatch_available:true,evaluation_mode:'hybrid',max_judge_calls:1,
  judge_configuration:'configured_unverified'};
 const run={workflow_schema_version:'1.0.0',run_id:'c'.repeat(32),evaluation_mode:'hybrid',execution_status:'completed',
  target_request_count:1,report_persisted:true,evidence_captured:false,artifact_provenance:'synthetic_mock',
  reporting_snapshot_contains_run:false,historical_verdict:'INCONCLUSIVE',reporting_run_reference:'c'.repeat(32),
  reporting_view:'run/'+'c'.repeat(32)};
 const spy=vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify(admitted)))
  .mockResolvedValueOnce(new Response(JSON.stringify(run)));
 mount(['rule_only','hybrid']);
 fireEvent.change(screen.getByLabelText('Evaluation mode'),{target:{value:'hybrid'}});
 fireEvent.click(screen.getByText('Check run readiness'));
 await screen.findByRole('button',{name:'Run one authorized test'});
 expect(JSON.parse(String(spy.mock.calls[0][1]?.body)).evaluation_mode).toBe('hybrid');
 fireEvent.change(screen.getByLabelText('Operator execution secret'),{target:{value:'synthetic-operator-secret'}});
 fireEvent.click(screen.getByRole('button',{name:'Run one authorized test'}));
 expect(await screen.findByRole('link',{name:'Open saved report'})).toHaveAttribute('href','#run/'+'c'.repeat(32));
 expect(JSON.parse(String(spy.mock.calls[1][1]?.body)).evaluation_mode).toBe('hybrid');
 expect(screen.getByText(/Recorded verdict: INCONCLUSIVE/)).toBeInTheDocument();
});

it('clears stale admission when evaluation mode changes',async()=>{
 vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response(JSON.stringify(response)));
 mount(['rule_only','hybrid']);
 fireEvent.click(screen.getByText('Check run readiness'));await screen.findByText('Ready: 0 / Blocked: 1');
 fireEvent.change(screen.getByLabelText('Evaluation mode'),{target:{value:'hybrid'}});
 expect(screen.queryByText('Ready: 0 / Blocked: 1')).not.toBeInTheDocument();
 expect(screen.queryByRole('button',{name:'Request admission decision'})).not.toBeInTheDocument();
});

it('rejects a claimed hybrid readiness response without server Judge confirmation',async()=>{
 vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response(JSON.stringify({...response,evaluation_mode:'hybrid',
  max_judge_calls:0,judge_configuration:'unavailable'})));
 mount(['rule_only','hybrid']);
 fireEvent.change(screen.getByLabelText('Evaluation mode'),{target:{value:'hybrid'}});
 fireEvent.click(screen.getByText('Check run readiness'));await screen.findByRole('alert');
 expect(screen.queryByRole('button',{name:'Run one authorized test'})).not.toBeInTheDocument();
});

it('keeps hybrid unavailable without backend advertisement',()=>{
 mount();
 expect(screen.queryByLabelText('Evaluation mode')).not.toBeInTheDocument();
 expect(screen.getByText(/Hybrid Judge is unavailable/)).toBeInTheDocument();
});
