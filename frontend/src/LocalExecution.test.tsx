import {afterEach,expect,it,vi} from 'vitest';
import {fireEvent,render,screen} from '@testing-library/react';
import LocalExecution from './LocalExecution';
import {draftFor} from './testingApi';
import {preset} from './test/targetFixtures';

afterEach(()=>vi.restoreAllMocks());
const plan={workflow_schema_version:'1.0.0',plan_id:'a'.repeat(64),blockers:[],
 items:[{testcase_id:'GH-C01',blockers:['execution_authorization_missing_or_expired']}]};
const target=draftFor(preset,'researchbot',30);
function mount(){render(<LocalExecution target={target} ids={['GH-C01']} categories={['ASI01']}
 nonce={'n'.repeat(43)} evaluationModes={['rule_only']} controlledRunsEnabled onFinished={vi.fn()}/>);}

it('uses one primary run action and shows the persisted response and verdict',async()=>{
 const run={workflow_schema_version:'1.0.0',run_id:'b'.repeat(32),execution_status:'completed',
  historical_verdict:'INCONCLUSIVE',target_request_count:1,response_captured:true,
  response_complete:true,http_status:200,evidence_captured:true,report_persisted:true,
  artifact_provenance:'target_observation',reporting_run_reference:'b'.repeat(32),
  reporting_view:'run/'+'b'.repeat(32)};
 const fetch=vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify(plan)))
  .mockResolvedValueOnce(new Response(JSON.stringify(run)));
 mount();
 const button=await screen.findByRole('button',{name:'Run selected tests'});
 expect(screen.queryByRole('button',{name:'Request admission decision'})).not.toBeInTheDocument();
 expect(screen.queryByRole('button',{name:'Authorize one benign run'})).not.toBeInTheDocument();
 fireEvent.click(button);fireEvent.click(button);
 expect(await screen.findByRole('heading',{name:'Completed with INCONCLUSIVE'})).toBeInTheDocument();
 expect(screen.getByText(/Response: captured/)).toBeInTheDocument();
 expect(screen.getByText(/Completeness: complete/)).toBeInTheDocument();
 expect(screen.getByRole('link',{name:'View report'})).toHaveAttribute('href','#run/'+'b'.repeat(32));
 expect(fetch).toHaveBeenCalledTimes(2);
 expect(fetch.mock.calls[1][0]).toBe('/api/testing/run-selected');
 expect(JSON.parse(String(fetch.mock.calls[1][1]?.body))).toMatchObject({authorization_confirmed:true,
  expected_plan_id:'a'.repeat(64),target_request_budget:1,testcase_ids:['GH-C01']});
});

it('blocks unreviewed targets and unsupported selections before a run request',async()=>{
 const fetch=vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify({
  ...plan,blockers:['operator_review_required']})));
 mount();
 expect(await screen.findByRole('heading',{name:'Execution blocked'})).toBeInTheDocument();
 expect(screen.getByText('operator review required')).toBeInTheDocument();
 expect(screen.queryByRole('button',{name:'Run selected tests'})).not.toBeInTheDocument();
 expect(fetch).toHaveBeenCalledTimes(1);
});

it('shows a stale-plan rejection without claiming an execution',async()=>{
 const fetch=vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify(plan)))
  .mockResolvedValueOnce(new Response(JSON.stringify({workflow_schema_version:'1.0.0',
   execution_status:'blocked',blockers:['stale_plan_identity'],target_request_count:0}),{status:409}));
 mount();fireEvent.click(await screen.findByRole('button',{name:'Run selected tests'}));
 expect(await screen.findByText('stale plan identity')).toBeInTheDocument();
 expect(screen.getByText(/No target request was sent/)).toBeInTheDocument();
 expect(fetch).toHaveBeenCalledTimes(2);
});

it('shows an evaluator ERROR as a technical failure, not a security verdict',async()=>{
 const run={workflow_schema_version:'1.0.0',run_id:'c'.repeat(32),execution_status:'completed',
  historical_verdict:'ERROR',target_request_count:1,response_captured:true,
  response_complete:true,http_status:200,evidence_captured:true,report_persisted:true,
  artifact_provenance:'synthetic_mock',reporting_run_reference:'c'.repeat(32),
  reporting_view:'run/'+'c'.repeat(32)};
 vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify(plan)))
  .mockResolvedValueOnce(new Response(JSON.stringify(run)));
 mount();fireEvent.click(await screen.findByRole('button',{name:'Run selected tests'}));
 expect(await screen.findByRole('heading',{name:'Execution failed due to system or provider error'})).toBeInTheDocument();
 expect(screen.getByRole('link',{name:'View report'})).toBeInTheDocument();
 expect(screen.queryByText(/Final verdict: FAIL/)).not.toBeInTheDocument();
});
