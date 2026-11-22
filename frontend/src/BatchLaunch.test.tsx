import {afterEach,expect,it,vi} from 'vitest';
import {fireEvent,render,screen} from '@testing-library/react';
import BatchLaunch from './BatchLaunch';
import {draftFor} from './testingApi';
import {preset} from './test/targetFixtures';

afterEach(()=>{vi.restoreAllMocks();location.hash='';});
const target=draftFor(preset,'researchbot',30);
const preview={workflow_schema_version:'1.0.0',plan_id:'a'.repeat(64),total:3,ready_count:1,
 target_request_budget:3,execution_model:'sequential_offline_mock',items:[
  {testcase_id:'CASE-0',name:'Synthetic case 0',asi_category:'ASI01',status:'ready',asset_sha256:'b'.repeat(64),input_sha256:'c'.repeat(64)},
  {testcase_id:'CASE-4',name:'Synthetic case 4',asi_category:'ASI01',status:'blocked',asset_sha256:'d'.repeat(64),input_sha256:'e'.repeat(64)},
  {testcase_id:'UNKNOWN',name:'Unknown',asi_category:'unknown',status:'unsupported',asset_sha256:'f'.repeat(64),input_sha256:'a'.repeat(64)}]};

it('reviews exact synthetic scope and submits once on a double click',async()=>{
 const fetch=vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify(preview)))
  .mockResolvedValueOnce(new Response(JSON.stringify({workflow_schema_version:'1.0.0',
   batch_run_id:'1'.repeat(32),plan_id:'a'.repeat(64),status:'preparing',
   progress_view:'/api/testing/batches/'+'1'.repeat(32)})));
 render(<BatchLaunch target={target} ids={['CASE-0','CASE-4','UNKNOWN']} nonce={'n'.repeat(43)}/>);
 expect(await screen.findByText(/Ready: 1 \/ Blocked: 1 \/ Unsupported: 1/)).toBeInTheDocument();
 const button=screen.getByRole('button',{name:'Run Selected Tests'});
 fireEvent.click(button);fireEvent.click(button);
 expect(await screen.findByText(/Offline synthetic batch/)).toBeInTheDocument();
 await vi.waitFor(()=>expect(location.hash).toBe('#batch/'+'1'.repeat(32)));
 expect(fetch).toHaveBeenCalledTimes(2);
 expect(JSON.parse(String(fetch.mock.calls[1][1]?.body))).toMatchObject({
  testcase_ids:['CASE-0','CASE-4','UNKNOWN'],total_request_budget:3,
  expected_plan_id:'a'.repeat(64),authorization_confirmed:true});
});

it('shows a blocked preview without sending a batch',async()=>{
 const fetch=vi.spyOn(globalThis,'fetch').mockRejectedValueOnce(Error('Target revision stale.'));
 render(<BatchLaunch target={target} ids={['CASE-0']} nonce={'n'.repeat(43)}/>);
 expect(await screen.findByRole('alert')).toHaveTextContent('Target revision stale.');
 expect(screen.queryByRole('button',{name:'Run Selected Tests'})).not.toBeInTheDocument();
 expect(fetch).toHaveBeenCalledTimes(1);
});

it('shows the sanitized Web Lab endpoint correction returned by the API',async()=>{
 const message='Web Lab endpoint mismatch. Edit the target to use http://127.0.0.1:17016/v1/chat/completions, save, and review the new revision.';
 const fetch=vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify({
  workflow_schema_version:'1.0.0',error:{code:'web_lab_endpoint_mismatch',message}}),{status:409}));
 render(<BatchLaunch target={target} ids={['GH-WEB-001']} nonce={'n'.repeat(43)} synthetic={false} webLab/>);
 expect(await screen.findByRole('alert')).toHaveTextContent(message);
 expect(screen.queryByRole('button',{name:'Run Selected Tests'})).not.toBeInTheDocument();
 expect(fetch).toHaveBeenCalledTimes(1);
});

it('does not repeat a submission whose response was lost',async()=>{
 const fetch=vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify(preview)))
  .mockRejectedValueOnce(Error('Connection lost'));
 render(<BatchLaunch target={target} ids={['CASE-0','CASE-4','UNKNOWN']} nonce={'n'.repeat(43)}/>);
 const button=await screen.findByRole('button',{name:'Run Selected Tests'});
 fireEvent.click(button);
 expect(await screen.findByRole('alert')).toHaveTextContent('Submission outcome could not be confirmed');
 expect(button).toBeDisabled();
 fireEvent.click(button);
 expect(fetch).toHaveBeenCalledTimes(2);
});

it('labels the controlled native slice and its exact blocker without claiming a mock run',async()=>{
 const controlled={...preview,execution_model:'sequential_reviewed_asi01',items:[
  {...preview.items[0],testcase_id:'GH-C01'},
  {...preview.items[1],testcase_id:'GH-WEB-C01',reason:'verified_web_fetch_and_action_scope_missing'},
  {...preview.items[2],testcase_id:'UNKNOWN'}]};
 vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify(controlled)));
 render(<BatchLaunch target={target} ids={['GH-C01','GH-WEB-C01','UNKNOWN']} nonce={'n'.repeat(43)} synthetic={false}/>);
 expect(await screen.findByText(/Ready: 1 \/ Blocked: 1 \/ Unsupported: 1/)).toBeInTheDocument();
 expect(screen.getByText(/Native text cases use the exact reviewed local target/)).toBeInTheDocument();
 expect(screen.getByText(/Web fetch and independent action scope evidence are not available/)).toBeInTheDocument();
 expect(screen.queryByText(/Offline synthetic batch/)).not.toBeInTheDocument();
});

it('previews ToolBot Lab TM-002 as Ready without GH-C01 baseline requirement',async()=>{
 const toolbotPreview={workflow_schema_version:'1.0.0',plan_id:'a'.repeat(64),total:2,ready_count:1,
  target_request_budget:1,execution_model:'sequential_synthetic_toolbot_lab',items:[
   {testcase_id:'TM-002',name:'Direct sensitive tool execution',asi_category:'ASI02',status:'ready',asset_sha256:'a'.repeat(64),input_sha256:'b'.repeat(64)},
   {testcase_id:'TM-001',name:'TM-001',asi_category:'ASI02',status:'unsupported',reason:'tm001_agent_confirmation_trace_unavailable',asset_sha256:'c'.repeat(64),input_sha256:'d'.repeat(64)}]};
 vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify(toolbotPreview)));
 render(<BatchLaunch target={target} ids={['TM-002','TM-001']} nonce={'n'.repeat(43)} synthetic={false} toolbotLab/>);
 expect(await screen.findByText(/Ready: 1 \/ Blocked: 0 \/ Unsupported: 1/)).toBeInTheDocument();
 expect(screen.getByText(/Offline synthetic ToolBot Lab/)).toBeInTheDocument();
 expect(screen.queryByText(/Requires a persisted GH-C01 PASS in this batch/)).not.toBeInTheDocument();
 const tm002Row=screen.getByText('TM-002').closest('li');
 expect(tm002Row).not.toBeNull();
 expect(tm002Row?.querySelector('.batch-cell-pill')?.textContent).toBe('Ready');
});

it('marks non-control ASI01 text cases as Conditional requiring GH-C01',async()=>{
 const asi01Preview={workflow_schema_version:'1.0.0',plan_id:'f'.repeat(64),total:2,ready_count:2,
  target_request_budget:2,execution_model:'sequential_reviewed_asi01',items:[
   {testcase_id:'GH-C01',name:'Control prompt',asi_category:'ASI01',status:'ready',asset_sha256:'1'.repeat(64),input_sha256:'2'.repeat(64)},
   {testcase_id:'GH-001',name:'Goal hijack 1',asi_category:'ASI01',status:'ready',asset_sha256:'3'.repeat(64),input_sha256:'4'.repeat(64)}]};
 vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify(asi01Preview)));
 render(<BatchLaunch target={target} ids={['GH-C01','GH-001']} nonce={'n'.repeat(43)} synthetic={false}/>);
 expect(await screen.findByText(/Ready: 2 \/ Blocked: 0 \/ Unsupported: 0/)).toBeInTheDocument();
 const ghC01Row=screen.getByText('GH-C01').closest('li');
 expect(ghC01Row?.querySelector('.batch-cell-pill')?.textContent).toBe('Ready');
 const gh001Row=screen.getByText('GH-001').closest('li');
 expect(gh001Row?.querySelector('.batch-cell-pill')?.textContent).toBe('Conditional');
 expect(screen.getByText(/Requires a persisted GH-C01 PASS in this batch/)).toBeInTheDocument();
});

it('previews custom imported testcases as Ready without GH-C01 prerequisite',async()=>{
 const customPreview={workflow_schema_version:'1.0.0',plan_id:'b'.repeat(64),total:2,ready_count:2,
  execution_mode:'custom_imported',dataset_id:'c'.repeat(32),items:[
   {testcase_id:'TC0001',name:'TC0001: excessive-agency',asi_category:'ASI02',status:'ready',asset_sha256:'1'.repeat(64),input_sha256:'2'.repeat(64)},
   {testcase_id:'TC0002',name:'TC0002: excessive-agency',asi_category:'ASI02',status:'ready',asset_sha256:'3'.repeat(64),input_sha256:'4'.repeat(64)}]};
 vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify(customPreview)));
 render(<BatchLaunch target={target} ids={['TC0001','TC0002']} nonce={'n'.repeat(43)} synthetic={false} customImported/>);
 expect(await screen.findByText(/Ready: 2 \/ Blocked: 0 \/ Unsupported: 0/)).toBeInTheDocument();
 expect(screen.getByText(/Custom imported testcase batch/)).toBeInTheDocument();
 expect(screen.queryByText(/Requires a persisted GH-C01 PASS in this batch/)).not.toBeInTheDocument();
 const tc001Row=screen.getByText('TC0001').closest('li');
 expect(tc001Row?.querySelector('.batch-cell-pill')?.textContent).toBe('Ready');
 const tc002Row=screen.getByText('TC0002').closest('li');
 expect(tc002Row?.querySelector('.batch-cell-pill')?.textContent).toBe('Ready');
});

it('keeps the explicit Live Local choice in preview and submission',async()=>{
 const imported={workflow_schema_version:'1.0.0',plan_id:'a'.repeat(64),total:1,ready_count:1,
  transport_mode:'live_local_http',target_request_budget:1,execution_mode:'custom_imported',items:[
   {testcase_id:'import-one',name:'Imported case',asi_category:'UNCLASSIFIED',status:'ready',asset_sha256:'b'.repeat(64),input_sha256:'c'.repeat(64)}]};
 const fetch=vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify(imported)))
  .mockResolvedValueOnce(new Response(JSON.stringify({workflow_schema_version:'1.0.0',
   batch_run_id:'1'.repeat(32),plan_id:'a'.repeat(64),status:'preparing',
   progress_view:'/api/testing/batches/'+'1'.repeat(32)})));
 render(<BatchLaunch target={target} ids={['import-one']} nonce={'n'.repeat(43)}
  synthetic={false} customImported datasetId={'d'.repeat(32)} transportMode="live_local_http"/>);
 expect(await screen.findByText(/Live Local sends each selected prompt/)).toBeInTheDocument();
 fireEvent.click(screen.getByRole('button',{name:'Run Selected Tests'}));
 await vi.waitFor(()=>expect(fetch).toHaveBeenCalledTimes(2));
 expect(JSON.parse(String(fetch.mock.calls[0][1]?.body)).transport_mode).toBe('live_local_http');
 expect(JSON.parse(String(fetch.mock.calls[1][1]?.body)).transport_mode).toBe('live_local_http');
});

it('routes an expired live connection proof back to Test Connection',async()=>{
 const blocked={workflow_schema_version:'1.0.0',plan_id:'a'.repeat(64),total:1,ready_count:0,
  execution_mode:'custom_imported',transport_mode:'live_local_http',items:[
   {testcase_id:'import-one',name:'Imported case',asi_category:'UNCLASSIFIED',status:'blocked',
    reason:'imported_live_connection_check_expired',asset_sha256:'b'.repeat(64),input_sha256:'c'.repeat(64)}]};
 vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify(blocked)));
 render(<BatchLaunch target={target} ids={['import-one']} nonce={'n'.repeat(43)}
  synthetic={false} customImported datasetId={'d'.repeat(32)} transportMode="live_local_http"/>);
 expect(await screen.findByText(/compatible connection check expired/)).toBeInTheDocument();
 expect(screen.getByRole('link',{name:/Go to Targets to run Test Connection/})).toHaveAttribute('href','#targets');
 expect(screen.getByRole('button',{name:'Run Selected Tests'})).toBeDisabled();
});
