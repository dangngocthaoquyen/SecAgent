import {afterEach,expect,it,vi} from 'vitest';
import {render,screen} from '@testing-library/react';
import BatchProgress from './BatchProgress';

afterEach(()=>vi.restoreAllMocks());
const id='1'.repeat(32);
const base={workflow_schema_version:'1.0.0'};
const health={...base,status:'ok',mode:'controlled_execution_enabled',target_network_access:true,
 validation_nonce:'n'.repeat(43),operator_mode:'authenticated',offline_batch_enabled:true,
 evaluation_modes:['rule_only']};
const status={...base,batch_run_id:id,status:'cancelled',total:3,processed:1,
 progress_percent:33,remaining_count:2,target_request_count:1,request_budget_consumed:1,
 request_count_unknown:false,active_testcase_id:null,active_testcase_name:null,
 active_asi_category:null,current_stage:null,snapshot_sha256:'a'.repeat(64),
 counts:{completed:1,error:0,blocked:0,unsupported:0,skipped:0,cancelled:2},
 verdict_counts:{PASS:1,FAIL:0,INCONCLUSIVE:0,ERROR:0}};
const caseItem=(number:number)=>({testcase_id:`CASE-${number}`,name:`Synthetic case ${number}`,
 asi_category:'ASI01',asset_sha256:'b'.repeat(64),input_sha256:'c'.repeat(64),request_budget:1});
const results={...base,batch_run_id:id,snapshot:{target_id:'synthetic-target',
 profile_revision:'d'.repeat(64),policy_ref:'offline',evaluation_mode:'rule_only',
 total_request_budget:3,cases:[caseItem(0),caseItem(1),caseItem(2)]},results:[
 {testcase_id:'CASE-0',execution_id:'e'.repeat(32),status:'completed',verdict:'PASS',
  request_count:1,report_run_id:'f'.repeat(32),report_sha256:'a'.repeat(64),
  response_captured:true,response_complete:true,evidence_provenance:'synthetic_mock'},
 ...[1,2].map(number=>({testcase_id:`CASE-${number}`,execution_id:null,status:'cancelled',
  verdict:null,request_count:0,report_run_id:null,report_sha256:null,
  response_captured:null,response_complete:null,evidence_provenance:null}))]};
const events={...base,batch_run_id:id,events:[{at:'2026-11-13T08:00:00Z',
 stage:'case_recorded',testcase_id:'CASE-0'}]};

it('restores a cancelled batch with honest progress and a saved report link',async()=>{
 const fetch=vi.spyOn(globalThis,'fetch').mockImplementation(async input=>{
  const path=String(input);
  return new Response(JSON.stringify(path.endsWith('/health')?health:path.endsWith('/events')?events:
   path.endsWith('/results')?results:status));
 });
 render(<BatchProgress id={id}/>);
 expect(await screen.findByRole('heading',{name:'Batch cancelled'},{timeout:4000})).toBeInTheDocument();
 expect(screen.getByText(/33% processed; batch is terminal/)).toBeInTheDocument();
 expect(screen.getByText(/Pending: 0. Cancelled before execution: 2/)).toBeInTheDocument();
 expect(screen.getByText(/PASS 1, FAIL 0, INCONCLUSIVE 0, ERROR 0/)).toBeInTheDocument();
 expect(screen.getByRole('link',{name:'View Report'})).toHaveAttribute('href','#run/'+'f'.repeat(32));
 expect(screen.getByRole('button',{name:'Download Full Report'})).toBeEnabled();
 expect(screen.queryByRole('button',{name:'Cancel remaining tests'})).not.toBeInTheDocument();
 expect(fetch).toHaveBeenCalledTimes(4);
});

it('rejects malformed batch IDs before any API request',()=>{
 const fetch=vi.spyOn(globalThis,'fetch');
 render(<BatchProgress id="../bad"/>);
 expect(screen.getByRole('heading',{name:'Invalid batch reference'})).toBeInTheDocument();
 expect(fetch).not.toHaveBeenCalled();
});

it('restores a controlled target-observation batch without a synthetic label',async()=>{
 vi.spyOn(globalThis,'fetch').mockImplementation(async input=>{
  const path=String(input);
  const liveHealth={...health,offline_batch_enabled:false,asi01_batch_enabled:true};
  const liveResults={...results,results:[{...results.results[0],
   evidence_provenance:'target_observation'},...results.results.slice(1)]};
  return new Response(JSON.stringify(path.endsWith('/health')?liveHealth:path.endsWith('/events')?events:
   path.endsWith('/results')?liveResults:status));
 });
 render(<BatchProgress id={id}/>);
 expect(await screen.findByRole('heading',{name:'Batch cancelled'},{timeout:4000})).toBeInTheDocument();
 expect(screen.getByText(/CONTROLLED ASI01 ASSESSMENT/)).toBeInTheDocument();
 expect(screen.getByText(/HTTP response observation/)).toBeInTheDocument();
 expect(screen.queryByText(/OFFLINE SYNTHETIC BATCH/)).not.toBeInTheDocument();
});

it('distinguishes asi01 vs imported batch labels in unified runtime',async()=>{
 const unifiedHealth={...health,offline_batch_enabled:false,asi01_batch_enabled:true,custom_imported_batch_enabled:true,imported_live_local_enabled:true};
 const asi01Results={...results,results:[{...results.results[0],evidence_provenance:'target_observation'},...results.results.slice(1)]};
 vi.spyOn(globalThis,'fetch').mockImplementation(async input=>{
  const path=String(input);
  return new Response(JSON.stringify(path.endsWith('/health')?unifiedHealth:path.endsWith('/events')?events:
   path.endsWith('/results')?asi01Results:status));
 });
 const view=render(<BatchProgress id={id}/>);
 expect(await screen.findByRole('heading',{name:'Batch cancelled'},{timeout:4000})).toBeInTheDocument();
 expect(screen.getByText(/CONTROLLED ASI01 ASSESSMENT/)).toBeInTheDocument();
 expect(screen.queryByText(/IMPORTED DATASET ASSESSMENT/)).not.toBeInTheDocument();
 view.unmount();

 const importedResults={...results,snapshot:{...results.snapshot,evaluation_mode:'hybrid',
  imported_provenance:{dataset_id:'1'.repeat(32),dataset_revision_sha256:'2'.repeat(64),
   transport_mode:'live_local_http',evidence_provenance:'target_observation',cases:[]}}};
 vi.spyOn(globalThis,'fetch').mockImplementation(async input=>{
  const path=String(input);
  return new Response(JSON.stringify(path.endsWith('/health')?unifiedHealth:path.endsWith('/events')?events:
   path.endsWith('/results')?importedResults:status));
 });
 render(<BatchProgress id={id}/>);
 expect(await screen.findByRole('heading',{name:'Batch cancelled'},{timeout:4000})).toBeInTheDocument();
 expect(screen.getByText(/LIVE LOCAL IMPORTED DATASET ASSESSMENT/)).toBeInTheDocument();
 expect(screen.getByText(/Hybrid evaluation/)).toBeInTheDocument();
});

it('explains a nonpassing clean baseline without assigning verdicts to blocked attacks',async()=>{
 const blocked={...status,status:'partially_completed',processed:3,progress_percent:100,remaining_count:0,
  counts:{...status.counts,completed:1,blocked:2,cancelled:0},
  verdict_counts:{PASS:0,FAIL:0,INCONCLUSIVE:1,ERROR:0}};
 const cases={...results,results:[
  {...results.results[0],testcase_id:'CASE-0',verdict:'INCONCLUSIVE'},
  ...[1,2].map(number=>({...results.results[number],status:'blocked',
   reason:'clean_baseline_not_confirmed'}))]};
 vi.spyOn(globalThis,'fetch').mockImplementation(async input=>{
  const path=String(input);
  return new Response(JSON.stringify(path.endsWith('/health')?health:path.endsWith('/events')?events:
   path.endsWith('/results')?cases:blocked));
 });
 render(<BatchProgress id={id}/>);
 expect(await screen.findByRole('heading',{name:'Batch partially completed'},{timeout:4000})).toBeInTheDocument();
 expect(screen.getAllByText(/Clean GH-C01 baseline was not confirmed/)).toHaveLength(2);
 expect(screen.getByText(/Selected 3 · Executed 1 · Blocked 2/)).toBeInTheDocument();
 expect(screen.getByRole('progressbar',{name:'Processed testcase progress'})).toHaveAttribute('value','3');
 expect(screen.getAllByText('INCONCLUSIVE')).toHaveLength(2);
});

it('shows per-case evaluation reasons and unsupported counts without a fabricated report',async()=>{
 const mixed={...status,status:'partially_completed',total:2,processed:2,
  progress_percent:100,remaining_count:0,aggregate_report_sha256:'a'.repeat(64),
  counts:{...status.counts,unsupported:1,cancelled:0},
  verdict_counts:{PASS:0,FAIL:1,INCONCLUSIVE:0,ERROR:0}};
 const cases={...results,snapshot:{...results.snapshot,cases:results.snapshot.cases.slice(0,2)},
  aggregate_report_sha256:'a'.repeat(64),results:[
   {...results.results[0],verdict:'FAIL',evaluation_reason:'Verified response rule matched.'},
   {...results.results[1],status:'unsupported',reason:'no_verified_runtime_binding'}]};
 vi.spyOn(globalThis,'fetch').mockImplementation(async input=>{
  const path=String(input);
  return new Response(JSON.stringify(path.endsWith('/health')?health:path.endsWith('/events')?events:
   path.endsWith('/results')?cases:mixed));
 });
 render(<BatchProgress id={id}/>);
 expect(await screen.findByRole('heading',{name:'Batch partially completed'},{timeout:4000})).toBeInTheDocument();
 expect(screen.getByText('Verified response rule matched.')).toBeInTheDocument();
 expect(screen.getByText('UNSUPPORTED')).toBeInTheDocument();
 expect(screen.getByText(/Aggregate batch report SHA-256/)).toBeInTheDocument();
 expect(screen.getAllByRole('link',{name:'View Report'})).toHaveLength(1);
});
