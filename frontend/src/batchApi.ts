import type {Draft} from './testingApi';

export const batchIdValid=(id:string)=>/^[a-f0-9]{32}$/.test(id);
const digestValid=(id:string)=>/^[a-f0-9]{64}$/.test(id);
const statuses=['preparing','running','completed','partially_completed','cancelled','failed','interrupted'] as const;
const caseStatuses=['completed','error','blocked','unsupported','skipped','cancelled'] as const;
const verdicts=['PASS','FAIL','INCONCLUSIVE','ERROR'] as const;
type BatchStatusName=typeof statuses[number];
type CaseStatusName=typeof caseStatuses[number];
type Verdict=typeof verdicts[number];
export type BatchSelection={target:Draft;testcase_ids:string[];total_request_budget:number;evaluation_mode:'rule_only'|'hybrid';workflow_id?:'asi01'|'imported';dataset_id?:string;transport_mode?:'offline_mock'|'live_local_http';asi_category?:'unclassified'|'ASI03'|'ASI05';execution_path?:'direct_chat'|'mcp_agent_runtime';mcp_target?:Draft};
export type BatchPreview={plan_id:string;total:number;ready_count:number;items:{testcase_id:string;name:string;asi_category:string;status:'ready'|'blocked'|'unsupported';reason?:string|null;asset_sha256:string;input_sha256:string;evaluation_readiness?:string;binding_id?:string}[];lab_image_sha256?:string;fixture_origin?:string;execution_mode?:string;dataset_id?:string;transport_mode?:'offline_mock'|'live_local_http';target_request_budget?:number};
export type BatchStatus={batch_run_id:string;status:BatchStatusName;total:number;processed:number;progress_percent:number;remaining_count:number;target_request_count:number;request_budget_consumed:number;request_count_unknown:boolean;active_testcase_id:string|null;active_testcase_name:string|null;active_asi_category:string|null;current_stage:string|null;aggregate_report_sha256?:string|null;counts:Record<CaseStatusName,number>;verdict_counts:Record<Verdict,number>};
export type BatchEvent={at:string;stage:string;testcase_id:string|null};
export type BatchCaseResult={testcase_id:string;execution_id:string|null;status:CaseStatusName;verdict:Verdict|null;request_count:number|null;report_run_id:string|null;report_sha256:string|null;response_captured:boolean|null;response_complete:boolean|null;evidence_provenance:string|null;reason?:string;evaluation_reason?:string|null};
export type BatchResults={snapshot:{imported_provenance?:{dataset_id:string;dataset_revision_sha256:string;transport_mode?:'offline_mock'|'live_local_http';evidence_provenance?:'synthetic_mock'|'target_observation';execution_path?:'direct_chat'|'mcp_agent_runtime';mcp_target_id?:string;agent_binding_id?:string;cases:{internal_id:string;source_testcase_id:string;prompt_sha256:string}[]};target_id:string;profile_revision:string;policy_ref:string;evaluation_mode:'rule_only'|'hybrid';total_request_budget:number;cases:{testcase_id:string;name:string;asi_category:string;asset_sha256:string;input_sha256:string;request_budget:number}[]};results:BatchCaseResult[];aggregate_report_sha256?:string|null};
export class BatchApiError extends Error{constructor(public code:string,public status:number,message?:string){super(message??code.replaceAll('_',' '));}}
function record(value:unknown):Record<string,unknown>{if(!value||typeof value!=='object'||Array.isArray(value))throw Error('Invalid batch response.');return value as Record<string,unknown>;}
function integer(value:unknown,min=0){if(!Number.isSafeInteger(value)||Number(value)<min)throw Error('Invalid batch response.');return Number(value);}
function envelope(value:unknown){const row=record(value);if(row.workflow_schema_version!=='1.0.0')throw Error('Invalid batch response.');return row;}
async function call(path:string,nonce:string,body?:unknown,signal?:AbortSignal){
 const response=await fetch(`/api/testing/${path}`,{method:body===undefined?'GET':'POST',credentials:'omit',cache:'no-store',
  signal:signal?AbortSignal.any([signal,AbortSignal.timeout(12000)]):AbortSignal.timeout(12000),
  headers:{'X-SecAgent-Validation':nonce,...(body===undefined?{}:{'Content-Type':'application/json'})},
  body:body===undefined?undefined:JSON.stringify(body)});
 const value=await response.json().catch(()=>null);
 if(!response.ok){const code=record(value??{}).error;
  const detail=code&&typeof code==='object'&&!Array.isArray(code)?code as Record<string,unknown>:{};
  const safe=typeof detail.code==='string'&&/^[a-z_]{1,80}$/.test(detail.code)?detail.code:`http_${response.status}`;
  const message=typeof detail.message==='string'&&detail.message.length<=240&&!/[\x00-\x1f\x7f]/.test(detail.message)?detail.message:undefined;
  throw new BatchApiError(safe,response.status,message);}
 return envelope(value);
}
function route(id:string,suffix=''){if(!batchIdValid(id))throw new BatchApiError('invalid_batch_id',400);return `batches/${id}${suffix}`;}
export const batchApi={
 preview:async(selection:BatchSelection,nonce:string,signal?:AbortSignal):Promise<BatchPreview>=>{
  const row=await call('batches/preview',nonce,selection,signal);
  if(!digestValid(String(row.plan_id))||!Array.isArray(row.items))throw Error('Invalid batch preview.');
  const items=row.items.map(value=>{const item=record(value);
   if(typeof item.testcase_id!=='string'||typeof item.name!=='string'||typeof item.asi_category!=='string'||
    !['ready','blocked','unsupported'].includes(String(item.status))||!digestValid(String(item.asset_sha256))||
    !digestValid(String(item.input_sha256)))throw Error('Invalid batch preview.');
   if(item.reason!==undefined&&item.reason!==null&&typeof item.reason!=='string')throw Error('Invalid batch preview.');
   return item as unknown as BatchPreview['items'][number];});
  if(integer(row.total)!==items.length||integer(row.ready_count)>items.length)throw Error('Invalid batch preview.');
  if(row.lab_image_sha256!==undefined&&(!digestValid(String(row.lab_image_sha256))||row.fixture_origin!=='http://172.30.79.3:8787'))throw Error('Invalid Web Lab preview.');
  if(row.transport_mode!==undefined&&!['offline_mock','live_local_http'].includes(String(row.transport_mode)))throw Error('Invalid transport mode.');
  if(row.target_request_budget!==undefined)integer(row.target_request_budget);
  return {plan_id:String(row.plan_id),total:items.length,ready_count:Number(row.ready_count),items,
   lab_image_sha256:row.lab_image_sha256 as string|undefined,fixture_origin:row.fixture_origin as string|undefined,
   execution_mode:row.execution_mode as string|undefined,dataset_id:row.dataset_id as string|undefined,
   transport_mode:row.transport_mode as BatchPreview['transport_mode'],target_request_budget:row.target_request_budget as number|undefined};
 },
 start:async(selection:BatchSelection,planId:string,submissionId:string,nonce:string)=>{
  if(!digestValid(planId)||!batchIdValid(submissionId))throw new BatchApiError('invalid_plan_or_submission',400);
  const row=await call('batches',nonce,{...selection,expected_plan_id:planId,submission_id:submissionId,authorization_confirmed:true});
  if(!batchIdValid(String(row.batch_run_id))||row.plan_id!==planId||row.progress_view!==`/api/testing/batches/${row.batch_run_id}`)throw Error('Invalid batch start response.');
  return String(row.batch_run_id);
 },
 status:async(id:string,nonce:string,signal?:AbortSignal):Promise<BatchStatus>=>{
  const row=await call(route(id),nonce,undefined,signal);
  if(row.batch_run_id!==id||!statuses.includes(row.status as BatchStatusName)||!digestValid(String(row.snapshot_sha256)))throw Error('Invalid batch status.');
  const total=integer(row.total,1),processed=integer(row.processed),percent=integer(row.progress_percent);
  if(processed>total||percent!==Math.floor(processed*100/total)||integer(row.remaining_count)!==total-processed||typeof row.request_count_unknown!=='boolean')throw Error('Invalid batch progress.');
  const counts=record(row.counts),verdictCounts=record(row.verdict_counts);
  if(row.aggregate_report_sha256!==undefined&&row.aggregate_report_sha256!==null&&!digestValid(String(row.aggregate_report_sha256)))throw Error('Invalid batch aggregate identity.');
  for(const name of caseStatuses)integer(counts[name]);for(const name of verdicts)integer(verdictCounts[name]);
  integer(row.target_request_count);integer(row.request_budget_consumed);
  for(const key of ['active_testcase_id','active_testcase_name','active_asi_category','current_stage'])
   if(row[key]!==null&&typeof row[key]!=='string')throw Error('Invalid batch status.');
  return row as unknown as BatchStatus;
 },
 events:async(id:string,nonce:string,signal?:AbortSignal):Promise<BatchEvent[]>=>{
  const row=await call(route(id,'/events'),nonce,undefined,signal);
  if(row.batch_run_id!==id||!Array.isArray(row.events)||row.events.length>2000)throw Error('Invalid batch events.');
  return row.events.map(value=>{const event=record(value);
   if(typeof event.at!=='string'||typeof event.stage!=='string'||!/^[a-z_]{1,40}$/.test(event.stage)||
    event.testcase_id!==null&&typeof event.testcase_id!=='string')throw Error('Invalid batch event.');
   return event as BatchEvent;});
 },
 results:async(id:string,nonce:string,signal?:AbortSignal):Promise<BatchResults>=>{
  const row=await call(route(id,'/results'),nonce,undefined,signal),snapshot=record(row.snapshot);
  if(row.batch_run_id!==id||!Array.isArray(snapshot.cases)||!Array.isArray(row.results)||row.results.length>snapshot.cases.length)throw Error('Invalid batch results.');
  if(row.aggregate_report_sha256!==undefined&&row.aggregate_report_sha256!==null&&!digestValid(String(row.aggregate_report_sha256)))throw Error('Invalid batch aggregate identity.');
  const cases=snapshot.cases.map(value=>{const item=record(value);if(typeof item.testcase_id!=='string'||typeof item.name!=='string'||typeof item.asi_category!=='string'||!digestValid(String(item.asset_sha256))||!digestValid(String(item.input_sha256)))throw Error('Invalid batch snapshot.');return item as BatchResults['snapshot']['cases'][number];});
  const ids=new Set(cases.map(item=>item.testcase_id));
  const results=row.results.map(value=>{const item=record(value);
   if(!ids.has(String(item.testcase_id))||!caseStatuses.includes(item.status as CaseStatusName)||
    item.verdict!==null&&!verdicts.includes(item.verdict as Verdict)||
    item.report_run_id!==null&&!batchIdValid(String(item.report_run_id))||
    item.report_sha256!==null&&!digestValid(String(item.report_sha256))||
    item.response_captured!==null&&typeof item.response_captured!=='boolean'||
    item.response_complete!==null&&typeof item.response_complete!=='boolean'||
    item.evidence_provenance!==null&&typeof item.evidence_provenance!=='string'||
    item.request_count!==null&&(!Number.isSafeInteger(item.request_count)||Number(item.request_count)<0)||
    item.evaluation_reason!==undefined&&item.evaluation_reason!==null&&(typeof item.evaluation_reason!=='string'||item.evaluation_reason.length>240))throw Error('Invalid batch case result.');
   return item as BatchCaseResult;});
  return {snapshot:snapshot as BatchResults['snapshot'],results,
   aggregate_report_sha256:row.aggregate_report_sha256 as string|null|undefined};
 },
 cancel:async(id:string,nonce:string)=>{
  const row=await call(route(id,'/cancel'),nonce,{});
  if(row.batch_run_id!==id||typeof row.cancellation_requested!=='boolean'||row.active_request_cancelled!==false)throw Error('Invalid cancellation response.');
  return {requested:row.cancellation_requested,active:row.active_testcase_id_at_request as string|null};
 },
};
