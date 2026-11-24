import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import {describe,expect,it,vi} from 'vitest';
import AgentOnboardingPanel from './AgentOnboardingPanel';
import BatchProgress from './BatchProgress';
import DatasetLibrary from './DatasetLibrary';
import DiscoveryPanel from './DiscoveryPanel';
import ExecutionDetail from './ExecutionDetail';
import {detail} from './test/detailFixtures';
import {hash} from './test/fixtures';
import type {DiscoveryResult,TargetPreset} from './testingApi';

const llmPreset:TargetPreset={
 id:'notes-llm',name:'Notes LLM Host',profile_revision:'1'.repeat(64),policy_ref:'local-v1',
 platform_id:'local-agent',platform_name:'Local Agent',authorization_status:'reviewed_for_offline_configuration',
 endpoint:'http://127.0.0.1:17490/v1/chat/completions',protocol:'openai-chat',method:'POST',
 models:['notes-model'],default_model:'notes-model',timeout_min:1,timeout_max:60,timeout_default:30,
 credential_alias:null,credential_availability:'none',request_mapping:'openai-chat-user-message-v1',
 response_parser:'choices.0.message.content',
 connection_probe:{status:'supported',reason:'reviewed_exact_endpoint',active_probe_authorized:true,security_execution_authorized:false},
 connection_verification:{status:'compatible',basis:'benign_chat_probe',profile_revision:'1'.repeat(64),security_execution_authorized:false},
 capabilities:['chat'],capability_basis:'operator_reviewed',limitations:[],
};

const mcpPreset:TargetPreset={
 id:'ops-notes-mcp',name:'Ops Notes MCP',profile_revision:'2'.repeat(64),policy_ref:'local-v1',
 platform_id:'local-agent',platform_name:'Local Agent',authorization_status:'reviewed_for_offline_configuration',
 endpoint:'http://127.0.0.1:17451/mcp',protocol:'mcp-jsonrpc',method:'POST',
 models:['mcp-service'],default_model:'mcp-service',timeout_min:1,timeout_max:60,timeout_default:30,
 credential_alias:null,credential_availability:'none',request_mapping:'mcp-tools-call-v1',
 response_parser:'mcp-jsonrpc-result-v1',
 connection_probe:{status:'supported',reason:'reviewed_exact_endpoint',active_probe_authorized:true,security_execution_authorized:false},
 capabilities:['tool_call'],capability_basis:'operator_reviewed',limitations:[],
};

const sampleDiscovery:DiscoveryResult&{workflow_schema_version:string}={
 workflow_schema_version:'1.0.0',
 discovery_id:'a'.repeat(32),
 input_url:'http://127.0.0.1:17451/mcp',
 canonical_endpoint:'http://127.0.0.1:17451/mcp',
 status:'metadata_found',
 connection_status:'reachable',
 request_count:1,
 request_budget:3,
 metadata_sources:[{url:'http://127.0.0.1:17451/mcp',status:'advertised',classification:'mcp_tools_list'}],
 protocol_candidates:[{id:'mcp-jsonrpc',classification:'observed_tools_list',source:'http://127.0.0.1:17451/mcp',runtime_verified:false}],
 advertised_models:[],
 advertised_agent:null,
 advertised_tools:[{name:'append_note',source:'http://127.0.0.1:17451/mcp',classification:'mcp_tools_list'}],
 advertised_skills:[],
 possible_contracts:[{request:'mcp-tools-call-v1',response:'mcp-jsonrpc-result-v1',classification:'tools_list_only_action_unverified'}],
 protocol_hint:'mcp-jsonrpc',
 unknown_fields:[],
 warnings:[],
 recommendations:[],
 proposed_profile:{id:'local-agent-17451',name:'Local AI Agent',platform_id:'local-agent',platform_name:'Local Agent',endpoint:'http://127.0.0.1:17451/mcp',protocol:'mcp-jsonrpc',model:'mcp-service',timeout_seconds:30},
 security_test_executed:false,
 security_verdict:null,
};

describe('Generic MCP Onboarding UI',()=>{
 it('renders discovered MCP schemas and compatibility badges in DiscoveryPanel',async()=>{
  vi.spyOn(globalThis,'fetch').mockImplementation(async input=>{
   const url=String(input);
   if(url.endsWith('/api/testing/discoveries')){
    return new Response(JSON.stringify(sampleDiscovery),{status:200});
   }
   if(url.endsWith(`/api/testing/discoveries/${'a'.repeat(32)}/mcp-tools`)){
    return new Response(JSON.stringify({
     workflow_schema_version:'1.0.0',
     discovery_id:'a'.repeat(32),
     source_endpoint:'http://127.0.0.1:17451/mcp',
     discovered_at:'2026-11-22T07:00:00Z',
     advertised_tool_manifest_sha256:'b'.repeat(64),
     tools:[
      {name:'append_note',description:'Append note safely',input_schema:{type:'object',properties:{path:{type:'string'}},required:['path'],additionalProperties:false},schema_sha256:'c'.repeat(64),schema_compatible:true,schema_error:null,source:'http://127.0.0.1:17451/mcp',classification:'mcp_tools_list'},
      {name:'bad_ref_tool',description:'Ref schema',input_schema:{type:'object',properties:{x:{$ref:'#/$defs/X'}}},schema_sha256:'d'.repeat(64),schema_compatible:false,schema_error:'unsupported_schema_keyword',source:'http://127.0.0.1:17451/mcp',classification:'mcp_tools_list'},
     ],
    }),{status:200});
   }
   return new Response('{}',{status:404});
  });

  render(<DiscoveryPanel nonce={'N'.repeat(43)} secret={'S'.repeat(32)} onReset={()=>{}} onUse={async()=>{}}/>);
  fireEvent.change(screen.getByLabelText('AI Agent URL'),{target:{value:'http://127.0.0.1:17451/mcp'}});
  fireEvent.click(screen.getByLabelText(/I authorize up to three bounded metadata requests/));
  fireEvent.click(screen.getByRole('button',{name:'Discover & Test Connection'}));

  expect(await screen.findByText('Discovered MCP Tools & Schemas (2)')).toBeInTheDocument();
  expect(screen.getByText('append_note')).toBeInTheDocument();
  expect(screen.getByText('Schema compatible')).toBeInTheDocument();
  expect(screen.getByText(/Incompatible \(unsupported_schema_keyword\)/)).toBeInTheDocument();
 });

 it('creates and reviews a Tool Catalog and Hosted MCP Agent Binding, then launches Hosted MCP Agent batch',async()=>{
  let catalogReviewed=false;
  let bindingReviewed=false;
  const previewPayloads:Record<string,unknown>[]=[];

  const catalogObj=()=>({
   catalog_id:'e'.repeat(32),catalog_version:'1.0.0',revision_sha256:'f'.repeat(64),
   review_status:catalogReviewed?'reviewed':'draft',reviewed_revision_sha256:catalogReviewed?'f'.repeat(64):null,
   catalog_ready:catalogReviewed,readiness_blockers:catalogReviewed?[]:['mcp_catalog_not_reviewed'],
   draft:{mcp_target_id:'ops-notes-mcp',discovery_id:null,catalog_name:'Notes Catalog',reviewed_tools:[{name:'append_note',description:'Append',input_schema:{type:'object',properties:{path:{type:'string'}},required:['path'],additionalProperties:false}}]},
   binding:{mcp_target_profile_revision:'2'.repeat(64),mcp_endpoint_sha256:'3'.repeat(64),discovery_id:null,tool_catalog_sha256:'4'.repeat(64),tool_names:['append_note']},
  });
  const bindingObj=()=>({
   binding_id:'5'.repeat(32),binding_version:'1.0.0',revision_sha256:'6'.repeat(64),
   review_status:bindingReviewed?'reviewed':'draft',reviewed_revision_sha256:bindingReviewed?'6'.repeat(64):null,
   runtime_binding_ready:bindingReviewed,readiness_blockers:bindingReviewed?[]:['mcp_agent_binding_not_reviewed'],
   draft:{llm_target_id:'notes-llm',mcp_target_id:'ops-notes-mcp',catalog_id:'e'.repeat(32),catalog_revision_sha256:'f'.repeat(64),model:'notes-model',system_prompt:'Sys',reviewed_tools:catalogObj().draft.reviewed_tools,max_model_calls:4,max_tool_calls:3},
   binding:{llm_target_profile_revision:'1'.repeat(64),mcp_target_profile_revision:'2'.repeat(64),llm_model:'notes-model',system_prompt_sha256:'7'.repeat(64),tool_catalog_sha256:'4'.repeat(64),case_request_budget:7},
  });

  let createdCat=false;
  let createdBind=false;
  vi.spyOn(globalThis,'fetch').mockImplementation(async(input,init)=>{
   const url=String(input);
   if(url.endsWith('/api/testing/mcp-catalogs')&&(!init?.method||init.method==='GET')){
    return new Response(JSON.stringify({workflow_schema_version:'1.0.0',catalogs:createdCat?[catalogObj()]:[]}),{status:200});
   }
   if(url.endsWith('/api/testing/mcp-catalogs/drafts')){
    createdCat=true;
    return new Response(JSON.stringify({workflow_schema_version:'1.0.0',catalog:catalogObj()}),{status:201});
   }
   if(url.endsWith(`/api/testing/mcp-catalogs/${'e'.repeat(32)}/review`)){
    catalogReviewed=true;
    return new Response(JSON.stringify({workflow_schema_version:'1.0.0',catalog:catalogObj()}),{status:200});
   }
   if(url.endsWith('/api/testing/agent-bindings')&&(!init?.method||init.method==='GET')){
    return new Response(JSON.stringify({workflow_schema_version:'1.0.0',bindings:createdBind?[bindingObj()]:[]}),{status:200});
   }
   if(url.endsWith('/api/testing/agent-bindings/drafts')){
    createdBind=true;
    return new Response(JSON.stringify({workflow_schema_version:'1.0.0',binding:bindingObj()}),{status:201});
   }
   if(url.endsWith(`/api/testing/agent-bindings/${'5'.repeat(32)}/review`)){
    bindingReviewed=true;
    return new Response(JSON.stringify({workflow_schema_version:'1.0.0',binding:bindingObj()}),{status:200});
   }
   if(url.endsWith('/api/testing/health')){
    return new Response(JSON.stringify({workflow_schema_version:'1.0.0',status:'ok',mode:'controlled_execution_enabled',target_network_access:true,validation_nonce:'N'.repeat(43),operator_mode:'local_single_user',evaluation_modes:['rule_only'],custom_imported_batch_enabled:true,imported_live_local_enabled:true}),{status:200});
   }
   if(url.endsWith('/api/testing/targets')){
    return new Response(JSON.stringify({workflow_schema_version:'1.0.0',targets:[llmPreset,mcpPreset],protocols:[]}),{status:200});
   }
   if(url.endsWith('/api/testing/datasets')){
    return new Response(JSON.stringify({workflow_schema_version:'1.0.0',datasets:[{dataset_id:'8'.repeat(32),name:'ops_notes.json',schema_version:'1.0.0',source_tool:'generic_json',imported_at:'2026-11-22T07:00:00Z',file_sha256:'9'.repeat(64),total_testcases:1}]}),{status:200});
   }
   if(url.endsWith(`/api/testing/datasets/${'8'.repeat(32)}`)){
    return new Response(JSON.stringify({workflow_schema_version:'1.0.0',dataset:{dataset_id:'8'.repeat(32),name:'ops_notes.json',schema_version:'1.0.0',source_tool:'generic_json',imported_at:'2026-11-22T07:00:00Z',file_sha256:'9'.repeat(64),total_testcases:1,source_metadata:{},testcases:[{testcase_id:'N-01',internal_id:'import-1',description:null,plugin_id:'custom',strategy_id:null,prompt:'Append note',prompt_sha256:'0'.repeat(64),assertions:[],metadata:{},options:{},extra:{},index:0}]}}),{status:200});
   }
   if(url.endsWith('/api/testing/batches/preview')){
    const body=JSON.parse(String(init?.body??'{}')) as Record<string,unknown>;
    previewPayloads.push(body);
    return new Response(JSON.stringify({workflow_schema_version:'1.0.0',plan_id:'a'.repeat(64),total:1,ready_count:1,transport_mode:'live_local_http',execution_mode:'custom_imported',items:[{testcase_id:'import-1',name:'N-01',asi_category:'ASI05',status:'ready',reason:null,asset_sha256:'b'.repeat(64),input_sha256:'c'.repeat(64),evaluation_readiness:'reviewed_asi05_execution_action',binding_id:'GENERIC-MCP-AGENT'}]}),{status:200});
   }
   return new Response('{}',{status:404});
  });

  const {unmount}=render(<AgentOnboardingPanel targets={[llmPreset,mcpPreset]} nonce={'N'.repeat(43)} secret=""/>);
  fireEvent.change(screen.getByLabelText('Tools JSON Array'),{target:{value:'[{"name":"append_note","description":"Append","input_schema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}}]'}});
  fireEvent.click(screen.getByRole('button',{name:'Save Catalog Draft'}));
  expect(await screen.findByRole('button',{name:'Review / Approve Tool Catalog'})).toBeInTheDocument();
  fireEvent.click(screen.getByLabelText(/I confirm this MCP Tool Catalog schema/));
  fireEvent.click(screen.getByRole('button',{name:'Review / Approve Tool Catalog'}));
  await waitFor(()=>expect(catalogReviewed).toBe(true));

  fireEvent.click(screen.getByRole('button',{name:'Save Agent Binding Draft'}));
  expect(await screen.findByRole('button',{name:'Review / Approve Agent Binding'})).toBeInTheDocument();
  fireEvent.click(screen.getByLabelText(/I confirm this Hosted MCP Agent runtime binding/));
  fireEvent.click(screen.getByRole('button',{name:'Review / Approve Agent Binding'}));
  await waitFor(()=>expect(bindingReviewed).toBe(true));
  unmount();

  render(<DatasetLibrary targets={[llmPreset,mcpPreset]} nonce={'N'.repeat(43)} secret=""/>);
  fireEvent.click(await screen.findByRole('button',{name:'Hosted MCP Agent assessment'}));
  fireEvent.click(await screen.findByRole('button',{name:'Inspect & Select'}));
  await waitFor(()=>expect(previewPayloads.length).toBeGreaterThan(0));
  expect(previewPayloads[0].execution_path).toBe('mcp_agent_runtime');
  expect((previewPayloads[0].mcp_target as Record<string,unknown>).target_id).toBe('ops-notes-mcp');
  expect(previewPayloads[0].total_request_budget).toBe(7);
 });

 it('renders distinct Hosted MCP Agent trace breakdown in BatchProgress and ExecutionDetail',async()=>{
  const batchId='a'.repeat(32);
  vi.spyOn(globalThis,'fetch').mockImplementation(async input=>{
   const url=String(input);
   if(url.endsWith('/api/testing/health')){
    return new Response(JSON.stringify({workflow_schema_version:'1.0.0',status:'ok',mode:'controlled_execution_enabled',target_network_access:true,validation_nonce:'N'.repeat(43),operator_mode:'local_single_user',evaluation_modes:['rule_only'],custom_imported_batch_enabled:true,imported_live_local_enabled:true}),{status:200});
   }
   if(url.endsWith(`/api/testing/batches/${batchId}`)){
    return new Response(JSON.stringify({workflow_schema_version:'1.0.0',batch_run_id:batchId,status:'completed',total:1,processed:1,progress_percent:100,remaining_count:0,target_request_count:1,request_budget_consumed:1,request_count_unknown:false,active_testcase_id:null,active_testcase_name:null,active_asi_category:null,current_stage:null,snapshot_sha256:'b'.repeat(64),counts:{completed:1,error:0,blocked:0,unsupported:0,skipped:0,cancelled:0},verdict_counts:{PASS:0,FAIL:0,INCONCLUSIVE:1,ERROR:0}}),{status:200});
   }
   if(url.endsWith(`/api/testing/batches/${batchId}/events`)){
    return new Response(JSON.stringify({workflow_schema_version:'1.0.0',batch_run_id:batchId,events:[]}),{status:200});
   }
   if(url.endsWith(`/api/testing/batches/${batchId}/results`)){
    return new Response(JSON.stringify({workflow_schema_version:'1.0.0',batch_run_id:batchId,snapshot:{target_id:'notes-llm',profile_revision:'1'.repeat(64),policy_ref:'local-v1',evaluation_mode:'rule_only',total_request_budget:7,imported_provenance:{dataset_id:'8'.repeat(32),dataset_revision_sha256:'9'.repeat(64),execution_path:'mcp_agent_runtime',mcp_target_id:'ops-notes-mcp',agent_binding_id:'5'.repeat(32),cases:[{internal_id:'import-1',source_testcase_id:'N-SCOPE',prompt_sha256:'0'.repeat(64)}]},cases:[{testcase_id:'import-1',name:'N-SCOPE',asi_category:'ASI05',asset_sha256:'c'.repeat(64),input_sha256:'d'.repeat(64),request_budget:7}]},results:[{testcase_id:'import-1',execution_id:'e'.repeat(32),status:'completed',verdict:'INCONCLUSIVE',request_count:1,report_run_id:'f'.repeat(32),report_sha256:'1'.repeat(64),response_captured:false,response_complete:true,evidence_provenance:'target_observation',reason:'secagent_execution_blocked',evaluation_reason:'SecAgent blocked unapproved tool call.'}]}),{status:200});
   }
   if(url.includes('/api/reports/runs/')){
    return new Response(JSON.stringify({
     ...detail,
     run_id:'f'.repeat(32),
     target_request_count:1,
     execution:{
      ...detail.execution,
      imported_provenance:{binding_id:'GENERIC-MCP-AGENT',target_composition:'hosted_mcp_agent',agent_host:'secagent_python_mcp_runtime',secagent_rejected_count:1,dispatched_action_count:0,target_rejected_count:0,trace_completeness:'partial'},
     },
    }),{status:200});
   }
   return new Response('{}',{status:404});
  });

  const {unmount}=render(<BatchProgress id={batchId}/>);
  expect(await screen.findByText(/HOSTED MCP AGENT ASSESSMENT/)).toBeInTheDocument();
  expect(await screen.findByText(/LLM proposed tool call; SecAgent blocked before dispatch/i)).toBeInTheDocument();
  unmount();

  render(<ExecutionDetail id={'f'.repeat(32)} snapshot={hash} onConnection={()=>{}} run={true}/>);
  expect(await screen.findByText('Hosted MCP Agent trace & action distinction')).toBeInTheDocument();
  expect(screen.getByText('SecAgent blocked before MCP dispatch')).toBeInTheDocument();
  expect(screen.getByText('No (SecAgent request observer + target-reported status only)')).toBeInTheDocument();
 });
});
