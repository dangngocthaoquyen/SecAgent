export type CapabilityState = 'supported'|'unsupported'|'unverified';
export type HttpInlineEvidenceMapping = {
  items: string;
  event_id?: string|null;
  action?: string|null;
  arguments?: string|null;
  decision?: string|null;
  status?: string|null;
  observation?: string|null;
  timestamp?: string|null;
  max_events?: number;
};
export type HttpResponseContract = {
  text_path: string;
  status_path?: string|null;
  complete_status_values?: string[];
  incomplete_status_values?: string[];
  correlation_id_path?: string|null;
  evidence_mapping?: HttpInlineEvidenceMapping|null;
};
export type HttpContractConfig = {
  method: 'POST';
  body_template: Record<string, unknown>;
  headers?: Record<string, string>;
  response: HttpResponseContract;
};
export type CapabilitySummary = {
  compatible_scopes: string[];
  unsupported_scopes: string[];
  unverified_scopes: string[];
  evidence_availability: string[];
  limitations: string[];
};
export type OpenApiRequiredFieldSpec = {
  name: string;
  type: string;
  location: string;
  enum?: (string|number|boolean)[];
};
export type OpenApiCandidate = {
  path: string;
  endpoint: string;
  method: 'POST';
  operation_id: string;
  summary: string;
  requires_auth: boolean;
  auth_status?: 'required'|'may_be_required'|'not_declared'|'unsupported';
  auth_schemes?: string[];
  auth_hints?: string[];
  auth_scheme_supported?: boolean;
  input_field: string;
  ambiguous_input_field?: boolean;
  extraction_incomplete?: boolean;
  unresolved_required_fields: string[];
  unresolved_required_field_specs?: OpenApiRequiredFieldSpec[];
  optional_field_specs?: { name: string; type: string; default?: unknown; enum?: (string|number|boolean)[] }[];
  unsupported_required_parameters?: { name: string; in: string }[];
  response_text_path_discovered: boolean;
  status_enum_values?: string[];
  mapping_provenance?: string;
  limitations?: string[];
  suggested_http_config: HttpContractConfig;
  classification: string;
  runtime_verified: false;
  operator_confirmed: false;
};
export type SessionAuthReference = {
  ref_id: string;
  auth_type: 'bearer'|'api_key';
  header_name: string;
};
export type SessionCredentialMetadata = {
  ref_id: string;
  scope_kind: 'target'|'discovery'|'draft';
  scope_id: string;
  bound_origin: string;
  auth_type: 'bearer'|'api_key';
  header_name: string;
  available: boolean;
  source: 'session_memory';
  generation: string;
  updated_at?: string;
};
export type TargetPreset = {
  id: string; name: string; profile_revision: string; policy_ref: string;
  platform_id?: string|null; platform_name?: string|null;
  authorization_status: 'review_required'|'reviewed_for_offline_configuration';
  endpoint: string; protocol: 'openai-chat'|'http-json'|'mcp-jsonrpc'; method: 'POST'; models: string[]; default_model: string;
  timeout_min: number; timeout_max: number; timeout_default: number;
  credential_alias: string|null; credential_availability: string;
  auth_source?: 'none'|'env_alias'|'session_memory';
  session_auth?: SessionAuthReference|null;
  request_mapping: 'openai-chat-user-message-v1'|'http-json-template-v1'|'mcp-tools-call-v1'; response_parser: string;
  http_config?: HttpContractConfig;
  capability_states?: Record<string, CapabilityState>;
  capability_provenance?: Record<string, string>;
  capability_summary?: CapabilitySummary;
  connection_probe: {status:'unsupported'|'supported'|'requires_confirmation';reason:string;active_probe_authorized:boolean;security_execution_authorized:false};
  connection_verification?: {status:'compatible'|'expired'|'stale'|'not_checked';basis:'benign_chat_probe';profile_revision:string;security_execution_authorized:false};
  reviewed_at?: string|null;
  platform_provenance?: 'seed_configured'|'discovery_suggested'|'operator_declared'|'legacy_unknown';
  capabilities: string[]; capability_basis: string; limitations: string[];
};
export type Draft = Pick<TargetPreset,'profile_revision'|'policy_ref'|'endpoint'|'protocol'|'method'|'request_mapping'|'response_parser'|'credential_alias'> & {target_id:string;model:string|null;timeout_seconds:number};
export type ValidationResult = {configuration_status:'valid'|'invalid';errors:string[];target_id:string;profile_revision:string;connection_reachable:null;runtime_protocol_compatible:null;target_execution_performed:false;security_verdict:null};
export type EvaluationMode = 'rule_only'|'hybrid';
export type Asi01TextTarget = {target_id:string;endpoint:string;model:string};
export type ManagedProfile = {id:string;name:string;platform_id:string;platform_name:string;endpoint:string;protocol:'openai-chat'|'http-json'|'mcp-jsonrpc';model:string|null;timeout_seconds:number;credential_alias?:string|null;session_auth?:SessionAuthReference|null;http_config?:HttpContractConfig|null;capability_states?:Record<string, CapabilityState>|null;capability_provenance?:Record<string, 'operator_declared'|'discovery_suggested'>|null};
export type PurgedTargetCounts = {application_contexts:number;discoveries:number;evidence_sources:number;policies_and_contracts:number;scan_runs:number};
export type DeleteTargetResult = {workflow_schema_version:'1.0.0';deleted_target_id:string;purged_counts:PurgedTargetCounts;active_targets:TargetPreset[]};
export type FieldProvenance = 'discovered_observed'|'suggested_unverified'|'operator_confirmed';
export type ApplicationContextDraft={target_id:string;target_revision:string;purpose:string;features:string;domain_industry?:string;operational_constraints?:string;available_tools:string;users:string;allowed_resources:string;prohibited_resources:string;authorized_actions?:string;sensitive_data_categories:string;protected_assets:string;high_risk_actions:string;data_handling_restrictions?:string;required_instructions:string;business_restrictions?:string;authorization_required:string;trust_boundaries:string;redteam_personas?:string;field_provenance?:Record<string,FieldProvenance>};
export type ApplicationContextRecord={schema_version:'1.0.0';provenance:'operator_declared';revision_sha256:string;updated_at:string;draft:ApplicationContextDraft};
export type ResponsePathSuggestion = {
  path: string;
  sample_type: string;
  source: string;
  confidence: string;
  ambiguous: boolean;
  limitation: string;
  observed_value?: string;
};
export type EvidenceMappingSuggestion = {
  items: string;
  items_observed: number;
  item_fields_observed: boolean;
  observed_item_keys?: string[];
  suggested_mapping: HttpInlineEvidenceMapping;
  ambiguous_fields?: string[];
  source: string;
  provenance: string;
  execution_verified: false;
  ambiguous: boolean;
  limitation: string;
};
export type ProbeMappingDiagnostics = {
  configured_text_path?: string|null;
  text_extracted?: boolean;
  configured_correlation_id_path?: string|null;
  observed_correlation_id?: string|null;
  configured_status_path?: string|null;
  observed_status_value?: string|null;
  configured_complete_status_values?: string[];
  configured_incomplete_status_values?: string[];
  response_complete?: boolean|null;
  completeness_unresolved?: boolean;
  inline_events_extracted?: number;
  evaluation_readiness_limitations?: string[];
  suggestions?: {
    text_path_candidates?: ResponsePathSuggestion[];
    text_path_ambiguous?: boolean;
    correlation_id_candidates?: ResponsePathSuggestion[];
    status_path_candidates?: ResponsePathSuggestion[];
    evidence_mapping_candidates?: EvidenceMappingSuggestion[];
  };
};
export type ProbeRequestPreview = {
  method: string;
  url: string;
  headers: Record<string, string>;
  body_preview: string;
};
export type ProbeResult = {
  connection_status:'succeeded'|'incompatible'|'unavailable'|'requires_approval'|'rejected'|'unsupported';
  reason:string;
  target_request_count:0|1;
  connection_reachable:boolean|null;
  runtime_protocol_compatible:boolean|null;
  http_status:number|null;
  diagnostic_category?:string|null;
  verification_state?:string|null;
  guidance?:string|null;
  request_preview?:ProbeRequestPreview|null;
  response_preview?:string|null;
  response_sample?:Record<string,unknown>|null;
  extracted_output?:string|null;
  mapping_diagnostics?:ProbeMappingDiagnostics|null;
  security_test_executed:false;
  security_verdict:null;
};
export type DiscoveryResult = {discovery_id:string;input_url:string;canonical_endpoint:string|null;status:string;request_count:number;request_budget:number;
 connection_status?:'reachable'|'unavailable';
 configuration_readiness?:'ready_for_review'|'incomplete_configuration'|'selection_required'|'manual_configuration_required'|'unsupported_authentication';
 exact_match_path?:string|null;
 metadata_sources:{url:string;status:string;classification:string}[];
 evidence_candidates?:{source_name:string;url:string;evidence_type:string;discovery_provenance:string;availability:string;verification_status:string;correlation_capability:string;required_authorization:string;limitations:string}[];
 protocol_candidates:{id:string;classification:string;source:string;runtime_verified:false}[];
 openapi_candidates?:OpenApiCandidate[];
 advertised_models:{id:string;source:string;classification:string}[];
 advertised_agent:{name:string;source:string;classification:string}|null;
 advertised_tools:{name:string;source:string;classification:string}[];
 advertised_skills:{name:string;source:string;classification:string}[];
 suggested_application_details?:{purpose:string;features:string;available_tools:string;field_provenance:Record<string,FieldProvenance>;operator_confirmed:boolean};
 possible_contracts:{request:string;response:string;classification:string}[];
 protocol_hint:string|null;
 unknown_fields:string[];warnings:string[];
 recommendations:{testcase_id:string;asi_category:string;status:'SUPPORTED'|'CONDITIONAL'|'UNSUPPORTED'|'UNKNOWN';reason:string;security_verdict:null}[];
 proposed_profile:ManagedProfile|null;security_test_executed:false;security_verdict:null};
export type DatasetSummary = {
 dataset_id: string; name: string; schema_version: string; source_tool: string;
 platform?: string|null; bot?: string|null; run_id?: string|null;
 imported_at: string; file_sha256: string; total_testcases: number;
 has_stored_responses?: boolean; supported_modes?: string[]; asi_breakdown?: Record<string, number>;
};
export type ImportedTestcase = {
 testcase_id: string; internal_id: string; description: string|null; plugin_id: string|null; strategy_id: string|null;
 prompt: string; prompt_sha256: string;
 assertions: Record<string, unknown>[]; metadata: Record<string, unknown>;
 options: Record<string, unknown>; extra: Record<string, unknown>; index: number;
};
export type DatasetEnvelope = DatasetSummary & {
 testcases: ImportedTestcase[]; source_metadata: Record<string, unknown>;
};
type Obj=Record<string,unknown>;
function obj(v:unknown):Obj{if(!v||typeof v!=='object'||Array.isArray(v))throw Error('contract');return v as Obj;}
function strings(v:unknown){if(!Array.isArray(v)||v.some(s=>typeof s!=='string'))throw Error('contract');}
function envelope(v:unknown){const o=obj(v);if(o.workflow_schema_version!=='1.0.0')throw Error('contract');return o;}
function textTargets(value:unknown):Asi01TextTarget[]{
 if(!Array.isArray(value)||value.length>10)throw Error('contract');
 return value.map(entry=>{const row=obj(entry);
  if(typeof row.target_id!=='string'||typeof row.endpoint!=='string'||typeof row.model!=='string'||
     !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(row.target_id)||
     !/^http:\/\/127\.0\.0\.1:\d{2,5}\/v1\/chat\/completions$/.test(row.endpoint)||
     !/^[A-Za-z0-9_.-]{1,128}$/.test(row.model))throw Error('contract');
  return {target_id:row.target_id,endpoint:row.endpoint,model:row.model};
 });
}
export function parseTargets(v:unknown):{targets:TargetPreset[];protocols:{id:string;state:string}[];credential_aliases?:string[];credential_alias_availability?:Record<string,'available'|'unavailable'>}{
 const o=envelope(v);if(!Array.isArray(o.targets)||!Array.isArray(o.protocols))throw Error('contract');
 if(o.credential_aliases!==undefined)strings(o.credential_aliases);
 const identities=new Set<string>(),platforms=new Map<string,string>();
 for(const t of o.targets){
  const p=obj(t),probe=obj(p.connection_probe);
  if(probe.security_execution_authorized!==false||
    !(probe.status==='unsupported'&&probe.active_probe_authorized===false&&['safe_probe_not_verified','operator_review_required'].includes(String(probe.reason))||
      probe.status==='supported'&&probe.active_probe_authorized===true&&probe.reason==='reviewed_exact_endpoint'&&p.authorization_status==='reviewed_for_offline_configuration'||
      probe.status==='requires_confirmation'&&probe.active_probe_authorized===false&&probe.reason==='authorization_confirmation_required'&&p.authorization_status==='review_required'))throw Error('contract');
  const url=new URL(String(p.endpoint));if(!["http:","https:"].includes(url.protocol)||url.username||url.password||url.search||url.hash)throw Error('contract');
  for(const k of ['id','name','profile_revision','policy_ref','endpoint','default_model','credential_availability','capability_basis'])if(typeof p[k]!=='string')throw Error('contract');
  const id=String(p.id);if(identities.has(id))throw Error('contract');identities.add(id);
  const platformId=p.platform_id??null,platformName=p.platform_name??null;
  if((platformId===null)!==(platformName===null))throw Error('contract');
  if(platformId!==null){
   if(typeof platformId!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(platformId)||typeof platformName!=='string'||!(/^[A-Za-z0-9 ._-]{1,80}$/.test(platformName)))throw Error('contract');
   if(platforms.has(platformId)&&platforms.get(platformId)!==platformName)throw Error('contract');platforms.set(platformId,platformName);
  }
  if(p.platform_provenance!==undefined&&!['seed_configured','discovery_suggested','operator_declared','legacy_unknown'].includes(String(p.platform_provenance)))throw Error('contract');
  if(!/^[a-f0-9]{64}$/.test(String(p.profile_revision))||p.method!=='POST'||!(p.protocol==='openai-chat'&&p.request_mapping==='openai-chat-user-message-v1'&&p.response_parser==='choices.0.message.content'||p.protocol==='http-json'&&p.request_mapping==='http-json-template-v1'&&typeof p.response_parser==='string'&&p.response_parser.length>0||p.protocol==='mcp-jsonrpc'&&p.request_mapping==='mcp-tools-call-v1'&&p.response_parser==='mcp-jsonrpc-result-v1'))throw Error('contract');
  if(!['review_required','reviewed_for_offline_configuration'].includes(String(p.authorization_status)))throw Error('contract');
  if(p.connection_verification!==undefined){const check=obj(p.connection_verification);
   if(!['compatible','expired','stale','not_checked'].includes(String(check.status))||check.basis!=='benign_chat_probe'||
    check.profile_revision!==p.profile_revision||check.security_execution_authorized!==false)throw Error('contract');}
  if(p.credential_alias!==null&&typeof p.credential_alias!=='string')throw Error('contract');
  if(p.session_auth!==undefined&&p.session_auth!==null){
   const sa=obj(p.session_auth);
   if(typeof sa.ref_id!=='string'||!/^sess_[a-f0-9]{24}$/.test(sa.ref_id)||!['bearer','api_key'].includes(String(sa.auth_type))||typeof sa.header_name!=='string')throw Error('contract');
  }
  for(const k of ['models','capabilities','limitations'])strings(p[k]);
  for(const k of ['timeout_min','timeout_max','timeout_default'])if(!Number.isSafeInteger(p[k])||Number(p[k])<1||Number(p[k])>600)throw Error('contract');
 }
 for(const p of o.protocols){if(typeof obj(p).id!=='string'||typeof obj(p).state!=='string')throw Error('contract');}return o as unknown as {targets:TargetPreset[];protocols:{id:string;state:string}[];credential_aliases?:string[];credential_alias_availability?:Record<string,'available'|'unavailable'>};
}
export function parseValidation(v:unknown):ValidationResult{const r=envelope(v);if(!['valid','invalid'].includes(String(r.configuration_status))||r.connection_reachable!==null||r.runtime_protocol_compatible!==null||r.target_execution_performed!==false||r.security_verdict!==null)throw Error('contract');strings(r.errors);if(typeof r.target_id!=='string'||typeof r.profile_revision!=='string'||(r.configuration_status==='valid'&&(r.errors as string[]).length))throw Error('contract');return r as unknown as ValidationResult;}
async function request<T>(route:string,parse:(v:unknown)=>T,signal:AbortSignal,body?:Draft,nonce?:string):Promise<T>{
 try{const r=await fetch(`/api/testing/${route}`,{method:body?'POST':'GET',credentials:'omit',cache:'no-store',signal:AbortSignal.any([signal,AbortSignal.timeout(10000)]),headers:body?{'Content-Type':'application/json','X-SecAgent-Validation':nonce!}:undefined,body:body?JSON.stringify(body):undefined});if(!r.ok)throw Error(`Workflow API rejected the request (HTTP ${r.status}). Reload the catalog and check the operator configuration. No target request was made.`);try{return parse(await r.json());}catch{throw Error('Workflow API returned an unsupported response. Configuration has not been validated.');}}
 catch(e){if(signal.aborted)throw e;if(e instanceof Error&&e.message.startsWith('Workflow API'))throw e;throw Error('Workflow API unavailable or timed out. Start the offline service on port 8092.');}
}
function parseProfile(v:unknown):TargetPreset{const o=envelope(v);return parseTargets({workflow_schema_version:'1.0.0',targets:[o.profile],protocols:[]}).targets[0];}
function parseProbe(v:unknown):ProbeResult{const o=envelope(v);if(!['succeeded','incompatible','unavailable','requires_approval','rejected','unsupported'].includes(String(o.connection_status))||
 ![0,1].includes(Number(o.target_request_count))||![null,true,false].includes(o.connection_reachable as null|boolean)||![null,true,false].includes(o.runtime_protocol_compatible as null|boolean)||o.security_test_executed!==false||o.security_verdict!==null||typeof o.reason!=='string')throw Error('contract');return o as unknown as ProbeResult;}
function parseDiscovery(v:unknown):DiscoveryResult{const o=envelope(v);
 if(typeof o.discovery_id!=='string'||!/^[a-f0-9]{32}$/.test(o.discovery_id)||
  typeof o.input_url!=='string'||!(o.canonical_endpoint===null||typeof o.canonical_endpoint==='string')||
  !Number.isSafeInteger(o.request_count)||Number(o.request_count)>3||o.request_budget!==3||
  !(o.connection_status===undefined||['reachable','unavailable'].includes(String(o.connection_status)))||
  !Array.isArray(o.metadata_sources)||o.metadata_sources.length!==o.request_count||
  !(o.evidence_candidates===undefined||Array.isArray(o.evidence_candidates)&&o.evidence_candidates.length<=20)||
  !Array.isArray(o.protocol_candidates)||!Array.isArray(o.advertised_models)||
  !Array.isArray(o.advertised_tools)||!Array.isArray(o.advertised_skills)||!Array.isArray(o.possible_contracts)||
  !Array.isArray(o.unknown_fields)||!Array.isArray(o.warnings)||!Array.isArray(o.recommendations)||
  o.security_test_executed!==false||o.security_verdict!==null)throw Error('contract');
 return o as unknown as DiscoveryResult;
}
async function adminRequest<T>(route:string,parse:(v:unknown)=>T,secret:string,nonce:string,body?:unknown,timeout=10000,extraHeaders?:Record<string,string>,rawBody?:Blob):Promise<T>{
 try{const r=await fetch(`/api/testing/${route}`,{method:body===undefined?'GET':'POST',credentials:'omit',cache:'no-store',signal:AbortSignal.timeout(timeout),
  headers:{...(secret?{'X-SecAgent-Operator':secret}:{}),...(nonce?{'X-SecAgent-Validation':nonce}:{}),...(body===undefined?{}:{'Content-Type':'application/json'}),...(extraHeaders||{})},body:rawBody??(body===undefined?undefined:JSON.stringify(body))});
  if(!r.ok){const value=await r.json().catch(()=>null);const message=value?.error?.message,code=value?.error?.code;
   const safeCode=typeof code==='string'&&/^[a-z0-9_]{1,80}$/.test(code)?` [${code}]`:'';
   throw Error(typeof message==='string'&&message.length<=240?`Workflow API${safeCode}: ${message}`:`Workflow API${safeCode} rejected the operator action (HTTP ${r.status}). Check authentication, profile revision and server readiness.`);}
  try{return parse(await r.json());}catch{throw Error('Workflow API returned an unsupported operator response.');}}
 catch(e){if(e instanceof Error&&e.message.startsWith('Workflow API'))throw e;throw Error('Workflow API unavailable or timed out.');}
}
export type Asi03ContractDraft={
 source_dataset_id:string;source_testcase_id:string;target_id:string;
 evaluation_scope:'identity_claim_response';legitimate_agent_identity:string;allowed_roles:string[];
 legitimate_user_goal:string;attacker_objective:string;prohibited_identity_claim:string|null;
 prohibited_authority_claim:string|null;attack_surface:string;delivery_surface:'direct_chat';
 required_evidence:['complete_response_text'];expected_security_boundary:string;
};
export type Asi03Contract={contract_id:string;revision_sha256:string;review_status:'draft'|'reviewed'|'stale';
 response_contract_ready:boolean;readiness_blockers:string[];draft:Asi03ContractDraft};
export type Asi03TargetPolicyDraft={target_id:string;legitimate_agent_identity:string;allowed_roles:string[];
 prohibited_identity_claim:string|null;prohibited_authority_claim:string|null;expected_security_boundary:string;
 evaluation_scope:'identity_claim_response';delivery_surface:'direct_chat'};
export type Asi03TargetPolicy={policy_id:string;revision_sha256:string;review_status:'draft'|'reviewed'|'stale';
 response_policy_ready:boolean;readiness_blockers:string[];draft:Asi03TargetPolicyDraft};
export type Asi05PolicyDraft={target_id:string;prohibited_command_behavior:string;allowed_benign_context:string;
 expected_response_boundary:string;evaluation_scope:'response_command_artifact';delivery_surface:'direct_chat'};
export type Asi05Policy={policy_id:string;revision_sha256:string;review_status:'draft'|'reviewed'|'stale';
 response_policy_ready:boolean;readiness_blockers:string[];draft:Asi05PolicyDraft};
export type EvidenceMapping={items:string;event_id?:string|null;request_id?:string|null;correlation_id?:string|null;invocation_id?:string|null;timestamp?:string|null;tool?:string|null;content?:string|null};
export type EvidenceSemantics='detector_reported'|'declared_tool_call'|'tool_handler_invoked'|'simulated_execution'|'runtime_execution_verified';
export type EvidenceSourceDraft={name:string;target_id:string;target_revision:string;source_type:'http_json';endpoint:string;credential_ref:string|null;collection_mode:'snapshot';mapping:EvidenceMapping;semantics:EvidenceSemantics;timeout_seconds:number;max_response_bytes:number;max_events:number;enabled:boolean};
export type EvidenceSource=EvidenceSourceDraft&{id:string;revision:string;schema_version:string;availability?:'not_checked'|'available'|'unavailable';correlation_status?:'uncorrelated';action_eligible?:false;configuration_status?:string;last_checked_at?:string|null;latest_capture_id?:string|null;collection_error?:string|null};
export type EvidenceCapture={id:string;source_id:string;source_revision:string;availability:'available'|'unavailable';error:string|null;action_eligible:false;correlation_status:'uncorrelated';request_count:number;events:unknown[];external_judge_disclosure:'forbidden'};
export type EvidenceSourceList={sources:EvidenceSource[];allowed_endpoints:{url:string;credential_ref:string|null}[]};
export type McpActionCase={testcase_id:string;asi_category:'ASI05';evaluation_scope:'execution_action';legitimate_objective:string;attacker_objective:string;target_id:string;tool_name:string;arguments_sha256:string;expected_evidence:string[];attribution:'tool_service/direct_request';policy_id:string;policy_revision_sha256:string;policy_status:'draft'|'reviewed';evidence_status:string;adapter_evidence_available:boolean;judge_status:string;official_verdict_eligible:boolean};
export type McpActionCatalog={catalog_sha256:string;cases:McpActionCase[];hybrid_configured:boolean};
export type McpActionResult={testcase_id:string;execution_id:string;target_id:string;profile_revision:string;catalog_sha256:string;target_request_count:number;evaluation_scope:'execution_action';attribution:'tool_service/direct_request';evidence_configuration:'request_only'|'configured_adapter';final_verdict:string;policy_status:string;semantic_invoked:boolean;report_path:string};
function evidenceSource(v:unknown):EvidenceSource{
 const o=obj(v);if(typeof o.id!=='string'||!/^[a-f0-9]{32}$/.test(o.id)||typeof o.revision!=='string'||!/^[a-f0-9]{64}$/.test(o.revision)||o.source_type!=='http_json'||o.collection_mode!=='snapshot'||typeof o.target_id!=='string'||typeof o.endpoint!=='string'||typeof o.name!=='string')throw Error('contract');return o as unknown as EvidenceSource;
}
export type McpCapabilityTool={name:string;description:string;input_schema:Record<string,unknown>|null;schema_sha256:string|null;schema_compatible:boolean;schema_error:string|null;source:string;classification:string};
export type McpCapabilityManifest={discovery_id:string;source_endpoint:string;discovered_at:string;advertised_tool_manifest_sha256:string;tools:McpCapabilityTool[]};
export type ReviewedToolSpec={name:string;description:string;input_schema:Record<string,unknown>};
export type McpToolCatalog={catalog_id:string;catalog_version:string;revision_sha256:string;review_status:'draft'|'reviewed'|'stale';reviewed_revision_sha256:string|null;catalog_ready:boolean;readiness_blockers:string[];draft:{mcp_target_id:string;discovery_id:string|null;catalog_name:string;reviewed_tools:ReviewedToolSpec[]};binding:{mcp_target_profile_revision:string;mcp_endpoint_sha256:string;discovery_id:string|null;tool_catalog_sha256:string;tool_names:string[]}};
export type EnvironmentAuthorizationScope={allowed_write_path_prefixes?:string[];write_scoped_tools?:string[];allowed_fetch_hosts?:string[];fetch_scoped_tools?:string[]};
export type ToolArgumentPredicate={schema_version?:'1.0';predicate_id:string;tool_name:string;argument_key:string;match_kind:'exact_string'|'exact_prefix'|'contains_shell_operator'|'command_binary_in'|'path_within_allowed_prefixes'|'path_outside_allowed_prefixes';values:string[];minimum_level?:'tool_invocation'|'simulated_execution'|'sandbox_effect'};
export type HostedMcpAgentBinding={binding_id:string;binding_version:string;revision_sha256:string;review_status:'draft'|'reviewed'|'stale';reviewed_revision_sha256:string|null;runtime_binding_ready:boolean;readiness_blockers:string[];draft:{llm_target_id:string;mcp_target_id:string;catalog_id?:string|null;catalog_revision_sha256?:string|null;model:string;system_prompt:string;reviewed_tools:ReviewedToolSpec[];environment_scope?:EnvironmentAuthorizationScope|null;max_model_calls:number;max_tool_calls:number;authorized_predicates?:ToolArgumentPredicate[];prohibited_predicates?:ToolArgumentPredicate[]};binding:{llm_target_profile_revision:string;mcp_target_profile_revision:string;llm_model:string;system_prompt_sha256:string;tool_catalog_sha256:string;case_request_budget:number;has_llm_credential?:boolean;has_mcp_credential?:boolean;catalog_id?:string;catalog_revision_sha256?:string}};
export type ResponsePolicyDraft={target_id:string;category:string;evaluation_scope:string;prohibited_behavior:string;allowed_benign_context:string;expected_response_boundary:string;delivery_surface?:string;extra_rules?:Record<string,unknown>};
export type ResponsePolicyRecord={policy_id:string;target_id:string;category:string;revision_sha256:string;evaluation_scope:string;review_status:'draft'|'reviewed';reviewed_by?:string|null;reviewed_at?:string|null;draft:ResponsePolicyDraft};
export type GenericRunCaseInput={case_id:string;category?:string;prompt:string;stored_response?:string;finish_reason?:string;required_capability?:string;tool_calls?:Record<string,unknown>[]};
export type GenericRunRequest={mode:'live'|'offline';target_id:string;asi_category?:string;use_judge:boolean;policy_id?:string|null;cases?:GenericRunCaseInput[];stored_payload?:unknown;dataset_id?:string;testcase_ids?:string[];capability_states?:Record<string,string>;evidence_sources?:Record<string,unknown>[];allowed_collector_roots?:string[];authorization_confirmed?:boolean;submission_id?:string;async_execution?:boolean;expected_target_revision?:string|null;expected_session_credential_generation?:string|null};
export type GenericPreviewItem={case_id:string;category:string;asi_code?:string;status:'ready'|'blocked'|'unsupported';reason:string|null;has_stored_response?:boolean;prompt_preview:string};
export type GenericSkippedCase={case_id:string;category:string;asi_code?:string;status:'blocked'|'unsupported';reason:string|null};
export type GenericJudgeStatus={judge_configured:boolean;credential_available:boolean;judge_ready:boolean;provider:string|null;model:string|null;reason:string};
export type GenericJudgeMetadata={mode:'rule_only'|'hybrid';judge_configured:boolean;credential_available:boolean;judge_ready:boolean;provider:string|null;model:string|null;invocation_status:'not_requested'|'running'|'succeeded'|'partial_failure'|'failed'|'not_invoked'|'unknown_unverified';request_count:number;success_count:number;failure_count:number;error_categories:string[]};
export type EvaluationIntegrityState='complete'|'degraded_technical_failures'|'partial_preflight_blocked'|'incomplete';
export type GenericEvaluationSummary={
 schema_version:string;
 policy_version:string;
 policy_statement?:string;
 total_cases:number;
 selected_cases?:number;
 processed_cases?:number;
 skipped_cases?:number;
 evaluated_cases:number;
 pass_count:number;
 fail_count:number;
 pass_rate?:number;
 pass_rate_percent?:number;
 fail_rate?:number;
 fail_rate_percent?:number;
 technical_failure_count?:number;
 technical_failure_reasons?:Record<string,number>;
 evidence_limitation_counts?:Record<string,number>;
 not_evaluated_count:number;
 evaluation_coverage:number;
 evaluation_coverage_percent:number;
 not_evaluated_reasons:Record<string,number>;
 evaluation_status_counts:Record<string,number>;
 cleanly_evaluated_cases?:number;
 clean_evaluation_coverage?:number;
 clean_evaluation_coverage_percent?:number;
 clean_pass_count?:number;
 clean_fail_count?:number;
 clean_pass_rate_percent?:number|null;
 degraded_pass_count?:number;
 degraded_fail_count?:number;
 evaluation_integrity_state?:EvaluationIntegrityState;
 legacy_inconclusive_count?:number;
 legacy_error_count?:number;
};
export type GenericTargetReservation={target_id:string;owner_kind:string;workflow_id?:string|null;run_id?:string|null;reserved_at?:string|null};
export type GenericCaseStatus={case_id:string;category:string;asi_code?:string;status:'queued'|'running'|'completed'|'error'|'unsupported'|'blocked'|'cancelled';stage:string;verdict:string|null;evaluation_status?:string|null;evaluation_reason_code?:string|null;reason:string|null;http_status_code?:number|null;duration_ms?:number|null;evidence_level:string|null;run_id:string|null;source_generic_run_id?:string|null;session_index?:number|null};
export type GenericRunEvent={at:string;stage:string;case_id:string|null;verdict?:string|null;evaluation_status?:string|null};
export type GenericRunPreview={workflow_schema_version:'1.0.0';mode:'live'|'offline';target_id:string;target_name:string;target_revision_sha256?:string|null;auth_source?:'none'|'env_alias'|'session_memory';session_credential_generation?:string|null;session_auth_type?:'bearer'|'api_key'|null;session_auth_header?:string|null;dataset_id?:string|null;dataset_name?:string|null;asi_category:string;use_judge:boolean;pi_judge_ready:boolean;judge_status?:GenericJudgeStatus;capability_states:Record<string,string>;capability_summary?:CapabilitySummary;evidence_source_count:number;active_evidence_source_count?:number;configured_evidence_source_count?:number;active_target_reservation?:GenericTargetReservation|null;selected_cases?:number;executed_cases?:number;total_cases?:number;asi_breakdown?:Record<string,number>;has_stored_responses?:boolean;available_modes?:('live'|'offline')[];ready_count:number;blocked_count:number;unsupported_count:number;skipped_count?:number;skipped_cases?:GenericSkippedCase[];target_request_budget?:number;judge_request_budget?:number;policy_id:string|null;policy_revision_sha256:string|null;policy_review_status:string;blocker:string|null;items:GenericPreviewItem[]};
export type GenericCollectorDiagnostic={collector_id:string;collector_kind:string;status:string;matched_count:number;uncorrelated_count:number;reason:string};
export type GenericEvidenceItem={kind:string;source:string;name?:string|null;data?:Record<string,unknown>};
export type GenericRunCaseResult={case_id:string;run_id:string;category:string;prompt:string;response_text:string|null;response_complete:boolean|null;verdict:string|null;evaluation_status?:string|null;evaluation_reason_code?:string|null;evidence_limitations?:string[];verdict_schema_version?:string|null;verdict_policy_version?:string|null;reason:string;judge_reason:string|null;judge_classification:string|null;semantic_invoked?:boolean;provider_fault_code?:string|null;json_validation_status?:string|null;provider_duration_ms?:number|null;evidence_level:string|null;provenance_tiers:string[];execution_status:string;http_status_code?:number|null;duration_ms?:number|null;collector_diagnostics:GenericCollectorDiagnostic[];evidence:GenericEvidenceItem[];report_path:string;source_generic_run_id?:string|null;session_index?:number|null};
export type LogicalScanStatus='preparing'|'running'|'completed'|'completed_with_errors'|'interrupted'|'failed'|'cancelled';
export type GenericRunSessionSummary={session_index:number;generic_run_id:string;continuation_of_run_id?:string|null;status:'preparing'|'running'|'completed'|'failed'|'interrupted'|'cancelled';started_at?:string|null;completed_at?:string|null;selected_cases:number;ready_count:number;executed_cases:number;verdict_counts:Record<string,number>;target_requests_used?:number|null;target_request_budget?:number|null;judge_requests_used?:number|null;judge_request_budget?:number|null;judge_metadata?:GenericJudgeMetadata|null;error_code?:string|null;interrupted_reason?:string|null};
export type GenericRunLineageSummary={root_run_id:string;parent_run_id:string|null;child_run_ids:string[];lineage_run_ids:string[];latest_run_id?:string;active_lineage_run_id:string|null;resumable_run_id?:string|null;logical_status?:LogicalScanStatus;integrity_status?:'valid'|'invalid_checkpoint';integrity_warning?:string|null;session_count?:number;resume_count?:number;started_at?:string|null;completed_at?:string|null;original_selected_cases:number;ready_count?:number;skipped_count?:number;lineage_completed_count:number;lineage_verdict_counts:Record<string,number>;remaining_pending_count:number;remaining_uncertain_count:number;has_resumable_work:boolean};
export type GenericRunUnifiedLineage={logical_scan_id:string;root_run_id:string;latest_run_id:string;active_session_run_id:string|null;resumable_run_id:string|null;logical_status:LogicalScanStatus;integrity_status?:'valid'|'invalid_checkpoint';integrity_warning?:string|null;out_of_scope_case_ids?:string[];execution_completed:boolean;has_evaluation_errors:boolean;verdict_schema_version?:string|null;verdict_policy_version?:string|null;started_at?:string|null;completed_at?:string|null;session_count:number;resume_count:number;selected_cases:number;ready_count:number;executed_cases:number;skipped_count:number;skipped_cases:GenericSkippedCase[];progress_percent:number;verdict_counts:Record<string,number>;evaluation_summary?:GenericEvaluationSummary|null;evidence_summary:Record<string,number>;judge_metadata?:GenericJudgeMetadata|null;target_requests_used:number|null;judge_requests_used:number|null;current_case_id?:string|null;current_stage?:string|null;active_session_started_at?:string|null;active_session_target_requests_used?:number|null;active_session_target_request_budget?:number|null;active_session_judge_requests_used?:number|null;active_session_judge_request_budget?:number|null;active_session_events?:GenericRunEvent[];sessions:GenericRunSessionSummary[];case_statuses:GenericCaseStatus[];cases:GenericRunCaseResult[]};
export type GenericRunResumeMetadata={parent_run_id:string;root_run_id:string;original_selected_cases:number;preserved_completed_case_ids:string[];resumed_pending_case_ids:string[];uncertain_case_ids:string[];included_uncertain_case_ids:string[];excluded_uncertain_case_ids:string[];skipped_case_ids:string[];selected_resume_case_ids:string[];resume_digest:string;stateful_target_acknowledged?:boolean;uncertain_reexecution_confirmed?:boolean};
export type GenericResumeCompletedSummary={case_id:string;verdict:string|null;evaluation_status?:string|null;evaluation_reason_code?:string|null;run_id:string|null;generic_run_id:string;report_path?:string|null;category?:string|null};
export type GenericResumePreview={workflow_schema_version:'1.0.0';parent_run_id:string;root_run_id:string;parent_status:string;original_selected_cases:number;completed_count:number;completed_case_ids:string[];completed_cases_summary:GenericResumeCompletedSummary[];pending_case_ids:string[];uncertain_case_ids:string[];included_uncertain_case_ids:string[];skipped_case_ids:string[];selected_resume_case_ids:string[];target_id:string;target_name:string;target_revision_sha256:string|null;target_ready:boolean;auth_source:'none'|'env_alias'|'session_memory';credential_availability:'available'|'unavailable'|'not_required';session_credential_generation:string|null;session_auth_type:'bearer'|'api_key'|null;session_auth_header:string|null;dataset_id:string|null;dataset_name:string|null;dataset_consistent:boolean;config_consistent:boolean;mode:'live'|'offline';asi_category:string;use_judge:boolean;original_judge_provider?:string|null;original_judge_model?:string|null;current_judge_provider?:string|null;current_judge_model?:string|null;judge_status:GenericJudgeStatus;target_request_budget:number;judge_request_budget:number;resume_digest:string;eligible:boolean;blocker:string|null;blockers:string[];warnings:string[]};
export type GenericResumeStartRequest={authorization_confirmed:true;expected_resume_digest:string;include_uncertain_case_ids?:string[];uncertain_reexecution_confirmed?:boolean;stateful_target_acknowledged?:boolean;expected_target_revision?:string|null;expected_session_credential_generation?:string|null;submission_id?:string;async_execution?:boolean};
export type GenericRunRecord={workflow_schema_version:'1.0.0';verdict_schema_version?:string|null;verdict_policy_version?:string|null;generic_run_id:string;workflow_id?:string|null;submission_id?:string|null;status?:'preparing'|'running'|'completed'|'failed'|'interrupted'|'cancelled';cancellation_requested?:boolean;cancellation_requested_at?:string|null;cancelled_at?:string|null;cancel_outcome?:string;error_code?:string|null;interrupted_reason?:string|null;started_at?:string|null;completed_at?:string|null;mode:'live'|'offline';target_id:string;target_name:string;dataset_id?:string|null;dataset_name?:string|null;asi_category:string;use_judge:boolean;policy_id:string|null;policy_revision_sha256:string|null;capability_states:Record<string,string>;selected_cases?:number;ready_count?:number;executed_cases?:number;total_cases:number;skipped_count?:number;skipped_cases?:GenericSkippedCase[];progress_percent?:number;current_case_id?:string|null;current_stage?:string|null;target_request_budget?:number;target_requests_used?:number;judge_request_budget?:number;judge_requests_used?:number;verdict_counts:Record<string,number>;evaluation_summary?:GenericEvaluationSummary|null;evidence_summary?:Record<string,number>;judge_metadata?:GenericJudgeMetadata;case_statuses?:GenericCaseStatus[];events?:GenericRunEvent[];cases:GenericRunCaseResult[];continuation_of_run_id?:string|null;root_run_id?:string|null;resume_metadata?:GenericRunResumeMetadata|null;child_run_ids?:string[];lineage_summary?:GenericRunLineageSummary|null;unified_lineage?:GenericRunUnifiedLineage|null};
export type GenericRunSummary={generic_run_id:string;workflow_id?:string|null;verdict_schema_version?:string|null;verdict_policy_version?:string|null;status:'preparing'|'running'|'completed'|'failed'|'interrupted'|'cancelled';cancellation_requested?:boolean;cancellation_requested_at?:string|null;cancelled_at?:string|null;started_at?:string|null;completed_at?:string|null;mode:'live'|'offline';target_id:string;target_name:string;dataset_id?:string|null;dataset_name?:string|null;asi_category:string;asi_categories?:string[];testcase_ids?:string[];use_judge:boolean;selected_cases:number;ready_count:number;executed_cases:number;total_cases:number;skipped_count:number;progress_percent:number;verdict_counts:Record<string,number>;evaluation_summary?:GenericEvaluationSummary|null;evidence_summary?:Record<string,number>;judge_metadata?:GenericJudgeMetadata;case_run_ids?:string[];continuation_of_run_id?:string|null;root_run_id?:string|null;child_run_ids?:string[];lineage_summary?:GenericRunLineageSummary|null};

export type ScanHandoffSelection={dataset_id?:string;target_id?:string;testcase_ids?:string[];source?:'ai_generate'|'existing_dataset'|'import_dataset'};
let pendingScanHandoff:ScanHandoffSelection|null=null;
let ephemeralOperatorSecret='';
export function setEphemeralOperatorSecret(secret:string):void{
 ephemeralOperatorSecret=secret;
}
export function getEphemeralOperatorSecret():string{
 return ephemeralOperatorSecret;
}
export type PendingScanSubmission={
 submission_id:string;
 target_id:string;
 target_name:string;
 dataset_id:string;
 dataset_name:string;
 mode:'live'|'offline';
 use_judge:boolean;
 ready_count:number;
 saved_at:string;
};
const PENDING_SUBMISSION_KEY='secagent_pending_generic_submission';
export function savePendingScanSubmission(sub:PendingScanSubmission):void{
 try{sessionStorage.setItem(PENDING_SUBMISSION_KEY,JSON.stringify(sub));}catch{}
}
export function loadPendingScanSubmission():PendingScanSubmission|null{
 try{
  const raw=sessionStorage.getItem(PENDING_SUBMISSION_KEY);
  if(!raw)return null;
  const parsed=JSON.parse(raw) as PendingScanSubmission;
  if(parsed&&typeof parsed.submission_id==='string'&&/^[a-f0-9]{32}$/.test(parsed.submission_id)){
   return parsed;
  }
 }catch{}
 return null;
}
export function clearPendingScanSubmission():void{
 try{sessionStorage.removeItem(PENDING_SUBMISSION_KEY);}catch{}
}
export function saveScanHandoff(selection:ScanHandoffSelection):void{
 pendingScanHandoff=selection;
 try{sessionStorage.setItem('secagent_scan_handoff',JSON.stringify(selection));}catch{}
}
export function consumeScanHandoff():ScanHandoffSelection|null{
 const mem=pendingScanHandoff;
 pendingScanHandoff=null;
 try{
  const raw=sessionStorage.getItem('secagent_scan_handoff');
  sessionStorage.removeItem('secagent_scan_handoff');
  if(mem)return mem;
  if(raw){
   const parsed=JSON.parse(raw) as ScanHandoffSelection;
   if(parsed&&typeof parsed.dataset_id==='string')return parsed;
  }
 }catch{}
 return mem;
}
export const testingApi={
 listMcpActions:(secret:string,nonce:string)=>adminRequest('mcp-actions',v=>{const o=envelope(v);if(!/^[a-f0-9]{64}$/.test(String(o.catalog_sha256))||!Array.isArray(o.cases)||typeof o.hybrid_configured!=='boolean')throw Error('contract');return o as unknown as McpActionCatalog;},secret,nonce),
 runMcpAction:(request:{testcase_id:string;target_id:string;profile_revision:string;catalog_sha256:string;evaluation_mode:'rule_only'|'hybrid';evidence_configuration:'request_only'|'configured_adapter';authorization_confirmed:true},secret:string,nonce:string)=>adminRequest('mcp-actions/run',v=>{const o=envelope(v),r=obj(o.result);if(r.testcase_id!==request.testcase_id||r.target_id!==request.target_id||r.profile_revision!==request.profile_revision||r.catalog_sha256!==request.catalog_sha256||r.attribution!=='tool_service/direct_request'||r.evaluation_scope!=='execution_action'||r.evidence_configuration!==request.evidence_configuration||![0,1].includes(Number(r.target_request_count))||!['PASS','FAIL','INCONCLUSIVE','ERROR'].includes(String(r.final_verdict)))throw Error('contract');return r as unknown as McpActionResult;},secret,nonce,request,70000),
 getApplicationContext:(targetId:string,secret:string,nonce:string)=>adminRequest(`application-contexts/target/${encodeURIComponent(targetId)}`,v=>{const o=envelope(v);if(!['current','stale'].includes(String(o.binding_status)))throw Error('contract');const row=o.context===null?null:obj(o.context);if(row&&(row.provenance!=='operator_declared'||row.schema_version!=='1.0.0'||typeof row.revision_sha256!=='string'||!(/^[a-f0-9]{64}$/.test(row.revision_sha256))||obj(row.draft).target_id!==targetId))throw Error('contract');return {context:row as ApplicationContextRecord|null,binding_status:o.binding_status as 'current'|'stale'};},secret,nonce),
 saveApplicationContext:(draft:ApplicationContextDraft,expectedRevision:string|null,secret:string,nonce:string)=>adminRequest('application-contexts/save',v=>{const o=envelope(v),row=obj(o.context);if(row.provenance!=='operator_declared'||row.schema_version!=='1.0.0'||obj(row.draft).target_id!==draft.target_id||obj(row.draft).target_revision!==draft.target_revision||o.binding_status!=='current')throw Error('contract');return row as ApplicationContextRecord;},secret,nonce,{draft,expected_revision:expectedRevision,safe_description_confirmed:true}),
 listEvidenceSources:(targetId:string,secret:string,nonce:string)=>adminRequest(`evidence-sources/target/${encodeURIComponent(targetId)}`,v=>{const o=envelope(v);if(!Array.isArray(o.sources)||!Array.isArray(o.allowed_endpoints)||o.action_verification_supported!==false)throw Error('contract');return {sources:o.sources.map(v=>{const source=evidenceSource(v);if(source.target_id!==targetId)throw Error('contract');return source;}),allowed_endpoints:o.allowed_endpoints.map(p=>{const r=obj(p);if(typeof r.url!=='string'||(r.credential_ref!==null&&typeof r.credential_ref!=='string'))throw Error('contract');return {url:r.url,credential_ref:r.credential_ref as string|null};})};},secret,nonce),
 saveEvidenceSource:(profile:EvidenceSourceDraft,sourceId:string|null,revision:string|null,secret:string,nonce:string)=>adminRequest('evidence-sources/save',v=>{const source=evidenceSource(envelope(v).source);if(source.target_id!==profile.target_id||source.target_revision!==profile.target_revision||(sourceId!==null&&source.id!==sourceId))throw Error('contract');return source;},secret,nonce,{profile,source_id:sourceId,expected_revision:revision}),
 collectEvidenceSource:(sourceId:string,revision:string,secret:string,nonce:string)=>adminRequest('evidence-sources/collect',v=>{const c=obj(envelope(v).capture);if(c.source_id!==sourceId||c.source_revision!==revision||c.action_eligible!==false||c.correlation_status!=='uncorrelated'||c.external_judge_disclosure!=='forbidden'||!['available','unavailable'].includes(String(c.availability))||!Array.isArray(c.events))throw Error('contract');return c as unknown as EvidenceCapture;},secret,nonce,{source_id:sourceId,expected_revision:revision,authorization_confirmed:true},25000),
 health:(signal:AbortSignal)=>request('health',v=>{const h=envelope(v);if(h.status!=='ok'||!['offline_configuration_only','controlled_execution_enabled'].includes(String(h.mode))||h.target_network_access!==(h.mode==='controlled_execution_enabled'&&h.toolbot_lab_batch_enabled!==true&&(h.custom_imported_batch_enabled!==true||(h.imported_live_local_enabled===true&&h.imported_live_local_mocked!==true)))||typeof h.validation_nonce!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(h.validation_nonce)||!['local_single_user','authenticated',undefined].includes(h.operator_mode as string|undefined)||![true,false,undefined].includes(h.offline_batch_enabled as boolean|undefined)||![true,false,undefined].includes(h.asi01_batch_enabled as boolean|undefined)||![true,false,undefined].includes(h.web_lab_batch_enabled as boolean|undefined)||![true,false,undefined].includes(h.toolbot_lab_batch_enabled as boolean|undefined)||![true,false,undefined].includes(h.custom_imported_batch_enabled as boolean|undefined)||![true,false,undefined].includes(h.imported_live_local_enabled as boolean|undefined)||![true,false,undefined].includes(h.imported_live_local_mocked as boolean|undefined)||(h.imported_live_local_mocked===true&&h.imported_live_local_enabled!==true)||(h.imported_live_local_enabled===true&&h.custom_imported_batch_enabled!==true)||([h.offline_batch_enabled,h.asi01_batch_enabled,h.web_lab_batch_enabled,h.toolbot_lab_batch_enabled,h.custom_imported_batch_enabled].filter(Boolean).length>1&&!(h.asi01_batch_enabled===true&&h.custom_imported_batch_enabled===true&&h.offline_batch_enabled!==true&&h.web_lab_batch_enabled!==true&&h.toolbot_lab_batch_enabled!==true)))throw Error('contract');const modes=h.evaluation_modes??['rule_only'];if(!Array.isArray(modes)||modes.length<1||modes.length>2||modes[0]!=='rule_only'||(modes.length===2&&modes[1]!=='hybrid')||(modes.length===2&&h.judge_configuration!=='configured_unverified'))throw Error('contract');const targets=textTargets(h.asi01_text_targets??[]);if(!h.asi01_batch_enabled&&targets.length)throw Error('contract');return {...({evidenceSourcesEnabled:h.evidence_sources_enabled===true,genericRunnerEnabled:h.generic_runner_enabled===true,piJudgeReady:h.pi_judge_ready===true,judgeStatus:(h.judge_status??undefined) as GenericJudgeStatus|undefined} as {evidenceSourcesEnabled?:boolean;genericRunnerEnabled?:boolean;piJudgeReady?:boolean;judgeStatus?:GenericJudgeStatus}),nonce:h.validation_nonce as string,evaluationModes:modes as EvaluationMode[],managementEnabled:h.target_management_enabled===true,controlledRunsEnabled:h.mode==='controlled_execution_enabled',localSingleUser:h.operator_mode==='local_single_user',offlineBatchEnabled:h.offline_batch_enabled===true,asi01BatchEnabled:h.asi01_batch_enabled===true,asi01TextTargets:targets,webLabBatchEnabled:h.web_lab_batch_enabled===true,toolbotLabBatchEnabled:h.toolbot_lab_batch_enabled===true,customImportedBatchEnabled:h.custom_imported_batch_enabled===true,importedLiveLocalEnabled:h.imported_live_local_enabled===true,importedLiveLocalMocked:h.imported_live_local_mocked===true,judgeSetupReason:typeof h.judge_setup_reason==='string'?h.judge_setup_reason:'judge_configuration_missing',mcpActionSetupReason:typeof h.mcp_action_setup_reason==='string'?h.mcp_action_setup_reason:'catalog_missing'};},signal),
 targets:(signal:AbortSignal)=>request('targets',parseTargets,signal),
 validate:(draft:Draft,nonce:string,signal:AbortSignal)=>request('target-drafts/validate',parseValidation,signal,draft,nonce),
 unlock:(secret:string,nonce:string)=>adminRequest('managed-targets',v=>{const o=envelope(v);return parseTargets({workflow_schema_version:'1.0.0',targets:o.targets,protocols:[]}).targets;},secret,nonce),
 validateManaged:(profile:ManagedProfile,expected:string|null,secret:string,nonce:string,discoveryId?:string)=>adminRequest('managed-targets/validate',v=>{const o=envelope(v);if(o.configuration_status!=='valid'||o.target_request_count!==0||o.target_execution_performed!==false)throw Error('contract');return true;},secret,nonce,{profile,expected_profile_revision:expected,...(discoveryId?{discovery_id:discoveryId}:{})}),
 saveManaged:(profile:ManagedProfile,expected:string|null,secret:string,nonce:string,discoveryId?:string,platformChangeConfirmed=false)=>adminRequest(`managed-targets/${expected?'update':'create'}`,parseProfile,secret,nonce,{profile,expected_profile_revision:expected,...(discoveryId?{discovery_id:discoveryId}:{}),platform_change_confirmed:platformChangeConfirmed}),
 deleteTarget:(target:{target_id:string;profile_revision:string},secret:string,nonce:string)=>adminRequest('managed-targets/delete',v=>{const o=envelope(v);if(o.deleted_target_id!==target.target_id||!Array.isArray(o.active_targets))throw Error('contract');const counts=obj(o.purged_counts);for(const k of ['application_contexts','discoveries','evidence_sources','policies_and_contracts','scan_runs'])if(!Number.isSafeInteger(counts[k])||Number(counts[k])<0)throw Error('contract');const activeTargets=parseTargets({workflow_schema_version:'1.0.0',targets:o.active_targets,protocols:[]}).targets;if(activeTargets.some(t=>t.id===target.target_id))throw Error('contract');return {workflow_schema_version:'1.0.0' as const,deleted_target_id:o.deleted_target_id as string,purged_counts:counts as unknown as PurgedTargetCounts,active_targets:activeTargets};},secret,nonce,{target_id:target.target_id,profile_revision:target.profile_revision,delete_confirmed:true},30000),
 setSessionCredential:(req:{scope_kind:'target'|'discovery'|'draft';scope_id:string;endpoint:string;auth_type:'bearer'|'api_key';header_name?:string;secret_value:string;ref_id?:string},secret:string,nonce:string)=>adminRequest('managed-targets/session-credentials',v=>{const o=envelope(v),c=obj(o.credential);if(typeof c.ref_id!=='string'||!/^sess_[a-f0-9]{24}$/.test(c.ref_id)||!['bearer','api_key'].includes(String(c.auth_type))||typeof c.header_name!=='string'||c.source!=='session_memory'||c.available!==true)throw Error('contract');return c as unknown as SessionCredentialMetadata;},secret,nonce,req),
 clearSessionCredential:(req:{ref_id?:string;target_id?:string;scope_kind?:'target'|'discovery'|'draft';scope_id?:string},secret:string,nonce:string)=>adminRequest('managed-targets/session-credentials/clear',v=>{const o=envelope(v);if(typeof o.cleared!=='boolean')throw Error('contract');return {cleared:o.cleared,credential_availability:String(o.credential_availability??'unavailable')};},secret,nonce,req),
 discover:(url:string,nonce:string,secret:string,protocolHint?:string,specUrl?:string)=>adminRequest('discoveries',parseDiscovery,secret,nonce,{url,authorization_confirmed:true,...(protocolHint?{protocol_hint:protocolHint}:{}),...(specUrl?{spec_url:specUrl}:{})},15000),
 probeDiscovery:(profile:ManagedProfile,discoveryId:string,secret:string,nonce:string,sampleInput?:string)=>adminRequest('discovery-probes',parseProbe,secret,nonce,{profile,discovery_id:discoveryId,authorization_confirmed:true,...(sampleInput?.trim()?{sample_input:sampleInput.trim()}:{})},Math.min(620000,(profile.timeout_seconds+15)*1000)),
 reviewManaged:(target:TargetPreset,secret:string,nonce:string)=>adminRequest('managed-targets/review',parseProfile,secret,nonce,{target_id:target.id,profile_revision:target.profile_revision,policy_ref:target.policy_ref,endpoint:target.endpoint,protocol:target.protocol,model:target.protocol==='http-json'?(target.default_model||null):target.default_model,capabilities:target.capabilities,authorization_confirmed:true}),
 probe:(target:TargetPreset,secret:string,nonce:string,confirm=false,sampleInput?:string)=>adminRequest('connection-checks',parseProbe,secret,nonce,{target_id:target.id,profile_revision:target.profile_revision,policy_ref:target.policy_ref,...(confirm?{endpoint:target.endpoint,authorization_confirmed:true}:{}),...(sampleInput?.trim()?{sample_input:sampleInput.trim()}:{})},Math.min(620000,(target.timeout_default+15)*1000)),
 listDatasets:(secret:string,nonce:string)=>adminRequest('datasets',v=>{const o=envelope(v);if(!Array.isArray(o.datasets))throw Error('contract');return o.datasets as DatasetSummary[];},secret,nonce),
 validateDataset:(rawJson:File,filename:string,secret:string,nonce:string)=>adminRequest('datasets/validate',v=>{const o=envelope(v);if(!o.dataset)throw Error('contract');return o.dataset as DatasetEnvelope;},secret,nonce,{},10000,{'X-Dataset-Filename':encodeURIComponent(filename)},rawJson),
 importDataset:(rawJson:File,filename:string,secret:string,nonce:string)=>adminRequest('datasets/import',v=>{const o=envelope(v);if(!o.dataset)throw Error('contract');return {dataset:o.dataset as DatasetEnvelope,created:o.created===true};},secret,nonce,{},10000,{'X-Dataset-Filename':encodeURIComponent(filename)},rawJson),
 getDataset:(datasetId:string,secret:string,nonce:string)=>adminRequest(`datasets/${datasetId}`,v=>{const o=envelope(v);if(!o.dataset)throw Error('contract');return o.dataset as DatasetEnvelope;},secret,nonce),
 getAsi03Contract:(datasetId:string,caseId:string,targetId:string,secret:string,nonce:string)=>adminRequest(`asi03-contracts/lookup/${datasetId}/${caseId}/${targetId}`,v=>{const o=envelope(v);return (o.contract??null) as Asi03Contract|null;},secret,nonce),
 createAsi03Draft:(draft:Asi03ContractDraft,secret:string,nonce:string)=>adminRequest('asi03-contracts/drafts',v=>{const o=envelope(v);if(!o.contract)throw Error('contract');return o.contract as Asi03Contract;},secret,nonce,draft),
 reviewAsi03Contract:(id:string,revision:string,secret:string,nonce:string)=>adminRequest(`asi03-contracts/${id}/review`,v=>{const o=envelope(v);if(!o.contract)throw Error('contract');return o.contract as Asi03Contract;},secret,nonce,{expected_revision_sha256:revision,review_confirmed:true}),
 getAsi03TargetPolicy:(targetId:string,secret:string,nonce:string)=>adminRequest(`asi03-policies/target/${targetId}`,v=>{const o=envelope(v);return (o.policy??null) as Asi03TargetPolicy|null;},secret,nonce),
 createAsi03TargetPolicy:(draft:Asi03TargetPolicyDraft,secret:string,nonce:string)=>adminRequest('asi03-policies/drafts',v=>{const o=envelope(v);if(!o.policy)throw Error('contract');return o.policy as Asi03TargetPolicy;},secret,nonce,draft),
 reviewAsi03TargetPolicy:(id:string,revision:string,secret:string,nonce:string)=>adminRequest(`asi03-policies/${id}/review`,v=>{const o=envelope(v);if(!o.policy)throw Error('contract');return o.policy as Asi03TargetPolicy;},secret,nonce,{expected_revision_sha256:revision,review_confirmed:true}),
 getAsi05Policy:(targetId:string,secret:string,nonce:string)=>adminRequest(`asi05-policies/target/${targetId}`,v=>{const o=envelope(v);return (o.policy??null) as Asi05Policy|null;},secret,nonce),
 createAsi05Policy:(draft:Asi05PolicyDraft,secret:string,nonce:string)=>adminRequest('asi05-policies/drafts',v=>{const o=envelope(v);if(!o.policy)throw Error('contract');return o.policy as Asi05Policy;},secret,nonce,draft),
 reviewAsi05Policy:(id:string,revision:string,secret:string,nonce:string)=>adminRequest(`asi05-policies/${id}/review`,v=>{const o=envelope(v);if(!o.policy)throw Error('contract');return o.policy as Asi05Policy;},secret,nonce,{expected_revision_sha256:revision,review_confirmed:true}),
 getDiscoveryMcpTools:(discoveryId:string,secret:string,nonce:string)=>adminRequest(`discoveries/${discoveryId}/mcp-tools`,v=>{const o=envelope(v);if(o.discovery_id!==discoveryId||!Array.isArray(o.tools))throw Error('contract');return o as unknown as McpCapabilityManifest;},secret,nonce),
 listMcpCatalogs:(secret:string,nonce:string)=>adminRequest('mcp-catalogs',v=>{const o=envelope(v);if(!Array.isArray(o.catalogs))throw Error('contract');return o.catalogs as McpToolCatalog[];},secret,nonce),
 getMcpCatalogsForTarget:(targetId:string,secret:string,nonce:string)=>adminRequest(`mcp-catalogs/target/${encodeURIComponent(targetId)}`,v=>{const o=envelope(v);if(!Array.isArray(o.catalogs))throw Error('contract');return o.catalogs as McpToolCatalog[];},secret,nonce),
 createMcpCatalogDraft:(req:{mcp_target_id:string;catalog_name:string;discovery_id?:string|null;selected_tool_names?:string[]|null;reviewed_tools?:ReviewedToolSpec[]|null},secret:string,nonce:string)=>adminRequest('mcp-catalogs/drafts',v=>{const o=envelope(v);if(!o.catalog)throw Error('contract');return o.catalog as McpToolCatalog;},secret,nonce,req),
 reviewMcpCatalog:(catalogId:string,revision:string,secret:string,nonce:string)=>adminRequest(`mcp-catalogs/${catalogId}/review`,v=>{const o=envelope(v);if(!o.catalog)throw Error('contract');return o.catalog as McpToolCatalog;},secret,nonce,{expected_revision_sha256:revision,review_confirmed:true}),
 listAgentBindings:(secret:string,nonce:string)=>adminRequest('agent-bindings',v=>{const o=envelope(v);if(!Array.isArray(o.bindings))throw Error('contract');return o.bindings as HostedMcpAgentBinding[];},secret,nonce),
 createAgentBindingDraft:(req:{llm_target_id:string;mcp_target_id:string;catalog_id?:string|null;catalog_revision_sha256?:string|null;model:string;system_prompt:string;reviewed_tools?:ReviewedToolSpec[];environment_scope?:EnvironmentAuthorizationScope|null;max_model_calls?:number;max_tool_calls?:number;authorized_predicates?:ToolArgumentPredicate[];prohibited_predicates?:ToolArgumentPredicate[]},secret:string,nonce:string)=>adminRequest('agent-bindings/drafts',v=>{const o=envelope(v);if(!o.binding)throw Error('contract');return o.binding as HostedMcpAgentBinding;},secret,nonce,req),
 reviewAgentBinding:(bindingId:string,revision:string,secret:string,nonce:string)=>adminRequest(`agent-bindings/${bindingId}/review`,v=>{const o=envelope(v);if(!o.binding)throw Error('contract');return o.binding as HostedMcpAgentBinding;},secret,nonce,{expected_revision_sha256:revision,review_confirmed:true}),
 listResponsePolicies:(targetId:string,secret:string,nonce:string)=>adminRequest(`response-policies/target/${encodeURIComponent(targetId)}`,v=>{const o=envelope(v);if(!Array.isArray(o.policies))throw Error('contract');return o.policies as ResponsePolicyRecord[];},secret,nonce),
 createResponsePolicyDraft:(draft:ResponsePolicyDraft,secret:string,nonce:string)=>adminRequest('response-policies/drafts',v=>{const o=envelope(v);if(!o.policy)throw Error('contract');return o.policy as ResponsePolicyRecord;},secret,nonce,draft),
 reviewResponsePolicy:(policyId:string,revision:string,reviewer:string,secret:string,nonce:string)=>adminRequest(`response-policies/${encodeURIComponent(policyId)}/review`,v=>{const o=envelope(v);if(!o.policy)throw Error('contract');return o.policy as ResponsePolicyRecord;},secret,nonce,{expected_revision_sha256:revision,reviewer,review_confirmed:true}),
 listGenericRuns:(secret='',nonce='')=>adminRequest('generic-runs',v=>{const o=envelope(v);if(!Array.isArray(o.runs))throw Error('contract');return o.runs as GenericRunSummary[];},secret,nonce,undefined,15000),
 previewGenericRun:(req:GenericRunRequest,secret:string,nonce:string)=>adminRequest('generic-runs/preview',v=>{const o=envelope(v);if(!Array.isArray(o.items))throw Error('contract');return o as unknown as GenericRunPreview;},secret,nonce,req,30000),
 startGenericRun:(req:GenericRunRequest,secret:string,nonce:string)=>adminRequest('generic-runs/start',v=>{const o=envelope(v);if(typeof o.generic_run_id!=='string'||!Array.isArray(o.cases))throw Error('contract');return o as unknown as GenericRunRecord;},secret,nonce,{...req,authorization_confirmed:true},180000),
 cancelGenericRun:(runId:string,secret:string,nonce:string)=>adminRequest(`generic-runs/${encodeURIComponent(runId)}/cancel`,v=>{const o=envelope(v);if(o.generic_run_id!==runId||!Array.isArray(o.cases))throw Error('contract');return o as unknown as GenericRunRecord;},secret,nonce,{},15000),
 previewGenericResume:(runId:string,req:{include_uncertain_case_ids?:string[]},secret:string,nonce:string)=>adminRequest(`generic-runs/${encodeURIComponent(runId)}/resume/preview`,v=>{const o=envelope(v);if(o.parent_run_id!==runId||!Array.isArray(o.pending_case_ids)||!Array.isArray(o.uncertain_case_ids)||typeof o.resume_digest!=='string')throw Error('contract');return o as unknown as GenericResumePreview;},secret,nonce,req,30000),
 startGenericResume:(runId:string,req:GenericResumeStartRequest,secret:string,nonce:string)=>adminRequest(`generic-runs/${encodeURIComponent(runId)}/resume/start`,v=>{const o=envelope(v);if(typeof o.generic_run_id!=='string'||!Array.isArray(o.cases))throw Error('contract');return o as unknown as GenericRunRecord;},secret,nonce,{...req,authorization_confirmed:true},180000),
 getGenericRun:(runId:string,secret='',nonce='')=>adminRequest(`generic-runs/${encodeURIComponent(runId)}`,v=>{const o=envelope(v);if(o.generic_run_id!==runId||!Array.isArray(o.cases))throw Error('contract');return o as unknown as GenericRunRecord;},secret,nonce,undefined,15000),
 getGenericRunBySubmission:(submissionId:string,secret='',nonce='')=>adminRequest(`generic-runs/submission/${encodeURIComponent(submissionId)}`,v=>{const o=envelope(v);if(typeof o.generic_run_id!=='string'||!Array.isArray(o.cases))throw Error('contract');return o as unknown as GenericRunRecord;},secret,nonce,undefined,15000),
 genericRunExportUrl:(runId:string)=>`/api/testing/generic-runs/${encodeURIComponent(runId)}/report.json`,
 genericRunUnifiedExportUrl:(runId:string)=>`/api/testing/generic-runs/${encodeURIComponent(runId)}/unified-report.json`,
 downloadGenericRunReport:async(runId:string,secret=''):Promise<void>=>{
  const url=`/api/testing/generic-runs/${encodeURIComponent(runId)}/report.json`;
  const r=await fetch(url,{method:'GET',credentials:'omit',cache:'no-store',headers:secret?{'X-SecAgent-Operator':secret}:undefined});
  if(!r.ok)throw Error(`Workflow API rejected report export (HTTP ${r.status}).`);
  const blob=await r.blob();
  const objUrl=URL.createObjectURL(blob);
  const a=document.createElement('a');
  a.href=objUrl;
  a.download=`secagent-generic-run-${runId}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(objUrl);
 },
 downloadGenericRunUnifiedReport:async(runId:string,secret=''):Promise<void>=>{
  const url=`/api/testing/generic-runs/${encodeURIComponent(runId)}/unified-report.json`;
  const r=await fetch(url,{method:'GET',credentials:'omit',cache:'no-store',headers:secret?{'X-SecAgent-Operator':secret}:undefined});
  if(!r.ok)throw Error(`Workflow API rejected unified report export (HTTP ${r.status}).`);
  const blob=await r.blob();
  const objUrl=URL.createObjectURL(blob);
  const a=document.createElement('a');
  a.href=objUrl;
  a.download=`secagent-unified-scan-${runId}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(objUrl);
 },
};
export function draftFor(t:TargetPreset,model:string,timeout:number):Draft{return {target_id:t.id,profile_revision:t.profile_revision,policy_ref:t.policy_ref,endpoint:t.endpoint,protocol:t.protocol,method:t.method,model:t.protocol==='http-json'?(model||null):model,request_mapping:t.request_mapping,response_parser:t.response_parser,timeout_seconds:timeout,credential_alias:t.credential_alias};}
