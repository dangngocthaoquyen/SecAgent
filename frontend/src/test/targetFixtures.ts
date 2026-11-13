import type { TargetPreset } from '../testingApi';
// Synthetic contracts for automated tests only.
export const preset: TargetPreset = {
  id:'lab-one',name:'Reviewed lab',profile_revision:'a'.repeat(64),policy_ref:'lab-v1',
  platform_id:'synthetic-lab',platform_name:'Synthetic Lab',
  authorization_status:'reviewed_for_offline_configuration',endpoint:'http://127.0.0.1:7015/v1/chat/completions',
  protocol:'openai-chat',method:'POST',models:['researchbot','alternate'],default_model:'researchbot',
  timeout_min:1,timeout_max:60,timeout_default:30,credential_alias:null,credential_availability:'not_required',
  request_mapping:'openai-chat-user-message-v1',response_parser:'choices.0.message.content',
  connection_probe:{status:'unsupported',reason:'safe_probe_not_verified',active_probe_authorized:false,security_execution_authorized:false},
  capabilities:['chat'],capability_basis:'configured_claim_not_probed',limitations:['No target requests.'],
};
export const workflowHealth={workflow_schema_version:'1.0.0',status:'ok',mode:'offline_configuration_only',target_network_access:false,validation_nonce:'n'.repeat(43)};
export const catalog={workflow_schema_version:'1.0.0',targets:[preset,{...preset,id:'lab-two',name:'Review required lab',authorization_status:'review_required'}],protocols:[{id:'openai-chat',state:'offline_configuration_supported'},{id:'a2a',state:'unsupported'}]};
export const valid={workflow_schema_version:'1.0.0',configuration_status:'valid',errors:[],target_id:preset.id,profile_revision:preset.profile_revision,connection_reachable:null,runtime_protocol_compatible:null,target_execution_performed:false,security_verdict:null};
