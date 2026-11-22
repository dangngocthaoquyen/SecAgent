import { afterEach, expect, it, vi } from 'vitest';
import { act,fireEvent, render, screen, waitFor } from '@testing-library/react';
import DiscoveryPanel from './DiscoveryPanel';
import {testingApi, type DiscoveryResult} from './testingApi';

afterEach(()=>vi.restoreAllMocks());

it('requires explicit authorization, separates advertised metadata, and hands off a suggestion',async()=>{
 const result={workflow_schema_version:'1.0.0',discovery_id:'a'.repeat(32),
  input_url:'http://127.0.0.1:7001/v1/chat/completions',
  canonical_endpoint:'http://127.0.0.1:7001/v1/chat/completions',
  status:'metadata_found',request_count:3,request_budget:3,protocol_hint:null,
  metadata_sources:[{url:'http://127.0.0.1:7001/v1/models',status:'advertised',classification:'advertised_metadata'}],
  protocol_candidates:[{id:'openai-chat',classification:'operator_supplied',source:'input',runtime_verified:false}],
  advertised_models:[{id:'candidate-model',source:'models',classification:'advertised_metadata'}],
  advertised_agent:null,advertised_tools:[],advertised_skills:[],possible_contracts:[],unknown_fields:['runtime_chat_contract'],
  warnings:['Runtime behavior remains unverified.'],recommendations:[{testcase_id:'GH-C01',asi_category:'ASI01',
   status:'CONDITIONAL',reason:'review_and_runtime_contract_required',security_verdict:null}],
  proposed_profile:{id:'candidate',name:'Candidate',platform_id:'local-http',platform_name:'Local HTTP',
   endpoint:'http://127.0.0.1:7001/v1/chat/completions',protocol:'openai-chat',model:'candidate-model',timeout_seconds:30},
  security_test_executed:false,security_verdict:null} as DiscoveryResult;
 const discover=vi.spyOn(testingApi,'discover').mockResolvedValue(result);
 const onUse=vi.fn();
 render(<DiscoveryPanel nonce={'n'.repeat(43)} secret="" onUse={onUse} onReset={vi.fn()}/>);
 fireEvent.change(screen.getByLabelText('AI Agent URL'),{target:{value:result.input_url}});
 fireEvent.change(screen.getByLabelText('Agent Name'),{target:{value:'My Code Assistant'}});
 expect(screen.getByRole('button',{name:'Discover & Test Connection'})).toBeDisabled();
 fireEvent.click(screen.getByLabelText(/I authorize up to three bounded metadata requests/));
 fireEvent.click(screen.getByRole('button',{name:'Discover & Test Connection'}));
 await waitFor(()=>expect(discover).toHaveBeenCalledWith(result.input_url,'n'.repeat(43),'',undefined));
 await waitFor(()=>expect(onUse).toHaveBeenCalledWith({...result.proposed_profile,name:'My Code Assistant'},result.discovery_id,result));
 expect(screen.getByText(/Configuration detected/)).toBeInTheDocument();
 expect(screen.getByText('Advanced Details').closest('details')).not.toHaveAttribute('open');
});

it('shows MCP metadata and unverified evidence candidates separately',async()=>{
 const row={discovery_id:'b'.repeat(32),input_url:'http://127.0.0.1:7010/',
  canonical_endpoint:'http://127.0.0.1:7010/',status:'metadata_found',
  connection_status:'reachable',request_count:1,request_budget:3,protocol_hint:'mcp-jsonrpc',
  metadata_sources:[{url:'http://127.0.0.1:7010/',status:'advertised',classification:'mcp_tools_list'}],
  protocol_candidates:[{id:'mcp-jsonrpc',classification:'observed_tools_list',source:'input',runtime_verified:false}],
  advertised_models:[],advertised_agent:null,
  advertised_tools:[{name:'read_file',source:'input',classification:'mcp_tools_list'}],
  advertised_skills:[],possible_contracts:[],unknown_fields:['model','handler_receipt'],warnings:[],
  evidence_candidates:[{source_name:'DVAA Attack Log',url:'http://127.0.0.1:9000/api/attack-log',
   evidence_type:'attack_log',discovery_provenance:'dvaa_adapter_known_endpoint',availability:'candidate_needs_review',
   verification_status:'not_verified',correlation_capability:'request_identity_not_guaranteed',
   required_authorization:'operator_review_and_exact_evidence_allowlist',limitations:'Target-owned telemetry only.'}],
  recommendations:[],proposed_profile:{id:'local-agent-7010',name:'Local AI Agent',platform_id:'local-agent',
   platform_name:'Local Agent',endpoint:'http://127.0.0.1:7010/',protocol:'mcp-jsonrpc',model:'mcp-service',timeout_seconds:30},
  security_test_executed:false,security_verdict:null} as DiscoveryResult;
 const discover=vi.spyOn(testingApi,'discover').mockResolvedValue(row);
 const onUse=vi.fn();render(<DiscoveryPanel nonce={'n'.repeat(43)} secret="" onUse={onUse} onReset={vi.fn()}/>);
 fireEvent.change(screen.getByLabelText('AI Agent URL'),{target:{value:row.input_url}});
 fireEvent.change(screen.getByLabelText('Protocol hint'),{target:{value:'mcp-jsonrpc'}});
 fireEvent.click(screen.getByLabelText(/I authorize up to three bounded metadata requests/));
 fireEvent.click(screen.getByRole('button',{name:'Discover & Test Connection'}));
 await waitFor(()=>expect(discover).toHaveBeenCalledWith(row.input_url,'n'.repeat(43),'','mcp-jsonrpc'));
 await waitFor(()=>expect(onUse).toHaveBeenCalledWith(row.proposed_profile,row.discovery_id,row));
 fireEvent.click(screen.getByText('Advanced Details'));
 expect(screen.getByText('DVAA Attack Log')).toBeInTheDocument();
 expect(screen.getByText(/Evidence candidates are not collected/)).toBeVisible();
 expect(screen.getByText(/none advertised/)).toBeInTheDocument();
});

it('discards a discovery response after the URL changes',async()=>{
 let complete:((row:DiscoveryResult)=>void)|undefined;
 vi.spyOn(testingApi,'discover').mockImplementation(()=>new Promise(resolve=>{complete=resolve;}));
 const onUse=vi.fn(),onReset=vi.fn();
 render(<DiscoveryPanel nonce={'n'.repeat(43)} secret="" onUse={onUse} onReset={onReset}/>);
 fireEvent.change(screen.getByLabelText('AI Agent URL'),{target:{value:'http://127.0.0.1:7010/'}});
 fireEvent.click(screen.getByLabelText(/I authorize up to three bounded metadata requests/));
 fireEvent.click(screen.getByRole('button',{name:/^Discover & Test Connection$/}));
 fireEvent.change(screen.getByLabelText('AI Agent URL'),{target:{value:'http://127.0.0.1:7004/v1/chat/completions'}});
 await act(async()=>complete?.({proposed_profile:{id:'old',name:'Old',platform_id:'local-agent',
  platform_name:'Local Agent',protocol:'mcp-jsonrpc',endpoint:'http://127.0.0.1:7010/',
  model:'mcp-service',timeout_seconds:30}} as DiscoveryResult));
 expect(onUse).not.toHaveBeenCalled();
 expect(screen.queryByText(/Configuration detected/)).not.toBeInTheDocument();
 expect(onReset).toHaveBeenCalled();
});
