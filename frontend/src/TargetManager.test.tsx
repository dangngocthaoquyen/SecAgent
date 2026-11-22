import { afterEach, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import TargetManager from './TargetManager';
import { testingApi, type DiscoveryResult } from './testingApi';
import { preset } from './test/targetFixtures';

afterEach(()=>vi.restoreAllMocks());

it('lists targets across protocols, filters by endpoint, and archives only confirmed selection',async()=>{
 const http={...preset,id:'codebot',name:'CodeBot',platform_id:'dvaa',platform_name:'DVAA',endpoint:'http://127.0.0.1:7004/v1/chat/completions'};
 const mcp={...preset,id:'toolbot',name:'ToolBot',platform_id:'dvaa',platform_name:'DVAA',protocol:'mcp-jsonrpc' as const,
  endpoint:'http://127.0.0.1:7010/',default_model:'mcp-service'};
 const archive=vi.spyOn(testingApi,'archiveTargets').mockResolvedValue({archived:[],active:[http]});
 vi.spyOn(testingApi,'archivedTargets').mockResolvedValue([]);
 const changed=vi.fn();
 render(<TargetManager enabled localSingleUser nonce={'n'.repeat(43)} target={http} existingProfiles={[http,mcp]} onChanged={changed}/>);
 expect(screen.getByRole('heading',{name:'DVAA'})).toBeInTheDocument();
 expect(screen.getByRole('button',{name:/ToolBot.*7010/})).toBeInTheDocument();
 fireEvent.change(screen.getByLabelText('Search targets'),{target:{value:'7010'}});
 expect(screen.queryByRole('button',{name:/CodeBot.*7004/})).not.toBeInTheDocument();
 fireEvent.change(screen.getByLabelText('Search targets'),{target:{value:''}});
 fireEvent.click(screen.getByLabelText('Select ToolBot for bulk archive'));
 fireEvent.click(screen.getByRole('button',{name:'Archive selected (1)'}));
 const dialog=screen.getByRole('dialog',{name:'Confirm target archive'});
 expect(dialog).toHaveTextContent('ToolBot');
 expect(dialog).not.toHaveTextContent('CodeBot');
 expect(screen.getByRole('button',{name:'Archive targets'})).toBeDisabled();
 fireEvent.click(screen.getByLabelText('I confirm the exact targets above should be archived.'));
 fireEvent.click(screen.getByRole('button',{name:'Archive targets'}));
 await waitFor(()=>expect(archive).toHaveBeenCalledWith([{target_id:'toolbot',profile_revision:mcp.profile_revision}],'','n'.repeat(43)));
});

it('requires explicit platform confirmation while preserving target identity on rename',async()=>{
 const selected={...preset,id:'local-agent-7010',name:'ToolBot',platform_id:'local-agent',platform_name:'Local Agent',
  protocol:'mcp-jsonrpc' as const,endpoint:'http://127.0.0.1:7010/',default_model:'mcp-service'};
 vi.spyOn(testingApi,'archivedTargets').mockResolvedValue([]);
 const validate=vi.spyOn(testingApi,'validateManaged').mockResolvedValue(true);
 const save=vi.spyOn(testingApi,'saveManaged').mockResolvedValue(selected);
 render(<TargetManager enabled localSingleUser nonce={'n'.repeat(43)} target={selected} existingProfiles={[selected]} onChanged={vi.fn()}/>);
 fireEvent.click(screen.getByRole('button',{name:'Edit'}));
 fireEvent.change(screen.getByLabelText('Target display name'),{target:{value:'DVAA ToolBot'}});
 fireEvent.click(screen.getByRole('button',{name:'Validate Target Details'}));
 await waitFor(()=>expect(validate).toHaveBeenCalled());
 fireEvent.click(screen.getByRole('button',{name:'Save Configuration'}));
 await waitFor(()=>expect(save).toHaveBeenCalledWith(expect.objectContaining({id:'local-agent-7010',name:'DVAA ToolBot'}),selected.profile_revision,'','n'.repeat(43)));
 fireEvent.click(screen.getByRole('button',{name:'Edit'}));
 fireEvent.change(screen.getByLabelText('Platform identifier'),{target:{value:'dvaa'}});
 fireEvent.change(screen.getByLabelText('Platform name'),{target:{value:'DVAA'}});
 fireEvent.click(screen.getByRole('button',{name:'Validate Target Details'}));
 await waitFor(()=>expect(screen.getByRole('button',{name:'Save Configuration'})).toBeDisabled());
 fireEvent.click(screen.getByLabelText(/I confirm this operator-declared platform association/));
 await waitFor(()=>expect(screen.getByRole('button',{name:'Save Configuration'})).toBeEnabled());
 fireEvent.click(screen.getByRole('button',{name:'Save Configuration'}));
 await waitFor(()=>expect(save).toHaveBeenLastCalledWith(expect.objectContaining({id:'local-agent-7010',platform_id:'dvaa',platform_name:'DVAA'}),selected.profile_revision,'','n'.repeat(43),undefined,true));
});

it('adds ResearchBot, requires review, then exposes one benign probe',async()=>{
 const unreviewed={...preset,id:'dvaa-researchbot',name:'DVAA ResearchBot',authorization_status:'review_required' as const,
  connection_probe:{status:'unsupported' as const,reason:'operator_review_required',active_probe_authorized:false,security_execution_authorized:false as const}};
 const reviewed={...unreviewed,authorization_status:'reviewed_for_offline_configuration' as const,
  connection_probe:{status:'supported' as const,reason:'reviewed_exact_endpoint',active_probe_authorized:true,security_execution_authorized:false as const}};
 vi.spyOn(testingApi,'unlock').mockResolvedValue([]);
 const validate=vi.spyOn(testingApi,'validateManaged').mockResolvedValue(true);
 const save=vi.spyOn(testingApi,'saveManaged').mockResolvedValue(unreviewed);
 const review=vi.spyOn(testingApi,'reviewManaged').mockResolvedValue(reviewed);
 const probe=vi.spyOn(testingApi,'probe').mockResolvedValue({connection_status:'succeeded',reason:'openai_chat_response',
  target_request_count:1,connection_reachable:true,runtime_protocol_compatible:true,http_status:200,security_test_executed:false,security_verdict:null});
 const changed=vi.fn();
 const view=render(<TargetManager enabled nonce={'n'.repeat(43)} onChanged={changed}/>);
 fireEvent.change(screen.getByLabelText('Operator secret'),{target:{value:'operator-test'}});
 fireEvent.click(screen.getByText('Unlock target management'));
 await screen.findByText('Add Target');
 fireEvent.click(screen.getByText('Add Target'));
 fireEvent.click(screen.getByText('Use DVAA ResearchBot example'));
 expect(screen.getByLabelText('Endpoint URL')).toHaveValue('http://127.0.0.1:7015/v1/chat/completions');
 fireEvent.click(screen.getByText('Validate Target Details'));
 await waitFor(()=>expect(validate).toHaveBeenCalledWith(expect.objectContaining({id:'dvaa-researchbot',model:'researchbot',timeout_seconds:30}),null,'operator-test','n'.repeat(43)));
 await waitFor(()=>expect(screen.getByText('Save Configuration')).toBeEnabled());
 fireEvent.click(screen.getByText('Save Configuration'));
 await waitFor(()=>expect(save).toHaveBeenCalledTimes(1));
 expect(changed).toHaveBeenCalledWith('dvaa-researchbot');
 view.rerender(<TargetManager enabled nonce={'n'.repeat(43)} target={unreviewed} onChanged={changed}/>);
 expect(screen.getByText('Review required')).toBeInTheDocument();
 expect(screen.getByText('Test Connection')).toBeDisabled();
 fireEvent.click(screen.getByLabelText(/I confirm authorization to test/));
 fireEvent.click(screen.getByText('Review / Approve Target'));
 await waitFor(()=>expect(review).toHaveBeenCalledWith(unreviewed,'operator-test','n'.repeat(43)));
 view.rerender(<TargetManager enabled nonce={'n'.repeat(43)} target={reviewed} onChanged={changed}/>);
 fireEvent.click(screen.getByLabelText(/I confirm authorization for one benign probe/));
 fireEvent.click(screen.getByText('Test Connection'));
 await waitFor(()=>expect(probe).toHaveBeenCalledWith(reviewed,'operator-test','n'.repeat(43),false));
 expect(await screen.findByText(/API compatibility: yes/)).toBeInTheDocument();
});

it('manages locally without token entry and confirms the first exact-endpoint probe',async()=>{
 const unreviewed={...preset,authorization_status:'review_required' as const,
  connection_probe:{status:'requires_confirmation' as const,reason:'authorization_confirmation_required',
   active_probe_authorized:false,security_execution_authorized:false as const}};
 const validate=vi.spyOn(testingApi,'validateManaged').mockResolvedValue(true);
 vi.spyOn(testingApi,'saveManaged').mockResolvedValue(unreviewed);
 const probe=vi.spyOn(testingApi,'probe').mockResolvedValue({connection_status:'succeeded',
  reason:'openai_chat_response',target_request_count:1,connection_reachable:true,
  runtime_protocol_compatible:true,http_status:200,security_test_executed:false,security_verdict:null});
 const changed=vi.fn();
 const view=render(<TargetManager enabled localSingleUser nonce={'n'.repeat(43)} onChanged={changed}/>);
 expect(screen.queryByLabelText('Operator secret')).not.toBeInTheDocument();
 fireEvent.click(screen.getByRole('button',{name:'Add Target'}));
 fireEvent.click(screen.getByRole('button',{name:'Use DVAA ResearchBot example'}));
 fireEvent.click(screen.getByRole('button',{name:'Validate Target Details'}));
 await waitFor(()=>expect(validate).toHaveBeenCalledWith(expect.any(Object),null,'','n'.repeat(43)));
 fireEvent.click(screen.getByRole('button',{name:'Save Configuration'}));
 await waitFor(()=>expect(changed).toHaveBeenCalled());
 view.rerender(<TargetManager enabled localSingleUser nonce={'n'.repeat(43)} target={unreviewed} onChanged={changed}/>);
 expect(screen.queryByRole('button',{name:'Review / Approve Target'})).not.toBeInTheDocument();
 const button=screen.getByRole('button',{name:'Test Connection'});
 expect(button).toBeDisabled();
 fireEvent.click(screen.getByLabelText(/I confirm authorization for one benign probe/));
 fireEvent.click(button);
 await waitFor(()=>expect(probe).toHaveBeenCalledWith(unreviewed,'','n'.repeat(43),true));
 expect(await screen.findByText(/API compatibility: yes/)).toBeInTheDocument();
});

it('allows explicit local authorization when a safe probe is unsupported',async()=>{
 const unreviewed={...preset,authorization_status:'review_required' as const,
  connection_probe:{status:'unsupported' as const,reason:'operator_review_required',
   active_probe_authorized:false,security_execution_authorized:false as const}};
 const reviewed={...unreviewed,authorization_status:'reviewed_for_offline_configuration' as const};
 const review=vi.spyOn(testingApi,'reviewManaged').mockResolvedValue(reviewed);
 render(<TargetManager enabled localSingleUser nonce={'n'.repeat(43)} target={unreviewed} onChanged={vi.fn()}/>);
 expect(screen.getByRole('button',{name:'Test Connection'})).toBeDisabled();
 const button=screen.getByRole('button',{name:'Authorize target for test selection'});
 expect(button).toBeDisabled();
 fireEvent.click(screen.getByLabelText(/I confirm authorization to test/));
 fireEvent.click(button);
 await waitFor(()=>expect(review).toHaveBeenCalledWith(unreviewed,'','n'.repeat(43)));
});

it('reviews the restricted Web Lab without a connection probe',async()=>{
 const target={...preset,id:'dvaa-researchbot-web-lab',
  endpoint:'http://127.0.0.1:17016/v1/chat/completions',
  authorization_status:'review_required' as const,
  connection_probe:{status:'requires_confirmation' as const,reason:'authorization_confirmation_required',
   active_probe_authorized:false,security_execution_authorized:false as const}};
 const review=vi.spyOn(testingApi,'reviewManaged').mockResolvedValue({...target,
  authorization_status:'reviewed_for_offline_configuration' as const});
 const probe=vi.spyOn(testingApi,'probe');
 render(<TargetManager enabled localSingleUser nonce={'n'.repeat(43)} target={target} onChanged={vi.fn()}/>);
 expect(screen.queryByRole('button',{name:'Test Connection'})).not.toBeInTheDocument();
 const button=screen.getByRole('button',{name:'Authorize target for test selection'});
 expect(button).toBeDisabled();
 fireEvent.click(screen.getByLabelText(/I confirm authorization to test/));
 fireEvent.click(button);
 await waitFor(()=>expect(review).toHaveBeenCalledWith(target,'','n'.repeat(43)));
 expect(probe).not.toHaveBeenCalled();
});

it('exposes an authorized benign probe for a reviewed Web Lab profile',async()=>{
 const target={...preset,id:'dvaa-researchbot-web-lab',
  endpoint:'http://127.0.0.1:17016/v1/chat/completions',default_model:'researchbot',
  authorization_status:'reviewed_for_offline_configuration' as const,
  connection_probe:{status:'supported' as const,reason:'reviewed_exact_endpoint',
   active_probe_authorized:true,security_execution_authorized:false as const}};
 const probe=vi.spyOn(testingApi,'probe').mockResolvedValue({connection_status:'succeeded',
  reason:'openai_chat_response',target_request_count:1,connection_reachable:true,
  runtime_protocol_compatible:true,http_status:200,security_test_executed:false,security_verdict:null});
 render(<TargetManager enabled localSingleUser nonce={'n'.repeat(43)} target={target} onChanged={vi.fn()}/>);
 const button=screen.getByRole('button',{name:'Test Connection'});
 expect(button).toBeDisabled();
 fireEvent.click(screen.getByLabelText(/I confirm authorization for one benign probe/));
 fireEvent.click(button);
 await waitFor(()=>expect(probe).toHaveBeenCalledWith(target,'','n'.repeat(43),false));
 expect(await screen.findByText(/API compatibility: yes/)).toBeInTheDocument();
 expect(screen.getByText(/HTTP status: 200/)).toBeInTheDocument();
});

it('keeps management locked when operator authentication fails',async()=>{
 vi.spyOn(testingApi,'unlock').mockRejectedValue(Error('private-provider-token'));
 render(<TargetManager enabled nonce={'n'.repeat(43)} onChanged={vi.fn()}/>);
 fireEvent.change(screen.getByLabelText('Operator secret'),{target:{value:'wrong'}});
 fireEvent.click(screen.getByText('Unlock target management'));
 expect(await screen.findByRole('alert')).toHaveTextContent('Operator access was rejected');
 expect(document.body.textContent).not.toContain('private-provider-token');
 expect(screen.queryByText('Add Target')).not.toBeInTheDocument();
});

it('passes the exact old revision on edit and requires new validation after changes',async()=>{
 vi.spyOn(testingApi,'unlock').mockResolvedValue([]);
 const validate=vi.spyOn(testingApi,'validateManaged').mockResolvedValue(true);
 const save=vi.spyOn(testingApi,'saveManaged').mockResolvedValue(preset);
 render(<TargetManager enabled nonce={'n'.repeat(43)} target={preset} onChanged={vi.fn()}/>);
 fireEvent.change(screen.getByLabelText('Operator secret'),{target:{value:'operator-test'}});
 fireEvent.click(screen.getByText('Unlock target management'));
 await screen.findByText('Edit Target');fireEvent.click(screen.getByText('Edit Target'));
 expect(screen.getByLabelText('Target identifier')).toHaveAttribute('readonly');
 fireEvent.click(screen.getByText('Validate Target Details'));
 await waitFor(()=>expect(validate).toHaveBeenCalledWith(expect.any(Object),preset.profile_revision,'operator-test','n'.repeat(43)));
 await waitFor(()=>expect(screen.getByText('Save Configuration')).toBeEnabled());
 fireEvent.change(screen.getByLabelText('Endpoint URL'),{target:{value:'http://127.0.0.1:7016/v1/chat/completions'}});
 expect(screen.getByText('Save Configuration')).toBeDisabled();
 fireEvent.click(screen.getByText('Validate Target Details'));
 await waitFor(()=>expect(screen.getByText('Save Configuration')).toBeEnabled());
 fireEvent.click(screen.getByText('Save Configuration'));
 await waitFor(()=>expect(save).toHaveBeenCalledWith(expect.objectContaining({endpoint:'http://127.0.0.1:7016/v1/chat/completions'}),preset.profile_revision,'operator-test','n'.repeat(43)));
});

it('retains a compatible connection when only the saved display name changes',async()=>{
 const original={...preset,connection_verification:{status:'compatible' as const,basis:'benign_chat_probe' as const,
  profile_revision:preset.profile_revision,security_execution_authorized:false as const}};
 const renamed={...original,name:'Renamed Research Assistant'};
 vi.spyOn(testingApi,'validateManaged').mockResolvedValue(true);
 const save=vi.spyOn(testingApi,'saveManaged').mockResolvedValue(renamed);
 const view=render(<TargetManager enabled localSingleUser nonce={'n'.repeat(43)} target={original} onChanged={vi.fn()}/>);
 expect(screen.getByText('Connected',{exact:true})).toBeInTheDocument();
 fireEvent.click(screen.getByRole('button',{name:'Edit Target'}));
 fireEvent.change(screen.getByLabelText('Target display name'),{target:{value:renamed.name}});
 fireEvent.click(screen.getByRole('button',{name:'Validate Target Details'}));
 await waitFor(()=>expect(screen.getByRole('button',{name:'Save Configuration'})).toBeEnabled());
 fireEvent.click(screen.getByRole('button',{name:'Save Configuration'}));
 await waitFor(()=>expect(save).toHaveBeenCalledWith(expect.objectContaining({name:renamed.name,
  endpoint:original.endpoint,model:original.default_model}),original.profile_revision,'','n'.repeat(43)));
 view.rerender(<TargetManager enabled localSingleUser nonce={'n'.repeat(43)} target={renamed} onChanged={vi.fn()}/>);
 expect(screen.getByText('Connected',{exact:true})).toBeInTheDocument();
});

it('quick-connects CodeBot with an operator model and clears the old target state',async()=>{
 const proposal={id:'local-agent-7004',name:'Local AI Agent',platform_id:'local-agent',platform_name:'Local Agent',
  protocol:'openai-chat' as const,endpoint:'http://127.0.0.1:7004/v1/chat/completions',model:'',timeout_seconds:30};
 const discovery={discovery_id:'b'.repeat(32),input_url:proposal.endpoint,canonical_endpoint:proposal.endpoint,
  status:'manual_configuration_required',connection_status:'reachable',request_count:3,request_budget:3,
  metadata_sources:[],protocol_candidates:[],advertised_models:[],advertised_agent:null,
  advertised_tools:[],advertised_skills:[],possible_contracts:[],unknown_fields:['model'],warnings:[],
  recommendations:[],proposed_profile:proposal,protocol_hint:null,security_test_executed:false,
  security_verdict:null} as DiscoveryResult;
 vi.spyOn(testingApi,'discover').mockResolvedValue(discovery);
 vi.spyOn(testingApi,'validateManaged').mockResolvedValue(true);
 const probe=vi.spyOn(testingApi,'probeDiscovery').mockResolvedValue({connection_status:'succeeded',
  reason:'openai_chat_response',target_request_count:1,connection_reachable:true,
  runtime_protocol_compatible:true,http_status:200,security_test_executed:false,security_verdict:null});
 const old={...preset,name:'DVAA ResearchBot',connection_verification:{status:'compatible' as const,
  basis:'benign_chat_probe' as const,profile_revision:preset.profile_revision,
  security_execution_authorized:false as const}};
 render(<TargetManager enabled localSingleUser nonce={'n'.repeat(43)} target={old} onChanged={vi.fn()}/>);
 expect(screen.getByRole('heading',{name:'DVAA ResearchBot'})).toBeInTheDocument();
 fireEvent.click(screen.getByRole('button',{name:'Connect new target'}));
 expect(screen.queryByRole('heading',{name:'DVAA ResearchBot'})).not.toBeInTheDocument();
 fireEvent.change(screen.getByLabelText('AI Agent URL'),{target:{value:proposal.endpoint}});
 fireEvent.click(screen.getByLabelText(/I authorize up to three bounded metadata requests/));
 fireEvent.click(screen.getByRole('button',{name:/^Discover & Test Connection$/}));
 expect(await screen.findByRole('heading',{name:'Auto-detected Configuration'})).toBeInTheDocument();
 expect(screen.getByLabelText('Endpoint URL')).toHaveValue(proposal.endpoint);
 expect(screen.getByText(/Model not advertised/)).toBeInTheDocument();
 expect(screen.getByRole('button',{name:'Test Connection'})).toBeDisabled();
 fireEvent.change(screen.getByLabelText('Model identifier'),{target:{value:'default'}});
 fireEvent.click(screen.getByLabelText(/I authorize one benign connection probe/));
 fireEvent.click(screen.getByRole('button',{name:'Test Connection'}));
 await waitFor(()=>expect(probe).toHaveBeenCalledWith(expect.objectContaining({endpoint:proposal.endpoint,
  protocol:'openai-chat',model:'default'}),discovery.discovery_id,'','n'.repeat(43)));
 expect(await screen.findByText(/Connected: openai chat response/)).toBeInTheDocument();
 fireEvent.change(screen.getByLabelText('Agent Name (from connection step)'),{target:{value:'Named CodeBot'}});
 await waitFor(()=>expect(screen.getByText(/Connected: openai chat response/)).toBeInTheDocument());
 expect(screen.getByLabelText('Agent Name (from connection step)')).toHaveValue('Named CodeBot');
 fireEvent.change(screen.getByLabelText('Model identifier'),{target:{value:'other'}});
 expect(screen.getByText(/Unverified: No connection probe/)).toBeInTheDocument();
 fireEvent.change(screen.getByLabelText('Endpoint URL'),{target:{value:'http://127.0.0.1:7004/chat/completions'}});
 expect(screen.getByText(/Endpoint or protocol changed/)).toBeInTheDocument();
 expect(screen.getByRole('button',{name:'Test Connection'})).toBeDisabled();
 expect(screen.getByRole('button',{name:'Save Target'})).toBeDisabled();
 fireEvent.change(screen.getByLabelText('AI Agent URL'),{target:{value:'http://127.0.0.1:7004/other'}});
 expect(screen.queryByRole('heading',{name:'Auto-detected Configuration'})).not.toBeInTheDocument();
 expect(screen.queryByRole('heading',{name:'DVAA ResearchBot'})).not.toBeInTheDocument();
});

it('probes an already saved MCP identifier without claiming it can be saved twice',async()=>{
 const proposal={id:'local-agent-7010',name:'Local AI Agent',platform_id:'local-agent',platform_name:'Local Agent',
  protocol:'mcp-jsonrpc' as const,endpoint:'http://127.0.0.1:7010/',model:'mcp-service',timeout_seconds:30};
 const discovery={discovery_id:'c'.repeat(32),input_url:proposal.endpoint,canonical_endpoint:proposal.endpoint,
  status:'metadata_found',request_count:1,request_budget:3,metadata_sources:[],protocol_candidates:[],
  advertised_models:[],advertised_agent:null,advertised_tools:[],advertised_skills:[],possible_contracts:[],
  unknown_fields:[],warnings:[],recommendations:[],proposed_profile:proposal,protocol_hint:'mcp-jsonrpc',
  security_test_executed:false,security_verdict:null} as DiscoveryResult;
 vi.spyOn(testingApi,'discover').mockResolvedValue(discovery);
 const validate=vi.spyOn(testingApi,'validateManaged').mockResolvedValue(true);
 const probe=vi.spyOn(testingApi,'probeDiscovery').mockResolvedValue({connection_status:'succeeded',
  reason:'mcp_tools_list_response',target_request_count:1,connection_reachable:true,
  runtime_protocol_compatible:true,http_status:200,security_test_executed:false,security_verdict:null});
 render(<TargetManager enabled localSingleUser initialConnect existingTargetIds={['local-agent-7010']}
  nonce={'n'.repeat(43)} onChanged={vi.fn()}/>);
 fireEvent.change(screen.getByLabelText('AI Agent URL'),{target:{value:proposal.endpoint}});
 fireEvent.click(screen.getByLabelText(/I authorize up to three bounded metadata requests/));
 fireEvent.click(screen.getByRole('button',{name:'Discover & Test Connection'}));
 expect(await screen.findByText(/Connected: mcp tools list response/)).toBeInTheDocument();
 expect(probe).toHaveBeenCalledTimes(1);
 expect(validate).not.toHaveBeenCalled();
 expect(screen.getByText(/Target identifier already exists/)).toBeInTheDocument();
 expect(screen.getByRole('button',{name:'Save Target'})).toBeDisabled();
 fireEvent.click(screen.getByText('Advanced target fields'));
 fireEvent.change(screen.getByLabelText('Target identifier'),{target:{value:'local-agent-7010-new'}});
 expect(screen.getByText(/Unverified: No connection probe/)).toBeInTheDocument();
 fireEvent.click(screen.getByLabelText(/I authorize one benign connection probe/));
 fireEvent.click(screen.getByRole('button',{name:'Test Connection'}));
 await waitFor(()=>expect(validate).toHaveBeenCalledWith(expect.objectContaining({id:'local-agent-7010-new'}),null,'','n'.repeat(43)));
 expect(await screen.findByText(/Connected: mcp tools list response/)).toBeInTheDocument();
 expect(screen.getByRole('button',{name:'Save Target'})).toBeEnabled();
});

it('suggests the existing target when endpoint, protocol and service are already saved',async()=>{
 const proposal={id:'new-toolbot',name:'New ToolBot',platform_id:'lab',platform_name:'Lab',
  protocol:'mcp-jsonrpc' as const,endpoint:'http://127.0.0.1:7010/',model:'mcp-service',timeout_seconds:30};
 const existing={...preset,id:'saved-toolbot',name:'Saved ToolBot',protocol:'mcp-jsonrpc' as const,
  endpoint:proposal.endpoint,default_model:proposal.model,models:[proposal.model]};
 vi.spyOn(testingApi,'discover').mockResolvedValue({discovery_id:'c'.repeat(32),input_url:proposal.endpoint,
  canonical_endpoint:proposal.endpoint,status:'metadata_found',request_count:1,request_budget:3,
  metadata_sources:[],protocol_candidates:[],advertised_models:[],advertised_agent:null,
  advertised_tools:[],advertised_skills:[],possible_contracts:[],unknown_fields:[],warnings:[],
  recommendations:[],proposed_profile:proposal,protocol_hint:'mcp-jsonrpc',
  security_test_executed:false,security_verdict:null} as DiscoveryResult);
 vi.spyOn(testingApi,'probeDiscovery').mockResolvedValue({connection_status:'succeeded',reason:'mcp_tools_list_response',
  target_request_count:1,connection_reachable:true,runtime_protocol_compatible:true,http_status:200,
  security_test_executed:false,security_verdict:null});
 const validate=vi.spyOn(testingApi,'validateManaged');const changed=vi.fn();
 render(<TargetManager enabled localSingleUser initialConnect existingProfiles={[existing]} nonce={'n'.repeat(43)} onChanged={changed}/>);
 fireEvent.change(screen.getByLabelText('AI Agent URL'),{target:{value:proposal.endpoint}});
 fireEvent.click(screen.getByLabelText(/I authorize up to three bounded metadata requests/));
 fireEvent.click(screen.getByRole('button',{name:'Discover & Test Connection'}));
 expect(await screen.findByText(/This endpoint, protocol and model are already saved/)).toBeInTheDocument();
 expect(validate).not.toHaveBeenCalled();
 expect(screen.getByRole('button',{name:'Save Target'})).toBeDisabled();
 fireEvent.click(screen.getByRole('button',{name:'Use Saved ToolBot'}));
 expect(changed).toHaveBeenCalledWith('saved-toolbot');
});
