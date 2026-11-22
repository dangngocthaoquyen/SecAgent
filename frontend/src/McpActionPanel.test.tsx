import {afterEach,expect,it,vi} from 'vitest';
import {fireEvent,render,screen} from '@testing-library/react';
import McpActionPanel from './McpActionPanel';
import {testingApi,type TargetPreset} from './testingApi';
import {preset} from './test/targetFixtures';

afterEach(()=>vi.restoreAllMocks());

const action={testcase_id:'ASI05-DVAA-LAB-READ-001',asi_category:'ASI05' as const,
 evaluation_scope:'execution_action' as const,legitimate_objective:'Read dummy canary',
 attacker_objective:'Observe action',target_id:'local-agent-7010',tool_name:'read_file',
 arguments_sha256:'a'.repeat(64),expected_evidence:['secagent_observed_request'],
 attribution:'tool_service/direct_request' as const,policy_id:'draft-action',
 policy_revision_sha256:'b'.repeat(64),policy_status:'draft' as const,
 evidence_status:'partial',judge_status:'deterministic_action_scope_no_pi_skill',
 adapter_evidence_available:false,
 official_verdict_eligible:false};
const target={...preset,id:'local-agent-7010',name:'ToolBot',protocol:'mcp-jsonrpc',
 endpoint:'http://127.0.0.1:7010/',authorization_status:'reviewed_for_offline_configuration'} as TargetPreset;

it('keeps structured MCP separate and requires explicit authorization',async()=>{
 vi.spyOn(testingApi,'listMcpActions').mockResolvedValue({catalog_sha256:'c'.repeat(64),cases:[action],hybrid_configured:true});
 const run=vi.spyOn(testingApi,'runMcpAction').mockResolvedValue({testcase_id:action.testcase_id,
  execution_id:'d'.repeat(32),target_id:target.id,profile_revision:target.profile_revision,
  catalog_sha256:'c'.repeat(64),target_request_count:1,evaluation_scope:'execution_action',
  attribution:'tool_service/direct_request',final_verdict:'INCONCLUSIVE',policy_status:'draft',
  evidence_configuration:'request_only',semantic_invoked:false,report_path:'report.json'});
 render(<McpActionPanel targets={[target]} nonce={'n'.repeat(43)} secret=""/>);
 const button=await screen.findByRole('button',{name:'Run one MCP action'});
 expect(button).toBeDisabled();
 expect(screen.getByText(/no reviewed action Judge Skill/)).toBeInTheDocument();
 fireEvent.click(screen.getByRole('checkbox'));
 expect(button).toBeEnabled();
 fireEvent.click(button);
 await screen.findByText(/1 target request/);
 expect(run).toHaveBeenCalledWith(expect.objectContaining({
  testcase_id:action.testcase_id,target_id:target.id,authorization_confirmed:true,
  catalog_sha256:'c'.repeat(64),evidence_configuration:'request_only'}),'','n'.repeat(43));
});

it('does not execute for an unreviewed target',async()=>{
 vi.spyOn(testingApi,'listMcpActions').mockResolvedValue({catalog_sha256:'c'.repeat(64),cases:[action],hybrid_configured:false});
 const run=vi.spyOn(testingApi,'runMcpAction');
 render(<McpActionPanel targets={[{...target,authorization_status:'review_required'}]} nonce={'n'.repeat(43)} secret=""/>);
 await screen.findByText(/Review the exact matching MCP target/);
 fireEvent.click(screen.getByRole('checkbox'));
 expect(screen.getByRole('button',{name:'Run one MCP action'})).toBeDisabled();
 expect(run).not.toHaveBeenCalled();
});
