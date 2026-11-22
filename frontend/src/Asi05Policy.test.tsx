import {afterEach,expect,it,vi} from 'vitest';
import {fireEvent,render,screen} from '@testing-library/react';
import Asi05PolicyReview from './Asi05Policy';

afterEach(()=>vi.restoreAllMocks());

it('reviews a target-scoped ASI05 response policy without testcase assertions',async()=>{
 const draft={target_id:'codebot',prohibited_command_behavior:'Issue unauthorized command artifacts',
  allowed_benign_context:'Read-only inspection after refusal',
  expected_response_boundary:'Do not issue prohibited command artifacts',
  evaluation_scope:'response_command_artifact',delivery_surface:'direct_chat'};
 const record={policy_id:'a'.repeat(32),revision_sha256:'b'.repeat(64),review_status:'draft',
  response_policy_ready:false,readiness_blockers:['asi05_policy_not_reviewed'],draft};
 const fetch=vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify({workflow_schema_version:'1.0.0',policy:null})))
  .mockResolvedValueOnce(new Response(JSON.stringify({workflow_schema_version:'1.0.0',policy:record})))
  .mockResolvedValueOnce(new Response(JSON.stringify({workflow_schema_version:'1.0.0',policy:{...record,
   review_status:'reviewed',response_policy_ready:true,readiness_blockers:[]}})));
 render(<Asi05PolicyReview targetId="codebot" nonce={'n'.repeat(43)} secret="" onChanged={()=>{}}/>);
 for(const [label,value] of [['Prohibited agent-issued command behavior',draft.prohibited_command_behavior],
  ['Allowed benign command context',draft.allowed_benign_context],
  ['Expected response boundary',draft.expected_response_boundary]]){
  fireEvent.change(screen.getByLabelText(label),{target:{value}});
 }
 fireEvent.click(screen.getByRole('button',{name:'Save ASI05 Policy Draft'}));
 const checkbox=await screen.findByRole('checkbox',{name:/I reviewed this response boundary/});
 expect(screen.getByRole('button',{name:'Review ASI05 Policy'})).toBeDisabled();
 fireEvent.click(checkbox);fireEvent.click(screen.getByRole('button',{name:'Review ASI05 Policy'}));
 expect(await screen.findByText(/ASI05 response policy reviewed/)).toBeInTheDocument();
 expect(JSON.parse(String(fetch.mock.calls[1][1]?.body))).toEqual(draft);
});
