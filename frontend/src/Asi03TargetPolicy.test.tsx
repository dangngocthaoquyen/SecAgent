import {afterEach,expect,it,vi} from 'vitest';
import {fireEvent,render,screen} from '@testing-library/react';
import Asi03TargetPolicy from './Asi03TargetPolicy';

afterEach(()=>vi.restoreAllMocks());

it('reviews one target policy without testcase-specific fields or imported assertions',async()=>{
 const draft={target_id:'legacybot',legitimate_agent_identity:'Lab assistant',allowed_roles:['assistant'],
  prohibited_identity_claim:null,prohibited_authority_claim:'Claim real Okta administrator authority',
  expected_security_boundary:'Never adopt administrative authority',evaluation_scope:'identity_claim_response',delivery_surface:'direct_chat'};
 const record={policy_id:'a'.repeat(32),revision_sha256:'b'.repeat(64),review_status:'draft',
  response_policy_ready:false,readiness_blockers:['asi03_policy_not_reviewed'],draft};
 const fetch=vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify({workflow_schema_version:'1.0.0',policy:null})))
  .mockResolvedValueOnce(new Response(JSON.stringify({workflow_schema_version:'1.0.0',policy:record})))
  .mockResolvedValueOnce(new Response(JSON.stringify({workflow_schema_version:'1.0.0',policy:{...record,
   review_status:'reviewed',response_policy_ready:true,readiness_blockers:[]}})));
 render(<Asi03TargetPolicy targetId="legacybot" nonce={'n'.repeat(43)} secret="" onChanged={()=>{}}/>);
 for(const [label,value] of [['Legitimate agent identity','Lab assistant'],['Allowed roles (comma separated)','assistant'],
  ['Prohibited first-party authority claim (optional if identity supplied)','Claim real Okta administrator authority'],
  ['Expected response identity boundary','Never adopt administrative authority']]){
  fireEvent.change(screen.getByLabelText(label),{target:{value}});
 }
 fireEvent.click(screen.getByRole('button',{name:'Save Policy Draft'}));
 const checkbox=await screen.findByRole('checkbox',{name:/I reviewed this identity boundary/});
 expect(screen.getByRole('button',{name:'Review Target Policy'})).toBeDisabled();
 fireEvent.click(checkbox);fireEvent.click(screen.getByRole('button',{name:'Review Target Policy'}));
 expect(await screen.findByText(/Target identity policy reviewed/)).toBeInTheDocument();
 const saved=JSON.parse(String(fetch.mock.calls[1][1]?.body));
 expect(saved).toEqual(draft);
 expect(saved.testcase_id).toBeUndefined();
});
