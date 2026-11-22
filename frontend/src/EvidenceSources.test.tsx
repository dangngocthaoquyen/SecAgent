import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import {expect,it,vi} from 'vitest';
import EvidenceSources from './EvidenceSources';
import {testingApi,type EvidenceSource,type EvidenceCapture} from './testingApi';
import {preset} from './test/targetFixtures';

const source:EvidenceSource={id:'a'.repeat(32),revision:'b'.repeat(64),schema_version:'1.0.0',
 name:'Detector log',target_id:preset.id,target_revision:preset.profile_revision,source_type:'http_json',
 endpoint:'http://127.0.0.1:7000/api/log',credential_ref:null,collection_mode:'snapshot',mapping:{items:''},
 semantics:'detector_reported',timeout_seconds:5,max_response_bytes:65536,max_events:200,enabled:true,
 availability:'not_checked',correlation_status:'uncorrelated',action_eligible:false,configuration_status:'configured'};
const capture:EvidenceCapture={id:'c'.repeat(32),source_id:source.id,source_revision:source.revision,
 availability:'available',error:null,action_eligible:false,correlation_status:'uncorrelated',request_count:1,
 events:[],external_judge_disclosure:'forbidden'};
function mocks(sources:EvidenceSource[]=[source]){
 vi.spyOn(testingApi,'listEvidenceSources').mockResolvedValue({sources,allowed_endpoints:[{url:source.endpoint,credential_ref:null}]});
 vi.spyOn(testingApi,'saveEvidenceSource').mockResolvedValue(source);
 return vi.spyOn(testingApi,'collectEvidenceSource').mockResolvedValue(capture);
}
it('loads local configuration without collecting, requires explicit authorization and keeps evidence uncorrelated',async()=>{
 const collect=mocks();render(<EvidenceSources target={preset} nonce="nonce" secret="" authorized/>);
 fireEvent.click(screen.getByText('Evidence Sources'));
 await screen.findByText('Detector log');
 expect(collect).not.toHaveBeenCalled();
 expect(screen.getByRole('button',{name:'Test Source'})).toBeDisabled();
 fireEvent.click(screen.getByLabelText(/I authorize one read-only snapshot/));
 fireEvent.click(screen.getByRole('button',{name:'Test Source'}));
 await waitFor(()=>expect(collect).toHaveBeenCalledWith(source.id,source.revision,'','nonce'));
 expect(await screen.findByText('At last snapshot')).toBeInTheDocument();
 expect(screen.getByText(/Uncorrelated/)).toBeInTheDocument();
 expect(screen.getByText('Not independently verified')).toBeInTheDocument();
 expect(screen.getByRole('button',{name:'Test Source'})).toBeDisabled();
});
it('saves an explicit HTTP source without issuing a Target request',async()=>{
 const collect=mocks([]);render(<EvidenceSources target={preset} nonce="nonce" secret="" authorized/>);
 fireEvent.click(screen.getByText('Evidence Sources'));
 await screen.findByText('No evidence sources configured.');
 fireEvent.click(screen.getByRole('button',{name:'Add Evidence Source'}));
 fireEvent.change(screen.getByLabelText('Source name'),{target:{value:'New source'}});
 fireEvent.change(screen.getByLabelText('Allowlisted endpoint'),{target:{value:source.endpoint}});
 expect(screen.getByText('Advanced source settings').closest('details')).not.toHaveAttribute('open');
 fireEvent.click(screen.getByRole('button',{name:'Save Source'}));
 await waitFor(()=>expect(testingApi.saveEvidenceSource).toHaveBeenCalledWith(expect.objectContaining({
   target_id:preset.id,target_revision:preset.profile_revision,endpoint:source.endpoint,collection_mode:'snapshot'}),null,null,'','nonce'));
 expect(collect).not.toHaveBeenCalled();
});
it('never loads or collects without operator access',()=>{
 const collect=mocks();render(<EvidenceSources target={preset} nonce="nonce" secret="" authorized={false}/>);
 expect(testingApi.listEvidenceSources).not.toHaveBeenCalled();expect(collect).not.toHaveBeenCalled();
});
it('explains explicit startup policy when no endpoint is allowlisted',async()=>{
 const collect=mocks([]);
 vi.mocked(testingApi.listEvidenceSources).mockResolvedValue({sources:[],allowed_endpoints:[]});
 render(<EvidenceSources target={preset} nonce="nonce" secret="" authorized/>);
 fireEvent.click(screen.getByText('Evidence Sources'));
 expect(await screen.findByText(/Evidence collection is off for this server session/)).toBeInTheDocument();
 expect(screen.getByText(/--evidence-policy/)).toBeInTheDocument();
 expect(screen.getByRole('button',{name:'Add Evidence Source'})).toBeDisabled();
 expect(collect).not.toHaveBeenCalled();
});
it('shows source failure without changing action readiness or retrying',async()=>{
 const collect=mocks();collect.mockResolvedValue({...capture,availability:'unavailable',error:'malformed_json'});
 render(<EvidenceSources target={preset} nonce="nonce" secret="" authorized/>);
 fireEvent.click(screen.getByText('Evidence Sources'));await screen.findByText('Detector log');
 fireEvent.click(screen.getByLabelText(/I authorize one read-only snapshot/));fireEvent.click(screen.getByRole('button',{name:'Test Source'}));
 await screen.findByText('Failed at last snapshot');expect(collect).toHaveBeenCalledTimes(1);
 expect(screen.getByRole('button',{name:'Test Source'})).toBeDisabled();
 expect(screen.getByText('Not independently verified')).toBeInTheDocument();
});
it('edits with an exact revision and allows disabling without deleting captures',async()=>{
 const collect=mocks();render(<EvidenceSources target={preset} nonce="nonce" secret="" authorized/>);
 fireEvent.click(screen.getByText('Evidence Sources'));await screen.findByText('Detector log');
 fireEvent.click(screen.getByRole('button',{name:'Edit'}));fireEvent.click(screen.getByLabelText('Source enabled'));
 fireEvent.click(screen.getByRole('button',{name:'Save Source'}));
 await waitFor(()=>expect(testingApi.saveEvidenceSource).toHaveBeenCalledWith(expect.objectContaining({enabled:false}),source.id,source.revision,'','nonce'));
 expect(collect).not.toHaveBeenCalled();
});
it('discards a late collection result after switching target',async()=>{
 let resolve!:(v:EvidenceCapture)=>void;
 const collect=mocks();collect.mockImplementation(()=>new Promise(r=>{resolve=r;}));
 const view=render(<EvidenceSources target={preset} nonce="nonce" secret="" authorized/>);
 fireEvent.click(screen.getByText('Evidence Sources'));await screen.findByText('Detector log');
 fireEvent.click(screen.getByLabelText(/I authorize one read-only snapshot/));fireEvent.click(screen.getByRole('button',{name:'Test Source'}));
 vi.mocked(testingApi.listEvidenceSources).mockResolvedValue({sources:[],allowed_endpoints:[]});
 view.rerender(<EvidenceSources target={{...preset,id:'other'}} nonce="nonce" secret="" authorized/>);
 resolve(capture);await screen.findByText('No evidence sources configured.');
 expect(screen.queryByText('Detector log')).not.toBeInTheDocument();
 expect(screen.queryByText('At last snapshot')).not.toBeInTheDocument();
});
it('rejects source API records belonging to another selected target',async()=>{
 vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response(JSON.stringify({workflow_schema_version:'1.0.0',
  sources:[{...source,target_id:'other'}],allowed_endpoints:[],action_verification_supported:false}),{status:200}));
 await expect(testingApi.listEvidenceSources(preset.id,'','nonce')).rejects.toThrow('unsupported operator response');
});
it('rejects API claims which promote collected log content to trusted action evidence',async()=>{
 vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response(JSON.stringify({workflow_schema_version:'1.0.0',
  capture:{...capture,action_eligible:true}}),{status:200}));
 await expect(testingApi.collectEvidenceSource(source.id,source.revision,'','nonce')).rejects.toThrow('unsupported operator response');
});
it('does not accept a saved profile bound to a different target revision',async()=>{
 vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response(JSON.stringify({workflow_schema_version:'1.0.0',
  source:{...source,target_revision:'f'.repeat(64)}}),{status:200}));
 await expect(testingApi.saveEvidenceSource(source,source.id,source.revision,'','nonce')).rejects.toThrow('unsupported operator response');
});
