import {fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import {expect, it, vi} from 'vitest';
import TargetConfiguration from './TargetConfiguration';
import TargetManager from './TargetManager';
import App from './App';
import {testingApi, type ProbeResult, type ValidationResult} from './testingApi';
import {preset, valid} from './test/targetFixtures';

const connected: ProbeResult = {connection_status:'succeeded', reason:'openai_chat_response',
 target_request_count:1, connection_reachable:true, runtime_protocol_compatible:true,
 http_status:200, security_test_executed:false, security_verdict:null};
const reviewed = {...preset, connection_probe:{status:'supported' as const,
 reason:'reviewed_exact_endpoint', active_probe_authorized:true, security_execution_authorized:false as const}};
function setup(){
 vi.spyOn(testingApi,'health').mockResolvedValue({nonce:'n'.repeat(43), evaluationModes:['rule_only'],
  managementEnabled:true, localSingleUser:true, controlledRunsEnabled:true, offlineBatchEnabled:false,
  asi01BatchEnabled:false, asi01TextTargets:[], webLabBatchEnabled:false, toolbotLabBatchEnabled:false,
  customImportedBatchEnabled:true, importedLiveLocalEnabled:true, importedLiveLocalMocked:false,
  judgeSetupReason:'judge_configuration_missing',mcpActionSetupReason:'catalog_missing'});
 vi.spyOn(testingApi,'targets').mockResolvedValue({targets:[reviewed,{...reviewed,id:'other',name:'Other agent',
  platform_id:'other',platform_name:'Other',default_model:'other-model',models:['other-model'],
  endpoint:'http://127.0.0.1:7100/v1/chat/completions',profile_revision:'b'.repeat(64)}],protocols:[]});
 vi.spyOn(testingApi,'validate').mockImplementation(async draft=>({...valid,configuration_status:'valid' as const,target_execution_performed:false as const,target_id:draft.target_id,profile_revision:draft.profile_revision}));
 return vi.spyOn(testingApi,'probe').mockResolvedValue(connected);
}
it('validates saved settings offline, keeps evidence optional and never probes on load or selection',async()=>{
 const probe=setup();render(<TargetConfiguration/>);
 fireEvent.click(await screen.findByRole('button',{name:'Select existing target'}));
 await screen.findByText('Configuration valid');
 expect(screen.getByRole('button',{name:'Test Connection'})).toBeDisabled();
 expect(screen.getByText('Advanced Settings').closest('details')).not.toHaveAttribute('open');
 expect(screen.getByText('Evidence Sources').closest('details')).not.toHaveAttribute('open');
 fireEvent.click(screen.getByText('Evidence Sources'));
 expect(screen.getByRole('button',{name:'Add Evidence Source'})).toBeDisabled();
 expect(screen.getByText(/Source configuration is not supported/)).toBeInTheDocument();
 expect(screen.getByText('Action verification not ready')).toBeInTheDocument();
 fireEvent.click(screen.getByRole('button',{name:/Other agent/}));
 fireEvent.click(screen.getByText('Advanced Settings'));
 await waitFor(()=>expect(screen.getByLabelText('Model')).toHaveValue('other-model'));
 expect(probe).not.toHaveBeenCalled();
});
it('probes only the explicitly authorized selection and revision',async()=>{
 const probe=setup();render(<TargetConfiguration/>);
 fireEvent.click(await screen.findByRole('button',{name:'Select existing target'}));
 await screen.findByText('Configuration valid');
 fireEvent.click(screen.getByRole('button',{name:/Other agent/}));
 await screen.findByRole('heading',{name:'Other agent'});
 await screen.findByText('Configuration valid',{}, {timeout:4000});
 fireEvent.click(screen.getByLabelText(/I confirm authorization for one benign probe/));
 await waitFor(()=>expect(screen.getByRole('button',{name:'Test Connection'})).toBeEnabled(),{timeout:4000});
 fireEvent.click(screen.getByRole('button',{name:'Test Connection'}));
 await waitFor(()=>expect(probe).toHaveBeenCalledTimes(1),{timeout:4000});
 expect(probe.mock.calls[0][0]).toMatchObject({id:'other',profile_revision:'b'.repeat(64),default_model:'other-model'});
});
it.each(['other','lab-one'])('discards a late probe result after switching target/revision to %s',async(id)=>{
 let resolve!:(result:ProbeResult)=>void;
 vi.spyOn(testingApi,'probe').mockImplementation(()=>new Promise(r=>{resolve=r;}));
 const changed=vi.fn();
 const view=render(<TargetManager enabled localSingleUser nonce={'n'.repeat(43)} target={reviewed} onChanged={changed}/>);
 fireEvent.click(screen.getByLabelText(/I confirm authorization for one benign probe/));
 fireEvent.click(screen.getByRole('button',{name:'Test Connection'}));
 view.rerender(<TargetManager enabled localSingleUser nonce={'n'.repeat(43)} target={{...reviewed,id,profile_revision:'b'.repeat(64)}} onChanged={changed}/>);
 resolve(connected);
 await waitFor(()=>expect(screen.getByRole('button',{name:'Test Connection'})).toBeDisabled());
 expect(screen.queryByText('Connected')).not.toBeInTheDocument();
 expect(changed).not.toHaveBeenCalled();
});
it('ignores a delayed offline validation for the previous selection',async()=>{
 setup();let resolve!:(value:ValidationResult)=>void;
 vi.mocked(testingApi.validate).mockImplementation(draft=>draft.target_id==='lab-one'?new Promise(r=>{resolve=r;}):Promise.resolve({
  ...valid,configuration_status:'invalid',target_execution_performed:false,target_id:draft.target_id,profile_revision:draft.profile_revision,errors:['stale_profile_revision']}));
 render(<TargetConfiguration/>);
 fireEvent.click(await screen.findByRole('button',{name:'Select existing target'}));
 await screen.findByRole('button',{name:/Other agent/});
 await waitFor(()=>expect(testingApi.validate).toHaveBeenCalled());
 fireEvent.click(screen.getByRole('button',{name:/Other agent/}));
 await screen.findByRole('heading',{name:'Configuration invalid'},{timeout:4000});
 resolve({...valid,configuration_status:'valid',target_execution_performed:false});
 await waitFor(()=>expect(screen.getByRole('heading',{name:'Configuration invalid'})).toBeInTheDocument());
 expect(screen.queryByText('Configuration valid')).not.toBeInTheDocument();
});
it('carries the selected target to Dataset Library without carrying authorization',async()=>{
 const probe=setup();
 const dataset={dataset_id:'d'.repeat(32),name:'Synthetic review dataset',schema_version:'1.0',source_tool:'test',imported_at:'2026-11-15T00:00:00Z',file_sha256:'e'.repeat(64),total_testcases:0};
 vi.spyOn(testingApi,'listDatasets').mockResolvedValue([dataset]);
 vi.spyOn(testingApi,'getDataset').mockResolvedValue({...dataset,testcases:[],source_metadata:{}});
 location.hash='#targets';render(<App/>);
 fireEvent.click(await screen.findByRole('button',{name:'Select existing target'}));
 await screen.findByText('Configuration valid');
 fireEvent.click(screen.getByRole('button',{name:/Other agent/}));
 await screen.findByRole('heading',{name:'Other agent'});
 fireEvent.click(screen.getByRole('link',{name:'Select Dataset'}));
 await screen.findByRole('button',{name:'Inspect & Select'},{timeout:4000});
 fireEvent.click(screen.getByRole('button',{name:'Inspect & Select'}));
 await waitFor(()=>expect(screen.getByLabelText('Target')).toHaveValue('other'));
 expect(probe).not.toHaveBeenCalled();
});
it('shows failed connection without claiming response-level readiness',async()=>{
 const probe=setup();probe.mockResolvedValue({...connected,connection_status:'unavailable',connection_reachable:false,runtime_protocol_compatible:null,http_status:null});
 render(<TargetConfiguration/>);
 fireEvent.click(await screen.findByRole('button',{name:'Select existing target'}));
 await screen.findByText('Configuration valid');
 fireEvent.click(screen.getByLabelText(/I confirm authorization for one benign probe/));
 fireEvent.click(screen.getByRole('button',{name:'Test Connection'}));
 await within(screen.getByLabelText('Selected target')).findByText('Connection failed');
 expect(screen.queryByText('Ready for response-level planning')).not.toBeInTheDocument();
 expect(screen.getByRole('button',{name:'Retry'})).toBeDisabled();
});
it('requires fresh consent in authenticated mode too',async()=>{
 vi.spyOn(testingApi,'unlock').mockResolvedValue([]);
 const probe=vi.spyOn(testingApi,'probe').mockResolvedValue(connected);
 render(<TargetManager enabled nonce={'n'.repeat(43)} target={reviewed} onChanged={vi.fn()}/>);
 fireEvent.change(screen.getByLabelText('Operator secret'),{target:{value:'synthetic-secret'}});
 fireEvent.click(screen.getByText('Unlock target management'));
 await screen.findByRole('button',{name:'Add Target'});
 expect(screen.getByRole('button',{name:'Test Connection'})).toBeDisabled();
 expect(probe).not.toHaveBeenCalled();
});
