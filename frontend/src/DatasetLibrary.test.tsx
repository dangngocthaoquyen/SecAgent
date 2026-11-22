import {afterEach,expect,it,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import DatasetLibrary from './DatasetLibrary';
import {testingApi} from './testingApi';
import {preset} from './test/targetFixtures';

afterEach(()=>vi.restoreAllMocks());

it('uploads the identical original File for validation and persistence',async()=>{
 const file=new File(['[ {"id":"雪","prompt":" spaced ","n":9007199254740993} ]\r\n'],'original.json',{type:'application/json'});
 const bodies:unknown[]=[];
 vi.spyOn(globalThis,'fetch').mockImplementation(async (_input,init)=>{
  bodies.push(init?.body);
  return new Response(JSON.stringify({workflow_schema_version:'1.0.0',dataset:mockEnvelope,created:true}));
 });
 await testingApi.validateDataset(file,file.name,'','n'.repeat(43));
 await testingApi.importDataset(file,file.name,'','n'.repeat(43));
 expect(bodies).toEqual([file,file]);
});

it('keeps the uploaded File through component preview and confirmation',async()=>{
 const file=new File(['[ {"id":"雪","prompt":" spaced ","n":9007199254740993} ]\r\n'],'original.json',{type:'application/json'});
 const uploads:unknown[]=[];
 vi.spyOn(globalThis,'fetch').mockImplementation(async (input,init)=>{
  const url=String(input);
  if(url.endsWith('/health'))return new Response(JSON.stringify({workflow_schema_version:'1.0.0',status:'ok',mode:'offline_configuration_only',target_network_access:false,custom_imported_batch_enabled:true,validation_nonce:'n'.repeat(43)}));
  if(url.endsWith('/targets'))return new Response(JSON.stringify({workflow_schema_version:'1.0.0',targets:[],protocols:[]}));
  if(url.endsWith('/datasets')&&init?.method!=='POST')return new Response(JSON.stringify({workflow_schema_version:'1.0.0',datasets:[]}));
  if(init?.method==='POST'){
   uploads.push(init.body);
   return new Response(JSON.stringify({workflow_schema_version:'1.0.0',dataset:mockEnvelope,created:true}));
  }
  return new Response('{}',{status:404});
 });
 const {container}=render(<DatasetLibrary/>);
 await waitFor(()=>expect(screen.queryByText('Imported execution requires the offline custom-import startup mode.')).not.toBeInTheDocument());
 fireEvent.change(container.querySelector('input[type="file"]')!,{target:{files:[file]}});
 await screen.findByRole('heading',{name:/Validation Preview:/});
 fireEvent.click(screen.getByRole('button',{name:'Confirm & Import to Library'}));
 await screen.findByRole('heading',{name:/30 testcases/});
 expect(uploads).toEqual([file,file]);
 expect(screen.queryByText('Imported execution requires the offline custom-import startup mode.')).not.toBeInTheDocument();
});

const mockDatasets = [
 {
  dataset_id: 'a'.repeat(32),
  name: 'codebot_asi02.json',
  schema_version: '1.0',
  source_tool: 'promptfoo',
  platform: 'DVAA',
  bot: 'codebot',
  run_id: 'asi02',
  imported_at: '2026-11-14T08:00:00Z',
  file_sha256: '1'.repeat(64),
  total_testcases: 30,
 }
];

const mockEnvelope = {
 ...mockDatasets[0],
 testcases: [
  {
   testcase_id: 'TC0001', internal_id: 'import-'+'1'.repeat(24),
   description: null,
   plugin_id: 'excessive-agency',
   strategy_id: null,
   prompt: 'Ask the developer sitting at desk B-14...',
   prompt_sha256: '2'.repeat(64),
   assertions: [{type: 'promptfoo:redteam:excessive-agency', metric: 'ExcessiveAgency'}],
   metadata: {pluginId: 'excessive-agency'},
   options: {},
   extra: {},
   index: 0,
  },
  {
   testcase_id: 'TC0002', internal_id: 'import-'+'2'.repeat(24),
   description: null,
   plugin_id: 'excessive-agency',
   strategy_id: null,
   prompt: 'Change the production database password...',
   prompt_sha256: '3'.repeat(64),
   assertions: [{type: 'promptfoo:redteam:excessive-agency', metric: 'ExcessiveAgency'}],
   metadata: {pluginId: 'excessive-agency'},
   options: {},
   extra: {},
   index: 1,
  }
 ],
 source_metadata: {},
};

it('renders dataset library and displays listed datasets',async()=>{
 vi.spyOn(globalThis,'fetch').mockImplementation(async input=>{
  const url=String(input);
  if(url.endsWith('/health'))return new Response(JSON.stringify({workflow_schema_version:'1.0.0',status:'ok',mode:'offline_configuration_only',target_network_access:false,validation_nonce:'n'.repeat(43)}));
  if(url.endsWith('/targets'))return new Response(JSON.stringify({workflow_schema_version:'1.0.0',targets:[],protocols:[]}));
  if(url.endsWith('/datasets'))return new Response(JSON.stringify({workflow_schema_version:'1.0.0',datasets:mockDatasets}));
  return new Response('{}',{status:404});
 });

 render(<DatasetLibrary nonce={'n'.repeat(43)}/>);
 expect(screen.getByRole('heading',{name:'Testcase Datasets'})).toBeInTheDocument();
 expect(await screen.findByText('codebot_asi02.json')).toBeInTheDocument();
 expect(screen.getByText('Available Datasets (1)')).toBeInTheDocument();
});

it('inspects a dataset and selects testcases',async()=>{
 vi.spyOn(globalThis,'fetch').mockImplementation(async input=>{
  const url=String(input);
  if(url.endsWith('/health'))return new Response(JSON.stringify({workflow_schema_version:'1.0.0',status:'ok',mode:'offline_configuration_only',target_network_access:false,validation_nonce:'n'.repeat(43)}));
  if(url.endsWith('/targets'))return new Response(JSON.stringify({workflow_schema_version:'1.0.0',targets:[],protocols:[]}));
  if(url.endsWith('/datasets'))return new Response(JSON.stringify({workflow_schema_version:'1.0.0',datasets:mockDatasets}));
  if(url.includes('/datasets/'+'a'.repeat(32)))return new Response(JSON.stringify({workflow_schema_version:'1.0.0',dataset:mockEnvelope}));
  return new Response('{}',{status:404});
 });

 render(<DatasetLibrary nonce={'n'.repeat(43)}/>);
 await screen.findByText('codebot_asi02.json');
 fireEvent.click(screen.getByRole('button',{name:'Inspect & Select'}));

 expect(await screen.findByRole('heading',{name:/codebot_asi02.json \(30 testcases\)/})).toBeInTheDocument();
 expect(screen.getByText('TC0001')).toBeInTheDocument();
 expect(screen.getByText('TC0002')).toBeInTheDocument();

 fireEvent.click(screen.getByRole('button',{name:'Clear Selection'}));
 expect(screen.getByText('0 of 30 selected')).toBeInTheDocument();

 fireEvent.click(screen.getByRole('button',{name:'Select All Cases'}));
 expect(screen.getByText('2 of 30 selected')).toBeInTheDocument();
});

it('keeps imported source taxonomy separate from the selected ASI policy and blocks unsupported action scope',async()=>{
 const getAsi03=vi.spyOn(testingApi,'getAsi03TargetPolicy').mockResolvedValue(null);
 const getAsi05=vi.spyOn(testingApi,'getAsi05Policy').mockResolvedValue(null);
 vi.spyOn(globalThis,'fetch').mockImplementation(async input=>{
  const url=String(input);
  if(url.endsWith('/health'))return new Response(JSON.stringify({workflow_schema_version:'1.0.0',status:'ok',mode:'offline_configuration_only',target_network_access:false,validation_nonce:'n'.repeat(43),custom_imported_batch_enabled:true,evaluation_modes:['rule_only','hybrid'],judge_configuration:'configured_unverified'}));
  if(url.endsWith('/targets'))return new Response(JSON.stringify({workflow_schema_version:'1.0.0',targets:[preset,{...preset,id:'second-chat',name:'Second Chat',profile_revision:'e'.repeat(64),endpoint:'http://127.0.0.1:7016/v1/chat/completions'}],protocols:[]}));
  if(url.endsWith('/datasets'))return new Response(JSON.stringify({workflow_schema_version:'1.0.0',datasets:mockDatasets}));
  if(url.includes('/datasets/'+'a'.repeat(32)))return new Response(JSON.stringify({workflow_schema_version:'1.0.0',dataset:{...mockEnvelope,testcases:mockEnvelope.testcases.map(c=>({...c,plugin_id:'shell-injection'}))}}));
  return new Response('{}',{status:404});
 });
 render(<DatasetLibrary nonce={'n'.repeat(43)}/>);
 await screen.findByText('codebot_asi02.json');
 fireEvent.click(screen.getByRole('button',{name:'Inspect & Select'}));
 await screen.findByText('TC0001');
 expect(screen.queryByRole('button',{name:'Review response claim'})).not.toBeInTheDocument();
 fireEvent.change(screen.getByLabelText('ASI'),{target:{value:'ASI05'}});
 expect(await screen.findByRole('heading',{name:/ASI05 response policy/})).toBeInTheDocument();
 expect(screen.queryByRole('heading',{name:/ASI03 identity policy/})).not.toBeInTheDocument();
 expect(getAsi05).toHaveBeenCalledWith(preset.id,'','n'.repeat(43));
 expect(getAsi03).not.toHaveBeenCalled();
 fireEvent.change(screen.getByRole('combobox',{name:'Target'}),{target:{value:'second-chat'}});
 await waitFor(()=>expect(getAsi05).toHaveBeenCalledWith('second-chat','','n'.repeat(43)));
 fireEvent.change(screen.getByLabelText('Evaluation scope'),{target:{value:'execution_action'}});
 expect(screen.getByText(/Not available for official evaluation/)).toBeInTheDocument();
 expect(screen.queryByRole('heading',{name:/ASI05 response policy/})).not.toBeInTheDocument();
 fireEvent.change(screen.getByLabelText('ASI'),{target:{value:'ASI03'}});
 expect(await screen.findByRole('heading',{name:/ASI03 identity policy/})).toBeInTheDocument();
 expect(screen.queryByRole('heading',{name:/ASI05 response policy/})).not.toBeInTheDocument();
});
