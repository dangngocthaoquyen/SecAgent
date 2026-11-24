import {useEffect,useState,useRef,type ChangeEvent} from 'react';
import {testingApi,saveScanHandoff,type DatasetSummary,type DatasetEnvelope,type HostedMcpAgentBinding,type ImportedTestcase,type TargetPreset,draftFor} from './testingApi';
import BatchLaunch from './BatchLaunch';
import Asi03Review from './Asi03Review';
import Asi03TargetPolicy from './Asi03TargetPolicy';
import Asi05PolicyReview from './Asi05Policy';
import McpActionPanel from './McpActionPanel';
import AgentOnboardingPanel from './AgentOnboardingPanel';

export default function DatasetLibrary({nonce:propNonce,secret:propSecret='',targets:propTargets,initialTargetId=''}:{nonce?:string;secret?:string;targets?:TargetPreset[];initialTargetId?:string}={}){
 const [nonce,setNonce]=useState(propNonce||'');
 const [secret,setSecret]=useState(propSecret);
 const [targets,setTargets]=useState<TargetPreset[]>(propTargets||[]);
 const [datasets,setDatasets]=useState<DatasetSummary[]>([]);
 const [selectedDataset,setSelectedDataset]=useState<DatasetEnvelope|null>(null);
 const [selectedCaseIds,setSelectedCaseIds]=useState<string[]>([]);
 const [sourceFile,setSourceFile]=useState<File|null>(null);
 const [executionEnabled,setExecutionEnabled]=useState(false);
 const [liveLocalEnabled,setLiveLocalEnabled]=useState(false);
 const [hybridAvailable,setHybridAvailable]=useState(false);
 const [judgeSetupReason,setJudgeSetupReason]=useState('judge_configuration_missing');
 const [mcpSetupReason,setMcpSetupReason]=useState('catalog_missing');
 const [evaluationMode,setEvaluationMode]=useState<'rule_only'|'hybrid'>('rule_only');
 const [selectedAsi,setSelectedAsi]=useState<'unclassified'|'ASI01'|'ASI02'|'ASI03'|'ASI05'>('unclassified');
 const [asi05Scope,setAsi05Scope]=useState<'response_command_artifact'|'execution_action'>('response_command_artifact');
 const [assessmentKind,setAssessmentKind]=useState<'chat'|'mcp'|'hosted_agent'>('chat');
 const [agentBindings,setAgentBindings]=useState<HostedMcpAgentBinding[]>([]);
 const [selectedBindingId,setSelectedBindingId]=useState('');
 const [legacyCaseReview,setLegacyCaseReview]=useState(false);
 const [transportMode,setTransportMode]=useState<'offline_mock'|'live_local_http'>('offline_mock');
 const [previewEnvelope,setPreviewEnvelope]=useState<DatasetEnvelope|null>(null);
 const [error,setError]=useState('');
 const [busy,setBusy]=useState(false);
 const [selectedTargetId,setSelectedTargetId]=useState<string>(initialTargetId);
 const [reviewCaseId,setReviewCaseId]=useState<string>('');
 const [contractRevision,setContractRevision]=useState(0);
 const fileInputRef=useRef<HTMLInputElement|null>(null);

 useEffect(()=>{
  const controller=new AbortController();
  Promise.all([testingApi.health(controller.signal),testingApi.targets(controller.signal)])
   .then(([h,t])=>{
    if(controller.signal.aborted)return;
    setNonce(h.nonce);
    setExecutionEnabled(h.customImportedBatchEnabled);
    setLiveLocalEnabled(h.importedLiveLocalEnabled);
    setHybridAvailable(h.piJudgeReady===true&&h.judgeSetupReason!=='credential_missing');
    setJudgeSetupReason(h.piJudgeReady===true&&h.judgeSetupReason!=='credential_missing'?'ready_to_validate_at_run':h.judgeSetupReason);
    setMcpSetupReason(h.mcpActionSetupReason);
    setTargets(t.targets);
    setSelectedTargetId(current=>t.targets.some(target=>target.id===current)?current:(t.targets[0]?.id??''));
   })
   .catch(e=>{
    if(!controller.signal.aborted)setError(e instanceof Error?e.message:'Target service unavailable.');
   });
  return()=>controller.abort();
 },[propNonce,propTargets]);

 function reloadDatasets(){
  if(!nonce)return;
  testingApi.listDatasets(secret,nonce).then(items=>{
   setDatasets(items);
  }).catch(e=>{
   setError(e instanceof Error?e.message:'Failed to load dataset library.');
  });
 }

 useEffect(()=>{
  if(nonce)reloadDatasets();
 },[nonce,secret]);

 function reloadAgentBindings(){
  if(!nonce)return;
  testingApi.listAgentBindings(secret,nonce).then(items=>{
   setAgentBindings(items);
   setSelectedBindingId(curr=>items.some(b=>b.binding_id===curr)?curr:(items.find(b=>b.runtime_binding_ready)?.binding_id??items[items.length-1]?.binding_id??''));
  }).catch(()=>{});
 }

 useEffect(()=>{
  if(nonce&&assessmentKind==='hosted_agent')reloadAgentBindings();
 },[nonce,secret,assessmentKind]);

 async function handleFile(file:File){
  setError('');
  setSourceFile(null);
  setPreviewEnvelope(null);
  setBusy(true);
  try{
   if(file.size>5*1024*1024)throw new Error('Dataset file exceeds the 5 MB limit.');
   const preview=await testingApi.validateDataset(file,file.name,secret,nonce);
   setSourceFile(file);
   setPreviewEnvelope(preview);
  }catch(e){
   setError(e instanceof Error?e.message:'Invalid dataset file.');
   setPreviewEnvelope(null);
  }finally{
   setBusy(false);
  }
 }

 function onFileInputChange(e:ChangeEvent<HTMLInputElement>){
  const file=e.target.files?.[0];
  if(file)void handleFile(file);
 }

 async function savePreview(){
  if(!previewEnvelope||!sourceFile)return;
  setBusy(true);
  setError('');
  try{
   const result=await testingApi.importDataset(sourceFile,sourceFile.name,secret,nonce);
   setPreviewEnvelope(null);
   setSourceFile(null);
   reloadDatasets();
   setSelectedDataset(result.dataset);
   setReviewCaseId('');
   setSelectedCaseIds(result.dataset.testcases.map(c=>c.internal_id));
  }catch(e){
   setError(e instanceof Error?e.message:'Failed to import dataset.');
  }finally{
   setBusy(false);
  }
 }

 async function openDataset(datasetId:string){
  setError('');
  setBusy(true);
  try{
   const envelope=await testingApi.getDataset(datasetId,secret,nonce);
   setSelectedDataset(envelope);
   setReviewCaseId('');
   setSelectedCaseIds(envelope.testcases.map(c=>c.internal_id));
  }catch(e){
   setError(e instanceof Error?e.message:'Failed to load dataset.');
  }finally{
   setBusy(false);
  }
 }

 const isHostedAgent=assessmentKind==='hosted_agent';
 const selectedBinding=agentBindings.find(b=>b.binding_id===selectedBindingId)??agentBindings[0]??null;
 const bindingLlmTarget=selectedBinding?targets.find(t=>t.id===selectedBinding.draft.llm_target_id):undefined;
 const bindingMcpTarget=selectedBinding?targets.find(t=>t.id===selectedBinding.draft.mcp_target_id):undefined;
 const activeTarget=isHostedAgent?bindingLlmTarget:(targets.find(t=>t.id===selectedTargetId)??targets[0]);
 const targetDraft=activeTarget?draftFor(activeTarget,isHostedAgent&&selectedBinding?selectedBinding.draft.model:activeTarget.default_model,activeTarget.timeout_default):null;
 const mcpTargetDraft=isHostedAgent&&bindingMcpTarget?draftFor(bindingMcpTarget,bindingMcpTarget.default_model,bindingMcpTarget.timeout_default):undefined;
 const evaluationCategory=isHostedAgent?'ASI05':(selectedAsi==='ASI03'||selectedAsi==='ASI05'?selectedAsi:'unclassified');
 const scopeSupported=isHostedAgent?(Boolean(selectedBinding?.runtime_binding_ready)&&Boolean(targetDraft)&&Boolean(mcpTargetDraft)):(selectedAsi==='unclassified'||selectedAsi==='ASI03'||selectedAsi==='ASI05'&&asi05Scope==='response_command_artifact');
 const targetCompatible=isHostedAgent?(Boolean(targetDraft)&&Boolean(mcpTargetDraft)):(activeTarget?.protocol==='openai-chat');

 return (
  <div className="detail-page dataset-library">
   <div className="page-title">
    <div>
     <span className="eyebrow">SECURITY TESTING / DATASET LIBRARY</span>
     <h1>Testcase Datasets</h1>
     <p>Upload, review, and execute external JSON testcase collections</p>
    </div>
    <button disabled={busy} onClick={()=>{setPreviewEnvelope(null);setSourceFile(null);setSelectedDataset(null);reloadDatasets();}}>
     Refresh Library
    </button>
   </div>

   {error&&<div className="notice error" role="alert"><strong>Validation Error</strong><p>{error}</p></div>}
   <p className="caption" role="status">Shared Judge: {hybridAvailable?'Configured; each run still checks policy, credential and budget.':judgeSetupReason==='credential_missing'?'Setup required: Judge credential is absent in this application process.':'Setup required: add one operator-owned Judge configuration to runtime.json.'} MCP actions: {mcpSetupReason==='configured'?'Catalog configured; each action still needs admission.':'Setup required: select a structured MCP action catalog in runtime.json.'}</p>

   <div className="assessment-kind-tabs" role="group" aria-label="Assessment transport">
    <button aria-pressed={assessmentKind==='chat'} onClick={()=>setAssessmentKind('chat')}>Chat prompt assessment</button>
    <button aria-pressed={assessmentKind==='hosted_agent'} onClick={()=>setAssessmentKind('hosted_agent')}>Hosted MCP Agent assessment</button>
    <button aria-pressed={assessmentKind==='mcp'} onClick={()=>setAssessmentKind('mcp')}>MCP tool-action assessment</button>
   </div>
   {assessmentKind==='mcp'?<McpActionPanel targets={targets} nonce={nonce} secret={secret}/>:<>
   {isHostedAgent&&<details className="panel" open={agentBindings.length===0}>
    <summary><strong>Configure Hosted MCP Agent Tool Catalog &amp; Binding</strong> ({agentBindings.filter(b=>b.runtime_binding_ready).length} ready)</summary>
    <AgentOnboardingPanel targets={targets} nonce={nonce} secret={secret} onChanged={()=>{reloadAgentBindings();setContractRevision(v=>v+1);}}/>
   </details>}

   <section className="panel upload-panel">
    <h2>Import JSON Testcases</h2>
    <p>Upload a SecAgent envelope or Promptfoo redteam testcase export (max 5 MB, up to 100 cases).</p>
    <div className="upload-controls">
     <input
      type="file"
      accept=".json,.jsonl,.yaml,.yml,application/json"
      ref={fileInputRef}
      disabled={busy||!nonce}
      style={{display:'none'}}
      onChange={onFileInputChange}
     />
     <button className="primary" disabled={busy||!nonce} onClick={()=>fileInputRef.current?.click()}>
      {busy?'Processing...':'Choose JSON File'}
     </button>
    </div>

    {previewEnvelope&&<div className="panel preview-box">
     <h3>Validation Preview: {previewEnvelope.name}</h3>
     <p>
      Source tool: <strong>{previewEnvelope.source_tool}</strong> · Platform: <strong>{previewEnvelope.platform||'N/A'}</strong> · Bot: <strong>{previewEnvelope.bot||'N/A'}</strong> · Cases: <strong>{previewEnvelope.total_testcases}</strong>
     </p>
     <p>
      Supported Scan Modes: <span className="batch-cell-pill ready">Live Test</span>{' '}
      {(previewEnvelope.has_stored_responses===true||previewEnvelope.source_metadata?.has_stored_responses===true)&&<span className="batch-cell-pill ready">Offline Evaluation (Stored Responses)</span>}
     </p>
     <p><small>SHA-256: <code>{previewEnvelope.file_sha256}</code></small></p>
     <button className="primary" disabled={busy} onClick={savePreview}>
      Confirm & Import to Library
     </button>
     <button disabled={busy} onClick={()=>{setPreviewEnvelope(null);setSourceFile(null);}}>
      Discard
     </button>
    </div>}
   </section>

   <section className="panel library-list-panel">
    <h2>Available Datasets ({datasets.length})</h2>
    <p className="dataset-scroll-hint">Scroll the table horizontally to see all dataset columns.</p>
    {datasets.length===0?<p>No datasets imported yet. Upload a JSON testcase file above.</p>:(
     <div className="table-scroll">
      <table>
       <thead>
        <tr>
         <th>Dataset Name</th>
         <th>Cases</th>
         <th>Source Tool</th>
         <th>Platform / Bot</th>
         <th>Imported</th>
         <th>Action</th>
        </tr>
       </thead>
       <tbody>
        {datasets.map(d=>(
         <tr key={d.dataset_id} className={selectedDataset?.dataset_id===d.dataset_id?'selected-row':''}>
          <td><strong>{d.name}</strong></td>
          <td>{d.total_testcases}</td>
          <td>{d.source_tool}</td>
          <td>{d.platform||'-'} / {d.bot||'-'}</td>
          <td><small>{new Date(d.imported_at).toLocaleString()}</small></td>
          <td>
           <button onClick={()=>openDataset(d.dataset_id)}>
            {selectedDataset?.dataset_id===d.dataset_id?'Selected':'Inspect & Select'}
           </button>{' '}
           <a
            className="button-link"
            href="#scan"
            onClick={()=>{
             const selectedTestcaseIds=selectedDataset?.dataset_id===d.dataset_id
              ?selectedDataset.testcases.filter(tc=>selectedCaseIds.includes(tc.internal_id)).map(tc=>tc.testcase_id)
              :undefined;
             saveScanHandoff({
              dataset_id:d.dataset_id,
              target_id:activeTarget?.id,
              testcase_ids:selectedTestcaseIds,
             });
            }}
           >
            Scan →
           </a>
          </td>
         </tr>
        ))}
       </tbody>
      </table>
     </div>
    )}
   </section>

   {selectedDataset&&<section className="panel dataset-cases-panel">
    <div className="section-title">
     <div>
      <span className="eyebrow">DATASET INSPECTION</span>
      <h2>{selectedDataset.name} ({selectedDataset.total_testcases} testcases)</h2>
      <p>Source: {selectedDataset.source_tool} {selectedDataset.bot?`· ${selectedDataset.bot}`:''} {selectedDataset.run_id?`· run ${selectedDataset.run_id}`:''}</p>
     </div>
     <strong>{selectedCaseIds.length} of {selectedDataset.total_testcases} selected</strong>
    </div>

    {isHostedAgent&&<div className="target-selection-box panel" aria-label="Hosted MCP Agent Setup">
     <span className="eyebrow">HOSTED MCP AGENT SETUP</span><h3>Select reviewed agent binding</h3>
     {agentBindings.length===0?<p className="notice" role="status">No Hosted MCP Agent Bindings found. Configure and approve a Tool Catalog + Agent Binding above.</p>:(
      <label htmlFor="hosted-agent-binding-select">Hosted MCP Agent Binding
       <select id="hosted-agent-binding-select" value={selectedBinding?.binding_id??''} onChange={e=>{setSelectedBindingId(e.target.value);setContractRevision(v=>v+1);}}>
        {agentBindings.map(b=><option key={b.binding_id} value={b.binding_id}>{b.draft.llm_target_id} + {b.draft.mcp_target_id} ({b.draft.model}) · {b.review_status.toUpperCase()} {b.runtime_binding_ready?'[Ready]':'[Blocked]'}</option>)}
       </select>
      </label>
     )}
     {selectedBinding&&!selectedBinding.runtime_binding_ready&&<p className="notice" role="status"><strong>Agent binding not ready:</strong> {selectedBinding.readiness_blockers.join(', ')}.</p>}
    </div>}

    {!isHostedAgent&&targets.length>0&&<div className="target-selection-box panel" aria-label="Evaluation Setup">
     <span className="eyebrow">EVALUATION SETUP</span><h3>Target, scope and policy</h3>
     <p>Choose the target and evaluation scope before reviewing cases. Imported source labels are taxonomy only; they do not review a Security Policy.</p>
     <div className="evaluation-setup-grid">
      <label htmlFor="dataset-target-select">Target<select id="dataset-target-select" value={selectedTargetId} onChange={e=>{setSelectedTargetId(e.target.value);setReviewCaseId('');setContractRevision(v=>v+1);}}>{targets.map(t=><option key={t.id} value={t.id}>{t.name} ({t.endpoint}) [{t.authorization_status==='reviewed_for_offline_configuration'?'Reviewed':'Unreviewed'}]</option>)}</select></label>
      <label htmlFor="dataset-evaluation-category">ASI<select id="dataset-evaluation-category" value={selectedAsi} onChange={e=>{const value=e.target.value as typeof selectedAsi;setSelectedAsi(value);setReviewCaseId('');setLegacyCaseReview(false);setContractRevision(v=>v+1);if(value==='ASI03'||value==='ASI05')if(hybridAvailable)setEvaluationMode('hybrid');}}>
       <option value="unclassified">Imported / legacy rule-only</option><option value="ASI01">ASI01 · Goal hijacking</option><option value="ASI02">ASI02 · Tool misuse</option><option value="ASI03">ASI03 · Identity claims</option><option value="ASI05">ASI05 · Unexpected code execution</option>
      </select></label>
      <label htmlFor="dataset-evaluation-scope">Evaluation scope<select id="dataset-evaluation-scope" value={selectedAsi==='ASI05'?asi05Scope:selectedAsi==='ASI03'?'identity_claim_response':selectedAsi==='ASI01'?'goal_hijacking':selectedAsi==='ASI02'?'tool_action':'imported_rule_only'} onChange={e=>{if(selectedAsi==='ASI05'){setAsi05Scope(e.target.value as typeof asi05Scope);setReviewCaseId('');}}}>
       {selectedAsi==='ASI05'?<><option value="response_command_artifact">Response command artifact</option><option value="execution_action">Execution / action</option></>:<option value={selectedAsi==='ASI03'?'identity_claim_response':selectedAsi==='ASI01'?'goal_hijacking':selectedAsi==='ASI02'?'tool_action':'imported_rule_only'}>{selectedAsi==='ASI03'?'Identity claim in response':selectedAsi==='ASI01'?'Goal hijacking':selectedAsi==='ASI02'?'Tool action':'Imported rule-only'}</option>}
      </select></label>
      <label htmlFor="dataset-transport-mode">Transport<select id="dataset-transport-mode" value={transportMode} onChange={e=>setTransportMode(e.target.value as 'offline_mock'|'live_local_http')}><option value="offline_mock">Offline Mock · no target request</option>{liveLocalEnabled&&<option value="live_local_http">Live Local · reviewed chat target</option>}</select></label>
      <label htmlFor="dataset-evaluation-mode">Evaluation mode<select id="dataset-evaluation-mode" value={evaluationMode} onChange={e=>setEvaluationMode(e.target.value as 'rule_only'|'hybrid')}><option value="rule_only">Rule-only</option>{hybridAvailable&&<option value="hybrid">Hybrid Judge · reviewed response policy</option>}</select></label>
     </div>
     {transportMode==='live_local_http'&&<p>A compatible Test Connection on this exact reviewed target revision is required. Live Local sends each selected prompt once.</p>}
     {!scopeSupported&&<p className="notice" role="status"><strong>Not available for official evaluation.</strong> {selectedAsi==='ASI01'?'Use the controlled ASI01 workflow with a legitimate baseline and attack objective.':selectedAsi==='ASI02'?'Imported prompts do not provide tool invocation, handler receipts, authorization or correlation evidence.':'The imported chat workflow has no reviewed execution policy binding or correlated action trace.'}</p>}
     {!targetCompatible&&<p className="notice" role="status"><strong>Target incompatible.</strong> Imported natural-language prompts require an OpenAI-compatible chat target. They cannot be converted into MCP tools/call. Select a chat target or use a dedicated tool-action workflow.</p>}
     <p className="caption">Source taxonomy: {selectedDataset.source_tool}. Plugin names and assertions are untrusted import metadata; they do not select or review a SecAgent Policy.</p>
     {selectedAsi==='unclassified'&&<details className="target-advanced"><summary>Legacy ASI03 per-case contracts</summary><label className="target-consent"><input type="checkbox" checked={legacyCaseReview} onChange={e=>{setLegacyCaseReview(e.target.checked);setReviewCaseId('');}}/><span>Show the legacy per-case ASI03 contract editor. Only use it for identity claim response cases.</span></label></details>}
    </div>}

    {selectedAsi==='ASI03'&&activeTarget&&<Asi03TargetPolicy key={`${activeTarget.id}-${contractRevision}`} targetId={activeTarget.id}
      nonce={nonce} secret={secret} onChanged={()=>setContractRevision(value=>value+1)}/>}
    {selectedAsi==='ASI05'&&asi05Scope==='response_command_artifact'&&activeTarget&&<Asi05PolicyReview key={`${activeTarget.id}-${contractRevision}`} targetId={activeTarget.id}
      nonce={nonce} secret={secret} onChanged={()=>setContractRevision(value=>value+1)}/>}
    {selectedAsi==='unclassified'&&legacyCaseReview&&activeTarget&&reviewCaseId&&selectedDataset.testcases.some(c=>c.internal_id===reviewCaseId)&&<Asi03Review
      key={`${activeTarget.id}-${reviewCaseId}`} datasetId={selectedDataset.dataset_id}
      testcase={selectedDataset.testcases.find(c=>c.internal_id===reviewCaseId)!}
      targetId={activeTarget.id} nonce={nonce} secret={secret}
      onReviewed={()=>setContractRevision(value=>value+1)}/>}

    <div className="batch-selection-actions">
     <button onClick={()=>setSelectedCaseIds(selectedDataset.testcases.map(c=>c.internal_id))}>
      Select All Cases
     </button>
     <button onClick={()=>setSelectedCaseIds([])}>
      Clear Selection
     </button>
    </div>

    <p className="dataset-scroll-hint">Scroll the table horizontally to see all testcase columns.</p>

    <div className="table-scroll">
     <table>
      <thead>
       <tr>
        <th>Select</th>
        <th>ID</th>
        <th>Plugin / Assertion</th>
        <th>Prompt Content</th>
        <th>Policy / scope</th>
       </tr>
      </thead>
      <tbody>
       {selectedDataset.testcases.map((c:ImportedTestcase)=>(
        <tr key={c.testcase_id}>
         <td>
          <input
           type="checkbox"
           aria-label={`Select ${c.testcase_id}`}
           checked={selectedCaseIds.includes(c.internal_id)}
           onChange={e=>{
            setSelectedCaseIds(e.target.checked
             ?[...selectedCaseIds,c.internal_id]
             :selectedCaseIds.filter(id=>id!==c.internal_id));
           }}
          />
         </td>
         <td><strong>{c.testcase_id}</strong></td>
         <td>
          <span className="batch-cell-pill">{c.plugin_id||'prompt'}</span>
          {c.assertions.length>0&&<small>{String(c.assertions[0].type||'')}</small>}
         </td>
         <td className="prompt-cell">
          <p>{c.prompt}</p>
          <small>Hash: <code>{c.prompt_sha256.slice(0,16)}...</code></small>
         </td>
         <td>{selectedAsi==='unclassified'&&legacyCaseReview?<button onClick={()=>setReviewCaseId(c.internal_id)}>Review ASI03 case contract</button>:selectedAsi==='ASI03'||selectedAsi==='ASI05'&&scopeSupported?<span>Target policy</span>:<span>{scopeSupported?'Rule-only':'Unavailable'}</span>}</td>
        </tr>
       ))}
      </tbody>
     </table>
    </div>

    {!isHostedAgent&&selectedCaseIds.length>0&&(
     <div className="scan-step-actions" style={{marginTop:'1rem'}}>
      <a
       className="button-link primary"
       href="#scan"
       onClick={()=>{
        const selectedTestcaseIds=selectedDataset.testcases
         .filter(tc=>selectedCaseIds.includes(tc.internal_id))
         .map(tc=>tc.testcase_id);
        saveScanHandoff({
         dataset_id:selectedDataset.dataset_id,
         target_id:activeTarget?.id,
         testcase_ids:selectedTestcaseIds,
        });
       }}
      >
       Open Selected in New Scan ({selectedCaseIds.length} cases) →
      </a>
     </div>
    )}
    {isHostedAgent&&!executionEnabled&&<p>Imported execution requires the custom-import startup mode.</p>}
    {isHostedAgent&&executionEnabled&&scopeSupported&&targetCompatible&&targetDraft&&selectedCaseIds.length>0&&(
     <BatchLaunch
      key={`${assessmentKind}-${selectedDataset.dataset_id}-${activeTarget?.id}-${activeTarget?.profile_revision}-${mcpTargetDraft?.target_id}-${selectedBinding?.revision_sha256}-${selectedAsi}-${asi05Scope}-${transportMode}-${evaluationMode}-${contractRevision}`}
      target={targetDraft}
      ids={selectedCaseIds}
      nonce={nonce}
      synthetic={false}
      customImported={true}
      workflowId="imported"
      datasetId={selectedDataset.dataset_id}
      transportMode={isHostedAgent?'live_local_http':transportMode}
      evaluationMode={isHostedAgent?'rule_only':evaluationMode}
      evaluationCategory={evaluationCategory}
      executionPath={isHostedAgent?'mcp_agent_runtime':'direct_chat'}
      mcpTarget={mcpTargetDraft}
      agentBudgetMultiplier={selectedBinding?.binding.case_request_budget}
     />
    )}
   </section>}
   </>}
  </div>
 );
}
