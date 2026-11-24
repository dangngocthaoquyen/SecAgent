import {useEffect,useState} from 'react';
import {
 testingApi,
 type EnvironmentAuthorizationScope,
 type HostedMcpAgentBinding,
 type McpCapabilityTool,
 type McpToolCatalog,
 type ReviewedToolSpec,
 type TargetPreset,
 type ToolArgumentPredicate,
} from './testingApi';

function csvList(raw:string):string[]{
 return raw.split(',').map(s=>s.trim()).filter(Boolean);
}

export default function AgentOnboardingPanel({
 targets,
 nonce,
 secret,
 onChanged,
}:{
 targets:TargetPreset[];
 nonce:string;
 secret:string;
 onChanged?:()=>void;
}){
 const llmTargets=targets.filter(t=>t.protocol==='openai-chat');
 const mcpTargets=targets.filter(t=>t.protocol==='mcp-jsonrpc');

 const [mcpTargetId,setMcpTargetId]=useState(mcpTargets[0]?.id??'');
 const [llmTargetId,setLlmTargetId]=useState(llmTargets[0]?.id??'');
 const [catalogs,setCatalogs]=useState<McpToolCatalog[]>([]);
 const [bindings,setBindings]=useState<HostedMcpAgentBinding[]>([]);
 const [discoveryId,setDiscoveryId]=useState('');
 const [discoveredTools,setDiscoveredTools]=useState<McpCapabilityTool[]|null>(null);
 const [selectedToolNames,setSelectedToolNames]=useState<string[]>([]);
 const [catalogName,setCatalogName]=useState('Reviewed MCP Tool Catalog');
 const [manualToolsJson,setManualToolsJson]=useState('');
 const [activeCatalogId,setActiveCatalogId]=useState('');
 const [catalogConfirm,setCatalogConfirm]=useState(false);

 const [model,setModel]=useState(llmTargets[0]?.default_model??'');
 const [systemPrompt,setSystemPrompt]=useState('You are an AI assistant. Follow operator policy and security boundaries.');
 const [writePrefixes,setWritePrefixes]=useState('');
 const [writeScopedTools,setWriteScopedTools]=useState('');
 const [fetchHosts,setFetchHosts]=useState('');
 const [fetchScopedTools,setFetchScopedTools]=useState('');
 const [authPredicatesJson,setAuthPredicatesJson]=useState('[]');
 const [prohibPredicatesJson,setProhibPredicatesJson]=useState('[]');
 const [maxModelCalls,setMaxModelCalls]=useState(4);
 const [maxToolCalls,setMaxToolCalls]=useState(3);
 const [bindingConfirm,setBindingConfirm]=useState(false);

 const [busy,setBusy]=useState(false);
 const [error,setError]=useState('');
 const [statusMessage,setStatusMessage]=useState('');

 async function refresh(){
  if(!nonce)return;
  try{
   const [cats,binds]=await Promise.all([
    testingApi.listMcpCatalogs(secret,nonce),
    testingApi.listAgentBindings(secret,nonce),
   ]);
   setCatalogs(cats);
   setBindings(binds);
   if(!activeCatalogId&&cats.length){
    const preferred=cats.find(c=>c.draft.mcp_target_id===(mcpTargetId||mcpTargets[0]?.id))??cats[0];
    if(preferred)setActiveCatalogId(preferred.catalog_id);
   }
  }catch{
   // Panel remains usable once Workflow API management endpoints are ready.
  }
 }

 useEffect(()=>{
  setMcpTargetId(curr=>mcpTargets.some(t=>t.id===curr)?curr:(mcpTargets[0]?.id??''));
  setLlmTargetId(curr=>{
   const valid=llmTargets.some(t=>t.id===curr);
   if(valid)return curr;
   const first=llmTargets[0];
   if(first&&!model)setModel(first.default_model);
   return first?.id??'';
  });
 },[targets]);

 useEffect(()=>{
  const llm=llmTargets.find(t=>t.id===llmTargetId);
  if(llm&&!llm.models.includes(model))setModel(llm.default_model);
 },[llmTargetId]);

 useEffect(()=>{
  void refresh();
 },[nonce,secret,targets.length]);

 async function loadDiscovery(){
  if(!discoveryId.trim()||!nonce)return;
  setBusy(true);setError('');setStatusMessage('');
  try{
   const manifest=await testingApi.getDiscoveryMcpTools(discoveryId.trim(),secret,nonce);
   setDiscoveredTools(manifest.tools);
   setSelectedToolNames(manifest.tools.filter(t=>t.schema_compatible).map(t=>t.name));
   setStatusMessage(`Loaded ${manifest.tools.length} discovered MCP tools.`);
  }catch(e){
   setError(e instanceof Error?e.message:'Failed to load discovered MCP tools.');
  }finally{setBusy(false);}
 }

 async function saveCatalogDraft(){
  if(!mcpTargetId||!nonce)return;
  setBusy(true);setError('');setStatusMessage('');
  try{
   let created:McpToolCatalog;
   if(manualToolsJson.trim()){
    const parsed=JSON.parse(manualToolsJson) as ReviewedToolSpec[];
    if(!Array.isArray(parsed)||parsed.length===0)throw Error('Manual tools JSON must be a non-empty array.');
    created=await testingApi.createMcpCatalogDraft({
     mcp_target_id:mcpTargetId,
     catalog_name:catalogName.trim()||'Reviewed MCP Tool Catalog',
     ...(discoveryId.trim()?{discovery_id:discoveryId.trim()}:{}),
     reviewed_tools:parsed,
    },secret,nonce);
   }else{
    if(!discoveryId.trim())throw Error('Provide a 32-hex Discovery ID or paste manual tool schemas JSON.');
    created=await testingApi.createMcpCatalogDraft({
     mcp_target_id:mcpTargetId,
     catalog_name:catalogName.trim()||'Reviewed MCP Tool Catalog',
     discovery_id:discoveryId.trim(),
     selected_tool_names:selectedToolNames,
    },secret,nonce);
   }
   setActiveCatalogId(created.catalog_id);
   setCatalogConfirm(false);
   setStatusMessage(`Saved Tool Catalog draft ${created.catalog_id.slice(0,12)} (${created.review_status}).`);
   await refresh();
   onChanged?.();
  }catch(e){
   setError(e instanceof Error?e.message:'Failed to save MCP Tool Catalog draft.');
  }finally{setBusy(false);}
 }

 async function approveCatalog(cat:McpToolCatalog){
  if(!nonce||!catalogConfirm)return;
  setBusy(true);setError('');setStatusMessage('');
  try{
   const reviewed=await testingApi.reviewMcpCatalog(cat.catalog_id,cat.revision_sha256,secret,nonce);
   setCatalogConfirm(false);
   setStatusMessage(`Tool Catalog ${reviewed.catalog_id.slice(0,12)} reviewed (${reviewed.binding.tool_catalog_sha256.slice(0,12)}...).`);
   await refresh();
   onChanged?.();
  }catch(e){
   setError(e instanceof Error?e.message:'Failed to review MCP Tool Catalog.');
  }finally{setBusy(false);}
 }

 async function saveBindingDraft(){
  if(!llmTargetId||!mcpTargetId||!nonce)return;
  setBusy(true);setError('');setStatusMessage('');
  try{
   const authPreds=JSON.parse(authPredicatesJson||'[]') as ToolArgumentPredicate[];
   const prohibPreds=JSON.parse(prohibPredicatesJson||'[]') as ToolArgumentPredicate[];
   const wp=csvList(writePrefixes),wt=csvList(writeScopedTools),fh=csvList(fetchHosts),ft=csvList(fetchScopedTools);
   const envScope:EnvironmentAuthorizationScope|null=(wp.length||wt.length||fh.length||ft.length)?{
    ...(wp.length?{allowed_write_path_prefixes:wp}:{}),
    ...(wt.length?{write_scoped_tools:wt}:{}),
    ...(fh.length?{allowed_fetch_hosts:fh}:{}),
    ...(ft.length?{fetch_scoped_tools:ft}:{}),
   }:null;
   const chosenCat=catalogs.find(c=>c.catalog_id===activeCatalogId);
   let manualReviewedTools:ReviewedToolSpec[]|undefined;
   if(!chosenCat&&manualToolsJson.trim()){
    manualReviewedTools=JSON.parse(manualToolsJson) as ReviewedToolSpec[];
   }
   const created=await testingApi.createAgentBindingDraft({
    llm_target_id:llmTargetId,
    mcp_target_id:mcpTargetId,
    ...(chosenCat?{catalog_id:chosenCat.catalog_id,catalog_revision_sha256:chosenCat.revision_sha256}:{}),
    ...(manualReviewedTools?{reviewed_tools:manualReviewedTools}:{}),
    model:model.trim(),
    system_prompt:systemPrompt,
    environment_scope:envScope,
    max_model_calls:maxModelCalls,
    max_tool_calls:maxToolCalls,
    authorized_predicates:authPreds,
    prohibited_predicates:prohibPreds,
   },secret,nonce);
   setBindingConfirm(false);
   setStatusMessage(`Saved Agent Binding draft ${created.binding_id.slice(0,12)} (${created.review_status}).`);
   await refresh();
   onChanged?.();
  }catch(e){
   setError(e instanceof Error?e.message:'Failed to save Hosted MCP Agent Binding draft.');
  }finally{setBusy(false);}
 }

 async function approveBinding(binding:HostedMcpAgentBinding){
  if(!nonce||!bindingConfirm)return;
  setBusy(true);setError('');setStatusMessage('');
  try{
   const reviewed=await testingApi.reviewAgentBinding(binding.binding_id,binding.revision_sha256,secret,nonce);
   setBindingConfirm(false);
   setStatusMessage(`Hosted MCP Agent Binding ${reviewed.binding_id.slice(0,12)} approved (${reviewed.runtime_binding_ready?'ready':'blockers remain'}).`);
   await refresh();
   onChanged?.();
  }catch(e){
   setError(e instanceof Error?e.message:'Failed to approve Hosted MCP Agent Binding.');
  }finally{setBusy(false);}
 }

 const mcpCatalogs=catalogs.filter(c=>!mcpTargetId||c.draft.mcp_target_id===mcpTargetId);
 const activeCatalog=catalogs.find(c=>c.catalog_id===activeCatalogId)??mcpCatalogs[mcpCatalogs.length-1]??null;
 const matchingBindings=bindings.filter(b=>(!llmTargetId||b.draft.llm_target_id===llmTargetId)&&(!mcpTargetId||b.draft.mcp_target_id===mcpTargetId));
 const latestBinding=matchingBindings[matchingBindings.length-1]??bindings[bindings.length-1]??null;

 return <section className="panel agent-onboarding-panel" aria-label="Hosted MCP Agent Onboarding">
  <div className="section-title">
   <div>
    <span className="eyebrow">GENERIC HOSTED MCP AGENT</span>
    <h2>Tool Catalog &amp; Agent Composition</h2>
    <p>Compose any Hosted MCP Agent (LLM Host + System Prompt + Reviewed Tool Catalog + MCP Server) without editing source code.</p>
   </div>
   <button type="button" disabled={busy} onClick={()=>void refresh()}>Reload Catalogs &amp; Bindings</button>
  </div>

  {error&&<p role="alert" className="notice error">{error}</p>}
  {statusMessage&&<p role="status" className="notice">{statusMessage}</p>}

  <div className="onboarding-grid">
   <fieldset className="panel">
    <legend>1 · MCP Tool Catalog Review</legend>
    <label htmlFor="onboarding-mcp-target">MCP Tool Server Target
     <select id="onboarding-mcp-target" value={mcpTargetId} onChange={e=>setMcpTargetId(e.target.value)}>
      {mcpTargets.length===0&&<option value="">No MCP targets configured</option>}
      {mcpTargets.map(t=><option key={t.id} value={t.id}>{t.name} ({t.id}) [{t.authorization_status==='reviewed_for_offline_configuration'?'Reviewed':'Unreviewed'}]</option>)}
     </select>
    </label>
    <div className="onboarding-row">
     <label htmlFor="onboarding-discovery-id">Discovery ID (optional)
      <input id="onboarding-discovery-id" value={discoveryId} onChange={e=>setDiscoveryId(e.target.value)} placeholder="32-hex discovery ID from Connect target"/>
     </label>
     <button type="button" disabled={busy||!discoveryId.trim()} onClick={()=>void loadDiscovery()}>Load Discovered Tools</button>
    </div>

    {discoveredTools&&<div className="discovered-tools-checklist" aria-label="Select discovered tools">
     <p className="caption">Select schema-compatible tools to include in this catalog:</p>
     <ul>{discoveredTools.map(tool=>(
      <li key={tool.name}>
       <label>
        <input
         type="checkbox"
         disabled={!tool.schema_compatible}
         checked={selectedToolNames.includes(tool.name)}
         onChange={e=>setSelectedToolNames(prev=>e.target.checked?[...prev,tool.name]:prev.filter(n=>n!==tool.name))}
        />
        <strong>{tool.name}</strong> ({tool.schema_compatible?'compatible':`incompatible: ${tool.schema_error}`})
       </label>
       {tool.description&&<small> — {tool.description}</small>}
      </li>
     ))}</ul>
    </div>}

    <label htmlFor="onboarding-catalog-name">Catalog Name
     <input id="onboarding-catalog-name" value={catalogName} onChange={e=>setCatalogName(e.target.value)}/>
    </label>

    <details>
     <summary>Manual Tool Schemas JSON (fallback when discovery is unavailable)</summary>
     <label htmlFor="onboarding-manual-tools-json">Tools JSON Array
      <textarea id="onboarding-manual-tools-json" rows={4} value={manualToolsJson} onChange={e=>setManualToolsJson(e.target.value)} placeholder='[{"name":"list_notes","description":"List notes","input_schema":{"type":"object","properties":{"folder":{"type":"string"}},"required":["folder"],"additionalProperties":false}}]'/>
     </label>
    </details>

    <button type="button" className="primary" disabled={busy||!mcpTargetId} onClick={()=>void saveCatalogDraft()}>Save Catalog Draft</button>

    {mcpCatalogs.length>0&&<div className="saved-catalogs">
     <label htmlFor="onboarding-catalog-select">Saved Catalogs for Target
      <select id="onboarding-catalog-select" value={activeCatalog?.catalog_id??''} onChange={e=>setActiveCatalogId(e.target.value)}>
       {mcpCatalogs.map(c=><option key={c.catalog_id} value={c.catalog_id}>{c.draft.catalog_name} ({c.catalog_id.slice(0,8)}) · {c.review_status.toUpperCase()} · {c.binding.tool_names.length} tools</option>)}
      </select>
     </label>
     {activeCatalog&&<div className="catalog-status-card" role="status">
      <p>Status: <strong>{activeCatalog.review_status}</strong> · Catalog SHA-256: <code>{activeCatalog.binding.tool_catalog_sha256.slice(0,16)}...</code></p>
      <p>Tools: {activeCatalog.binding.tool_names.join(', ')}</p>
      {activeCatalog.readiness_blockers.length>0&&<p className="caption">Blockers: {activeCatalog.readiness_blockers.join(', ')}</p>}
      {activeCatalog.review_status==='draft'&&<>
       <label className="target-consent">
        <input type="checkbox" checked={catalogConfirm} onChange={e=>setCatalogConfirm(e.target.checked)}/>
        <span>I confirm this MCP Tool Catalog schema &amp; tool exposure for revision {activeCatalog.revision_sha256.slice(0,12)}...</span>
       </label>
       <button type="button" className="primary" disabled={busy||!catalogConfirm} onClick={()=>void approveCatalog(activeCatalog)}>Review / Approve Tool Catalog</button>
      </>}
     </div>}
    </div>}
   </fieldset>

   <fieldset className="panel">
    <legend>2 · Hosted MCP Agent Binding &amp; Policy</legend>
    <p className="caption">Separates <strong>Tool Exposure</strong> (Reviewed Tool Catalog) from <strong>Operator Safety Scope</strong> (<code>environment_scope</code>) and <strong>ASI05 Action Predicates</strong>. Credentials stay on the server.</p>
    <label htmlFor="onboarding-llm-target">LLM Host Target (OpenAI-compatible)
     <select id="onboarding-llm-target" value={llmTargetId} onChange={e=>setLlmTargetId(e.target.value)}>
      {llmTargets.length===0&&<option value="">No OpenAI-chat targets configured</option>}
      {llmTargets.map(t=><option key={t.id} value={t.id}>{t.name} ({t.id}) [{t.authorization_status==='reviewed_for_offline_configuration'?'Reviewed':'Unreviewed'}]</option>)}
     </select>
    </label>
    <label htmlFor="onboarding-model">LLM Model
     <input id="onboarding-model" value={model} onChange={e=>setModel(e.target.value)}/>
    </label>
    <label htmlFor="onboarding-system-prompt">Agent System Prompt
     <textarea id="onboarding-system-prompt" rows={3} value={systemPrompt} onChange={e=>setSystemPrompt(e.target.value)}/>
    </label>
    <div className="onboarding-row">
     <label htmlFor="onboarding-max-model">Max Model Calls
      <input id="onboarding-max-model" type="number" min={1} max={4} value={maxModelCalls} onChange={e=>setMaxModelCalls(Number(e.target.value)||4)}/>
     </label>
     <label htmlFor="onboarding-max-tool">Max Tool Calls
      <input id="onboarding-max-tool" type="number" min={0} max={3} value={maxToolCalls} onChange={e=>setMaxToolCalls(Number(e.target.value)||0)}/>
     </label>
    </div>

    <details>
     <summary>Operator Safety Scope (environment_scope · optional)</summary>
     <label htmlFor="onboarding-write-prefixes">Allowed write path prefixes (comma-separated)
      <input id="onboarding-write-prefixes" value={writePrefixes} onChange={e=>setWritePrefixes(e.target.value)} placeholder="notes/public/, lab/disposable/"/>
     </label>
     <label htmlFor="onboarding-write-tools">Write-scoped tools (comma-separated)
      <input id="onboarding-write-tools" value={writeScopedTools} onChange={e=>setWriteScopedTools(e.target.value)} placeholder="write_file, append_note"/>
     </label>
     <label htmlFor="onboarding-fetch-hosts">Allowed fetch hosts (comma-separated)
      <input id="onboarding-fetch-hosts" value={fetchHosts} onChange={e=>setFetchHosts(e.target.value)} placeholder="127.0.0.1, localhost"/>
     </label>
     <label htmlFor="onboarding-fetch-tools">Fetch-scoped tools (comma-separated)
      <input id="onboarding-fetch-tools" value={fetchScopedTools} onChange={e=>setFetchScopedTools(e.target.value)} placeholder="fetch_url, webhook_post"/>
     </label>
    </details>

    <details>
     <summary>ASI05 Tool Argument Predicates (JSON · optional)</summary>
     <label htmlFor="onboarding-auth-predicates">Authorized Predicates JSON
      <textarea id="onboarding-auth-predicates" rows={3} value={authPredicatesJson} onChange={e=>setAuthPredicatesJson(e.target.value)}/>
     </label>
     <label htmlFor="onboarding-prohib-predicates">Prohibited Predicates JSON
      <textarea id="onboarding-prohib-predicates" rows={3} value={prohibPredicatesJson} onChange={e=>setProhibPredicatesJson(e.target.value)}/>
     </label>
    </details>

    <button type="button" className="primary" disabled={busy||!llmTargetId||!mcpTargetId} onClick={()=>void saveBindingDraft()}>Save Agent Binding Draft</button>

    {latestBinding&&<div className="binding-status-card" role="status">
     <p>Latest Binding: <strong>{latestBinding.draft.llm_target_id} + {latestBinding.draft.mcp_target_id}</strong> · Status: <strong>{latestBinding.review_status}</strong> · Ready: <strong>{latestBinding.runtime_binding_ready?'Yes':'No'}</strong></p>
     <p><small>Revision: <code>{latestBinding.revision_sha256.slice(0,16)}...</code> · Case request budget: {latestBinding.binding.case_request_budget}</small></p>
     {latestBinding.readiness_blockers.length>0&&<p className="caption">Blockers: {latestBinding.readiness_blockers.join(', ')}</p>}
     {latestBinding.review_status==='draft'&&<>
      <label className="target-consent">
       <input type="checkbox" checked={bindingConfirm} onChange={e=>setBindingConfirm(e.target.checked)}/>
       <span>I confirm this Hosted MCP Agent runtime binding &amp; policy revision {latestBinding.revision_sha256.slice(0,12)}...</span>
      </label>
      <button type="button" className="primary" disabled={busy||!bindingConfirm} onClick={()=>void approveBinding(latestBinding)}>Review / Approve Agent Binding</button>
     </>}
    </div>}
   </fieldset>
  </div>
 </section>;
}
