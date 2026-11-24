import {useRef,useState} from 'react';
import {testingApi,type DiscoveryResult,type ManagedProfile,type McpCapabilityManifest,type OpenApiCandidate} from './testingApi';

export default function DiscoveryPanel({nonce,secret,onUse,onReset}:{nonce:string;secret:string;
 onUse:(profile:ManagedProfile,discoveryId:string,result:DiscoveryResult,candidate?:OpenApiCandidate)=>Promise<void>;onReset:()=>void}){
 const [url,setUrl]=useState(''),[agentName,setAgentName]=useState(''),[hint,setHint]=useState(''),[specUrl,setSpecUrl]=useState(''),[confirmed,setConfirmed]=useState(false);
 const [busy,setBusy]=useState(false),[error,setError]=useState('');
 const [result,setResult]=useState<DiscoveryResult|null>(null);
 const [mcpManifest,setMcpManifest]=useState<McpCapabilityManifest|null>(null);
 const sequence=useRef(0);
 function reset(){sequence.current++;setBusy(false);setConfirmed(false);setResult(null);setMcpManifest(null);setError('');onReset();}
 async function selectOpenApiCandidate(candidate:OpenApiCandidate){
  if(!result)return;
  const parsed=new URL(candidate.endpoint);
  const slug=candidate.path.replace(/^\/+|\/+$/g,'').replace(/[^A-Za-z0-9_.-]+/g,'-').slice(0,40)||'http-api';
  const nameSlug=agentName.trim().toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,24);
  const baseId=`local-http-${parsed.port||80}-${slug}${nameSlug?`-${nameSlug}`:''}`.slice(0,120);
  const draft:ManagedProfile={
   id:baseId,
   name:agentName.trim()||candidate.summary||`HTTP Agent (${candidate.path})`.replace(/[^A-Za-z0-9 ._-]+/g,' ').trim().slice(0,100),
   platform_id:'local-agent',
   platform_name:'Local Agent',
   endpoint:candidate.endpoint,
   protocol:'http-json',
   model:null,
   timeout_seconds:30,
   http_config:candidate.suggested_http_config,
   capability_states:{response_behavior:'unverified',tool_intent:'unverified'},
  };
  await onUse(draft,result.discovery_id,result,candidate);
 }
 async function discover(){if(!confirmed||busy)return;const token=++sequence.current;setBusy(true);setError('');setResult(null);setMcpManifest(null);onReset();
  try{const row=specUrl.trim()?await testingApi.discover(url,nonce,secret,hint||undefined,specUrl.trim()):await testingApi.discover(url,nonce,secret,hint||undefined);if(token!==sequence.current)return;setResult(row);
   if(row.proposed_profile?.protocol==='mcp-jsonrpc'){
    const cap=await testingApi.getDiscoveryMcpTools(row.discovery_id,secret,nonce).catch(()=>null);
    if(token===sequence.current&&cap)setMcpManifest(cap);
   }
   if(row.proposed_profile)await onUse({...row.proposed_profile,name:agentName.trim()||row.proposed_profile.name},row.discovery_id,row);
   if(token===sequence.current)setConfirmed(false);
  }catch(e){if(token===sequence.current)setError(e instanceof Error?e.message:'Discovery unavailable.');}
  finally{if(token===sequence.current)setBusy(false);}
 }
 return <section className="discovery-panel" aria-label="Discover target from URL">
  <div className="connection-card-heading"><span className="target-step">01 · CONNECTION</span><h2>Connect an AI Agent</h2><p>Enter the local API URL. SecAgent will identify its protocol and check a safe connection contract.</p></div>
  <label className="agent-url-field">AI Agent URL<input type="url" value={url} onChange={e=>{setUrl(e.target.value);reset();}} placeholder="http://127.0.0.1:7004/v1/chat/completions"/></label>
  <label className="agent-name-field">Agent Name <span className="field-optional">Optional</span><input aria-label="Agent Name" value={agentName} maxLength={100} pattern="[A-Za-z0-9 ._-]+" onChange={e=>setAgentName(e.target.value)} placeholder="e.g. DVAA ToolBot"/><small>Display name only. The target identifier and connection address stay separate.</small></label>
  {!result?.proposed_profile&&<><label className="target-consent"><input type="checkbox" checked={confirmed} onChange={e=>setConfirmed(e.target.checked)}/><span>I authorize up to three bounded metadata requests and one benign connection probe to this exact local service. MCP uses tools/list only; no tool execution or security payload.</span></label>
  <div className="discovery-action"><button className="primary" disabled={!url||!confirmed||busy||!!agentName.trim()&&!/^[A-Za-z0-9 ._-]{1,100}$/.test(agentName.trim())} onClick={discover}>{busy?'Discovering and checking...':'Discover & Test Connection'}</button><span>Requests are limited by timeout, size and loopback rules.</span></div></>}
  <details className="target-advanced"><summary>Discovery options</summary>
   <label>Protocol hint<select value={hint} onChange={e=>{setHint(e.target.value);reset();}}><option value="">Automatic / adapter metadata</option><option value="openai-chat">OpenAI-compatible chat</option><option value="openapi-http">HTTP REST / OpenAPI</option><option value="mcp-jsonrpc">MCP JSON-RPC tools/list</option><option value="a2a">A2A metadata</option></select></label>
   <label>API specification URL <span className="field-optional">Optional (same local origin)</span><input type="url" value={specUrl} onChange={e=>{setSpecUrl(e.target.value);reset();}} placeholder="http://127.0.0.1:8000/openapi.json"/></label>
  </details>
  {error&&<p role="alert">{error}</p>}
  {result&&<div className="discovery-result" role="status">
   <p><strong>{result.proposed_profile?'Configuration detected':result.openapi_candidates?.length?'Candidate API operations discovered':'Configuration unverified'}</strong>: {result.canonical_endpoint??result.input_url}</p>
   <p>{result.proposed_profile?'Review the detected configuration below. A connection check runs automatically when the model is known.':result.openapi_candidates?.length?'Select an API operation below and confirm unresolved required parameters or authentication before saving.':'No supported endpoint was verified. Check the URL or configure a target manually.'}</p>
   {!!result.openapi_candidates?.length&&!result.proposed_profile&&<section className="panel discovery-openapi-candidates" aria-label="Discovered OpenAPI candidates">
    <h4>Discovered HTTP API Candidates ({result.openapi_candidates.length})</h4>
    <p className="caption">Draft suggestions from API specification metadata only (not runtime verified). Resolve any required fields before saving.</p>
    <ul>{result.openapi_candidates.map(c=><li key={c.endpoint}><strong>{c.method} <code>{c.path}</code></strong>{c.summary?` · ${c.summary}`:''}{c.requires_auth?' · Requires authentication':''}{c.unresolved_required_fields.length>0?` · Unresolved required fields: ${c.unresolved_required_fields.join(', ')}`:''}{c.unsupported_required_parameters?.length?` · Unsupported required params: ${c.unsupported_required_parameters.map(p=>`${p.in}:${p.name}`).join(', ')}`:''} <button type="button" onClick={()=>void selectOpenApiCandidate(c)}>Select &amp; Review Draft</button>{!!c.limitations?.length&&<p className="caption">{c.limitations.join(' ')}</p>}</li>)}</ul>
   </section>}
   {mcpManifest&&<section className="panel discovery-mcp-manifest" aria-label="Discovered MCP tools">
    <h4>Discovered MCP Tools &amp; Schemas ({mcpManifest.tools.length})</h4>
    <p className="caption">Source: <code>{mcpManifest.source_endpoint}</code> · Manifest SHA-256: <code>{mcpManifest.advertised_tool_manifest_sha256.slice(0,16)}...</code> · Discovery ID: <code>{mcpManifest.discovery_id}</code></p>
    <ul>{mcpManifest.tools.map(t=><li key={t.name}><strong>{t.name}</strong> · <span className={`batch-cell-pill ${t.schema_compatible?'ready':'blocked'}`}>{t.schema_compatible?'Schema compatible':`Incompatible (${t.schema_error??'unsupported'})`}</span>{t.description&&<p>{t.description}</p>}{t.input_schema&&<details><summary>Inspect JSON Schema</summary><pre>{JSON.stringify(t.input_schema,null,2)}</pre></details>}</li>)}</ul>
   </section>}
   <details className="target-advanced"><summary>Advanced Details</summary>
    <p>Metadata service: {result.connection_status??'unverified'}; requests: {result.request_count}/{result.request_budget}; security tests: none.</p>
    <p>Input: <code>{result.input_url}</code>. Operator hint: {result.protocol_hint??'none'}.</p>
    <h4>Metadata sources</h4><ul>{result.metadata_sources.map(source=><li key={source.url}><code>{source.url}</code>: {source.status.replaceAll('_',' ')} ({source.classification.replaceAll('_',' ')})</li>)}</ul>
    <h4>Protocol candidates</h4><ul>{result.protocol_candidates.map(p=><li key={p.id}>{p.id}: {p.classification.replaceAll('_',' ')}; action runtime unverified</li>)}</ul>
    <p>Advertised models: {result.advertised_models.map(m=>m.id).join(', ')||'not discovered'}.</p>
    <p>Advertised agent: {result.advertised_agent?.name??'not discovered'}.</p>
    <p>Advertised tools: {result.advertised_tools.map(t=>t.name).join(', ')||'none advertised'}; execution unverified.</p>
    <p>Advertised skills: {result.advertised_skills.map(t=>t.name).join(', ')||'none advertised'}.</p>
    <h4>Evidence source candidates</h4>{result.evidence_candidates?.length?<ul>{result.evidence_candidates.map(source=><li key={source.url}><strong>{source.source_name}</strong>: <code>{source.url}</code>; candidate / needs review; {source.verification_status.replaceAll('_',' ')}; correlation: {source.correlation_capability.replaceAll('_',' ')}. {source.limitations}</li>)}</ul>:<p>Not Discovered. Configure an exact source manually after saving.</p>}
    <p>Evidence candidates are not collected, authorized, or passed to the Judge.</p>
    <p>Unknown capabilities: {result.unknown_fields.join(', ')||'none recorded'}.</p>
    {result.warnings.map(w=><p key={w}>{w}</p>)}
    <h4>Testcase compatibility recommendations</h4><ul>{result.recommendations.map(row=><li key={row.testcase_id}>{row.testcase_id} ({row.asi_category}): {row.status}; {row.reason.replaceAll('_',' ')}</li>)}</ul>
    <p>Recommendations are planning hints. Backend admission decides execution.</p>
   </details>
  </div>}
 </section>;
}
