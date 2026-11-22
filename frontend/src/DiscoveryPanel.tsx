import {useRef,useState} from 'react';
import {testingApi,type DiscoveryResult,type ManagedProfile} from './testingApi';

export default function DiscoveryPanel({nonce,secret,onUse,onReset}:{nonce:string;secret:string;
 onUse:(profile:ManagedProfile,discoveryId:string,result:DiscoveryResult)=>Promise<void>;onReset:()=>void}){
 const [url,setUrl]=useState(''),[agentName,setAgentName]=useState(''),[hint,setHint]=useState(''),[confirmed,setConfirmed]=useState(false);
 const [busy,setBusy]=useState(false),[error,setError]=useState('');
 const [result,setResult]=useState<DiscoveryResult|null>(null);
 const sequence=useRef(0);
 function reset(){sequence.current++;setBusy(false);setConfirmed(false);setResult(null);setError('');onReset();}
 async function discover(){if(!confirmed||busy)return;const token=++sequence.current;setBusy(true);setError('');setResult(null);onReset();
  try{const row=await testingApi.discover(url,nonce,secret,hint||undefined);if(token!==sequence.current)return;setResult(row);
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
   <label>Protocol hint<select value={hint} onChange={e=>{setHint(e.target.value);reset();}}><option value="">Automatic / adapter metadata</option><option value="openai-chat">OpenAI-compatible chat</option><option value="mcp-jsonrpc">MCP JSON-RPC tools/list</option><option value="openapi-http">OpenAPI HTTP</option><option value="a2a">A2A metadata</option></select></label>
  </details>
  {error&&<p role="alert">{error}</p>}
  {result&&<div className="discovery-result" role="status">
   <p><strong>{result.proposed_profile?'Configuration detected':'Configuration unverified'}</strong>: {result.canonical_endpoint??result.input_url}</p>
   <p>{result.proposed_profile?'Review the detected configuration below. A connection check runs automatically when the model is known.':'No supported endpoint was verified. Check the URL or configure a target manually.'}</p>
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
