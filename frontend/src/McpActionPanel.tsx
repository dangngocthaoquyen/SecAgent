import {useEffect,useState} from 'react';
import DownloadReport from './DownloadReport';
import {testingApi,type McpActionCatalog,type McpActionResult,type TargetPreset} from './testingApi';

export default function McpActionPanel({targets,nonce,secret}:{targets:TargetPreset[];nonce:string;secret:string}){
 const [catalog,setCatalog]=useState<McpActionCatalog|null>(null);
 const [caseId,setCaseId]=useState('');
 const [targetId,setTargetId]=useState('');
 const [mode,setMode]=useState<'rule_only'|'hybrid'>('rule_only');
 const [evidenceConfiguration,setEvidenceConfiguration]=useState<'request_only'|'configured_adapter'>('request_only');
 const [consent,setConsent]=useState(false);
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState('');
 const [result,setResult]=useState<McpActionResult|null>(null);
 useEffect(()=>{
  if(!nonce)return;
  testingApi.listMcpActions(secret,nonce).then(data=>{
   setCatalog(data);setCaseId(data.cases[0]?.testcase_id??'');
  }).catch(e=>setError(e instanceof Error?e.message:'MCP action workflow unavailable.'));
 },[nonce,secret]);
 const selected=catalog?.cases.find(c=>c.testcase_id===caseId);
 const compatible=targets.filter(t=>t.protocol==='mcp-jsonrpc'&&t.id===selected?.target_id);
 const target=compatible.find(t=>t.id===targetId)??compatible[0];
 const reviewed=target?.authorization_status==='reviewed_for_offline_configuration';
 async function run(){
  if(!catalog||!selected||!target||!consent)return;
  setBusy(true);setError('');setResult(null);
  try{
   const response=await testingApi.runMcpAction({testcase_id:selected.testcase_id,target_id:target.id,
    profile_revision:target.profile_revision,catalog_sha256:catalog.catalog_sha256,
    evaluation_mode:mode,evidence_configuration:evidenceConfiguration,
    authorization_confirmed:true},secret,nonce);
   setResult(response);setConsent(false);
  }catch(e){setError(e instanceof Error?e.message:'MCP action was rejected.');}
  finally{setBusy(false);}
 }
 return <section className="panel mcp-action-panel" aria-label="MCP tool-action assessment">
  <span className="eyebrow">STRUCTURED MCP TESTCASE</span>
  <h2>MCP tool-action assessment</h2>
  <p>This runs an exact, preconfigured <code>tools/call</code>. It does not convert imported chat prompts to tool calls or establish autonomous Agent action.</p>
  {error&&<p className="notice error" role="alert">{error}</p>}
  {!catalog?<p>Start SecAgent with a structured MCP action catalog to use this workflow.</p>:<>
   <div className="mcp-action-grid">
    <label>Testcase<select value={caseId} onChange={e=>{setCaseId(e.target.value);setConsent(false);setResult(null);}}>
     {catalog.cases.map(c=><option value={c.testcase_id} key={c.testcase_id}>{c.testcase_id} · {c.asi_category}</option>)}
    </select></label>
    <label>Execution target<select value={target?.id??''} onChange={e=>{setTargetId(e.target.value);setConsent(false);setResult(null);}}>
     {compatible.length===0?<option value="">No matching MCP target</option>:compatible.map(t=><option value={t.id} key={t.id}>{t.name} · {t.endpoint}</option>)}
    </select></label>
   </div>
   {selected&&<div className="mcp-action-summary">
    <p><strong>Scope:</strong> {selected.evaluation_scope} · <strong>Tool:</strong> {selected.tool_name} · <strong>Attribution:</strong> direct request</p>
    <p><strong>Legitimate objective:</strong> {selected.legitimate_objective}</p>
    <p><strong>Attack objective:</strong> {selected.attacker_objective}</p>
    <p><strong>Policy:</strong> {selected.policy_status} ({selected.policy_id}) · <strong>Evidence:</strong> partial until correlated receipt verified</p>
    <p><strong>Shared Judge:</strong> {catalog.hybrid_configured?'configured':'disabled'}; execution-action semantic Pi call is gated because no reviewed action Judge Skill is bound. The existing deterministic execution resolver still runs in Hybrid mode.</p>
    <details><summary>Evidence and binding details</summary><p>Expected: {selected.expected_evidence.join(', ')}</p><p>Arguments SHA-256: <code>{selected.arguments_sha256}</code></p><p>Policy revision: <code>{selected.policy_revision_sha256}</code></p></details>
   </div>}
   {!reviewed&&<p className="notice" role="status">Review the exact matching MCP target revision in Targets before executing this case. A successful connection check is not security-test authorization.</p>}
   <label>Evaluation mode<select value={mode} onChange={e=>{setMode(e.target.value as 'rule_only'|'hybrid');setConsent(false);setResult(null);}}>
    <option value="rule_only">Rule-only</option>{catalog.hybrid_configured&&<option value="hybrid">Shared Hybrid infrastructure · action Judge gated</option>}
   </select></label>
   <label>Evidence configuration<select value={evidenceConfiguration} onChange={e=>{setEvidenceConfiguration(e.target.value as 'request_only'|'configured_adapter');setConsent(false);setResult(null);}}>
    <option value="request_only">SecAgent observed request · partial trace</option>
    {selected?.adapter_evidence_available&&<option value="configured_adapter">Configured target evidence adapter · correlation checked</option>}
   </select></label>
   <label className="target-consent"><input type="checkbox" checked={consent} onChange={e=>setConsent(e.target.checked)}/><span>I authorize one direct MCP <code>tools/call</code> to the selected endpoint for this structured testcase. No autonomous Agent action is implied.</span></label>
   <button className="primary" disabled={!reviewed||!consent||busy||!selected} onClick={()=>void run()}>{busy?'Running one MCP action…':'Run one MCP action'}</button>
   {result&&<div className="notice" role="status"><strong>{result.final_verdict}</strong> · {result.target_request_count} target request · execution {result.execution_id}. Native report: <code>{result.report_path}</code>. Pi invoked: {result.semantic_invoked?'yes':'no'}.{/^[a-f0-9]{32}$/.test(result.execution_id)&&<> <a href={`#mcp-run/${result.execution_id}`}>View run detail</a> <DownloadReport kind="mcp-runs" id={result.execution_id}/></>}</div>}
  </>}
 </section>;
}
