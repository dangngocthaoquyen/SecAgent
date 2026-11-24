import {useEffect,useState,type FormEvent} from 'react';
import {testingApi,type ApplicationContextDraft,type ApplicationContextRecord,type DiscoveryResult,type FieldProvenance,type TargetPreset} from './testingApi';

type TextFieldKey = Exclude<keyof ApplicationContextDraft,'target_id'|'target_revision'|'field_provenance'>;

type SectionDef = {
 title: string;
 subtitle: string;
 fields: [TextFieldKey, string, string][];
};

const SECTIONS: SectionDef[] = [
 {
  title: 'A. Core Application Details',
  subtitle: 'Primary purpose, capabilities, domain, and operational rules.',
  fields: [
   ['purpose', 'Purpose', 'What is the primary purpose of your application?'],
   ['features', 'Features', 'What are the key features and capabilities?'],
   ['domain_industry', 'Industry / Domain', 'What industry or domain does it operate in?'],
   ['operational_constraints', 'Operational constraints', 'Are there specific rules or constraints it must follow?'],
  ],
 },
 {
  title: 'B. Access & Permissions',
  subtitle: 'Connected systems, restricted resources, user roles, tools, and trust boundaries.',
  fields: [
   ['allowed_resources', 'Allowed resources', 'What systems, data, or resources should the application have access to?'],
   ['prohibited_resources', 'Prohibited resources', 'What systems, data, or resources should it NOT have access to?'],
   ['users', 'Users and roles', 'What types of users interact with it, and what are their roles/permissions?'],
   ['authorized_actions', 'Authorized actions', 'What actions or operations can the application perform on behalf of users?'],
   ['available_tools', 'Available tools', 'Declared tools or MCP capabilities'],
   ['authorization_required', 'Actions requiring confirmation', 'Operations requiring explicit human confirmation'],
   ['trust_boundaries', 'Trust boundaries', 'Isolation boundaries between untrusted content and privileged actions'],
  ],
 },
 {
  title: 'C. Data & Content',
  subtitle: 'Confidential data categories, protected assets, high-risk actions, and compliance.',
  fields: [
   ['sensitive_data_categories', 'Sensitive data categories', 'What types of sensitive or confidential data does it handle?'],
   ['protected_assets', 'Protected assets', 'Is there specific content or information that should never be disclosed?'],
   ['high_risk_actions', 'High-risk actions', 'Irreversible or high-impact actions (e.g., shell, file write, external POST)'],
   ['data_handling_restrictions', 'Data handling & compliance', 'Are there data handling, privacy, or compliance requirements?'],
  ],
 },
 {
  title: 'D. Business Context',
  subtitle: 'Mandatory system instructions and business restrictions.',
  fields: [
   ['required_instructions', 'Required instructions', 'System instructions the agent must always follow'],
   ['business_restrictions', 'Sensitive topics & business restrictions', 'What topics, competitors, or business areas should it avoid or handle carefully?'],
  ],
 },
 {
  title: 'E. Red Team User',
  subtitle: 'Typical user personas, roles, and relevant attacker personas.',
  fields: [
   ['redteam_personas', 'Red Team User & Personas', 'Describe typical users, their roles, and relevant attacker personas.'],
  ],
 },
];

const ALL_KEYS: TextFieldKey[] = SECTIONS.flatMap(s => s.fields.map(f => f[0]));

function blank(target:TargetPreset):ApplicationContextDraft{
 return {
  target_id:target.id,target_revision:target.profile_revision,
  purpose:'',features:'',domain_industry:'',operational_constraints:'',
  available_tools:'',users:'',allowed_resources:'',prohibited_resources:'',
  authorized_actions:'',sensitive_data_categories:'',protected_assets:'',
  high_risk_actions:'',data_handling_restrictions:'',required_instructions:'',
  business_restrictions:'',authorization_required:'',trust_boundaries:'',
  redteam_personas:'',field_provenance:{},
 };
}

export default function ApplicationContext({target,nonce,secret,discovery}:{target:TargetPreset;nonce:string;secret:string;discovery?:DiscoveryResult|null}){
 const [draft,setDraft]=useState<ApplicationContextDraft>(()=>blank(target));
 const [record,setRecord]=useState<ApplicationContextRecord|null>(null);
 const [status,setStatus]=useState<'current'|'stale'>('current');
 const [confirmed,setConfirmed]=useState(false),[busy,setBusy]=useState(false);
 const [message,setMessage]=useState(''),[error,setError]=useState('');

 useEffect(()=>{
  setDraft(blank(target));setRecord(null);setStatus('current');setConfirmed(false);setMessage('');setError('');
  testingApi.getApplicationContext(target.id,secret,nonce).then(row=>{
   setRecord(row.context);setStatus(row.binding_status);
   if(row.context)setDraft({...blank(target),...row.context.draft,target_revision:target.profile_revision});
  }).catch(e=>setError(e instanceof Error?e.message:'Application Context unavailable.'));
 },[target.id,target.profile_revision,secret,nonce]);

 function applyDiscoverySuggestions(){
  const sug=discovery?.suggested_application_details;
  const tools=sug?.available_tools||(discovery?.advertised_tools?.map(t=>t.name).join(', ')??'');
  const skills=sug?.features||(discovery?.advertised_skills?.map(s=>s.name).join(', ')??'');
  const purpose=sug?.purpose||(discovery?.advertised_agent?.name?`AI Agent service (${discovery.advertised_agent.name})`:'');
  const nextProv:Record<string,FieldProvenance>={...(draft.field_provenance??{})};
  if(tools)nextProv.available_tools='discovered_observed';
  if(skills)nextProv.features='suggested_unverified';
  if(purpose)nextProv.purpose='suggested_unverified';
  setDraft({
   ...draft,
   purpose:draft.purpose||purpose,
   features:draft.features||skills,
   available_tools:draft.available_tools||tools,
   field_provenance:nextProv,
  });
  setConfirmed(false);
  setMessage('Imported discovered suggestions as unverified metadata. Review and save to confirm for evaluation.');
 }

 async function save(e:FormEvent){
  e.preventDefault();if(!confirmed||busy)return;setBusy(true);setMessage('');setError('');
  const confirmedProv:Record<string,FieldProvenance>={};
  for(const k of ALL_KEYS){
   const val=draft[k];
   if(typeof val==='string'&&val.trim())confirmedProv[k]='operator_confirmed';
  }
  try{
   const saved=await testingApi.saveApplicationContext(
    {...draft,target_revision:target.profile_revision,field_provenance:confirmedProv},
    record?.revision_sha256??null,secret,nonce,
   );
   setRecord(saved);setDraft({...blank(target),...saved.draft,target_revision:target.profile_revision});
   setStatus('current');setConfirmed(false);
   setMessage('Application Context saved (operator_confirmed). Ready for security scan evaluation context.');
  }catch(e){setError(e instanceof Error?e.message:'Application Context could not be saved.');}
  finally{setBusy(false);}
 }

 const hasDiscoverySuggestions=!!(
  discovery?.suggested_application_details?.available_tools||
  discovery?.advertised_tools?.length||
  discovery?.advertised_skills?.length||
  discovery?.advertised_agent
 );

 return <section className="application-context" aria-label="Application Context">
  <div className="target-list-head">
   <div>
    <h3>Application Context &amp; Security Boundaries</h3>
    <p className="caption">Operator-declared application details and security boundaries (Promptfoo-style). Discovered metadata remains unverified until confirmed and saved here.</p>
   </div>
   {hasDiscoverySuggestions&&(
    <button type="button" disabled={busy} onClick={applyDiscoverySuggestions}>
     Auto-Fill from Discovery (Unverified)
    </button>
   )}
  </div>
  {record&&<p className="caption">Provenance: <strong>{record.provenance.replaceAll('_',' ')}</strong> · Binding: <strong>{status}</strong> · Revision: <code>{record.revision_sha256.slice(0,12)}</code></p>}
  {status==='stale'&&<p role="status">Target settings changed after this description was saved. Save again to bind it to the current target revision.</p>}
  <form className="target-form" onSubmit={save}>
   {SECTIONS.map(sec=>(
    <fieldset key={sec.title} className="app-context-section">
     <legend><strong>{sec.title}</strong> — <small>{sec.subtitle}</small></legend>
     {sec.fields.map(([key,label,placeholder])=>{
      const prov=draft.field_provenance?.[key];
      return <label key={key}>{label} {prov&&<span className="batch-cell-pill">{prov}</span>}
       <textarea rows={2} maxLength={1000} placeholder={placeholder} value={(draft[key] as string)??''} onChange={e=>{
        const nextProv={...(draft.field_provenance??{})};
        if(e.target.value.trim())nextProv[key]='operator_confirmed';
        else delete nextProv[key];
        setDraft({...draft,[key]:e.target.value,field_provenance:nextProv});
        setConfirmed(false);setMessage('');
       }}/>
      </label>;
     })}
    </fieldset>
   ))}
   <label className="target-consent"><input type="checkbox" checked={confirmed} onChange={e=>setConfirmed(e.target.checked)}/><span>I confirm this operator-declared description contains no real credentials or secrets.</span></label>
   <button type="submit" disabled={!confirmed||busy}>Save Application Context</button>
  </form>
  {message&&<p role="status">{message}</p>}{error&&<p role="alert">{error}</p>}
 </section>;
}
