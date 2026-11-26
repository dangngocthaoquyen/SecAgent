import {useEffect,useRef,useState} from 'react';
import ScanPreviewPanel from './ScanPreviewPanel';
import ScanResumePanel from './ScanResumePanel';
import {
 BudgetUsage,
 CurrentTestcase,
 ExecutionCounters,
 ProgressMetadata,
 ScanProgressBar,
 TestcaseStatusList,
} from './ScanProgressComponents';
import ScanResultsView from './ScanResultsView';
import { resolveUnifiedDisplay } from './scanLineage';
import {
 clearPendingScanSubmission,
 consumeScanHandoff,
 getEphemeralOperatorSecret,
 loadPendingScanSubmission,
 savePendingScanSubmission,
 setEphemeralOperatorSecret,
 testingApi,
 type DatasetEnvelope,
 type DatasetSummary,
 type GenericCaseStatus,
 type GenericResumePreview,
 type GenericRunPreview,
 type GenericRunRecord,
 type GenericRunSummary,
 type PendingScanSubmission,
 type TargetPreset,
} from './testingApi';

type ScanStep = 1 | 2 | 3;

const TERMINAL_RUN_STATUSES=new Set(['completed','failed','interrupted','cancelled']);

function randomHex32():string{
 const bytes=new Uint8Array(16);
 if(typeof crypto!=='undefined'&&crypto.getRandomValues){
  crypto.getRandomValues(bytes);
 }else{
  for(let i=0;i<16;i++)bytes[i]=Math.floor(Math.random()*256);
 }
 return Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
}

export default function SecurityScanWizard({
 initialRunId,
 initialTargetId,
 initialDatasetId,
 maxPollRetries=5,
}:{
 initialRunId?:string;
 initialTargetId?:string;
 initialDatasetId?:string;
 maxPollRetries?:number;
}={}){
 const [step,setStep]=useState<ScanStep>(initialRunId?3:1);
 const [nonce,setNonce]=useState('');
 const [secret,setSecret]=useState(()=>getEphemeralOperatorSecret());
 const [unlocked,setUnlocked]=useState(()=>Boolean(getEphemeralOperatorSecret()));
 const [localSingleUser,setLocalSingleUser]=useState(true);
 const [piJudgeReady,setPiJudgeReady]=useState(false);
 const [judgeSetupReason,setJudgeSetupReason]=useState('judge_configuration_missing');

 const [targets,setTargets]=useState<TargetPreset[]>([]);
 const [datasets,setDatasets]=useState<DatasetSummary[]>([]);
 const [savedRuns,setSavedRuns]=useState<GenericRunSummary[]>([]);
 const [selectedTargetId,setSelectedTargetId]=useState(initialTargetId||'');
 const [selectedDatasetId,setSelectedDatasetId]=useState(initialDatasetId||'');
 const [datasetDetail,setDatasetDetail]=useState<DatasetEnvelope|null>(null);
 const [pendingTestcaseIds,setPendingTestcaseIds]=useState<string[]|null>(null);

 const [scanMode,setScanMode]=useState<'live'|'offline'>('live');
 const [useJudge,setUseJudge]=useState(true);
 const [selectedCaseIds,setSelectedCaseIds]=useState<string[]>([]);
 const [preview,setPreview]=useState<GenericRunPreview|null>(null);
 const [scanAuthorized,setScanAuthorized]=useState(false);
 const [submissionId,setSubmissionId]=useState<string>('');
 const [pendingSubmission,setPendingSubmission]=useState<PendingScanSubmission|null>(null);
 const [verifyingSubmission,setVerifyingSubmission]=useState(false);
 const [submissionVerifyNote,setSubmissionVerifyNote]=useState('');
 const [activeRunId,setActiveRunId]=useState<string>(initialRunId||'');
 const [runRecord,setRunRecord]=useState<GenericRunRecord|null>(null);
 const [recoverIdInput,setRecoverIdInput]=useState<string>('');

 const [resumeOpen,setResumeOpen]=useState(false);
 const [resumePreview,setResumePreview]=useState<GenericResumePreview|null>(null);
 const [resumePreviewStale,setResumePreviewStale]=useState(false);
 const [resumeLoading,setResumeLoading]=useState(false);
 const [resumeStarting,setResumeStarting]=useState(false);
 const [resumeError,setResumeError]=useState('');
 const [selectedUncertainIds,setSelectedUncertainIds]=useState<string[]>([]);
 const [resumeSubmissionId,setResumeSubmissionId]=useState('');
 const resumePreviewSeqRef=useRef(0);

 const [busy,setBusy]=useState(false);
 const [error,setError]=useState('');
 const [pollConnectionLost,setPollConnectionLost]=useState(false);
 const [pollStopped,setPollStopped]=useState(false);
 const [pollEpoch,setPollEpoch]=useState(0);
 const pollingBusy=useRef(false);
 const pollFailureCount=useRef(0);
 const prevInitialRunId=useRef<string|undefined>(initialRunId);
 const busyRef=useRef(false);
 const pendingSubmissionRef=useRef<PendingScanSubmission|null>(null);

 function updateBusy(next:boolean){
  busyRef.current=next;
  setBusy(next);
 }

 function updatePendingSubmission(next:PendingScanSubmission|null){
  pendingSubmissionRef.current=next;
  setPendingSubmission(next);
 }

 function isActionLocked():boolean{
  return busy||busyRef.current||Boolean(pendingSubmission)||Boolean(pendingSubmissionRef.current);
 }

 useEffect(()=>{
  const handoff=consumeScanHandoff();
  if(handoff){
   if(handoff.dataset_id)setSelectedDatasetId(handoff.dataset_id);
   if(handoff.target_id)setSelectedTargetId(handoff.target_id);
   if(Array.isArray(handoff.testcase_ids)&&handoff.testcase_ids.length>0){
    setPendingTestcaseIds(handoff.testcase_ids);
   }
  }
  const pendingSub=loadPendingScanSubmission();
  if(pendingSub){
   updatePendingSubmission(pendingSub);
   setSubmissionId(pendingSub.submission_id);
   if(pendingSub.target_id)setSelectedTargetId(pendingSub.target_id);
   if(pendingSub.dataset_id)setSelectedDatasetId(pendingSub.dataset_id);
   setScanMode(pendingSub.mode);
   setUseJudge(pendingSub.use_judge);
  }
  if(!initialRunId){
   try{
    const persistedRun=sessionStorage.getItem('secagent_active_generic_run_id');
    if(persistedRun&&/^[a-f0-9]{32}$/.test(persistedRun)){
     setActiveRunId(persistedRun);
     setStep(3);
     return;
    }
   }catch{}
  }
 },[initialRunId]);

 useEffect(()=>{
  if(initialRunId&&/^[a-f0-9]{32}$/.test(initialRunId)){
   setActiveRunId(initialRunId);
   setStep(3);
  }else if(prevInitialRunId.current&&!initialRunId){
   resetToNewScan();
  }
  prevInitialRunId.current=initialRunId;
 },[initialRunId]);

 useEffect(()=>{
  const ctrl=new AbortController();
  Promise.all([testingApi.health(ctrl.signal),testingApi.targets(ctrl.signal)])
   .then(([h,t])=>{
    if(ctrl.signal.aborted)return;
    setNonce(h.nonce);
    setLocalSingleUser(h.localSingleUser);
    setJudgeSetupReason(h.judgeSetupReason);
    // Authoritative Generic Scan Judge readiness: strictly from piJudgeReady and judgeSetupReason
    const judgeReady=h.piJudgeReady===true&&h.judgeSetupReason!=='credential_missing';
    setPiJudgeReady(judgeReady);
    setUseJudge(judgeReady);
    setTargets(t.targets);
    setSelectedTargetId(curr=>curr&&t.targets.some(x=>x.id===curr)?curr:(t.targets[0]?.id??''));
   })
   .catch(e=>{if(!ctrl.signal.aborted)setError(e instanceof Error?e.message:'Failed to load targets.');});
  return ()=>ctrl.abort();
 },[]);

 useEffect(()=>{
  if(!nonce||!(localSingleUser||unlocked))return;
  testingApi.listDatasets(secret,nonce)
   .then(rows=>{
    setDatasets(rows);
    setSelectedDatasetId(curr=>curr&&rows.some(r=>r.dataset_id===curr)?curr:(rows[0]?.dataset_id??''));
   })
   .catch(()=>{});
  testingApi.listGenericRuns(secret,nonce)
   .then(runs=>setSavedRuns(runs))
   .catch(()=>{});
 },[nonce,localSingleUser,unlocked,secret]);

 useEffect(()=>{
  if(!nonce||!(localSingleUser||unlocked)||!selectedDatasetId){
   setDatasetDetail(null);
   setSelectedCaseIds([]);
   return;
  }
  testingApi.getDataset(selectedDatasetId,secret,nonce)
   .then(env=>{
    setDatasetDetail(env);
    const allIds=env.testcases.map(tc=>tc.testcase_id);
    if(pendingTestcaseIds&&pendingTestcaseIds.length>0){
     const validSubset=allIds.filter(id=>pendingTestcaseIds.includes(id));
     setSelectedCaseIds(validSubset.length>0?validSubset:allIds);
     setPendingTestcaseIds(null);
    }else{
     setSelectedCaseIds(allIds);
    }
    const hasStored=env.has_stored_responses===true||
     env.source_metadata?.has_stored_responses===true||
     env.testcases.some(tc=>typeof (tc.extra?.stored_response??tc.extra?.response_text)==='string');
    setScanMode(hasStored?'offline':'live');
   })
   .catch(e=>setError(e instanceof Error?e.message:'Failed to load dataset details.'));
 },[selectedDatasetId,nonce,localSingleUser,unlocked,secret]);

 // Automatically query exact pending submission_id on reload without sending a new POST Start
 useEffect(()=>{
  if(!pendingSubmission||activeRunId||busy||!nonce||!(localSingleUser||unlocked))return;
  let cancelled=false;
  async function checkPending(){
   setVerifyingSubmission(true);
   setSubmissionVerifyNote('');
   try{
    const recovered=await testingApi.getGenericRunBySubmission(pendingSubmission!.submission_id,secret,nonce);
    if(cancelled)return;
    clearPendingScanSubmission();
    updatePendingSubmission(null);
    setRunRecord(recovered);
    setActiveRunId(recovered.generic_run_id);
    const rst=recovered.status??'completed';
    if(!TERMINAL_RUN_STATUSES.has(rst)){
     try{sessionStorage.setItem('secagent_active_generic_run_id',recovered.generic_run_id);}catch{}
    }
    try{
     location.hash=`#scan/${recovered.generic_run_id}`;
     window.history.replaceState(null,'',`#scan/${recovered.generic_run_id}`);
    }catch{}
    setStep(3);
    setError('');
   }catch(e){
    if(cancelled)return;
    const msg=e instanceof Error?e.message:'';
    setSubmissionVerifyNote(
     msg.includes('generic_submission_in_progress')
      ?'Backend is still initializing this submission. Click Verify Submission Status to check again without resending payloads.'
      :'No completed Run record was returned yet for this submission ID. Do not assume the scan was not executed if the browser disconnected during startup; verify again or inspect Backend logs before starting a new scan.',
    );
   }finally{
    if(!cancelled)setVerifyingSubmission(false);
   }
  }
  void checkPending();
  return ()=>{cancelled=true;};
 },[pendingSubmission,activeRunId,nonce,localSingleUser,unlocked,secret]);

 // Poll or load activeRunId from backend
 useEffect(()=>{
  if(!activeRunId||!/^[a-f0-9]{32}$/.test(activeRunId)||!(localSingleUser||unlocked))return;
  if(runRecord&&runRecord.generic_run_id===activeRunId&&TERMINAL_RUN_STATUSES.has(runRecord.status??'completed')&&!runRecord.lineage_summary?.active_lineage_run_id)return;
  let timer:ReturnType<typeof setTimeout>|undefined;
  let cancelled=false;

  async function refreshRun(){
   if(pollingBusy.current||cancelled)return;
   pollingBusy.current=true;
   try{
    const loaded=await testingApi.getGenericRun(activeRunId,secret,nonce);
    if(cancelled)return;
    pollFailureCount.current=0;
    setPollConnectionLost(false);
    setPollStopped(false);
    const currentPending=pendingSubmissionRef.current;
    if(currentPending&&loaded.submission_id&&loaded.submission_id===currentPending.submission_id){
     clearPendingScanSubmission();
     updatePendingSubmission(null);
    }
    setRunRecord(loaded);
    setStep(3);
    setError('');
    const st=loaded.status??'completed';
    if(!TERMINAL_RUN_STATUSES.has(st)||Boolean(loaded.lineage_summary?.active_lineage_run_id)){
     timer=setTimeout(refreshRun,350);
    }else{
     try{sessionStorage.removeItem('secagent_active_generic_run_id');}catch{}
     testingApi.listGenericRuns(secret,nonce).then(setSavedRuns).catch(()=>{});
    }
   }catch(e){
    if(!cancelled){
     pollFailureCount.current+=1;
     if(pollFailureCount.current<=maxPollRetries){
      setPollConnectionLost(true);
      setPollStopped(false);
      const backoffMs=Math.min(2000,150*pollFailureCount.current);
      timer=setTimeout(refreshRun,backoffMs);
     }else{
      setPollConnectionLost(false);
      setPollStopped(true);
      setError(e instanceof Error?e.message:`Polling stopped after repeated failures for Scan Run ${activeRunId}.`);
     }
    }
   }finally{
    pollingBusy.current=false;
   }
  }

  void refreshRun();
  return ()=>{
   cancelled=true;
   if(timer)clearTimeout(timer);
   pollingBusy.current=false;
  };
 },[activeRunId,localSingleUser,unlocked,secret,nonce,runRecord?.generic_run_id,runRecord?.status,pollEpoch,maxPollRetries]);

 const selectedTarget=targets.find(t=>t.id===selectedTargetId)??null;
 const selectedDatasetSummary=datasets.find(d=>d.dataset_id===selectedDatasetId)??null;
 const datasetHasStoredResponses=
  selectedDatasetSummary?.has_stored_responses===true||
  datasetDetail?.has_stored_responses===true||
  datasetDetail?.source_metadata?.has_stored_responses===true||
  (datasetDetail?.testcases.some(tc=>typeof (tc.extra?.stored_response??tc.extra?.response_text)==='string')??false);

 async function unlockOperator(){
  if(!secret.trim()||!nonce)return;
  setBusy(true);setError('');
  try{
   const trimmed=secret.trim();
   await testingApi.unlock(trimmed,nonce);
   setEphemeralOperatorSecret(trimmed);
   setSecret(trimmed);
   setUnlocked(true);
  }catch{
   setError('Operator authentication rejected.');
  }finally{
   setBusy(false);
  }
 }

 function reconnectToRun(){
  if(!activeRunId)return;
  pollFailureCount.current=0;
  setPollStopped(false);
  setPollConnectionLost(false);
  setError('');
  setPollEpoch(n=>n+1);
 }

 async function verifyPendingSubmissionNow(){
  const currentPending=pendingSubmissionRef.current??pendingSubmission;
  if(!currentPending||verifyingSubmission)return;
  setVerifyingSubmission(true);
  setSubmissionVerifyNote('');
  try{
   const recovered=await testingApi.getGenericRunBySubmission(currentPending.submission_id,secret,nonce);
   clearPendingScanSubmission();
   updatePendingSubmission(null);
   setRunRecord(recovered);
   setActiveRunId(recovered.generic_run_id);
   const rst=recovered.status??'completed';
   if(!TERMINAL_RUN_STATUSES.has(rst)){
    try{sessionStorage.setItem('secagent_active_generic_run_id',recovered.generic_run_id);}catch{}
   }
   try{
    location.hash=`#scan/${recovered.generic_run_id}`;
    window.history.replaceState(null,'',`#scan/${recovered.generic_run_id}`);
   }catch{}
   setStep(3);
   setError('');
  }catch(e){
   const msg=e instanceof Error?e.message:'';
   setSubmissionVerifyNote(
    msg.includes('generic_submission_in_progress')
     ?'Backend is still initializing this submission. Wait a moment and click Verify Submission Status again.'
     :'Backend Run record was not found yet for this submission ID. Do not assume the scan was not executed if the connection dropped; verify again or dismiss only if you confirmed no run started.',
   );
  }finally{
   setVerifyingSubmission(false);
  }
 }

 function resetResumeState(){
  resumePreviewSeqRef.current+=1;
  setResumeOpen(false);
  setResumePreview(null);
  setResumePreviewStale(false);
  setResumeLoading(false);
  setResumeStarting(false);
  setResumeError('');
  setSelectedUncertainIds([]);
  setResumeSubmissionId('');
 }

 function resetToNewScan(){
  resetResumeState();
  const unresolved=pendingSubmissionRef.current??loadPendingScanSubmission();
  if(unresolved){
   updatePendingSubmission(unresolved);
   setSubmissionId(unresolved.submission_id);
  }else{
   clearPendingScanSubmission();
   updatePendingSubmission(null);
   setSubmissionVerifyNote('');
  }
  try{sessionStorage.removeItem('secagent_active_generic_run_id');}catch{}
  try{
   location.hash='#scan';
   window.history.replaceState(null,'','#scan');
  }catch{}
  pollFailureCount.current=0;
  setPollConnectionLost(false);
  setPollStopped(false);
  setError('');
  setRunRecord(null);
  setActiveRunId('');
  setPreview(null);
  setStep(1);
 }

 async function loadPreview(modeOverride?:'live'|'offline',judgeOverride?:boolean,caseIdsOverride?:string[]){
  if(isActionLocked()||!selectedTargetId||!selectedDatasetId||!nonce)return;
  const effectiveMode=modeOverride??scanMode;
  const effectiveJudge=judgeOverride??useJudge;
  const effectiveCases=caseIdsOverride??selectedCaseIds;
  updateBusy(true);setError('');setPreview(null);setScanAuthorized(false);
  try{
   const res=await testingApi.previewGenericRun({
    mode:effectiveMode,
    target_id:selectedTargetId,
    dataset_id:selectedDatasetId,
    testcase_ids:effectiveCases,
    use_judge:effectiveJudge,
   },secret,nonce);
   setPreview(res);
   setSubmissionId(randomHex32());
   setStep(2);
  }catch(e){
   setError(e instanceof Error?e.message:'Failed to generate scan preview.');
  }finally{
   updateBusy(false);
  }
 }

 async function startScan(){
  if(!preview||!scanAuthorized||isActionLocked())return;
  const activeSubmissionId=submissionId||randomHex32();
  if(!submissionId)setSubmissionId(activeSubmissionId);
  const pendingMeta:PendingScanSubmission={
   submission_id:activeSubmissionId,
   target_id:selectedTargetId,
   target_name:preview.target_name||selectedTarget?.name||selectedTargetId,
   dataset_id:selectedDatasetId,
   dataset_name:preview.dataset_name||datasetDetail?.name||selectedDatasetId,
   mode:scanMode,
   use_judge:useJudge,
   ready_count:preview.ready_count,
   saved_at:new Date().toISOString(),
  };
  savePendingScanSubmission(pendingMeta);
  setSubmissionVerifyNote('');
  updateBusy(true);setError('');setRunRecord(null);
  try{
   const rec=await testingApi.startGenericRun({
    mode:scanMode,
    target_id:selectedTargetId,
    dataset_id:selectedDatasetId,
    testcase_ids:selectedCaseIds,
    use_judge:useJudge,
    submission_id:activeSubmissionId,
    async_execution:true,
    ...(preview.target_revision_sha256?{expected_target_revision:preview.target_revision_sha256}:{}),
    ...(preview.session_credential_generation?{expected_session_credential_generation:preview.session_credential_generation}:{}),
   },secret,nonce);
   clearPendingScanSubmission();
   updatePendingSubmission(null);
   setRunRecord(rec);
   setActiveRunId(rec.generic_run_id);
   const st=rec.status??'completed';
   if(!TERMINAL_RUN_STATUSES.has(st)){
    try{sessionStorage.setItem('secagent_active_generic_run_id',rec.generic_run_id);}catch{}
   }
   try{
    location.hash=`#scan/${rec.generic_run_id}`;
    window.history.replaceState(null,'',`#scan/${rec.generic_run_id}`);
   }catch{}
   setStep(3);
  }catch(e){
   // If Backend explicitly rejected before run creation (e.g. preflight blocker / conflict), clear pending submission
   const errMsg=e instanceof Error?e.message:'';
   const staleAuthError=(
    errMsg.includes('[credential_unavailable]')||
    errMsg.includes('[generic_session_credential_stale]')||
    errMsg.includes('[generic_session_credential_authorization_required]')||
    errMsg.includes('[generic_target_revision_stale]')
   );
   if(
    staleAuthError||
    errMsg.includes('[policy_')||
    errMsg.includes('[judge_provider_unavailable]')||
    errMsg.includes('[unmapped_asi_category]')||
    errMsg.includes('[application_context_stale]')||
    errMsg.includes('[unverified_discovery_metadata_rejected]')||
    errMsg.includes('[generic_no_executable_cases]')||
    errMsg.includes('[generic_submission_conflict]')
   ){
    clearPendingScanSubmission();
    updatePendingSubmission(null);
    if(staleAuthError){
     setScanAuthorized(false);
     setPreview(null);
     setSubmissionId('');
     setStep(1);
    }
    setError(errMsg);
    return;
   }
   // If HTTP connection timed out or dropped after Backend accepted the submission, recover by exact submission_id
   for(let attempt=1;attempt<=3;attempt++){
    try{
     const recovered=await testingApi.getGenericRunBySubmission(activeSubmissionId,secret,nonce);
     clearPendingScanSubmission();
     updatePendingSubmission(null);
     setRunRecord(recovered);
     setActiveRunId(recovered.generic_run_id);
     const rst=recovered.status??'completed';
     if(!TERMINAL_RUN_STATUSES.has(rst)){
      try{sessionStorage.setItem('secagent_active_generic_run_id',recovered.generic_run_id);}catch{}
     }
     try{
      location.hash=`#scan/${recovered.generic_run_id}`;
      window.history.replaceState(null,'',`#scan/${recovered.generic_run_id}`);
     }catch{}
     setStep(3);
     setError('');
     return;
    }catch{
     if(attempt<3){
      await new Promise(r=>setTimeout(r,120*attempt));
     }
    }
   }
   updatePendingSubmission(pendingMeta);
   setSubmissionVerifyNote(
    'The start request lost connection before a Run ID was returned. Submission status requires verification — do not assume the scan was not executed.',
   );
   setError(e instanceof Error?e.message:'Scan execution failed.');
  }finally{
   updateBusy(false);
  }
 }

 async function openExistingRun(runId:string){
  const clean=runId.trim().toLowerCase();
  if(!/^[a-f0-9]{32}$/.test(clean)){
   setError('Enter a valid 32-character hexadecimal Generic Run ID.');
   return;
  }
  resetResumeState();
  setError('');
  setRunRecord(null);
  setActiveRunId(clean);
  setStep(3);
  if(typeof window!=='undefined'){
   window.location.hash=`#scan/${clean}`;
  }
 }

 async function loadResumePreview(parentRunId:string,includeUncertain:string[],autoIncludeAllUncertain=false){
  if(!nonce)return;
  const seq=++resumePreviewSeqRef.current;
  setResumeLoading(true);
  setResumePreviewStale(true);
  setResumeError('');
  try{
   let res=await testingApi.previewGenericResume(
    parentRunId,
    {include_uncertain_case_ids:includeUncertain},
    secret,
    nonce,
   );
   if(seq!==resumePreviewSeqRef.current)return;
   if(autoIncludeAllUncertain&&res.uncertain_case_ids.length>0){
    const allUncertain=res.uncertain_case_ids;
    res=await testingApi.previewGenericResume(
     parentRunId,
     {include_uncertain_case_ids:allUncertain},
     secret,
     nonce,
    );
    if(seq!==resumePreviewSeqRef.current)return;
    setSelectedUncertainIds(allUncertain);
   }else{
    setSelectedUncertainIds(res.included_uncertain_case_ids);
   }
   setResumePreview(res);
   setResumePreviewStale(false);
   setResumeSubmissionId(randomHex32());
  }catch(e){
   if(seq!==resumePreviewSeqRef.current)return;
   // R06: Invalidate stale preview immediately on refresh failure; require fresh preview before confirming.
   setResumePreview(null);
   setResumePreviewStale(true);
   setResumeSubmissionId('');
   setResumeError(e instanceof Error?e.message:'Failed to load resume preview.');
  }finally{
   if(seq===resumePreviewSeqRef.current){
    setResumeLoading(false);
   }
  }
 }

 async function openResumePreview(){
  if(!runRecord||resumeLoading||resumeStarting||isActionLocked())return;
  const resumeSourceId=runRecord.unified_lineage?.resumable_run_id||runRecord.lineage_summary?.resumable_run_id||runRecord.generic_run_id;
  setResumeOpen(true);
  setResumePreview(null);
  setResumePreviewStale(true);
  setSelectedUncertainIds([]);
  await loadResumePreview(resumeSourceId,[],true);
 }

 async function handleToggleUncertain(caseId:string,checked:boolean){
  if(!runRecord||resumeLoading||resumeStarting)return;
  const resumeSourceId=resumePreview?.parent_run_id||runRecord.unified_lineage?.resumable_run_id||runRecord.lineage_summary?.resumable_run_id||runRecord.generic_run_id;
  const nextIds=checked
   ?(selectedUncertainIds.includes(caseId)?selectedUncertainIds:[...selectedUncertainIds,caseId])
   :selectedUncertainIds.filter(id=>id!==caseId);
  setSelectedUncertainIds(nextIds);
  setResumePreviewStale(true);
  await loadResumePreview(resumeSourceId,nextIds,false);
 }

 async function handleConfirmAndResume(){
  if(
   !runRecord||
   !resumePreview||
   resumePreviewStale||
   !resumePreview.eligible||
   resumePreview.selected_resume_case_ids.length===0||
   resumePreview.included_uncertain_case_ids.length!==selectedUncertainIds.length||
   !selectedUncertainIds.every(id=>resumePreview.included_uncertain_case_ids.includes(id))||
   resumeLoading||
   resumeStarting||
   isActionLocked()
  )return;
  const resumeSourceId=resumePreview.parent_run_id;
  const activeSubId=resumeSubmissionId||randomHex32();
  if(!resumeSubmissionId)setResumeSubmissionId(activeSubId);
  const includedUncertain=resumePreview.included_uncertain_case_ids;
  setResumeStarting(true);
  setResumeError('');
  try{
   const rec=await testingApi.startGenericResume(
    resumeSourceId,
    {
     authorization_confirmed:true,
     expected_resume_digest:resumePreview.resume_digest,
     include_uncertain_case_ids:includedUncertain,
     uncertain_reexecution_confirmed:includedUncertain.length>0,
     stateful_target_acknowledged:resumePreview.mode==='live',
     expected_target_revision:resumePreview.target_revision_sha256,
     expected_session_credential_generation:resumePreview.session_credential_generation,
     submission_id:activeSubId,
     async_execution:true,
    },
    secret,
    nonce,
   );
   resetResumeState();
   pollFailureCount.current=0;
   setPollConnectionLost(false);
   setPollStopped(false);
   setError('');
   setRunRecord(rec);
   setActiveRunId(rec.generic_run_id);
   setStep(3);
   if(typeof window!=='undefined'){
    window.location.hash=`#scan/${rec.generic_run_id}`;
   }
  }catch(e){
   setResumeError(e instanceof Error?e.message:'Failed to start resumed scan.');
  }finally{
   setResumeStarting(false);
  }
 }

 const canOperatorAct=localSingleUser||unlocked;
 const isRunningRecord=Boolean(runRecord&&(!TERMINAL_RUN_STATUSES.has(runRecord.status??'completed')||Boolean(runRecord.lineage_summary?.active_lineage_run_id)));
 const hasUnresolvedSubmission=Boolean(pendingSubmission);
 const isSubmissionLocked=busy||hasUnresolvedSubmission;

 return (
  <div className="detail-page scan-wizard-page">
   <div className="page-title">
    <div>
     <span className="eyebrow">SECURITY SCAN · DATASET-FIRST WORKFLOW</span>
     <h1>New Security Scan</h1>
     <p>Select a configured Target and an imported Dataset, inspect the automated readiness preview, and monitor live execution progress through final results.</p>
    </div>
    <div className="scan-stepper" role="navigation" aria-label="Scan steps">
     <span className={`step-badge ${step===1?'active':step>1?'done':''}`}>1 · Select Target &amp; Dataset</span>
     <span className={`step-badge ${step===2?'active':step>2?'done':''}`}>2 · Scan Preview</span>
     <span className={`step-badge ${step===3?'active':''}`}>3 · {isRunningRecord?'Live Progress':'Run & Results'}</span>
    </div>
   </div>

   {!canOperatorAct&&(
    <section className="panel">
     <h2>Operator Authentication Required</h2>
     <div className="inline-row">
      <label htmlFor="scan-operator-secret">Operator Secret
       <input id="scan-operator-secret" type="password" value={secret} onChange={e=>setSecret(e.target.value)}/>
      </label>
      <button className="primary" disabled={!secret.trim()||busy} onClick={unlockOperator}>Unlock</button>
     </div>
    </section>
   )}

   {error&&<div className="notice error" role="alert"><strong>Scan Notice:</strong> {error}</div>}
   {pendingSubmission&&(
    <section className="panel notice warn" role="alert" aria-label="Pending Scan Submission Verification">
     <strong>Submission Verification Required:</strong>{' '}
     A scan submission (ID: <code className="mono">{pendingSubmission.submission_id}</code>) for Target <strong>{pendingSubmission.target_name}</strong> (<code className="mono">{pendingSubmission.target_id}</code>) and Dataset <strong>{pendingSubmission.dataset_name}</strong> ({pendingSubmission.ready_count} ready cases, mode: <code className="mono">{pendingSubmission.mode.toUpperCase()}</code>) was initiated before the browser reloaded or lost connection.
     <p style={{marginTop:'0.5rem'}}>
      {verifyingSubmission
       ?'Querying Backend for exact submission ID without resending payloads...'
       :(submissionVerifyNote||'Do not assume the request was not executed merely because the frontend lost connection. Verify the submission status with the Backend before starting a new scan.')}
     </p>
     <div className="inline-row" style={{marginTop:'0.6rem'}}>
      <button type="button" className="btn primary" disabled={verifyingSubmission||!canOperatorAct} onClick={()=>void verifyPendingSubmissionNow()}>
       {verifyingSubmission?'Verifying Submission...':'Verify Submission Status'}
      </button>
      <button
       type="button"
       className="btn ghost"
       disabled={verifyingSubmission}
       onClick={()=>{
        clearPendingScanSubmission();
        updatePendingSubmission(null);
        setSubmissionVerifyNote('');
       }}
      >
       Dismiss Pending Submission
      </button>
     </div>
    </section>
   )}
   {pollConnectionLost&&!pollStopped&&(
    <div className="notice warn" role="status">
     <strong>Polling Connection Lost:</strong> Temporarily unable to reach Workflow API for Scan Run <code className="mono">{activeRunId}</code>. Preserving partial progress and retrying automatically without restarting scan...
    </div>
   )}
   {pollStopped&&(
    <div className="notice warn reconnect-banner" role="alert">
     <div>
      <strong>Automatic Polling Stopped:</strong> Repeated connection failures occurred while polling Scan Run <code className="mono">{activeRunId}</code>. Automatic retries have stopped and partial progress is safely preserved.
     </div>
     <button type="button" className="btn primary" onClick={reconnectToRun}>
      Reconnect to Run
     </button>
    </div>
   )}

   {canOperatorAct&&step===1&&(
    <section className="panel" aria-label="Step 1: Select Target and Dataset">
     <div className="section-title">
      <div>
       <span className="eyebrow">STEP 1 OF 3</span>
       <h2>1 · Select Target and Dataset</h2>
       <p>Choose a configured Target profile and an imported Testcase Dataset. Target connection details and Application Details are managed in Targets.</p>
      </div>
     </div>

     <div className="split config-grid">
      <div className="card">
       <div className="card-head-row">
        <h3>Target Agent</h3>
        <a className="btn ghost sm" href="#targets">Add or Edit Target →</a>
       </div>
       <label htmlFor="scan-target-select">Select Saved Target
        <select
         id="scan-target-select"
         value={selectedTargetId}
         disabled={isSubmissionLocked}
         onChange={e=>{
          if(isActionLocked())return;
          setSelectedTargetId(e.target.value);
         }}
        >
         {targets.length===0&&<option value="">-- No saved targets --</option>}
         {targets.map(t=>(
          <option key={t.id} value={t.id}>
           {t.name} ({t.protocol==='mcp-jsonrpc'?'MCP':'HTTP Chat'} · {t.endpoint})
          </option>
         ))}
         {datasetHasStoredResponses&&!targets.some(t=>t.id==='generic-stored-target')&&(
          <option value="generic-stored-target">Offline Stored-Response Target (generic-stored-target)</option>
         )}
        </select>
       </label>

       {selectedTarget?(
        <div className="detail-grid compact" aria-label="Selected Target Summary" style={{marginTop:'0.75rem'}}>
         <div className="detail-pair">
          <span>Target ID</span>
          <strong className="mono">{selectedTarget.id}</strong>
         </div>
         <div className="detail-pair">
          <span>Protocol &amp; Model</span>
          <strong>
           <code className="mono">{selectedTarget.protocol}</code> · <code className="mono">{selectedTarget.default_model}</code>
          </strong>
         </div>
         <div className="detail-pair">
          <span>Endpoint</span>
          <strong className="mono wrap-anywhere">{selectedTarget.endpoint}</strong>
         </div>
         <div className="detail-pair">
          <span>Authorization Review</span>
          <strong>
           {selectedTarget.authorization_status==='reviewed_for_offline_configuration'
            ?'Reviewed'
            :'Review required'}
          </strong>
         </div>
        </div>
       ):(
        <div className="empty-box" style={{marginTop:'0.75rem'}}>
         {selectedTargetId==='generic-stored-target'
          ?'Using offline stored-response target binding (0 live HTTP requests).'
          :'Select a Target agent profile to continue.'}
        </div>
       )}
      </div>

      <div className="card">
       <div className="card-head-row">
        <h3>Test Dataset</h3>
        <a className="btn ghost sm" href="#datasets">Import Dataset →</a>
       </div>
       <label htmlFor="scan-dataset-select">Select Imported Dataset
        <select
         id="scan-dataset-select"
         value={selectedDatasetId}
         disabled={isSubmissionLocked}
         onChange={e=>{
          if(isActionLocked())return;
          setSelectedDatasetId(e.target.value);
         }}
        >
         {datasets.length===0&&<option value="">-- No imported datasets --</option>}
         {datasets.map(d=>(
          <option key={d.dataset_id} value={d.dataset_id}>
           {d.name} ({d.total_testcases} cases · {d.source_tool}{d.has_stored_responses?' · Stored Responses':''})
          </option>
         ))}
        </select>
       </label>

       {datasetDetail?(
        <div className="detail-grid compact" aria-label="Selected Dataset Summary" style={{marginTop:'0.75rem'}}>
         <div className="detail-pair">
          <span>Dataset Name</span>
          <strong>{datasetDetail.name}</strong>
         </div>
         <div className="detail-pair">
          <span>Total Testcases</span>
          <strong>{datasetDetail.total_testcases} testcases</strong>
         </div>
         <div className="detail-pair">
          <span>Source / Format</span>
          <strong className="mono">{datasetDetail.source_tool}</strong>
         </div>
         <div className="detail-pair">
          <span>Available Modes</span>
          <div className="badge-wrap">
           <span className="batch-cell-pill ready">Live Test</span>
           {datasetHasStoredResponses&&(
            <span className="batch-cell-pill ready">Offline Evaluation (Stored Responses)</span>
           )}
          </div>
         </div>
        </div>
       ):(
        <div className="empty-box" style={{marginTop:'0.75rem'}}>
         Select an imported security dataset to inspect testcase metadata.
        </div>
       )}
      </div>
     </div>

     <div className="notice info" role="note" style={{marginTop:'0.9rem'}}>
      <strong>Judge Engine Readiness:</strong>{' '}
      {piJudgeReady&&judgeSetupReason!=='credential_missing'
       ?'Hybrid LLM Judge + Rules is ready on the server (selectable in Step 2 Preview).'
       :judgeSetupReason==='credential_missing'
        ?'Server Judge credential is missing; Deterministic Rules / Evidence Only remains available in Step 2.'
        :'Judge setup unavailable; Deterministic Rules / Evidence Only remains available in Step 2.'}
     </div>

     <div className="scan-step-actions">
      <button
       type="button"
       className="btn primary"
       disabled={isSubmissionLocked||!selectedTargetId||!selectedDatasetId||selectedCaseIds.length===0}
       onClick={()=>{
        if(isActionLocked())return;
        void loadPreview();
       }}
      >
       {busy?'Checking Readiness...':'Continue to Scan Preview →'}
      </button>
     </div>

     <details className="target-advanced" style={{marginTop:'1rem'}} aria-label="Recover or open saved Scan Run">
      <summary>Open or Recover a Saved Generic Scan Run ({savedRuns.length} saved)</summary>
      <div className="inline-row" style={{marginTop:'0.6rem'}}>
       <label htmlFor="recover-run-id-input">Generic Run ID
        <input
         id="recover-run-id-input"
         value={recoverIdInput}
         onChange={e=>setRecoverIdInput(e.target.value)}
         placeholder="e.g. 4cb9995ab434410eb427e88c7ac202b7"
         maxLength={32}
        />
       </label>
       <button type="button" className="btn ghost sm" onClick={()=>void openExistingRun(recoverIdInput)}>
        Open Saved Run
       </button>
      </div>
      {savedRuns.length>0&&(
       <div className="tablewrap" style={{marginTop:'0.65rem'}}>
        <table className="history-table">
         <thead>
          <tr>
           <th>Run ID</th>
           <th>Target</th>
           <th>Mode</th>
           <th>Cases</th>
           <th>Verdicts</th>
           <th>Status</th>
           <th>Action</th>
          </tr>
         </thead>
         <tbody>
          {savedRuns.slice(0,10).map(sr=>(
           <tr key={sr.generic_run_id}>
            <td><code className="mono">{sr.generic_run_id}</code></td>
            <td>{sr.target_name} (<code className="mono">{sr.target_id}</code>)</td>
            <td><code className="mono">{sr.mode.toUpperCase()}</code></td>
            <td>{sr.executed_cases} / {sr.selected_cases}</td>
            <td>
             PASS: {sr.verdict_counts?.PASS??0} · FAIL: {sr.verdict_counts?.FAIL??0} · INC: {sr.verdict_counts?.INCONCLUSIVE??0}
            </td>
            <td><span className="pill">{sr.status}</span></td>
            <td>
             <button type="button" className="btn ghost sm" onClick={()=>void openExistingRun(sr.generic_run_id)}>
              Open Results
             </button>
            </td>
           </tr>
          ))}
         </tbody>
        </table>
       </div>
      )}
     </details>
    </section>
   )}

   {canOperatorAct&&step===2&&preview&&(
    <ScanPreviewPanel
     preview={preview}
     datasetDetail={datasetDetail}
     scanMode={scanMode}
     useJudge={useJudge}
     datasetHasStoredResponses={datasetHasStoredResponses}
     judgeSetupReason={judgeSetupReason}
     selectedCaseIds={selectedCaseIds}
     authorized={scanAuthorized}
     busy={busy}
     submissionLocked={hasUnresolvedSubmission}
     onBackToStep1={()=>{
      if(isActionLocked())return;
      setStep(1);
     }}
     onChangeMode={nextMode=>{
      if(isActionLocked())return;
      setScanMode(nextMode);
      void loadPreview(nextMode,useJudge,selectedCaseIds);
     }}
     onChangeEngine={nextJudge=>{
      if(isActionLocked())return;
      setUseJudge(nextJudge);
      void loadPreview(scanMode,nextJudge,selectedCaseIds);
     }}
     onSelectCases={next=>{
      if(isActionLocked())return;
      if(next.length>0){
       setSelectedCaseIds(next);
       void loadPreview(scanMode,useJudge,next);
      }
     }}
     onToggleAuthorized={checked=>{
      if(isActionLocked())return;
      setScanAuthorized(checked);
     }}
     onStartScan={()=>{
      if(isActionLocked())return;
      void startScan();
     }}
    />
   )}

   {canOperatorAct&&step===3&&runRecord&&isRunningRecord&&(()=>{
    const unified=resolveUnifiedDisplay(runRecord);
    const caseStatuses:GenericCaseStatus[]=unified.caseStatuses;
    return (
     <section className="panel" aria-label="Step 3: Live Scan Progress">
      <div className="section-title">
       <div>
        <span className="eyebrow">
         STEP 3 OF 3 · LIVE SCAN IN PROGRESS{unified.isUnified&&unified.resumeCount>0?` · RESUME SESSION #${unified.resumeCount}`:''}
        </span>
        <h2>
         3 · Live Scan Progress: <code className="mono">{unified.logicalScanId}</code>
        </h2>
       </div>
      </div>
      <ProgressMetadata record={runRecord}/>
      <ScanProgressBar record={runRecord}/>
      <ExecutionCounters record={runRecord}/>
      <div className="split live-work-grid">
       <CurrentTestcase record={runRecord}/>
       <BudgetUsage record={runRecord}/>
      </div>
      <TestcaseStatusList cases={caseStatuses}/>
     </section>
    );
   })()}

   {canOperatorAct&&step===3&&runRecord&&!isRunningRecord&&(
    <>
     {resumeOpen&&(
      <ScanResumePanel
       preview={resumePreview}
       previewStale={resumePreviewStale}
       loading={resumeLoading}
       starting={resumeStarting}
       error={resumeError}
       selectedUncertainIds={selectedUncertainIds}
       onToggleUncertain={(cid,checked)=>{void handleToggleUncertain(cid,checked);}}
       onRecheck={()=>{
        const resumeSourceId=resumePreview?.parent_run_id||runRecord.unified_lineage?.resumable_run_id||runRecord.lineage_summary?.resumable_run_id||runRecord.generic_run_id;
        void loadResumePreview(resumeSourceId,selectedUncertainIds,false);
       }}
       onConfirmAndResume={()=>{void handleConfirmAndResume();}}
       onCancel={resetResumeState}
      />
     )}
     <ScanResultsView
      runRecord={runRecord}
      localSingleUser={localSingleUser}
      secret={secret}
      onNewScan={resetToNewScan}
      onExportError={setError}
      onResumeScan={()=>{void openResumePreview();}}
      onOpenRun={id=>{void openExistingRun(id);}}
      resumeBusy={resumeLoading||resumeStarting||busy}
      resumePanelOpen={resumeOpen}
     />
    </>
   )}
  </div>
 );
}
