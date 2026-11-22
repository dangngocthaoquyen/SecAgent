import {useEffect,useState} from 'react';
import {api,emptySavedRunFilters,safeLabel,type SavedRunFilters,type SavedRunsPage} from './api';
import {Badge} from './components';
import DownloadReport from './DownloadReport';

export default function SavedRuns(){
 const [draft,setDraft]=useState<SavedRunFilters>({...emptySavedRunFilters}),[filters,setFilters]=useState<SavedRunFilters>({...emptySavedRunFilters});
 const [page,setPage]=useState(1),[retry,setRetry]=useState(0),[data,setData]=useState<SavedRunsPage|null>(null),[error,setError]=useState('');
 useEffect(()=>{const controller=new AbortController();setError('');api.savedRuns(filters,page,25,controller.signal).then(setData).catch(e=>{if(!controller.signal.aborted)setError(e instanceof Error?e.message:'Saved history unavailable.');});return()=>controller.abort();},[filters,page,retry]);
 const edit=(key:keyof SavedRunFilters,value:string)=>setDraft(current=>({...current,[key]:value}));
 return <section className="panel results-panel" aria-label="Saved run history">
  <div className="page-title"><div><span className="eyebrow">PERSISTENT HISTORY</span><h2>Saved Native Reports</h2><p>Read from the configured local report root on each request. Archived Targets remain in history. Execution ERROR states are distinct from security PASS/FAIL findings.</p></div></div>
  <form className="filters" onSubmit={e=>{e.preventDefault();if(draft.date_from&&draft.date_to&&draft.date_from>draft.date_to){setError('Date from must not be after Date to.');return;}setError('');setPage(1);setFilters({...draft,testcase_id:draft.testcase_id.trim(),target_id:draft.target_id.trim()});}}>
   <label>ASI<select value={draft.asi_category} onChange={e=>edit('asi_category',e.target.value)}><option value="">All</option>{['ASI01','ASI02','ASI03','ASI05'].map(v=><option key={v}>{v}</option>)}<option value="unknown">Unknown</option></select></label>
   <label>Target ID<input value={draft.target_id} onChange={e=>edit('target_id',e.target.value)} maxLength={256}/></label>
   <label>Testcase ID<input value={draft.testcase_id} onChange={e=>edit('testcase_id',e.target.value)} maxLength={256}/></label>
   <label>Verdict / Outcome<select value={draft.verdict} onChange={e=>edit('verdict',e.target.value)}><option value="">All</option>{['PASS','FAIL','INCONCLUSIVE','ERROR'].map(v=><option key={v} value={v}>{v==='ERROR'?'ERROR (execution error)':v}</option>)}</select></label>
   <label>Date from<input type="date" value={draft.date_from} onChange={e=>edit('date_from',e.target.value)}/></label>
   <label>Date to<input type="date" value={draft.date_to} onChange={e=>edit('date_to',e.target.value)}/></label>
   <button type="submit">Filter</button><button type="button" onClick={()=>{setError('');setDraft({...emptySavedRunFilters});setFilters({...emptySavedRunFilters});setPage(1);}}>Reset</button><button type="button" onClick={()=>setRetry(n=>n+1)}>Refresh</button>
  </form>
  {error&&<p role="alert">{error}</p>}
  {data&&<><p role="status">{data.total} saved reports{data.invalid_artifact_count>0?`; ${data.invalid_artifact_count} invalid artifacts excluded`:''}.</p>
   <div className="table-scroll"><table className="execution-table"><thead><tr><th>Date</th><th>Testcase</th><th>ASI</th><th>Target</th><th>Outcome / Verdict</th><th>Source</th><th>Export</th></tr></thead><tbody>
    {data.items.map(row=><tr key={`${row.kind}-${row.run_id}`}><td>{safeLabel(row.started_at)}</td><th scope="row"><a href={`#${row.kind==='mcp_action'?'mcp-run':'run'}/${row.run_id}`}>{safeLabel(row.testcase_id)}</a></th><td>{safeLabel(row.asi_category)}</td><td>{safeLabel(row.target_id)}</td><td><Badge value={row.verdict}/></td><td>{row.kind==='mcp_action'?'MCP action':'Controlled run'}</td><td><DownloadReport kind={row.kind==='mcp_action'?'mcp-runs':'runs'} id={row.run_id}/></td></tr>)}
   </tbody></table></div>
   <div className="pagination"><button disabled={page<=1} onClick={()=>setPage(n=>n-1)}>Previous</button><span>Page {page} of {Math.max(1,Math.ceil(data.total/25))}</span><button disabled={page*25>=data.total} onClick={()=>setPage(n=>n+1)}>Next</button></div>
  </>}
 </section>;
}
