import {useEffect,useState} from 'react';
import {get,safeLabel} from './api';
import {Badge} from './components';
import DownloadReport from './DownloadReport';

type McpRun={run_id:string;report_sha256:string;native_report:Record<string,unknown>;provenance_limit:string};
function parse(value:unknown):McpRun{
 if(!value||typeof value!=='object'||Array.isArray(value))throw Error('Invalid MCP report.');
 const row=value as Record<string,unknown>;
 if(row.api_schema_version!=='1.0.0'||typeof row.run_id!=='string'||!/^[a-f0-9]{32}$/.test(row.run_id)||typeof row.report_sha256!=='string'||!/^[a-f0-9]{64}$/.test(row.report_sha256)||!row.native_report||typeof row.native_report!=='object'||Array.isArray(row.native_report)||typeof row.provenance_limit!=='string')throw Error('Invalid MCP report.');
 return row as McpRun;
}
export default function McpRunDetail({id}:{id:string}){
 const [data,setData]=useState<McpRun|null>(null),[error,setError]=useState('');
 useEffect(()=>{const controller=new AbortController();setData(null);setError('');if(!/^[a-f0-9]{32}$/.test(id)){setError('Invalid run identity.');return;}
  get(`mcp-runs/${id}`,parse,controller.signal).then(row=>{if(row.run_id!==id)throw Error('Run identity changed.');setData(row);}).catch(e=>{if(!controller.signal.aborted)setError(e instanceof Error?e.message:'MCP report unavailable.');});return()=>controller.abort();},[id]);
 if(error)return <p role="alert">{error}</p>;
 if(!data)return <p role="status">Loading MCP Native Report...</p>;
 const report=data.native_report;
 const verdict=typeof report.final_verdict==='string'?report.final_verdict:null;
 return <section className="panel detail-page"><a href="#executions">Back to history</a><h1>MCP action Native Report</h1>
  <p>Testcase: {safeLabel(typeof report.testcase_id==='string'?report.testcase_id:null)} · Target: {safeLabel(typeof report.target_id==='string'?report.target_id:null)}</p>
  <p>Scope: {safeLabel(typeof report.evaluation_scope==='string'?report.evaluation_scope:null)} · Outcome: <Badge value={verdict}/></p>
  {verdict==='ERROR'&&<p className="notice" role="status">Execution error occurred before a definitive security outcome was established. This is not a security FAIL or discovered vulnerability.</p>}
  <p>{data.provenance_limit}</p><DownloadReport kind="mcp-runs" id={id}/>
  <details><summary>Sanitized Native Report details</summary><pre className="report-json">{JSON.stringify(report,null,2)}</pre></details>
 </section>;
}
