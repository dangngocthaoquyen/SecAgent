import {useEffect,useRef,useState} from 'react';

export default function DownloadReport({kind,id,format}:{kind:'batches'|'runs'|'mcp-runs'|'executions';id:string;format?:'zip'|'json'}){
 const [busy,setBusy]=useState(false),[error,setError]=useState('');
 const wantsJson=kind!=='batches'||format==='json';
 const request=useRef<AbortController|null>(null),identity=`${kind}/${id}/${format??'default'}`,current=useRef(identity);
 current.current=identity;
 useEffect(()=>{setBusy(false);setError('');return()=>{request.current?.abort();request.current=null;};},[identity]);
 async function download(){
  if(request.current)return;
  if(!(kind==='executions'?/^execution:[a-f0-9]{64}$/:/^[a-f0-9]{32}$/).test(id)){setError('Invalid report identity.');return;}
  const controller=new AbortController(),key=identity;request.current=controller;setBusy(true);setError('');
  const timeout=setTimeout(()=>controller.abort(),60000);
  try{
   const suffix=kind==='batches'&&format==='json'?'report.json':'download';
   const response=await fetch(`/api/reports/${kind}/${encodeURIComponent(id)}/${suffix}`,{method:'GET',credentials:'omit',cache:'no-store',signal:controller.signal});
   if(!response.ok)throw Error(response.status===404?'Report or batch is not available in this reporting workspace.':response.status===409?'Export rejected: batch is still active or saved report integrity could not be confirmed.':response.status===403?'Download access denied. Use the authorized local reporting session.':'Report download failed. Try again after checking the reporting service.');
   const filename=/^attachment; filename="([A-Za-z0-9_-]+\.(?:zip|json))"$/.exec(response.headers.get('Content-Disposition')??'')?.[1];
   const mime=wantsJson?'application/json':'application/zip';
   if(!filename||!filename.endsWith(wantsJson?'.json':'.zip')||response.headers.get('X-SecAgent-Export-Schema')!=='1.0.0'||!response.headers.get('Content-Type')?.startsWith(mime))throw Error('Unsupported export response. No file was saved.');
   const blob=await response.blob();
   if(controller.signal.aborted||current.current!==key)return;
   if(blob.size>70*1024*1024)throw Error('Export exceeds the download size limit.');
   const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=filename;document.body.append(link);link.click();link.remove();
   setTimeout(()=>URL.revokeObjectURL(url),1000);
  }catch(e){if(current.current===key&&request.current===controller)setError(controller.signal.aborted?'Export timed out. No automatic retry was made.':e instanceof Error?e.message:'Export unavailable.');}
  finally{clearTimeout(timeout);if(request.current===controller){request.current=null;setBusy(false);}}
 }
 return <span className="report-download"><button type="button" disabled={busy} onClick={()=>void download()}>{busy?'Preparing export...':kind==='batches'?'Download Full Report':'Download Report'}</button>{error&&<span role="alert">{error}</span>}</span>;
}
