import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import {expect,it,vi} from 'vitest';
import DownloadReport from './DownloadReport';

function browserSave(){
 const create=vi.fn(()=> 'blob:synthetic-export'),revoke=vi.fn();
 Object.defineProperty(URL,'createObjectURL',{configurable:true,value:create});
 Object.defineProperty(URL,'revokeObjectURL',{configurable:true,value:revoke});
 const click=vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{});
 return {create,click};
}
it('downloads backend ZIP only on click with a safe filename',async()=>{
 const {click}=browserSave();const fetch=vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response('zip-bytes',{
  headers:{'Content-Type':'application/zip','Content-Disposition':'attachment; filename="secagent-batch.zip"','X-SecAgent-Export-Schema':'1.0.0'}}));
 render(<DownloadReport kind="batches" id={'a'.repeat(32)}/>);
 expect(fetch).not.toHaveBeenCalled();fireEvent.click(screen.getByRole('button',{name:'Download Full Report'}));
 await waitFor(()=>expect(click).toHaveBeenCalledOnce());
 expect(fetch.mock.calls[0][0]).toBe('/api/reports/batches/'+ 'a'.repeat(32)+'/download');
 expect((click.mock.instances[0] as HTMLAnchorElement).download).toBe('secagent-batch.zip');
});
it('shows generating state and discards late downloads after switching batch',async()=>{
 const {click}=browserSave();let resolve!:(r:Response)=>void;
 vi.spyOn(globalThis,'fetch').mockImplementation(()=>new Promise(r=>{resolve=r;}));
 const view=render(<DownloadReport kind="batches" id={'a'.repeat(32)}/>);
 fireEvent.click(screen.getByRole('button'));expect(screen.getByRole('button',{name:'Preparing export...'})).toBeDisabled();
 view.rerender(<DownloadReport kind="batches" id={'b'.repeat(32)}/>);
 resolve(new Response('zip',{headers:{'Content-Type':'application/zip','Content-Disposition':'attachment; filename="old.zip"','X-SecAgent-Export-Schema':'1.0.0'}}));
 await waitFor(()=>expect(screen.getByRole('button',{name:'Download Full Report'})).toBeEnabled());expect(click).not.toHaveBeenCalled();
});
it('reports missing batch without downloading or retrying',async()=>{
 const {click}=browserSave();const fetch=vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response('{}',{status:404}));
 render(<DownloadReport kind="runs" id={'a'.repeat(32)}/>);fireEvent.click(screen.getByRole('button',{name:'Download Report'}));
 expect(await screen.findByRole('alert')).toHaveTextContent('not available');expect(click).not.toHaveBeenCalled();expect(fetch).toHaveBeenCalledOnce();
});
