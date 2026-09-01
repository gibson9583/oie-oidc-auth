import { platform } from '@oie/web-shell';
const React=platform.React,api=platform.api;const {toast,taskButton}=platform.ui;const EXT='/extensions/oidcauth';
const fields=[
 ['discovery-url','Discovery URL','url'],['client-id','Client ID','text'],['username-claim','Username claim','text'],['username-prefix','Username prefix','text'],
 ['jit.email-claim','Email claim','text'],['jit.name-claim','Name claim','text'],['jit.organization-claim','Organization claim','text'],
 ['allowed-algorithms','Allowed algorithms','text'],['clock-skew-seconds','Clock skew (seconds)','number'],['max-token-age-seconds','Maximum token age (seconds)','number'],['jwks-cache-ttl-seconds','JWKS cache TTL (seconds)','number'],
 ['roles.claim','Roles claim','text'],['roles.default','Default role','text']
];
// The wire format for map-shaped policy is comma-joined key=value; editing that
// by hand is error-prone, so render rows and serialize on the way out.
const parsePairs=(value)=>String(value||'').split(',').map(s=>s.trim()).filter(Boolean).map(item=>{const i=item.indexOf('=');return i>0?{k:item.slice(0,i).trim(),v:item.slice(i+1).trim()}:{k:item.trim(),v:''};});
const serializePairs=(rows)=>rows.filter(r=>r.k.trim()&&r.v.trim()).map(r=>`${r.k.trim()}=${r.v.trim()}`).join(',');
function PairEditor({label,value,onChange,disabled,keyPlaceholder,valuePlaceholder,addLabel}){
 const [rows,setRows]=React.useState(()=>parsePairs(value));
 const last=React.useRef(value);
 // Refresh/load replaced the form value externally — rebuild the rows.
 React.useEffect(()=>{if(value!==last.current){last.current=value;setRows(parsePairs(value));}},[value]);
 const commit=(next)=>{setRows(next);const s=serializePairs(next);if(s!==last.current){last.current=s;onChange(s);}};
 const edit=(i,part,text)=>commit(rows.map((r,at)=>at===i?{...r,[part]:text.replace(/[,=]/g,'')}:r));
 return <div className="field">
  <label>{label}</label>
  {rows.map((row,i)=><div key={i} style={{display:'flex',gap:8,alignItems:'center',marginBottom:8}}>
   <input style={{flex:1}} type="text" value={row.k} placeholder={keyPlaceholder} disabled={disabled} onChange={e=>edit(i,'k',e.target.value)}/>
   <span className="text-text-faint">→</span>
   <input style={{flex:1}} type="text" value={row.v} placeholder={valuePlaceholder} disabled={disabled} onChange={e=>edit(i,'v',e.target.value)}/>
   <button className="btn" type="button" disabled={disabled} title="Remove" onClick={()=>commit(rows.filter((_,at)=>at!==i))}>×</button>
  </div>)}
  <button className="btn" type="button" disabled={disabled} onClick={()=>{setRows([...rows,{k:'',v:''}]);}}>{addLabel}</button>
 </div>}
// The servlet exchanges JSON TEXT in String parameters/returns, which the
// engine's XStream serializer carries as {"string": "<json>"} on the wire:
// api.get unwraps the root key and hands us the inner string to parse, and
// writes must wrap the JSON text back under {string} for the body reader.
const decode=(value)=>{if(typeof value==='string')return value?JSON.parse(value):{};return value&&typeof value==='object'?(typeof value.string==='string'?JSON.parse(value.string):value):{};};
function OidcPanel({setTasks,setSave,markDirty,markClean}){const [form,setForm]=React.useState(null),[error,setError]=React.useState('');
 // Task closures read the CURRENT form through a ref. Putting `form` in the
 // task-registration effect's deps — with load() rewriting form on every
 // response — re-fired load() per response: an infinite GET loop.
 const formRef=React.useRef(null);formRef.current=form;
 const load=React.useCallback(async()=>{try{setForm(decode(await api.get(`${EXT}/configuration`)));setError('');markClean();}catch(e){setError(e.message||'Failed to load OIDC configuration.');}},[markClean]);
 // Re-read after every save: the PUT answers 204, so the ONLY way to see what
 // the engine actually kept is to ask for it. A save that silently didn't
 // stick then shows up in the form instead of hiding behind a success toast.
 const save=React.useCallback(async()=>{try{await api.put(`${EXT}/configuration`,{string:JSON.stringify(form)});setForm(decode(await api.get(`${EXT}/configuration`)));toast('OIDC configuration saved.','success');markClean();return true;}catch(e){toast(e.message||'OIDC configuration could not be saved.','error');return false;}},[form,markClean]);
 const saveRef=React.useRef(save);saveRef.current=save;
 // Fetch exactly once per mount; the Refresh task re-runs it on demand.
 // eslint-disable-next-line react-hooks/exhaustive-deps
 React.useEffect(()=>{load();},[]);
 // Save leads the task pane, like every built-in settings tab; the doSave
 // task/group lets RBAC hide it from read-only viewers.
 React.useEffect(()=>{setTasks('OIDC Authentication Tasks',[
  taskButton('Save','save',()=>saveRef.current(),{primary:true,task:'doSave',group:'settings_OIDC Authentication'}),
  taskButton('Refresh','refresh',load),
  taskButton('Test connection','check',async()=>{try{const r=decode(await api.post(`${EXT}/test`,{string:JSON.stringify(formRef.current)}));toast(`OIDC discovery succeeded: ${r.issuer||'issuer verified'}`,'success');}catch(e){toast(e.message||'OIDC connection test failed.','error');}})
 ]);},[load,setTasks]);
 React.useEffect(()=>setSave(()=>save),[save,setSave]);const patch=(key,value)=>{setForm(f=>({...f,[key]:value}));markDirty();};
 if(error)return <div className="p-4" style={{color:'var(--err)'}}>{error}</div>;if(!form)return <div className="p-4 text-text-faint">Loading…</div>;
 return <div className="p-4" style={{maxWidth:820}}>
 <div className="mb-4"><label className="check"><input type="checkbox" checked={String(form.enabled)==='true'} onChange={e=>patch('enabled',String(e.target.checked))}/>Enable OIDC login</label></div>
 <div className="grid grid-cols-2 gap-4">{fields.map(([key,label,type])=><div className="field" key={key}><label>{label}</label><input type={type} value={form[key]||''} onChange={e=>patch(key,e.target.value)} disabled={String(form.enabled)!=='true'}/></div>)}
 <div className="field"><label>JIT provision unknown users</label><select value={form['jit.enabled']||'false'} onChange={e=>patch('jit.enabled',e.target.value)} disabled={String(form.enabled)!=='true'}><option value="true">Yes</option><option value="false">No</option></select></div>
 <div className="field"><label>Role synchronization</label><select value={form['roles.sync']||'always'} onChange={e=>patch('roles.sync',e.target.value)} disabled={String(form.enabled)!=='true'}><option value="always">Every login</option><option value="jit-only">JIT only</option><option value="never">Never</option></select></div>
 <div className="field"><label>Infer roles by name</label><select value={form['roles.infer']||'false'} onChange={e=>patch('roles.infer',e.target.value)} disabled={String(form.enabled)!=='true'}><option value="false">No — mapped claims only</option><option value="true">Yes — claim values matching a role name</option></select></div></div>
 <div className="mt-4" style={{maxWidth:560}}>
  <PairEditor label="Claim-to-role mappings" value={form['roles.map']||''} disabled={String(form.enabled)!=='true'}
   keyPlaceholder="claim value (e.g. oie-admins)" valuePlaceholder="RBAC role (e.g. Administrator)" addLabel="Add mapping"
   onChange={v=>patch('roles.map',v)}/>
  <PairEditor label="Linked accounts" value={form['linked-accounts']||''} disabled={String(form.enabled)!=='true'}
   keyPlaceholder="engine username" valuePlaceholder="issuer#subject" addLabel="Link account"
   onChange={v=>patch('linked-accounts',v)}/>
 </div>
 </div>}
export async function register(host){
 // Mirror the RBAC plugin's own Settings-panel pattern: load the signed-in
 // user's permission set during awaited plugin registration, and only register
 // the panel when its extension permission is present. Without RBAC installed,
 // the engine uses its normal allow-all authorization controller, so the panel
 // remains available and its own API still enforces the active controller.
 try{
  let raw=await api.get('/extensions/rbac/my-permissions');
  if(raw&&typeof raw==='object'&&!Array.isArray(raw))raw=raw.string;
  const permissions=new Set((raw==null||raw===''?[]:Array.isArray(raw)?raw:[raw]).map(String));
  if(!permissions.has('manageOIDC'))return;
 }catch(e){
  if(!(e&&(e.status===404||e.status===501))){console.warn('[oidcauth] permission load failed — hiding settings panel:',e);return;}
 }
 host.registerSettingsPanel({label:'OIDC Authentication',order:80,component:OidcPanel});
}
