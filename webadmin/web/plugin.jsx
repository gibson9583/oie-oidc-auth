import { platform } from '@oie/web-shell';
const React=platform.React,api=platform.api;const {toast,taskButton}=platform.ui;const EXT='/extensions/oidcauth';
// The wire format for map-shaped policy is comma-joined key=value; editing that
// by hand is error-prone, so render rows and serialize on the way out.
// Rows carry a stable id. Keying by array index remounts every row below a
// removal, so React hands the wrong DOM node the wrong value and focus/caret
// jump to a different row mid-edit.
let nextRowId=0;
// Split on the FIRST '=' only: a key cannot contain one, but a value routinely
// does — a linked-accounts subject is `issuer#subject`, and base64url subjects
// carry '=' padding. Stripping it from input made those unenterable.
// The schema carries values; these are the words an operator reads for them.
// Anything unlisted falls back to the raw value, so adding a choice engine-side
// shows up here immediately rather than rendering blank.
const CHOICE_LABELS={'jit.enabled':{true:'Yes',false:'No'},'roles.infer':{false:'No — mapped claims only',true:'Yes — claim values matching a role name'},'roles.sync':{always:'Every login','jit-only':'JIT only',never:'Never'}};
const choiceLabel=(key,value)=>(CHOICE_LABELS[key]&&CHOICE_LABELS[key][value])||value;
// The engine parses booleans strictly, so mirror it rather than treating every
// unrecognized value as false — a policy the engine rejects should not render
// as a confidently unticked box.
const truthy=(value)=>['true','yes','on','1'].includes(String(value==null?'':value).trim().toLowerCase());
const parsePairs=(value)=>String(value||'').split(',').map(s=>s.trim()).filter(Boolean).map(item=>{const i=item.indexOf('=');return {id:++nextRowId,...(i>0?{k:item.slice(0,i).trim(),v:item.slice(i+1).trim()}:{k:item.trim(),v:''})};});
const serializePairs=(rows)=>rows.filter(r=>r.k.trim()&&r.v.trim()).map(r=>`${r.k.trim()}=${r.v.trim()}`).join(',');
// What serializePairs would silently discard, said out loud. A half-filled row
// never reaches the PUT but stays on screen, so without this the operator gets a
// success toast, a phantom mapping, and a tab that no longer matches the engine.
const pairProblem=(rows)=>{
 if(rows.some(r=>!!r.k.trim()!==!!r.v.trim()))return 'Every row needs both a key and a value — fill the blank one in, or remove the row.';
 const keys=rows.map(r=>r.k.trim()).filter(Boolean);
 const duplicate=keys.find((k,i)=>keys.indexOf(k)!==i);
 return duplicate?`"${duplicate}" appears more than once — only the last would take effect.`:null;
};
// A select over names the engine knows that never swallows one it does not: a
// role typed before RBAC listed it, or renamed since, stays visible and selected
// — marked — instead of snapping to the first option and quietly rewriting the
// policy on the next save.
function ChoiceSelect({value,options,placeholder,disabled,onChange,style}){
 const current=String(value||'');
 return <select style={style} value={current} disabled={disabled} onChange={e=>onChange(e.target.value)}>
  <option value="">{placeholder||'— choose —'}</option>
  {options.map(o=><option key={o} value={o}>{o}</option>)}
  {current&&!options.includes(current)?<option value={current}>{current} (not an existing role)</option>:null}
 </select>}
// The RBAC role list in whichever shape the engine's serializer hands over: the
// XStream root key may or may not have been unwrapped, and a one-role list
// arrives as a bare object rather than an array.
const roleNamesOf=(raw)=>{
 const inner=raw&&typeof raw==='object'&&!Array.isArray(raw)&&raw.list?raw.list:raw;
 const roles=inner&&typeof inner==='object'&&!Array.isArray(inner)&&inner['com.diridium.rbac.Role']!==undefined?inner['com.diridium.rbac.Role']:inner;
 const list=Array.isArray(roles)?roles:roles&&typeof roles==='object'?[roles]:[];
 return list.map(r=>r&&r.name).filter(Boolean);};
function PairEditor({label,value,onChange,onProblem,disabled,keyPlaceholder,valuePlaceholder,valueOptions,addLabel}){
 const [rows,setRows]=React.useState(()=>parsePairs(value));
 const last=React.useRef(value);
 // Refresh/load replaced the form value externally — rebuild the rows.
 React.useEffect(()=>{if(value!==last.current){last.current=value;setRows(parsePairs(value));}},[value]);
 // Only while editable. A problem inherited from stored data — a hand-written
 // policy, or an OIE_OIDC_* pin — would otherwise block Save with rows the
 // operator cannot touch, since every input is disabled until OIDC is enabled.
 const problem=disabled?null:pairProblem(rows);
 React.useEffect(()=>{onProblem(problem);return()=>onProblem(null);},[problem,onProblem]);
 const commit=(next)=>{setRows(next);const s=serializePairs(next);if(s!==last.current){last.current=s;onChange(s);}};
 // ',' separates entries so neither side may carry one; '=' separates the pair,
 // so only the KEY has to avoid it.
 const edit=(id,part,text)=>commit(rows.map(r=>r.id===id?{...r,[part]:part==='k'?text.replace(/[,=]/g,''):text.replace(/,/g,'')}:r));
 return <div className="field">
  <label>{label}</label>
  {rows.map((row)=><div key={row.id} style={{display:'flex',gap:8,alignItems:'center',marginBottom:8}}>
   <input style={{flex:1}} type="text" value={row.k} placeholder={keyPlaceholder} disabled={disabled} onChange={e=>edit(row.id,'k',e.target.value)}/>
   <span className="text-text-faint">→</span>
   {Array.isArray(valueOptions)
    ? <ChoiceSelect style={{flex:1}} value={row.v} options={valueOptions} placeholder={valuePlaceholder} disabled={disabled} onChange={v=>edit(row.id,'v',v)}/>
    : <input style={{flex:1}} type="text" value={row.v} placeholder={valuePlaceholder} disabled={disabled} onChange={e=>edit(row.id,'v',e.target.value)}/>}
   <button className="btn" type="button" disabled={disabled} title="Remove" onClick={()=>commit(rows.filter(r=>r.id!==row.id))}>×</button>
  </div>)}
  <button className="btn" type="button" disabled={disabled} onClick={()=>{setRows([...rows,{id:++nextRowId,k:'',v:''}]);}}>{addLabel}</button>
  {problem?<div style={{color:'var(--err)',fontSize:12,marginTop:4}}>{problem}</div>:null}
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
 // A row the editors would drop must block the save rather than ride along as a
 // success toast over a config the engine never received.
 const [pairProblems,setPairProblems]=React.useState({});
 // One STABLE callback per editor, cached by key. Returning a fresh closure per
 // render put a new function in PairEditor's effect deps every render, and since
 // the effect's cleanup nulls the problem before re-setting it, neither state
 // update could bail — every render scheduled another. A single half-filled row
 // spun past 500 renders into React's update-depth invariant, which is worse
 // than the silent drop this was written to fix.
 const problemHandlers=React.useRef({});
 const noteProblem=React.useCallback((which)=>{
  if(!problemHandlers.current[which])problemHandlers.current[which]=(problem)=>setPairProblems(p=>(p[which]===problem?p:{...p,[which]:problem}));
  return problemHandlers.current[which];
 },[]);
 const problemsRef=React.useRef(pairProblems);problemsRef.current=pairProblems;
 const save=React.useCallback(async()=>{
  const blocking=Object.values(problemsRef.current).filter(Boolean);
  if(blocking.length){toast(blocking[0],'error');return false;}
  try{await api.put(`${EXT}/configuration`,{string:JSON.stringify(form)});}
  catch(e){toast(e.message||'OIDC configuration could not be saved.','error');return false;}
  // The PUT succeeded. The re-read below is how the form comes to show what the
  // engine actually kept, but it is a SEPARATE request — failing it does not
  // un-save anything, and reporting an error here told the operator their change
  // was lost when it had landed. Say what is true: saved, display may be stale.
  markClean();
  try{setForm(decode(await api.get(`${EXT}/configuration`)));toast('OIDC configuration saved.','success');}
  catch(e){toast(`OIDC configuration saved, but the tab could not re-read it: ${e.message||'refresh to confirm.'}`,'warn');}
  return true;},[form,markClean]);
 const saveRef=React.useRef(save);saveRef.current=save;
 // The RBAC role list, for the two fields that name roles. null = unavailable
 // (RBAC not installed, or this user cannot read roles), and those fields stay
 // free text. The engine only checks that a default role is SET, so a typo in a
 // typed name surfaces later, at someone's login, as "role does not exist;
 // leaving role unchanged" — a list removes the typo.
 const [roleNames,setRoleNames]=React.useState(null);
 React.useEffect(()=>{let alive=true;(async()=>{try{const names=roleNamesOf(await api.get('/extensions/rbac/roles'));if(alive&&names.length)setRoleNames(names);}catch(e){/* free text */}})();return()=>{alive=false;};},[]);
 // Fetch exactly once per mount; the Refresh task re-runs it on demand.
 // eslint-disable-next-line react-hooks/exhaustive-deps
 React.useEffect(()=>{load();},[]);
 // Save leads the task pane, like every built-in settings tab; the doSave
 // task/group lets RBAC hide it from read-only viewers.
 React.useEffect(()=>{setTasks('OIDC Authentication Tasks',[
  taskButton('Save','save',()=>saveRef.current(),{primary:true,task:'doSave',group:'settings_OIDC Authentication'}),
  taskButton('Refresh','refresh',load),
  taskButton('Test connection','check',async()=>{try{const r=decode(await api.post(`${EXT}/test`,{string:JSON.stringify(formRef.current)}));toast(`OIDC verified: ${r.issuer||'issuer'} — ${r.keyCount||0} signing key(s) reachable`,'success');}catch(e){toast(e.message||'OIDC connection test failed.','error');}})
 ]);},[load,setTasks]);
 // The host stores what it is given and CALLS it when the operator picks
 // "Save" in the unsaved-changes prompt (settings.tsx: saveRef.current()). This
 // used to register ()=>save — a function that RETURNS save — so that call
 // handed back a function, which is not === false, and the host proceeded as if
 // the save had succeeded: changes were discarded behind an apparent save.
 // Register the save itself, as every built-in tab does.
 React.useEffect(()=>{setSave(save);},[save,setSave]);const patch=(key,value)=>{setForm(f=>({...f,[key]:value}));markDirty();};
 if(error)return <div className="p-4" style={{color:'var(--err)'}}>{error}</div>;if(!form)return <div className="p-4 text-text-faint">Loading…</div>;
 // Effective state the stored policy cannot express (see the servlet's reserved
 // "_" keys): an emergency switch thrown outside the UI, and a policy the engine
 // rejected at load. Both leave the checkbox below ticked while SSO is in fact
 // off, which is the state most likely to be misread as healthy.
 const pinned=Array.isArray(form._pinned)?form._pinned:[];
 const schema=Array.isArray(form._schema)?form._schema:[];
 // The single answer to "can this be edited?": not while the policy is off, and
 // never for a key the operator pinned outside the database.
 const locked=(key)=>(key!=='enabled'&&!truthy(form.enabled))||pinned.includes(key);
 const pinnedNote=(key)=>pinned.includes(key)?<span className="text-text-faint" style={{fontWeight:'normal'}}> — pinned</span>:null;
 return <div className="p-4" style={{maxWidth:820}}>
 {String(form._killSwitch)==='true'?<div className="mb-4 p-2" style={{border:'1px solid var(--err)',borderRadius:6,color:'var(--err)'}}>
  <strong>SSO is switched off by the emergency kill switch.</strong> The engine is refusing every OIDC sign-in and no longer advertises SSO to the login screen, whatever this form says. Clear <code>OIE_OIDC_DISABLED</code> (or the <code>org.openintegrationengine.oidc.disabled</code> system property) and restart to re-enable.
 </div>:null}
 {form._error?<div className="mb-4 p-2" style={{border:'1px solid var(--err)',borderRadius:6,color:'var(--err)'}}>
  <strong>This policy is not in force.</strong> The engine rejected it at load: {form._error} Until it parses, the login screen offers no SSO button and sign-in attempts are told SSO is disabled.
 </div>:null}
 {pinned.length?<div className="mb-4 p-2" style={{border:'1px solid var(--line)',borderRadius:6}}>
  Pinned by the operator environment — an <code>OIE_OIDC_*</code> variable or system property overrides these, so they are shown read-only and saving leaves the stored policy untouched: <strong>{pinned.join(', ')}</strong>
 </div>:null}
 <div className="mb-4 text-text-faint" style={{fontSize:12}}>Redirect URI to register with your provider: <code>{form._redirectUri||'<web-administrator-origin>/oidc/callback'}</code></div>
 {/* Every control below derives from the schema the engine sent, so "is this
     field editable?" is answered in ONE place. The tab used to keep its own
     field list beside hand-written disabled= expressions, and they disagreed:
     five of six controls ignored pinning entirely, so an operator could tick
     "Enable OIDC login" against an OIE_OIDC_ENABLED=false pin, get a success
     toast, and watch the re-read silently revert it — the exact failure the
     pinned banner claims to prevent. */}
 {schema.filter(f=>f.key==='enabled').map(f=><div className="mb-4" key={f.key}>
  <label className="check"><input type="checkbox" checked={truthy(form.enabled)} disabled={locked(f.key)}
   onChange={e=>patch('enabled',String(e.target.checked))}/>{f.label}{pinnedNote(f.key)}</label>
 </div>)}
 <div className="grid grid-cols-2 gap-4">{schema.filter(f=>f.key!=='enabled'&&f.kind!=='pairs').map(f=>
  <div className="field" key={f.key}><label>{f.label}{pinnedNote(f.key)}</label>
   {f.kind==='boolean'||f.kind==='enum'
    ? <select value={form[f.key]||''} disabled={locked(f.key)} onChange={e=>patch(f.key,e.target.value)}>
       {(f.kind==='boolean'?['true','false']:f.choices||[]).map(c=><option key={c} value={c}>{choiceLabel(f.key,c)}</option>)}
      </select>
    : f.key==='roles.default'&&roleNames
     ? <ChoiceSelect value={form[f.key]||''} options={roleNames} placeholder="— no default role —" disabled={locked(f.key)} onChange={v=>patch(f.key,v)}/>
     : <input type={f.kind==='number'?'number':f.kind==='url'?'url':'text'} value={form[f.key]||''}
       disabled={locked(f.key)} onChange={e=>patch(f.key,e.target.value)}/>}
  </div>)}</div>
 <div className="mt-4" style={{maxWidth:560}}>{schema.filter(f=>f.kind==='pairs').map(f=>
  <PairEditor key={f.key} label={f.label+(pinned.includes(f.key)?' — pinned':'')} value={form[f.key]||''}
   disabled={locked(f.key)} addLabel={f.key==='roles.map'?'Add mapping':'Link account'}
   keyPlaceholder={f.key==='roles.map'?'claim value (e.g. oie-admins)':'engine username'}
   valuePlaceholder={f.key==='roles.map'?(roleNames?'— choose a role —':'RBAC role (e.g. Administrator)'):'issuer#subject'}
   valueOptions={f.key==='roles.map'?roleNames:undefined}
   onChange={v=>patch(f.key,v)} onProblem={noteProblem(f.key)}/>)}
 </div>
 </div>}
export async function register(host){
 // Ask the endpoint this panel actually needs, rather than reading RBAC's
 // permission list and inferring. GET /configuration carries PERMISSION_MANAGE
 // (manageOIDC), so a 403 here is authoritative: it answers exactly the question
 // being asked, and it drops this plugin's dependency on a sibling extension's
 // API shape and permission model.
 //
 // Everything else shows the tab. The gate is cosmetic — the servlet enforces
 // per operation — so an unreachable engine or an unexpected status should cost
 // an operator a visible error inside the panel, not an invisible tab.
 try{
  await api.get(`${EXT}/configuration`);
 }catch(e){
  if(e&&e.status===403){console.warn('[oidcauth] manageOIDC not granted — hiding settings panel');return;}
  console.warn('[oidcauth] permission probe inconclusive — showing settings panel:',e);
 }
 host.registerSettingsPanel({label:'OIDC Authentication',order:80,component:OidcPanel});
}
