"use client";
import { apiPath } from "@/lib/base-path";

import { FormEvent, useEffect, useMemo, useState } from "react";
import { Icon } from "@/components/icons";

type Scan = {
  id:string; status:string; security_score:number|null; overall_risk:string|null;
  finding_counts:Record<string,number>|null; summary:Record<string,any>|null;
  started_at:string; completed_at:string|null; error_message:string|null;
};
type Connection = {
  id:string; website_id:string|null; provider:string; name:string; project_ref:string;
  secret_hint:string|null; access_mode:string; status:string; last_checked_at:string|null;
  last_error:string|null; created_at:string; updated_at:string; latestScan:Scan|null;
  guard_enabled?:boolean; guard_installed_at?:string|null; guard_tables?:string[]; guard_anon_insert_tables?:string[];
  guard_trusted_db_users?:string[]; guard_last_poll_at?:string|null; guard_last_error?:string|null;
  audit_interval_minutes?:number; next_audit_at?:string|null;
};
type Activity = {
  id:string; connection_id:string; occurred_at:string; table_schema:string; table_name:string; operation:string;
  db_user:string|null; jwt_role:string|null; user_id:string|null; client_ip:string|null; row_pk:string|null;
  changed_columns:string[]; suspicious:boolean; severity:string; reasons:string[]; reviewed_at:string|null;
};
type TableInfo = { table:string; rlsEnabled:boolean; approxRows:number };
type Finding = {
  id:string; connection_id:string; scan_id:string; finding_key:string; category:string; severity:string;
  title:string; description:string; impact:string|null; evidence:Record<string,unknown>;
  recommended_fix:string|null; fix_type:string; status:string; created_at:string; updated_at:string;
};
type Job = {
  id:string; connection_id:string; finding_id:string|null; action_type:string;
  proposed_change:Record<string,unknown>; status:string; result:Record<string,unknown>;
  approved_at:string|null; applied_at:string|null; created_at:string;
};
type Payload = {
  setupRequired:boolean; message?:string; connections:Connection[]; selectedConnectionId:string|null;
  findings:Finding[]; remediationJobs:Job[]; activity?:Activity[];
};

function ago(value?:string|null){
  if(!value)return "Never";
  const diff=Math.max(0,Date.now()-new Date(value).getTime());
  const min=Math.floor(diff/60000);
  if(min<1)return "Just now";
  if(min<60)return `${min}m ago`;
  const hr=Math.floor(min/60);
  if(hr<24)return `${hr}h ago`;
  return `${Math.floor(hr/24)}d ago`;
}
function tone(severity?:string|null){
  const s=String(severity||"").toLowerCase();
  if(s==="critical")return "critical";
  if(s==="high")return "high";
  if(s==="medium")return "medium";
  return "safe";
}
function metric(value:unknown,fallback="0"){
  return value==null?fallback:String(value);
}

export function DatabaseSecurity({ mode="security", admin=false }:{mode?:"security"|"fixes";admin?:boolean}) {
  const [data,setData]=useState<Payload|null>(null);
  const [selected,setSelected]=useState("");
  const [loading,setLoading]=useState(true);
  const [busy,setBusy]=useState("");
  const [error,setError]=useState("");
  const [notice,setNotice]=useState("");
  const [showConnect,setShowConnect]=useState(false);
  const [name,setName]=useState("Production Database");
  const [projectRef,setProjectRef]=useState("");
  const [accessToken,setAccessToken]=useState("");
  const [accessMode,setAccessMode]=useState("READ_ONLY");
  const [tables,setTables]=useState<TableInfo[]|null>(null);
  const [watch,setWatch]=useState<string[]>([]);
  const [anonTables,setAnonTables]=useState("");
  const [trustedUsers,setTrustedUsers]=useState("");
  const [onlySuspicious,setOnlySuspicious]=useState(true);
  const [preview,setPreview]=useState<{findingId:string;title:string;severity:string;fixType:string;sql:string;warning:string}|null>(null);

  async function load(connectionId?:string){
    setLoading(true); setError("");
    try{
      const suffix=connectionId?`?connectionId=${encodeURIComponent(connectionId)}`:"";
      const r=await fetch(apiPath("/api/database-security")+suffix,{cache:"no-store"});
      const b=await r.json();
      if(!r.ok||!b.ok)throw new Error(b?.error?.message||"Database Security could not be loaded.");
      const p=b.data as Payload;
      setData(p);
      const id=connectionId||p.selectedConnectionId||p.connections?.[0]?.id||"";
      setSelected(id);
      if(!p.connections?.length&&!p.setupRequired)setShowConnect(true);
    }catch(e){setError(e instanceof Error?e.message:"Database Security could not be loaded.");}
    finally{setLoading(false);}
  }
  useEffect(()=>{load();},[]);

  async function action(body:Record<string,unknown>,label:string){
    setBusy(label); setError(""); setNotice("");
    try{
      const r=await fetch(apiPath("/api/database-security"),{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});
      const b=await r.json();
      if(!r.ok||!b.ok)throw new Error(b?.error?.message||"Request failed.");
      return b.data;
    }catch(e){setError(e instanceof Error?e.message:"Request failed.");throw e;}
    finally{setBusy("");}
  }

  async function connect(e:FormEvent){
    e.preventDefault();
    try{
      const result=await action({action:"connect",provider:"SUPABASE",name,projectRef,accessToken,accessMode},"connect");
      setAccessToken(""); setProjectRef(""); setShowConnect(false);
      setNotice("Supabase database connected. Run the first security scan to generate findings.");
      await load(result?.id);
    }catch{}
  }

  async function scan(){
    if(!selected)return;
    try{
      await action({action:"scan",connectionId:selected},"scan");
      setNotice("Database security scan completed.");
      await load(selected);
    }catch{}
  }

  async function openFix(f:Finding){
    try{
      const result=await action({action:"preview_fix",findingId:f.id},"preview");
      setPreview(result);
    }catch{}
  }

  async function applyFix(){
    if(!preview)return;
    if(!window.confirm("Apply this approved database change? Review the SQL and make sure your application access requirements are understood."))return;
    try{
      await action({action:"apply_fix",findingId:preview.findingId},"apply");
      setPreview(null);
      setNotice("Remediation applied. Run another database scan to verify the resulting posture.");
      await load(selected);
    }catch{}
  }

  async function acceptRisk(id:string){
    if(!window.confirm("Mark this finding as accepted risk? It will stay visible but will no longer be treated as an open remediation item."))return;
    try{
      await action({action:"accept_risk",findingId:id},"accept");
      setNotice("Finding marked as accepted risk.");
      await load(selected);
    }catch{}
  }

  async function disconnect(){
    const current=data?.connections.find(x=>x.id===selected);
    if(!current||!window.confirm(`Disconnect ${current.name}? Stored scan history and findings for this connection may be removed by database cascade rules.`))return;
    try{
      await action({action:"disconnect",connectionId:selected},"disconnect");
      setNotice("Database disconnected.");
      setSelected("");
      await load();
    }catch{}
  }

  async function loadTables(){
    if(!selected)return;
    try{
      const result=await action({action:"list_tables",connectionId:selected},"tables") as {tables:TableInfo[];suggested:string[]};
      setTables(result.tables);
      const current=data?.connections.find(x=>x.id===selected);
      setWatch(current?.guard_tables?.length?current.guard_tables:result.suggested);
      setAnonTables((current?.guard_anon_insert_tables||[]).join(", "));
      setTrustedUsers((current?.guard_trusted_db_users||[]).join(", "));
    }catch{}
  }

  async function installGuard(){
    if(!watch.length){setError("Select at least one table to watch.");return;}
    if(!window.confirm(`Install Data Guard on ${watch.length} table(s)? WebShield will add an audit trigger to these tables in your database. It records who changed which row (not the row data) and never blocks your application's writes.`))return;
    try{
      await action({action:"install_guard",connectionId:selected,tables:watch,anonInsertTables:anonTables,trustedDbUsers:trustedUsers},"guard");
      setNotice("Data Guard is active. New inserts, updates and deletes on watched tables are checked every monitoring cycle (or press Check activity now).");
      setTables(null);
      await load(selected);
    }catch{}
  }

  async function saveGuardRules(){
    try{
      await action({action:"update_guard_rules",connectionId:selected,anonInsertTables:anonTables,trustedDbUsers:trustedUsers},"rules");
      setNotice("Data Guard rules saved.");
      await load(selected);
    }catch{}
  }

  async function uninstallGuard(){
    if(!window.confirm("Remove Data Guard triggers and the webshield_guard schema from this database? Unauthorized-change detection will stop."))return;
    try{
      await action({action:"uninstall_guard",connectionId:selected},"guard");
      setNotice("Data Guard removed from the database.");
      await load(selected);
    }catch{}
  }

  async function pollGuard(){
    try{
      const result=await action({action:"poll_guard",connectionId:selected},"poll") as {processed:number;suspicious:number;alerts:number};
      setNotice(`Checked ${result.processed} new database change(s): ${result.suspicious} suspicious, ${result.alerts} new alert(s).`);
      await load(selected);
    }catch{}
  }

  async function markReviewed(id:string){
    try{ await action({action:"review_activity",eventId:id},"review"); await load(selected); }catch{}
  }

  const connection=data?.connections.find(x=>x.id===selected)||data?.connections[0]||null;
  useEffect(()=>{setAnonTables((connection?.guard_anon_insert_tables||[]).join(", "));setTrustedUsers((connection?.guard_trusted_db_users||[]).join(", "));},[connection?.id,connection?.guard_anon_insert_tables?.join(),connection?.guard_trusted_db_users?.join()]);
  const scanInfo=connection?.latestScan||null;
  const summary=(scanInfo?.summary||{}) as Record<string,any>;
  const findings=useMemo(()=>{
    const all=data?.findings||[];
    return mode==="fixes" ? all.filter(f=>f.status==="OPEN"&&f.fix_type!=="MANUAL") : all;
  },[data,mode]);
  const open=findings.filter(f=>f.status==="OPEN");
  const jobs=(data?.remediationJobs||[]).filter(j=>!selected||j.connection_id===selected);

  if(loading)return <article className="panel"><p>Loading Database Security…</p></article>;
  if(data?.setupRequired)return <article className="panel">
    <div className="panelHead"><div><h3>Database Security activation required</h3><p>{data.message||"The Database Security schema is not active yet."}</p></div><span className="statusTag medium">SETUP REQUIRED</span></div>
    <div className="formNotice" style={{marginTop:14}}>The application code is ready, but the WebShield database must apply <code>supabase/migrations/0003_database_security.sql</code> and <code>0006_live_monitoring_and_data_guard.sql</code> before provider connections, scan history and Data Guard can be stored.</div>
  </article>;

  return <>
    {error&&<div className="formNotice error" style={{marginBottom:14}}>{error}</div>}
    {notice&&<div className="formNotice" style={{marginBottom:14}}>{notice}</div>}

    <section className="dashboardGrid equal">
      <article className="panel">
        <div className="panelHead"><div><h3>{mode==="fixes"?"Database Fix Center":"Database Connections"}</h3><p>{mode==="fixes"?"Review and approve database remediation actions.":"Connect a Supabase project with a scoped Management API token."}</p></div><span className="statusTag safe">ENCRYPTED CREDENTIALS</span></div>
        <div className="buttonRow" style={{marginTop:14,flexWrap:"wrap"}}>
          {data?.connections?.map(c=><button key={c.id} type="button" className={c.id===selected?"btn small":"ghostBtn small"} onClick={()=>{setSelected(c.id);load(c.id)}}>{c.name}</button>)}
          <button type="button" className="ghostBtn small" onClick={()=>setShowConnect(v=>!v)}><Icon name="plus" size={13}/> Connect Database</button>
        </div>
        {connection&&<div style={{marginTop:16}}>
          <div className="decisionRow"><span>Provider</span><b>{connection.provider}</b></div>
          <div className="decisionRow"><span>Project Ref</span><b>{connection.project_ref}</b></div>
          <div className="decisionRow"><span>Access</span><span className={`statusTag ${connection.access_mode==="REMEDIATION"?"medium":"safe"}`}>{connection.access_mode}</span></div>
          <div className="decisionRow"><span>Connection</span><span className={`statusTag ${connection.status==="CONNECTED"?"safe":"medium"}`}>{connection.status}</span></div>
          <div className="decisionRow"><span>Credential</span><b>{connection.secret_hint||"Stored securely"}</b></div>
          <div className="decisionRow"><span>Last checked</span><b>{ago(connection.last_checked_at)}</b></div>
          <div className="buttonRow" style={{marginTop:14}}><button className="btn small" onClick={scan} disabled={busy==="scan"}>{busy==="scan"?"Scanning…":"Run Database Scan"}</button><button className="ghostBtn small" onClick={disconnect} disabled={busy==="disconnect"}>Disconnect</button></div>
        </div>}
      </article>

      <article className="panel">
        <div className="panelHead"><div><h3>Database Security Health</h3><p>Postgres access controls and Supabase exposure posture.</p></div><span className={`statusTag ${tone(scanInfo?.overall_risk)}`}>{scanInfo?.overall_risk||"NOT SCANNED"}</span></div>
        <div className="metricGrid compact" style={{marginTop:14}}>
          <article className="metricCard"><div className="metricTop"><span>Security Score</span><div className="metricIcon"><Icon name="shield"/></div></div><strong>{scanInfo?.security_score??"—"}</strong><small>/100</small></article>
          <article className="metricCard"><div className="metricTop"><span>RLS Coverage</span><div className="metricIcon"><Icon name="lock"/></div></div><strong>{metric(summary.rlsCoverage,"—")}{summary.rlsCoverage!=null?"%":""}</strong><small>{metric(summary.rlsEnabled)} / {metric(summary.tables)} tables</small></article>
          <article className="metricCard"><div className="metricTop"><span>Open Findings</span><div className="metricIcon"><Icon name="threat"/></div></div><strong>{open.length}</strong><small>{metric(scanInfo?.finding_counts?.CRITICAL)} critical · {metric(scanInfo?.finding_counts?.HIGH)} high</small></article>
          <article className="metricCard"><div className="metricTop"><span>Anon Writes</span><div className="metricIcon"><Icon name="firewall"/></div></div><strong>{metric(summary.anonymousWriteGrants)}</strong><small>tables with write grants</small></article>
        </div>
        {!scanInfo&&<div className="cleanState compact"><span><Icon name="shield" size={18}/></span><b>Run the first audit</b><p>WebShield will check RLS, policies, grants, privileged functions and public storage posture.</p></div>}
      </article>
    </section>

    {showConnect&&<article className="panel" style={{marginTop:16,borderColor:"rgba(32,217,255,.28)"}}>
      <div className="panelHead"><div><h3>Connect Supabase Database</h3><p>Use a scoped Management API token with Database Read permission. Choose Remediation only when you intentionally grant Database Write permission.</p></div><span className="statusTag medium">SUPABASE</span></div>
      <form onSubmit={connect} className="settingsGrid" style={{marginTop:14}}>
        <label>Connection name<input value={name} onChange={e=>setName(e.target.value)} required/></label>
        <label>Project ref<input value={projectRef} onChange={e=>setProjectRef(e.target.value)} placeholder="abcdefghijklmnopqrst" required/></label>
        <label>Access mode<select value={accessMode} onChange={e=>setAccessMode(e.target.value)}><option value="READ_ONLY">Read-only audit</option><option value="REMEDIATION">Audit + approved remediation</option></select></label>
        <label>Scoped Management API token<input type="password" autoComplete="off" value={accessToken} onChange={e=>setAccessToken(e.target.value)} placeholder="Token is encrypted before storage" required/></label>
        <div className="formNotice">Prefer a project-scoped token with only the minimum Database permissions. WebShield never returns the stored token to the browser.</div>
        <div className="buttonRow"><button className="btn" disabled={busy==="connect"}>{busy==="connect"?"Verifying…":"Verify & Connect"}</button><button type="button" className="ghostBtn" onClick={()=>setShowConnect(false)}>Cancel</button></div>
      </form>
    </article>}

    <article className="panel" style={{marginTop:16}}>
      <div className="panelHead"><div><h3>{mode==="fixes"?"Approved Remediation Queue":"Security Findings"}</h3><p>{mode==="fixes"?"Only findings with supported controlled fixes are shown.":"Evidence-based database security findings from the latest audit."}</p></div><span className="statusTag medium">{findings.length} FINDINGS</span></div>
      <div style={{display:"grid",gap:10,marginTop:14}}>
        {findings.length?findings.map(f=><article key={f.id} style={{border:"1px solid rgba(120,190,225,.11)",borderRadius:12,padding:14,background:"rgba(5,13,22,.28)"}}>
          <div style={{display:"flex",justifyContent:"space-between",gap:12,alignItems:"flex-start"}}>
            <div><div style={{display:"flex",gap:7,alignItems:"center",flexWrap:"wrap"}}><span className={`statusTag ${tone(f.severity)}`}>{f.severity}</span><small style={{color:"#5e7e94"}}>{f.category}</small><span className={`statusTag ${f.status==="ACCEPTED_RISK"?"medium":"safe"}`}>{f.status}</span></div><h3 style={{margin:"9px 0 5px"}}>{f.title}</h3><p style={{margin:0}}>{f.description}</p></div>
            <Icon name={f.severity==="CRITICAL"||f.severity==="HIGH"?"threat":"shield"}/>
          </div>
          {f.impact&&<div className="formNotice" style={{marginTop:11}}><b>Impact</b><br/>{f.impact}</div>}
          {f.recommended_fix&&<div style={{marginTop:11}}><small style={{color:"#6f8da1"}}>RECOMMENDED FIX</small><p style={{margin:"5px 0 0"}}>{f.recommended_fix}</p></div>}
          <div className="buttonRow" style={{marginTop:12,flexWrap:"wrap"}}>
            {f.fix_type!=="MANUAL"&&f.status==="OPEN"&&<button className="btn small" onClick={()=>openFix(f)} disabled={busy==="preview"}>Review Fix</button>}
            {f.status==="OPEN"&&<button className="ghostBtn small" onClick={()=>acceptRisk(f.id)} disabled={busy==="accept"}>Accept Risk</button>}
          </div>
        </article>):<div className="cleanState compact"><span><Icon name="check" size={18}/></span><b>{scanInfo?"No matching open findings":"No scan data yet"}</b></div>}
      </div>
    </article>

    {preview&&<article className="panel" style={{marginTop:16,borderColor:"rgba(255,177,74,.28)"}}>
      <div className="panelHead"><div><h3>Review Database Fix</h3><p>{preview.title}</p></div><span className={`statusTag ${tone(preview.severity)}`}>{preview.severity}</span></div>
      <div className="formNotice" style={{marginTop:12}}>{preview.warning}</div>
      <label style={{display:"grid",gap:7,marginTop:13,fontSize:11,color:"#9db2c2"}}>Proposed SQL
        <textarea readOnly value={preview.sql} style={{width:"100%",minHeight:100,resize:"vertical",borderRadius:10,border:"1px solid rgba(120,190,225,.16)",background:"#06101b",color:"#8ce7f8",padding:12,fontFamily:"ui-monospace,SFMono-Regular,Menlo,monospace",fontSize:11}}/>
      </label>
      <div className="buttonRow" style={{marginTop:12}}><button className="btn small" onClick={applyFix} disabled={busy==="apply"||connection?.access_mode!=="REMEDIATION"}>{busy==="apply"?"Applying…":"Approve & Apply Fix"}</button><button className="ghostBtn small" onClick={()=>setPreview(null)}>Close</button></div>
      {connection?.access_mode!=="REMEDIATION"&&<div className="formNotice" style={{marginTop:10}}>This connection is read-only. Reconnect with Remediation access before applying changes.</div>}
    </article>}

    {mode==="security"&&connection&&<article className="panel" style={{marginTop:16,borderColor:connection.guard_enabled?"rgba(0,237,177,.25)":undefined}}>
      <div className="panelHead"><div><h3>Data Guard · unauthorized change detection</h3><p>Records every insert, update and delete on watched tables — who did it (logged-in user, anon key, backend key or direct database login) and from which IP — and alerts on writes without login, direct database edits, privilege changes and mass deletes.</p></div><span className={`statusTag ${connection.guard_enabled?"safe":"medium"}`}>{connection.guard_enabled?"ACTIVE":"NOT INSTALLED"}</span></div>
      {connection.guard_enabled&&<div style={{marginTop:12}}>
        <div className="decisionRow"><span>Watched tables</span><b>{connection.guard_tables?.length||0}</b></div>
        <div className="decisionRow"><span>Last check</span><b>{ago(connection.guard_last_poll_at)}</b></div>
        {connection.guard_last_error&&<div className="formNotice error" style={{marginTop:8}}>{connection.guard_last_error}</div>}
        <p style={{fontSize:12,color:"#6f8da1"}}>{(connection.guard_tables||[]).join(", ")}</p>
      </div>}
      <div className="buttonRow" style={{marginTop:12,flexWrap:"wrap"}}>
        {connection.guard_enabled&&<button className="btn small" onClick={pollGuard} disabled={busy==="poll"}>{busy==="poll"?"Checking…":"Check activity now"}</button>}
        <button className={connection.guard_enabled?"ghostBtn small":"btn small"} onClick={loadTables} disabled={busy==="tables"}>{busy==="tables"?"Loading tables…":connection.guard_enabled?"Change watched tables":"Choose tables to protect"}</button>
        {connection.guard_enabled&&<button className="ghostBtn small" onClick={uninstallGuard} disabled={busy==="guard"}>Remove Data Guard</button>}
      </div>
      {connection.access_mode!=="REMEDIATION"&&<div className="formNotice" style={{marginTop:10}}>Installing Data Guard adds a trigger to your database, so the connection needs <b>Audit + approved remediation</b> access. Reconnect this project with that access mode first.</div>}
      {tables&&<div style={{marginTop:14}}>
        <p style={{margin:"0 0 8px"}}>Select tables to watch ({watch.length} selected). Sensitive tables are pre-selected.</p>
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(230px,1fr))",gap:6,maxHeight:260,overflow:"auto",padding:8,border:"1px solid rgba(120,190,225,.11)",borderRadius:10}}>
          {tables.map(t=><label key={t.table} style={{display:"flex",gap:7,alignItems:"center",fontSize:12}}><input type="checkbox" checked={watch.includes(t.table)} onChange={e=>setWatch(e.target.checked?[...watch,t.table]:watch.filter(x=>x!==t.table))}/>{t.table}<small style={{color:"#5e7e94"}}>~{t.approxRows}</small></label>)}
        </div>
        <div className="buttonRow" style={{marginTop:8}}><button className="ghostBtn small" type="button" onClick={()=>setWatch(tables.map(t=>t.table))}>Select all</button><button className="ghostBtn small" type="button" onClick={()=>setWatch([])}>Clear</button></div>
      </div>}
      {(tables||connection.guard_enabled)&&<div className="settingsGrid" style={{marginTop:12}}>
        <label>Tables where public forms may insert without login (e.g. public.website_leads)<input value={anonTables} onChange={e=>setAnonTables(e.target.value)} placeholder="public.website_leads, public.akbs_inquiries"/></label>
        <label>Trusted database users for direct changes (e.g. a cron or migration user)<input value={trustedUsers} onChange={e=>setTrustedUsers(e.target.value)} placeholder="leave empty to alert on every direct change"/></label>
      </div>}
      <div className="buttonRow" style={{marginTop:10}}>
        {tables&&<button className="btn small" onClick={installGuard} disabled={busy==="guard"||connection.access_mode!=="REMEDIATION"}>{busy==="guard"?"Installing…":connection.guard_enabled?"Update watched tables":"Install Data Guard"}</button>}
        {connection.guard_enabled&&!tables&&<button className="ghostBtn small" onClick={saveGuardRules} disabled={busy==="rules"}>Save rules</button>}
      </div>
      {connection.guard_enabled&&<div style={{marginTop:16}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}><h3 style={{margin:0}}>Database activity</h3><label style={{fontSize:12}}><input type="checkbox" checked={onlySuspicious} onChange={e=>setOnlySuspicious(e.target.checked)}/> Suspicious only</label></div>
        {(()=>{const rows=(data?.activity||[]).filter(a=>!onlySuspicious||a.suspicious);return rows.length?<div className="refTable" style={{marginTop:8}}><table><thead><tr><th>When</th><th>Table</th><th>Change</th><th>Who</th><th>IP</th><th>Why flagged</th><th></th></tr></thead><tbody>{rows.slice(0,100).map(a=><tr key={a.id}><td>{new Date(a.occurred_at).toLocaleString()}</td><td>{a.table_schema}.{a.table_name}{a.row_pk&&<small> #{a.row_pk}</small>}</td><td><span className={`statusTag ${tone(a.severity)}`}>{a.operation}</span>{a.changed_columns?.length?<small> {a.changed_columns.join(", ")}</small>:null}</td><td>{a.user_id?`user ${a.user_id.slice(0,8)}…`:a.jwt_role||a.db_user||"unknown"}</td><td>{a.client_ip||"—"}</td><td style={{maxWidth:320}}>{a.reasons?.length?a.reasons.join(" "):"Normal activity"}</td><td>{a.suspicious&&!a.reviewed_at?<button className="ghostBtn small" onClick={()=>markReviewed(a.id)}>Reviewed</button>:a.reviewed_at?"✓":""}</td></tr>)}</tbody></table></div>:<div className="cockpitEmpty">{onlySuspicious?"No suspicious database changes recorded.":"No database changes recorded yet."}</div>})()}
      </div>}
    </article>}

    <article className="panel" style={{marginTop:16}}>
      <div className="panelHead"><div><h3>Remediation History</h3><p>Approved database changes and their execution status.</p></div><span className="statusTag safe">AUDITABLE</span></div>
      <div style={{display:"grid",marginTop:10}}>
        {jobs.length?jobs.slice(0,12).map(j=><div className="eventRow" key={j.id}><span className={`activityAlert ${j.status==="FAILED"?"high":"safe"}`}><Icon name={j.status==="FAILED"?"threat":"check"} size={14}/></span><div><b>{j.action_type}</b><small>{j.status} · {ago(j.applied_at||j.approved_at||j.created_at)}</small></div><span className={`statusTag ${j.status==="FAILED"?"high":"safe"}`}>{j.status}</span></div>):<div className="cockpitEmpty">No remediation jobs yet.</div>}
      </div>
    </article>
  </>;
}
