"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import { Icon } from "@/components/icons";

type Website = { id:string; domain:string; status:string; verified_at:string|null; ssl_status:string; integration_status:string; created_at:string };
type Integration = { id:string; domain:string; status:string; verified_at:string|null; integration_status:string; collector_key:string; collector_enabled:boolean; last_event_at:string|null };

export function BackendWebsites() {
  const [items,setItems] = useState<Website[]>([]);
  const [domain,setDomain] = useState("");
  const [error,setError] = useState("");
  const [notice,setNotice] = useState("");
  const [loading,setLoading] = useState(true);
  const [removingId,setRemovingId] = useState("");
  const [integration,setIntegration] = useState<Integration|null>(null);
  const [integrationBusy,setIntegrationBusy] = useState(false);
  const [integrationError,setIntegrationError] = useState("");
  const [copied,setCopied] = useState(false);

  const snippet = useMemo(() => integration?.collector_key
    ? `<script src="https://webshield-savrdh-technology.vercel.app/webshield.js" data-site-key="${integration.collector_key}" async></script>`
    : "", [integration]);

  async function load(){
    setLoading(true); setError("");
    try{
      const r=await fetch("/api/websites",{cache:"no-store"});
      const b=await r.json();
      if(!r.ok||!b.ok) throw new Error(b?.error?.message||"Could not load websites.");
      setItems(b.data||[]);
    }catch(e){setError(e instanceof Error?e.message:"Could not load websites.");}
    finally{setLoading(false);}
  }
  useEffect(()=>{load();},[]);

  async function add(e:FormEvent){
    e.preventDefault(); setError(""); setNotice("");
    try{
      const r=await fetch("/api/websites",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({domain})});
      const b=await r.json();
      if(!r.ok||!b.ok) throw new Error(b?.error?.message||"Could not add website.");
      setDomain("");
      if(b?.meta?.reused) setNotice(`This page belongs to the existing website ${b.data?.domain || "domain"}. No duplicate website was created.`);
      else setNotice(`Website ${b.data?.domain || ""} added. Click Connect Website to install WebShield monitoring.`);
      await load();
    }catch(e){setError(e instanceof Error?e.message:"Could not add website.");}
  }

  async function openIntegration(item:Website){
    setIntegrationBusy(true); setIntegrationError(""); setCopied(false);
    try{
      const r=await fetch("/api/websites/integration",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:item.id,action:"enable"})});
      const b=await r.json();
      if(!r.ok||!b.ok) throw new Error(b?.error?.message||"Could not prepare integration.");
      setIntegration(b.data);
    }catch(e){setIntegrationError(e instanceof Error?e.message:"Could not prepare integration.");}
    finally{setIntegrationBusy(false);}
  }

  async function checkConnection(){
    if(!integration) return;
    setIntegrationBusy(true); setIntegrationError("");
    try{
      const r=await fetch("/api/websites/integration",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:integration.id,action:"verify"})});
      const b=await r.json();
      if(!r.ok||!b.ok) throw new Error(b?.error?.message||"Connection not detected yet.");
      setIntegration(b.data);
      setNotice(`${b.data.domain} is connected to WebShield. Live visitor telemetry can now appear in the dashboard.`);
      await load();
    }catch(e){setIntegrationError(e instanceof Error?e.message:"Connection not detected yet.");}
    finally{setIntegrationBusy(false);}
  }

  async function copySnippet(){
    if(!snippet) return;
    try{
      await navigator.clipboard.writeText(snippet);
      setCopied(true);
      setTimeout(()=>setCopied(false),1800);
    }catch{ setIntegrationError("Could not copy automatically. Select the code and copy it manually."); }
  }

  async function removeWebsite(item:Website){
    const connected=item.integration_status==="COLLECTOR_CONNECTED" || Boolean(item.verified_at);
    const warning=connected
      ? `Remove ${item.domain}? This website is connected/verified, so linked website telemetry may also be removed.`
      : `Remove ${item.domain} from this WebShield workspace?`;
    if(!window.confirm(warning)) return;
    setRemovingId(item.id); setError(""); setNotice("");
    try{
      const r=await fetch(`/api/websites?id=${encodeURIComponent(item.id)}`,{method:"DELETE"});
      const b=await r.json();
      if(!r.ok||!b.ok) throw new Error(b?.error?.message||"Could not remove website.");
      if(integration?.id===item.id) setIntegration(null);
      setNotice(`${item.domain} removed from Website Management.`);
      await load();
    }catch(e){setError(e instanceof Error?e.message:"Could not remove website.");}
    finally{setRemovingId("");}
  }

  return <>
    <article className="panel" style={{marginBottom:16}}>
      <div className="panelHead"><div><h3>Website Management</h3><p>Add a domain or any page URL. WebShield stores only the root hostname, so internal links stay under the same website.</p></div><span className="statusTag safe">DATABASE</span></div>
      <form onSubmit={add} style={{display:"grid",gridTemplateColumns:"1fr auto",gap:10,marginTop:14}}>
        <input value={domain} onChange={e=>setDomain(e.target.value)} placeholder="example.com or https://example.com/services/page" required style={{height:44,borderRadius:10,border:"1px solid rgba(120,190,225,.15)",background:"#091522",color:"#edf8ff",padding:"0 13px"}}/>
        <button className="btn" type="submit">Add Website</button>
      </form>
      {error&&<div className="formNotice error" style={{marginTop:12}}>{error}</div>}
      {notice&&<div className="formNotice" style={{marginTop:12}}>{notice}</div>}
    </article>

    {loading?<article className="panel"><p>Loading websites…</p></article>:items.length?<div className="websiteGrid">{items.map(w=><article className="websiteCard" key={w.id}><div className="siteIcon"><Icon name="globe"/></div><div style={{flex:1,minWidth:0}}><h3>{w.domain}</h3><p>SSL: {w.ssl_status||"UNKNOWN"}</p><span className={`statusTag ${w.integration_status==="COLLECTOR_CONNECTED"?"safe":"medium"}`}>{w.status}</span><p>Integration: <b>{w.integration_status}</b></p><small>{w.verified_at?"Ownership verified":"Connection not verified yet"}</small><div style={{marginTop:14,display:"flex",gap:8,flexWrap:"wrap"}}><button type="button" className="btn small" onClick={()=>openIntegration(w)} disabled={integrationBusy}>{w.integration_status==="COLLECTOR_CONNECTED"?"Integration Details":"Connect Website"}</button><button type="button" className="ghostBtn small" onClick={()=>removeWebsite(w)} disabled={removingId===w.id} style={{borderColor:"rgba(255,110,130,.35)",color:"#ff8ea1"}}>{removingId===w.id?"Removing…":"Remove"}</button></div></div></article>)}</div>:<article className="panel"><p>No websites saved yet. Add your first domain above.</p></article>}

    {integration&&<article className="panel" style={{marginTop:16,borderColor:"rgba(32,217,255,.28)"}}>
      <div className="panelHead"><div><h3>Connect {integration.domain}</h3><p>Universal WebShield monitoring integration. Add this one script to the website&apos;s global layout/header.</p></div><span className={`statusTag ${integration.last_event_at?"safe":"medium"}`}>{integration.last_event_at?"EVENT RECEIVED":"INSTALL REQUIRED"}</span></div>

      <div className="dashboardGrid equal" style={{marginTop:14}}>
        <div>
          <div className="decisionRow"><span>Website</span><b>{integration.domain}</b></div>
          <div className="decisionRow"><span>Collector</span><span className={`statusTag ${integration.collector_enabled?"safe":"medium"}`}>{integration.collector_enabled?"ENABLED":"DISABLED"}</span></div>
          <div className="decisionRow"><span>Last event</span><b>{integration.last_event_at?new Date(integration.last_event_at).toLocaleString():"Not received yet"}</b></div>
          <div className="decisionRow"><span>Status</span><b>{integration.integration_status}</b></div>
        </div>
        <div className="formNotice" style={{alignSelf:"stretch"}}><b>Where to install</b><br/>HTML / PHP / Laravel: before <code>&lt;/head&gt;</code>.<br/>Next.js / React: global root layout.<br/>WordPress: site-wide header/script area.<br/><br/>A true zero-code connection requires provider authorization (for example Vercel or Cloudflare), which can be added as a separate one-click integration.</div>
      </div>

      <label style={{display:"grid",gap:7,marginTop:14,fontSize:11,color:"#9db2c2"}}>Universal integration code
        <textarea readOnly value={snippet} onFocus={e=>e.currentTarget.select()} style={{width:"100%",minHeight:90,resize:"vertical",borderRadius:10,border:"1px solid rgba(120,190,225,.16)",background:"#06101b",color:"#8ce7f8",padding:12,fontFamily:"ui-monospace,SFMono-Regular,Menlo,monospace",fontSize:11}}/>
      </label>
      <div className="buttonRow" style={{marginTop:12,flexWrap:"wrap"}}>
        <button type="button" className="btn small" onClick={copySnippet}>{copied?"Copied ✓":"Copy Code"}</button>
        <button type="button" className="ghostBtn small" onClick={checkConnection} disabled={integrationBusy}>{integrationBusy?"Checking…":"Check Connection"}</button>
        <button type="button" className="ghostBtn small" onClick={()=>setIntegration(null)}>Close</button>
      </div>
      {integrationError&&<div className="formNotice error" style={{marginTop:12}}>{integrationError}</div>}
      {integration.last_event_at&&<div className="formNotice" style={{marginTop:12}}>Connection detected. WebShield can collect visitor/session telemetry for this domain. Firewall blocking still requires a real traffic-path/WAF provider integration.</div>}
    </article>}
  </>;
}
