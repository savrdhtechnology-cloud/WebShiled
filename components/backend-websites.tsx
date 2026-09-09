"use client";

import { FormEvent, useEffect, useState } from "react";
import { Icon } from "@/components/icons";

type Website = { id:string; domain:string; status:string; verified_at:string|null; ssl_status:string; integration_status:string; created_at:string };

export function BackendWebsites() {
  const [items,setItems] = useState<Website[]>([]);
  const [domain,setDomain] = useState("");
  const [error,setError] = useState("");
  const [notice,setNotice] = useState("");
  const [loading,setLoading] = useState(true);
  const [removingId,setRemovingId] = useState("");

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
      if(b?.meta?.existing) setNotice(`This page belongs to the existing website ${b.data?.domain || "domain"}. No duplicate website was created.`);
      else setNotice(`Website ${b.data?.domain || ""} added.`);
      await load();
    }catch(e){setError(e instanceof Error?e.message:"Could not add website.");}
  }

  async function removeWebsite(item:Website){
    const connected=item.integration_status==="COLLECTOR_CONNECTED" || Boolean(item.verified_at);
    const warning=connected
      ? `Remove ${item.domain}? This website is connected/verified, so linked website telemetry may also be removed.`
      : `Remove ${item.domain} from this WebShield workspace?`;
    if(!window.confirm(warning)) return;
    setRemovingId(item.id); setError(""); setNotice("");
    try{
      const r=await fetch("/api/websites",{method:"DELETE",headers:{"content-type":"application/json"},body:JSON.stringify({id:item.id})});
      const b=await r.json();
      if(!r.ok||!b.ok) throw new Error(b?.error?.message||"Could not remove website.");
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
    {loading?<article className="panel"><p>Loading websites…</p></article>:items.length?<div className="websiteGrid">{items.map(w=><article className="websiteCard" key={w.id}><div className="siteIcon"><Icon name="globe"/></div><div style={{flex:1,minWidth:0}}><h3>{w.domain}</h3><p>SSL: {w.ssl_status||"UNKNOWN"}</p><span className={`statusTag ${w.status==="PROTECTED"?"safe":"medium"}`}>{w.status}</span><p>Integration: <b>{w.integration_status}</b></p><small>{w.verified_at?"Ownership verified":"Verification pending"}</small><div style={{marginTop:14}}><button type="button" className="btn small" onClick={()=>removeWebsite(w)} disabled={removingId===w.id} style={{background:"transparent",border:"1px solid rgba(255,110,130,.35)",color:"#ff8ea1"}}>{removingId===w.id?"Removing…":"Remove Website"}</button></div></div></article>)}</div>:<article className="panel"><p>No websites saved yet. Add your first domain above.</p></article>}
  </>;
}
