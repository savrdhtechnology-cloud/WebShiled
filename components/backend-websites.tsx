"use client";

import { FormEvent, useEffect, useState } from "react";
import { Icon } from "@/components/icons";

type Website = { id:string; domain:string; status:string; verified_at:string|null; ssl_status:string; integration_status:string; created_at:string };

export function BackendWebsites() {
  const [items,setItems] = useState<Website[]>([]);
  const [domain,setDomain] = useState("");
  const [error,setError] = useState("");
  const [loading,setLoading] = useState(true);

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
    e.preventDefault(); setError("");
    try{
      const r=await fetch("/api/websites",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({domain})});
      const b=await r.json();
      if(!r.ok||!b.ok) throw new Error(b?.error?.message||"Could not add website.");
      setDomain(""); await load();
    }catch(e){setError(e instanceof Error?e.message:"Could not add website.");}
  }

  return <>
    <article className="panel" style={{marginBottom:16}}>
      <div className="panelHead"><div><h3>Website Management</h3><p>Saved in the WebShield Supabase backend.</p></div><span className="statusTag safe">DATABASE</span></div>
      <form onSubmit={add} style={{display:"grid",gridTemplateColumns:"1fr auto",gap:10,marginTop:14}}>
        <input value={domain} onChange={e=>setDomain(e.target.value)} placeholder="example.com" required style={{height:44,borderRadius:10,border:"1px solid rgba(120,190,225,.15)",background:"#091522",color:"#edf8ff",padding:"0 13px"}}/>
        <button className="btn" type="submit">Add Website</button>
      </form>
      {error&&<div className="formNotice error" style={{marginTop:12}}>{error}</div>}
    </article>
    {loading?<article className="panel"><p>Loading websites…</p></article>:items.length?<div className="websiteGrid">{items.map(w=><article className="websiteCard" key={w.id}><div className="siteIcon"><Icon name="globe"/></div><div><h3>{w.domain}</h3><p>SSL: {w.ssl_status||"UNKNOWN"}</p><span className={`statusTag ${w.status==="PROTECTED"?"safe":"medium"}`}>{w.status}</span><p>Integration: <b>{w.integration_status}</b></p><small>{w.verified_at?"Ownership verified":"Verification pending"}</small></div></article>)}</div>:<article className="panel"><p>No websites saved yet. Add your first domain above.</p></article>}
  </>;
}
