import Link from "next/link";
import { BackendResource } from "@/components/backend-resource";
import { LiveTrafficIntelligencePage, PreIntegrationIntelligence } from "@/components/pre-integration-intelligence";

function SettingsPage({admin=false}:{admin?:boolean}){
  return <div className="pageWrap"><div className="pageHeader"><div><div className="breadcrumbs">WebShield <span>/</span> Settings</div><h1>Settings</h1><p>Workspace and protection settings for {admin?"administration":"your organization"}.</p></div><span className="statusTag safe">BACKEND READY</span></div><article className="panel"><div className="panelHead"><div><h3>Security defaults</h3><p>Only verified websites should be eligible for connected protection. Database access is tenant-isolated with RLS.</p></div></div><div className="settingsGrid">{["Require website verification before protection","Store firewall rules in backend","Use role-based access control","Do not display fake telemetry"].map(x=><div className="toggleRow" key={x}><b>{x}</b><i className="toggle on"/></div>)}</div></article></div>;
}

function ThreatPage(){
  return <div className="pageWrap"><div className="pageHeader"><div><div className="breadcrumbs">WebShield <span>/</span> Threat Center</div><h1>Threat Center</h1><p>Pre-integration scan findings are shown first. Real attack events appear below only after traffic/log integration.</p></div><span className="statusTag medium">SCAN + CONNECTED EVENTS</span></div><PreIntegrationIntelligence compact/><div style={{marginTop:16}}><BackendResource resource="threats" title="Connected Threat Events" description="Real threat detections stored in WebShield threat_events after a traffic collector/provider is connected."/></div></div>;
}

export function ClientModule({slug}:{slug:string}){
  if(slug==="live-visitors") return <LiveTrafficIntelligencePage/>;
  if(slug==="threat-center") return <ThreatPage/>;
  if(slug==="firewall") return <BackendResource resource="firewall" title="Firewall" description="Database-backed firewall policy. Provider enforcement is shown only when a real provider rule is connected." allowFirewallCreate/>;
  if(slug==="analytics") return <BackendResource resource="analytics" title="Analytics" description="Backend-derived visitor, session, threat and blocked-request totals after traffic integration."/>;
  if(slug==="reports") return <BackendResource resource="reports" title="Reports" description="Security report metrics derived from current backend records."/>;
  if(slug==="alerts") return <BackendResource resource="alerts" title="Alerts" description="Security alerts stored in the WebShield backend."/>;
  if(slug==="settings") return <SettingsPage/>;
  return <div className="pageWrap"><div className="pageHeader"><div><h1>Module unavailable</h1><p>This non-essential module is not exposed in the simplified WebShield navigation.</p></div></div><Link className="btn" href="/app/dashboard">Return to dashboard</Link></div>;
}

export function AdminModule({slug}:{slug:string}){
  if(slug==="websites") return <BackendResource resource="websites" title="Websites" description="Website inventory for the current WebShield workspace."/>;
  if(slug==="security-events") return <BackendResource resource="threats" title="Security Events" description="Threat and security events available to the current workspace."/>;
  if(slug==="plans") return <BackendResource resource="billing" title="Plans & Billing" description="Current subscription and plan limits from Supabase."/>;
  if(slug==="support-tickets") return <BackendResource resource="support" title="Support" description="Support tickets stored in the WebShield backend."/>;
  if(slug==="system-settings") return <SettingsPage admin/>;
  return <div className="pageWrap"><div className="pageHeader"><div><h1>Admin module unavailable</h1><p>This module is intentionally not shown in the simplified admin navigation.</p></div></div><Link className="btn" href="/admin/dashboard">Return to admin dashboard</Link></div>;
}
