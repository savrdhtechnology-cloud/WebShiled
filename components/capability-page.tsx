import Link from "next/link";
import { Icon } from "@/components/icons";
import type { FeatureDefinition } from "@/lib/feature-catalog";

function statusTone(status: FeatureDefinition["status"]) {
  if (status === "LIVE PASSIVE") return "safe";
  if (status === "DEMO TELEMETRY") return "medium";
  return "medium";
}

export function CapabilityPage({ feature }: { feature: FeatureDefinition }) {
  const isLive = feature.status === "LIVE PASSIVE";
  const isDemo = feature.status === "DEMO TELEMETRY";
  const source = isLive ? "Live passive scanner" : isDemo ? "Separated demo telemetry provider" : "Production provider not connected";
  const note = isLive
    ? "This module can use real passive HTTP/HTTPS posture data. It does not perform exploit or penetration testing."
    : isDemo
      ? "Values shown in this module are simulated demonstration telemetry and are not real security events."
      : "The UI, data model and workflow are prepared, but real enforcement/detection requires a connected production security provider.";

  return <div className="pageWrap">
    <div className="pageHeader">
      <div>
        <div className="breadcrumbs">WebShield <span>/</span> {feature.group} <span>/</span> {feature.title}</div>
        <h1>{feature.title}</h1>
        <p>{feature.description}</p>
      </div>
      <div className="headerActions"><span className={`statusTag ${statusTone(feature.status)}`}>{feature.status}</span></div>
    </div>

    <div className="metricGrid compact">
      <article className="metricCard"><span>Module State</span><strong>{isLive ? "LIVE" : isDemo ? "DEMO" : "READY"}</strong><small>{source}</small></article>
      <article className="metricCard"><span>Capabilities</span><strong>{feature.capabilities.length}</strong><small>Defined in WebShield V1</small></article>
      <article className="metricCard"><span>Audit Model</span><strong>ON</strong><small>Action logging foundation</small></article>
      <article className="metricCard"><span>Workspace</span><strong>Scoped</strong><small>Organization / website boundary</small></article>
    </div>

    <div className="dashboardGrid twoThirds">
      <article className="panel">
        <div className="panelHead"><div><h3>{feature.title} capabilities</h3><p>Requested WebShield feature coverage</p></div></div>
        {feature.capabilities.map((capability, index) => <div className="eventRow" key={capability}>
          <span className="featureIcon"><Icon name={index % 3 === 0 ? "shield" : index % 3 === 1 ? "chart" : "globe"} size={17}/></span>
          <div><b>{capability}</b><small>{isLive ? "Available through passive posture workflow where applicable" : isDemo ? "Demonstration data view" : "Provider integration contract prepared"}</small></div>
          <span className={`statusTag ${statusTone(feature.status)}`}>{isLive ? "LIVE" : isDemo ? "DEMO" : "READY"}</span>
        </div>)}
      </article>

      <article className="panel">
        <div className="panelHead"><div><h3>Data & protection status</h3><p>Transparent implementation state</p></div></div>
        <div className="decisionRow"><b>Data source</b><span>{source}</span></div>
        <div className="decisionRow"><b>Tenant scope</b><span>Organization + website</span></div>
        <div className="decisionRow"><b>Role access</b><span>RBAC foundation</span></div>
        <div className="decisionRow"><b>Auditability</b><span>Audit-log model</span></div>
        <div className="decisionRow"><b>Enforcement</b><span>{isLive ? "Passive only" : "Requires provider"}</span></div>
      </article>
    </div>

    <article className="panel">
      <div className="panelHead"><div><h3>Implementation note</h3><p>{note}</p></div></div>
      <div className="buttonRow">
        {feature.group === "Website Management" && <Link className="btn small" href="/app/websites">Open Website Security Scan</Link>}
        {feature.group.includes("Threat") && <Link className="ghostBtn small" href="/app/threat-center">Open Threat Center</Link>}
        {feature.group.includes("Firewall") && <Link className="ghostBtn small" href="/app/firewall">Open Firewall</Link>}
        {feature.group.includes("Analytics") && <Link className="ghostBtn small" href="/app/analytics">Open Analytics</Link>}
      </div>
    </article>
  </div>;
}
