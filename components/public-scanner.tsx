"use client";

import { useState } from "react";
import Link from "next/link";

type Finding = { severity: string; title: string; detail: string; fix: string };
type Scan = {
  hostname: string; finalUrl: string; status: number; responseMs: number; https: boolean; securityScore: number; grade: string;
  redirectHops: number; findings: Finding[]; scannedAt: string;
  capabilities: Record<string,string>;
};

const capabilityLabels: Record<string,string> = {
  visitorMonitoring: "Real-Time Visitor Monitoring",
  threatDetection: "Threat & Suspicious Activity Detection",
  websiteProtection: "Website Protection & Security",
  botDetection: "Bot & Malicious Traffic Detection",
  analytics: "Detailed Visitor & Security Analytics",
  alerts: "Attack & Threat Alerts",
  easyIntegration: "Easy Website Integration",
  reports: "Security Reports & Insights"
};

export function PublicScanner() {
  const [url, setUrl] = useState("");
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function runScan(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true); setError(""); setScan(null);
    try {
      const res = await fetch("/api/public-scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }) });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "Scan failed");
      setScan(data.scan);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally { setLoading(false); }
  }

  return <section className="publicScannerWrap container" id="scan">
    <div className="publicScannerCard">
      <div className="scannerHeading">
        <span>FREE WEBSITE SECURITY CHECK</span>
        <h2>Paste your website. See what WebShield can detect.</h2>
        <p>Run a real external security-posture check, get prioritized findings, then connect WebShield for live monitoring and automatic protection.</p>
      </div>
      <form className="scannerForm" onSubmit={runScan}>
        <input value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://yourwebsite.com" aria-label="Website URL" required />
        <button className="btn" disabled={loading}>{loading ? "Scanning…" : "Scan Website"}</button>
      </form>
      <small className="scannerSafety">Only scan websites you own or are authorized to assess. This public check is passive and does not exploit the target.</small>
      {error && <div className="scanError">{error}</div>}

      {scan && <div className="scanResult">
        <div className="scanScoreRow">
          <article><small>Security Score</small><strong>{scan.securityScore}/100</strong><em>Grade {scan.grade}</em></article>
          <article><small>HTTP Status</small><strong>{scan.status}</strong><em>{scan.finalUrl}</em></article>
          <article><small>HTTPS</small><strong>{scan.https ? "YES" : "NO"}</strong><em>{scan.redirectHops} redirect hops</em></article>
          <article><small>Response</small><strong>{scan.responseMs} ms</strong><em>Live external probe</em></article>
        </div>

        <div className="scanColumns">
          <div className="scanFindings">
            <h3>Security findings</h3>
            {scan.findings.length === 0 ? <p className="scanGood">No posture issues detected by this passive check.</p> : scan.findings.slice(0,8).map((f,i)=><article key={`${f.title}-${i}`}>
              <span className={`findingSeverity ${f.severity.toLowerCase()}`}>{f.severity}</span>
              <div><b>{f.title}</b><p>{f.detail}</p><small><strong>Fix:</strong> {f.fix}</small></div>
            </article>)}
          </div>
          <div className="scanCapabilities">
            <h3>WebShield coverage</h3>
            {Object.entries(scan.capabilities).map(([key,status])=><div key={key} className="coverageRow"><span>{capabilityLabels[key] || key}</span><b className={status === "AVAILABLE" || status.includes("SCAN") ? "available" : "requires"}>{status.replaceAll("_"," ")}</b></div>)}
            <div className="protectionNote"><strong>Why integration is required</strong><p>A URL scan sees only public responses. To detect every visitor/request and block attacks automatically, WebShield must sit in the traffic path through an edge/WAF/reverse-proxy or supported hosting integration.</p></div>
          </div>
        </div>
        <div className="scanCtaRow">
          <Link className="btn" href={`/register?site=${encodeURIComponent(scan.hostname)}`}>Protect this Website</Link>
          <Link className="ghostBtn" href="/features">See Protection Features</Link>
        </div>
      </div>}
    </div>
  </section>;
}
