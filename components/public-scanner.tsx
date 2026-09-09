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
    <style jsx>{`
      .publicScannerWrap{padding:0 0 80px}.publicScannerCard{border:1px solid rgba(32,217,255,.22);border-radius:22px;background:linear-gradient(145deg,rgba(12,27,43,.98),rgba(5,13,23,.98));padding:34px;box-shadow:0 35px 90px rgba(0,0,0,.36),0 0 70px rgba(32,217,255,.05)}
      .scannerHeading{max-width:760px}.scannerHeading>span{font-size:9px;letter-spacing:2px;font-weight:900;color:#20d9ff}.scannerHeading h2{font-size:clamp(28px,4vw,46px);line-height:1.05;letter-spacing:-2px;margin:12px 0}.scannerHeading p{margin:0;color:#7f96a9}.scannerForm{display:grid;grid-template-columns:1fr auto;gap:10px;margin-top:26px}.scannerForm input{height:52px;border:1px solid rgba(120,190,225,.17);background:#081522;color:#edf8ff;border-radius:12px;padding:0 16px;outline:none;font-size:14px}.scannerForm input:focus{border-color:rgba(32,217,255,.6);box-shadow:0 0 0 3px rgba(32,217,255,.06)}.scannerSafety{display:block;margin-top:9px;color:#668196;font-size:9px}.scanError{margin-top:15px;padding:12px;border:1px solid rgba(255,82,110,.3);background:rgba(255,82,110,.07);border-radius:10px;color:#ff92a3;font-size:11px}.scanResult{margin-top:28px;padding-top:24px;border-top:1px solid rgba(120,190,225,.13)}
      .scanScoreRow{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.scanScoreRow article{padding:15px;border:1px solid rgba(120,190,225,.13);border-radius:12px;background:#091522;min-width:0}.scanScoreRow small{display:block;color:#71899b;font-size:9px}.scanScoreRow strong{display:block;font-size:22px;margin:6px 0}.scanScoreRow em{display:block;font-style:normal;color:#668196;font-size:9px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.scanColumns{display:grid;grid-template-columns:1.15fr .85fr;gap:12px;margin-top:12px}.scanFindings,.scanCapabilities{padding:18px;border:1px solid rgba(120,190,225,.13);border-radius:12px;background:#08131f}.scanFindings h3,.scanCapabilities h3{margin:0 0 14px;font-size:14px}.scanFindings article{display:grid;grid-template-columns:auto 1fr;gap:10px;padding:12px 0;border-top:1px solid rgba(120,190,225,.09)}.scanFindings article:first-of-type{border-top:0}.scanFindings b{font-size:11px}.scanFindings p{font-size:10px;margin:3px 0;color:#738b9e}.scanFindings small{font-size:9px;color:#9cb1c0}.findingSeverity{align-self:start;border-radius:999px;padding:4px 6px;font-size:7px;font-weight:900;letter-spacing:.7px}.findingSeverity.high,.findingSeverity.critical{background:rgba(255,82,110,.1);color:#ff758b}.findingSeverity.medium{background:rgba(255,177,74,.1);color:#ffc16d}.findingSeverity.low,.findingSeverity.info{background:rgba(32,217,255,.08);color:#73e5fa}.scanGood{color:#54dda1}.coverageRow{display:flex;justify-content:space-between;gap:14px;padding:10px 0;border-top:1px solid rgba(120,190,225,.09);font-size:10px}.coverageRow span{color:#9bb0c1}.coverageRow b{font-size:7px;letter-spacing:.5px;text-align:right}.coverageRow .available{color:#51dda2}.coverageRow .requires{color:#ffbd66}.protectionNote{margin-top:14px;padding:12px;border:1px dashed rgba(32,217,255,.22);border-radius:10px;background:rgba(32,217,255,.03)}.protectionNote strong{font-size:10px;color:#7ce6fa}.protectionNote p{font-size:9px;margin:4px 0}.scanCtaRow{display:flex;gap:10px;margin-top:18px;flex-wrap:wrap}
      @media(max-width:850px){.scanScoreRow{grid-template-columns:1fr 1fr}.scanColumns{grid-template-columns:1fr}.scannerForm{grid-template-columns:1fr}.scannerForm :global(.btn){width:100%}}@media(max-width:520px){.publicScannerCard{padding:20px}.scanScoreRow{grid-template-columns:1fr}.scannerHeading h2{letter-spacing:-1px}}
    `}</style>
  </section>;
}
