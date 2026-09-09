"use client";

import { FormEvent, useState } from "react";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
type ScanFinding = { severity: Severity; category: string; title: string; detail: string; impact: string; fix: string };
type ScanResult = {
  requestedUrl: string;
  finalUrl: string;
  hostname: string;
  status: number;
  statusText: string;
  responseMs: number;
  https: boolean;
  redirectedToHttps: boolean;
  redirectChain: string[];
  securityScore: number;
  grade: string;
  overallRisk: Severity;
  findingCounts: Record<Severity, number>;
  findings: ScanFinding[];
  headers: { key: string; label: string; present: boolean; value: string | null; fix: string }[];
  server: string | null;
  poweredBy: string | null;
  cors: string | null;
  cookies: { observed: number; missingSecure: number; missingHttpOnly: number; missingSameSite: number };
  dns: { resolved: boolean; addresses: { address: string; family: number }[] };
  technologies: { signal: string; value: string }[];
  resources: { securityTxt: { exists: boolean; status: number; finalUrl: string | null }; robotsTxt: { exists: boolean; status: number; finalUrl: string | null } };
  capabilities: Record<string, string>;
  scannedAt: string;
  mode: string;
  note: string;
};

function tone(severity: string) {
  const s = severity.toLowerCase();
  if (s === "critical" || s === "high") return "critical";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "safe";
}

function capabilityLabel(key: string) {
  return ({
    visitorMonitoring: "Real-Time Visitor Monitoring",
    threatDetection: "Threat Detection",
    websiteProtection: "Website Protection",
    botDetection: "Bot & Malicious Traffic Detection",
    analytics: "Visitor & Security Analytics",
    alerts: "Attack & Threat Alerts",
    easyIntegration: "Website Integration",
    reports: "Security Reports & Insights"
  } as Record<string, string>)[key] || key;
}

export function WebsiteScanner() {
  const [url, setUrl] = useState("");
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    setScan(null);
    setLoading(true);
    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url })
      });
      const data = await response.json();
      if (!response.ok || !data?.ok) throw new Error(data?.error || "Scan failed.");
      const result = data.scan as ScanResult;
      setScan(result);
      try {
        window.localStorage.setItem("webshield:last-scan", JSON.stringify(result));
        window.dispatchEvent(new Event("webshield:scan-updated"));
      } catch { /* local storage can be disabled */ }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Scan failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <article className="panel" style={{ marginBottom: 16 }}>
      <div className="panelHead">
        <div>
          <h3>Website Security Scan</h3>
          <p>Live passive security-posture scan for websites you own or are authorized to assess.</p>
        </div>
        <span className="statusTag safe">LIVE CHECK</span>
      </div>

      <form onSubmit={submit} style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 10, marginTop: 16 }}>
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="example.com or https://example.com"
          required
          style={{ height: 44, borderRadius: 10, border: "1px solid rgba(120,190,225,.15)", background: "#091522", color: "#edf8ff", padding: "0 13px", outline: "none" }}
        />
        <button className="btn" type="submit" disabled={loading}>{loading ? "Scanning…" : "Scan Website"}</button>
      </form>

      <p style={{ fontSize: 10, marginTop: 10 }}>Passive checks only. No exploit, password attack, malware execution, or penetration testing.</p>
      {error && <div className="formNotice error" style={{ marginTop: 12 }}>{error}</div>}

      {scan && (
        <div style={{ marginTop: 18 }}>
          <div className="metricGrid compact">
            <article className="metricCard"><span>Security Score</span><strong>{scan.securityScore}/100</strong><small>Grade {scan.grade}</small></article>
            <article className="metricCard"><span>Overall Risk</span><strong>{scan.overallRisk}</strong><small>{scan.findings.length} finding(s)</small></article>
            <article className="metricCard"><span>HTTPS</span><strong>{scan.https ? "YES" : "NO"}</strong><small>{scan.redirectedToHttps ? "HTTP → HTTPS enforced" : "Redirect not confirmed"}</small></article>
            <article className="metricCard"><span>Response</span><strong>{scan.responseMs} ms</strong><small>HTTP {scan.status} · live probe</small></article>
          </div>

          <div className="metricGrid compact" style={{ marginTop: 12 }}>
            {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as Severity[]).map((s) => (
              <article className="metricCard" key={s}><span>{s} Findings</span><strong>{scan.findingCounts[s] || 0}</strong><small>Passive posture result</small></article>
            ))}
          </div>

          <article className="panel" style={{ marginTop: 14 }}>
            <div className="panelHead"><div><h3>Priority Security Findings</h3><p>Detected posture issues with impact and remediation guidance.</p></div></div>
            {scan.findings.length === 0 ? (
              <div className="formNotice">No material passive posture findings were detected by this scan.</div>
            ) : scan.findings.map((finding, index) => (
              <div className="eventRow" key={`${finding.title}-${index}`} style={{ alignItems: "flex-start" }}>
                <span className={`statusTag ${tone(finding.severity)}`}>{finding.severity}</span>
                <div style={{ flex: 1 }}>
                  <b>{finding.title}</b>
                  <small>{finding.category} · {finding.detail}</small>
                  <p style={{ margin: "8px 0 4px", fontSize: 12 }}><strong>Why it matters:</strong> {finding.impact}</p>
                  <p style={{ margin: 0, fontSize: 12 }}><strong>How to fix:</strong> {finding.fix}</p>
                </div>
              </div>
            ))}
          </article>

          <div className="dashboardGrid equal" style={{ marginTop: 14 }}>
            <article className="panel">
              <div className="panelHead"><div><h3>Security Controls</h3><p>Browser defensive controls observed on the final response.</p></div></div>
              {scan.headers.map((header) => (
                <div className="decisionRow" key={header.key}>
                  <span>{header.label}</span>
                  <span className={`statusTag ${header.present ? "safe" : "medium"}`}>{header.present ? "PRESENT" : "MISSING"}</span>
                </div>
              ))}
            </article>

            <article className="panel">
              <div className="panelHead"><div><h3>Technical Posture</h3><p>Live DNS, response and platform signals.</p></div></div>
              <div className="decisionRow"><span>Final URL</span><code style={{ maxWidth: "60%", overflow: "hidden", textOverflow: "ellipsis" }}>{scan.finalUrl}</code></div>
              <div className="decisionRow"><span>DNS addresses</span><b>{scan.dns.addresses.length}</b></div>
              <div className="decisionRow"><span>HTTP→HTTPS</span><span className={`statusTag ${scan.redirectedToHttps ? "safe" : "medium"}`}>{scan.redirectedToHttps ? "ENFORCED" : "NOT CONFIRMED"}</span></div>
              <div className="decisionRow"><span>CORS</span><code>{scan.cors || "Not exposed"}</code></div>
              <div className="decisionRow"><span>Cookies observed</span><b>{scan.cookies.observed}</b></div>
              <div className="decisionRow"><span>security.txt</span><span className={`statusTag ${scan.resources.securityTxt.exists ? "safe" : "medium"}`}>{scan.resources.securityTxt.exists ? "FOUND" : "NOT FOUND"}</span></div>
              <div className="decisionRow"><span>robots.txt</span><span className={`statusTag ${scan.resources.robotsTxt.exists ? "safe" : "medium"}`}>{scan.resources.robotsTxt.exists ? "FOUND" : "NOT FOUND"}</span></div>
            </article>
          </div>

          <div className="dashboardGrid equal" style={{ marginTop: 14 }}>
            <article className="panel">
              <div className="panelHead"><div><h3>Observed Technology Signals</h3><p>Only response signals actually exposed by the target are listed.</p></div></div>
              {scan.technologies.length ? scan.technologies.map((item, i) => <div className="decisionRow" key={`${item.signal}-${i}`}><span>{item.signal}</span><code>{item.value}</code></div>) : <div className="formNotice">No technology headers were exposed.</div>}
            </article>

            <article className="panel">
              <div className="panelHead"><div><h3>WebShield Protection Coverage</h3><p>What the scan can assess now vs what needs live website integration.</p></div></div>
              {Object.entries(scan.capabilities).map(([key, value]) => (
                <div className="decisionRow" key={key}>
                  <span>{capabilityLabel(key)}</span>
                  <span className={`statusTag ${value.includes("REQUIRES") ? "medium" : "safe"}`}>{value.replaceAll("_", " ")}</span>
                </div>
              ))}
              <div className="buttonRow" style={{ marginTop: 14 }}>
                <a className="btn small" href="/app/websites">Protect this Website</a>
              </div>
            </article>
          </div>

          <div className="formNotice" style={{ marginTop: 14 }}>{scan.note}</div>
        </div>
      )}
    </article>
  );
}
