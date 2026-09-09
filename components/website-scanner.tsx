"use client";

import { FormEvent, useState } from "react";

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
  headers: { key: string; label: string; present: boolean; value: string | null }[];
  server: string | null;
  poweredBy: string | null;
  scannedAt: string;
  mode: string;
  note: string;
};

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
      setScan(data.scan);
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
          <p>Real passive check for websites you own or are authorized to test.</p>
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
        <button className="btn" type="submit" disabled={loading}>
          {loading ? "Scanning…" : "Scan Website"}
        </button>
      </form>

      <p style={{ fontSize: 10, marginTop: 10 }}>
        Passive scan only: status, HTTPS, redirects, response time and defensive response headers. No exploit or attack testing.
      </p>

      {error && <div className="formNotice error" style={{ marginTop: 12 }}>{error}</div>}

      {scan && (
        <div style={{ marginTop: 18 }}>
          <div className="metricGrid compact">
            <article className="metricCard"><span>Security Score</span><strong>{scan.securityScore}/100</strong><small>Grade {scan.grade}</small></article>
            <article className="metricCard"><span>HTTP Status</span><strong>{scan.status}</strong><small>{scan.statusText || "Response received"}</small></article>
            <article className="metricCard"><span>HTTPS</span><strong>{scan.https ? "YES" : "NO"}</strong><small>{scan.redirectedToHttps ? "HTTP redirects to HTTPS" : scan.https ? "Encrypted transport" : "Not encrypted"}</small></article>
            <article className="metricCard"><span>Response</span><strong>{scan.responseMs} ms</strong><small>Server-side probe</small></article>
          </div>

          <div className="dashboardGrid equal" style={{ marginTop: 14 }}>
            <article className="panel">
              <div className="panelHead"><div><h3>Security headers</h3><p>Headers detected on the final response.</p></div></div>
              {scan.headers.map((header) => (
                <div className="decisionRow" key={header.key}>
                  <span>{header.label}</span>
                  <span className={`statusTag ${header.present ? "safe" : "medium"}`}>{header.present ? "PRESENT" : "MISSING"}</span>
                </div>
              ))}
            </article>

            <article className="panel">
              <div className="panelHead"><div><h3>Scan details</h3><p>Live HTTP response metadata.</p></div></div>
              <div className="decisionRow"><span>Final URL</span><code style={{ maxWidth: "60%", overflow: "hidden", textOverflow: "ellipsis" }}>{scan.finalUrl}</code></div>
              <div className="decisionRow"><span>Redirect hops</span><b>{Math.max(0, scan.redirectChain.length - 1)}</b></div>
              <div className="decisionRow"><span>Server header</span><code>{scan.server || "Not exposed"}</code></div>
              <div className="decisionRow"><span>X-Powered-By</span><code>{scan.poweredBy || "Not exposed"}</code></div>
              <div className="decisionRow"><span>Scan mode</span><span className="statusTag safe">PASSIVE</span></div>
            </article>
          </div>

          <div className="formNotice" style={{ marginTop: 14 }}>
            {scan.note}
          </div>
        </div>
      )}
    </article>
  );
}
