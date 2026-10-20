'use client';

import { FormEvent, useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import { apiPath, withBasePath } from '@/lib/base-path';
import { Icon } from './icons';

type Site = {
  id: string;
  domain: string;
  status?: string | null;
  verified_at?: string | null;
  integration_status?: string | null;
  collector_key?: string | null;
  collector_enabled?: boolean | null;
  last_event_at?: string | null;
};

type Platform = 'universal' | 'nextjs' | 'react' | 'wordpress' | 'shopify';

type DatabaseConnection = {
  id: string;
  website_id: string | null;
  provider: string;
  name: string;
  project_ref: string;
  secret_hint: string | null;
  access_mode: string;
  status: string;
  last_checked_at: string | null;
};

type DatabaseFinding = {
  key: string;
  category: string;
  severity: string;
  title: string;
  description: string;
  recommendedFix: string;
  fixType: string;
};

type DatabaseAudit = {
  scanId: string;
  findings: DatabaseFinding[];
  summary: {
    securityScore: number;
    overallRisk: string;
    findingCounts: Record<string, number>;
    tables: number;
    rlsEnabled: number;
    rlsCoverage: number;
    policies: number;
    anonymousWriteGrants: number;
    publicSecurityDefinerFunctions: number;
    publicStorageBuckets: number;
  };
  scannedAt: string;
};

function normalizeDomain(input: string) {
  const raw = input.trim();
  if (!raw) return '';
  try {
    return new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`).hostname.replace(/^www\./, '').toLowerCase();
  } catch {
    return '';
  }
}

function normalizeProjectRef(input: string) {
  const value = input.trim();
  if (!value) return '';
  try {
    const url = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`);
    if (url.hostname.endsWith('.supabase.co')) return url.hostname.split('.')[0].toLowerCase();
  } catch {}
  return value.replace(/^https?:\/\//i, '').replace(/\.supabase\.co.*$/i, '').replace(/[^a-z0-9_-]/gi, '').toLowerCase();
}

function detectedPlatform(domain: string): Platform {
  if (/\.vercel\.app$/i.test(domain)) return 'nextjs';
  if (/\.netlify\.app$/i.test(domain)) return 'react';
  if (/\.myshopify\.com$/i.test(domain)) return 'shopify';
  return 'universal';
}

export function ConnectWebsiteWizard({
  initialDomain = '',
  onDone,
  adminBase = '/admin'
}: {
  initialDomain?: string;
  onDone?: () => void | Promise<void>;
  adminBase?: string;
}) {
  const [domain, setDomain] = useState(initialDomain);
  const [site, setSite] = useState<Site | null>(null);
  const [step, setStep] = useState<1 | 2 | 3 | 4 | 5 | 6>(1);
  const [platform, setPlatform] = useState<Platform>('universal');
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [dbProjectRef, setDbProjectRef] = useState('');
  const [dbToken, setDbToken] = useState('');
  const [dbConnection, setDbConnection] = useState<DatabaseConnection | null>(null);
  const [dbAudit, setDbAudit] = useState<DatabaseAudit | null>(null);
  const [dbAuditError, setDbAuditError] = useState('');
  const [dbSkipped, setDbSkipped] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    const host = normalizeDomain(initialDomain);
    if (host) setPlatform(detectedPlatform(host));
  }, [initialDomain]);

  useEffect(() => () => {
    if (pollRef.current) clearInterval(pollRef.current);
  }, []);

  const collectorUrl = typeof window !== 'undefined'
    ? window.location.origin + withBasePath('/webshield.js')
    : 'https://savrdhtechnologies.com/webshield/webshield.js';

  const snippet = useMemo(() => site?.collector_key
    ? `<script async src="${collectorUrl}" data-site-key="${site.collector_key}"></script>`
    : '', [collectorUrl, site?.collector_key]);

  const guide = useMemo(() => {
    if (!snippet) return '';
    if (platform === 'nextjs') return `Add this once in app/layout.tsx inside <head> (or your root layout):\n\n${snippet}`;
    if (platform === 'react') return `Paste this once inside <head> in index.html, then redeploy:\n\n${snippet}`;
    if (platform === 'wordpress') return `Add this once to the site-wide header before </head> using your theme/header custom code area:\n\n${snippet}`;
    if (platform === 'shopify') return `Add this once in theme.liquid before </head>, then save the theme:\n\n${snippet}`;
    return `Paste this once before </head> on every page (or in your global layout/header):\n\n${snippet}`;
  }, [platform, snippet]);

  async function fetchIntegration(id: string) {
    const response = await fetch(apiPath('/api/websites/integration') + '?id=' + encodeURIComponent(id), { cache: 'no-store' });
    const body = await response.json();
    if (!response.ok || !body.ok) throw new Error(body?.error?.message || 'Could not load website connection.');
    return body.data as Site;
  }

  async function register(event: FormEvent) {
    event.preventDefault();
    const host = normalizeDomain(domain);
    if (!host) {
      setStatus('Enter a valid public website domain.');
      return;
    }
    setBusy(true);
    setStatus('Registering website in WebShield…');
    try {
      const response = await fetch(apiPath('/api/websites'), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ domain: host })
      });
      const body = await response.json();
      if (!response.ok || !body.ok) throw new Error(body?.error?.message || 'Could not add website.');
      const created = body.data as Site;
      let integration = await fetchIntegration(created.id);
      if (!integration.collector_enabled) {
        const enable = await fetch(apiPath('/api/websites/integration'), {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ id: created.id, action: 'enable' })
        });
        const enabled = await enable.json();
        if (!enable.ok || !enabled.ok) throw new Error(enabled?.error?.message || 'Could not enable collector.');
        integration = enabled.data;
      }
      setDomain(host);
      setPlatform(detectedPlatform(host));
      setSite(integration);
      setStep(2);
      setStatus('Website registered. Install the collector once, then verify.');
      await onDone?.();
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Could not add website.');
    } finally {
      setBusy(false);
    }
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      setStatus('Copy failed. Select the code manually.');
    }
  }

  async function checkConnection(silent = false) {
    if (!site) return false;
    if (!silent) {
      setBusy(true);
      setStatus('Checking for collector activity…');
    }
    try {
      const fresh = await fetchIntegration(site.id);
      setSite(fresh);
      if (!fresh.last_event_at) {
        if (!silent) setStatus('No collector event yet. Install the code, open the website once, then check again.');
        return false;
      }
      const response = await fetch(apiPath('/api/websites/integration'), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id: site.id, action: 'verify' })
      });
      const body = await response.json();
      if (!response.ok || !body.ok) throw new Error(body?.error?.message || 'Could not verify collector.');
      setSite(body.data);
      setStep(4);
      setStatus('Website and collector connected. Add the website database next for database security auditing.');
      if (pollRef.current) clearInterval(pollRef.current);
      await onDone?.();
      return true;
    } catch (error) {
      if (!silent) setStatus(error instanceof Error ? error.message : 'Could not verify collector.');
      return false;
    } finally {
      if (!silent) setBusy(false);
    }
  }

  function beginVerification() {
    setStep(3);
    setStatus('Waiting for the first collector event. Open your website once after installing the code.');
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(() => void checkConnection(true), 5000);
  }

  async function runDatabaseAudit(connectionId?: string) {
    const id = connectionId || dbConnection?.id;
    if (!id) return;
    setBusy(true);
    setDbAuditError('');
    setStatus('Running initial read-only database security audit…');
    try {
      const response = await fetch(apiPath('/api/database-security'), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ action: 'scan', connectionId: id })
      });
      const body = await response.json();
      if (!response.ok || !body.ok) throw new Error(body?.error?.message || 'Database audit failed.');
      setDbAudit(body.data as DatabaseAudit);
      setStep(5);
      setStatus('Database audit completed. Review the security score and findings before finishing setup.');
      await onDone?.();
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Database audit failed.';
      setDbAuditError(message);
      setStep(5);
      setStatus('Database connected, but the initial audit needs attention.');
    } finally {
      setBusy(false);
    }
  }

  async function connectDatabase(event: FormEvent) {
    event.preventDefault();
    if (!site) return;
    const projectRef = normalizeProjectRef(dbProjectRef);
    if (!projectRef) {
      setStatus('Enter a valid Supabase project ref or project URL.');
      return;
    }
    if (dbToken.trim().length < 20) {
      setStatus('Enter a scoped Supabase Management API token in this secure form.');
      return;
    }

    setBusy(true);
    setDbAuditError('');
    setStatus('Testing Supabase database access…');
    try {
      const response = await fetch(apiPath('/api/database-security'), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          action: 'connect',
          provider: 'SUPABASE',
          name: site.domain + ' Database',
          projectRef,
          accessToken: dbToken,
          accessMode: 'READ_ONLY',
          websiteId: site.id
        })
      });
      const body = await response.json();
      if (!response.ok || !body.ok) throw new Error(body?.error?.message || 'Could not connect Supabase database.');
      const connection = body.data as DatabaseConnection;
      setDbConnection(connection);
      setDbProjectRef(projectRef);
      setDbToken('');
      setDbSkipped(false);
      setStatus('Database connected securely. Running initial audit…');
      setBusy(false);
      await runDatabaseAudit(connection.id);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Could not connect Supabase database.');
      setBusy(false);
    }
  }

  function skipDatabase() {
    setDbSkipped(true);
    setDbToken('');
    setStep(6);
    setStatus('Website setup complete. Database Security is still pending and can be connected later.');
  }

  const counts = dbAudit?.summary.findingCounts || {};

  return <div className="connectWizard">
    <div className="connectWizardSteps" aria-label="Website and database connection progress">
      {[
        ['1','Website'],
        ['2','Collector'],
        ['3','Verify'],
        ['4','Database'],
        ['5','Audit'],
        ['6','Ready']
      ].map(([n,label],i) => <div key={n} className={(step >= i + 1 ? 'active ' : '') + (step === i + 1 ? 'current' : '')}>
        <b>{step > i + 1 ? '✓' : n}</b><span>{label}</span>
      </div>)}
    </div>

    {step === 1 && <form onSubmit={register} className="connectWizardBody">
      <div className="connectWizardIntro"><Icon name="globe" size={32}/><div><h3>Connect any website</h3><p>Register the website in WebShield first. Then connect traffic telemetry and, optionally, its database security.</p></div></div>
      <label>Website URL<input autoFocus value={domain} onChange={e => setDomain(e.target.value)} placeholder="https://example.com" required /></label>
      <p className="studioHint">Works with Vercel / Next.js, React / Vite, WordPress, Shopify and normal HTML sites.</p>
      <button className="refPrimary" disabled={busy}>{busy ? 'Setting up…' : 'Continue Setup →'}</button>
    </form>}

    {step === 2 && site && <div className="connectWizardBody">
      <div className="connectWizardIntro"><Icon name="shield" size={32}/><div><h3>Install WebShield Collector</h3><p>{site.domain} is registered. Add the generated code once to the global site header/layout.</p></div></div>
      <label>Website platform<select value={platform} onChange={e => setPlatform(e.target.value as Platform)}>
        <option value="universal">Universal HTML / Other</option>
        <option value="nextjs">Next.js / Vercel</option>
        <option value="react">React / Vite / Netlify</option>
        <option value="wordpress">WordPress</option>
        <option value="shopify">Shopify</option>
      </select></label>
      <label>Installation instructions<textarea readOnly value={guide} onFocus={e => e.currentTarget.select()} rows={7}/></label>
      <div className="refActions">
        <button type="button" onClick={() => copy(snippet)}>{copied ? 'Copied ✓' : 'Copy Collector Code'}</button>
        <a className="refPrimary" href={'https://' + site.domain} target="_blank" rel="noopener noreferrer">Open Website ↗</a>
        <button type="button" onClick={beginVerification}>I Installed It →</button>
      </div>
      <p className="studioHint">The collector sends traffic/security telemetry only for this registered domain. It does not read database credentials.</p>
    </div>}

    {step === 3 && site && <div className="connectWizardBody">
      <div className="connectWizardIntro"><Icon name="chart" size={32}/><div><h3>Verify Collector Connection</h3><p>WebShield is waiting for the first page event from {site.domain}.</p></div></div>
      <div className="moduleDetail">
        <p>Collector: {site.collector_enabled ? 'Enabled' : 'Disabled'}</p>
        <p>Last event: {site.last_event_at ? new Date(site.last_event_at).toLocaleString() : 'Waiting…'}</p>
        <p>Integration: {site.integration_status || 'NOT_CONNECTED'}</p>
      </div>
      <div className="refActions">
        <a href={'https://' + site.domain} target="_blank" rel="noopener noreferrer">Open Website ↗</a>
        <button className="refPrimary" type="button" disabled={busy} onClick={() => void checkConnection(false)}>{busy ? 'Checking…' : 'Check Connection'}</button>
        <button type="button" onClick={() => setStep(2)}>Back to Install</button>
      </div>
      <p className="studioHint">Automatic check runs every 5 seconds while this step is open.</p>
    </div>}

    {step === 4 && site && <form onSubmit={connectDatabase} className="connectWizardBody">
      <div className="connectWizardSuccess"><b>✓</b><div><h3>Website + Collector Connected</h3><p>{site.domain} is receiving WebShield telemetry. Now connect its database for database security checks.</p></div></div>
      <div className="connectWizardIntro"><Icon name="database" size={32}/><div><h3>Connect Supabase Database</h3><p>WebShield will verify the project and store the scoped token encrypted server-side. The onboarding audit is read-only.</p></div></div>
      <label>Supabase Project Ref or Project URL<input value={dbProjectRef} onChange={e => setDbProjectRef(e.target.value)} placeholder="project-ref or https://project-ref.supabase.co" required /></label>
      <label>Scoped Supabase Management API Token<input type="password" autoComplete="off" value={dbToken} onChange={e => setDbToken(e.target.value)} placeholder="Enter token securely here" required /></label>
      <div className="moduleDetail">
        <p>Access mode: READ ONLY</p>
        <p>Website link: {site.domain}</p>
        <p>Token storage: Encrypted server-side</p>
        <p>Automatic fixes: Disabled during onboarding</p>
      </div>
      <p className="studioHint">Do not paste database passwords into chat. Enter the scoped token only in this secure WebShield form. Remediation access can be enabled later from Database Security after review.</p>
      <div className="refActions">
        <button className="refPrimary" disabled={busy}>{busy ? 'Connecting…' : 'Connect & Run Audit →'}</button>
        <button type="button" disabled={busy} onClick={skipDatabase}>Skip for now</button>
      </div>
    </form>}

    {step === 5 && site && <div className="connectWizardBody">
      <div className="connectWizardIntro"><Icon name="database" size={32}/><div><h3>Database Security Audit</h3><p>{dbConnection ? `${dbConnection.project_ref} is connected to ${site.domain}.` : 'Database connection is being checked.'}</p></div></div>
      {dbAudit ? <>
        <div className="connectWizardAuditMetrics">
          <div><span>Security Score</span><strong>{dbAudit.summary.securityScore}<small>/100</small></strong></div>
          <div><span>Overall Risk</span><strong>{dbAudit.summary.overallRisk}</strong></div>
          <div><span>RLS Coverage</span><strong>{dbAudit.summary.rlsCoverage}<small>%</small></strong></div>
          <div><span>Open Findings</span><strong>{dbAudit.findings.length}</strong></div>
        </div>
        <div className="moduleDetail">
          <p>Tables: {dbAudit.summary.tables}</p>
          <p>RLS enabled: {dbAudit.summary.rlsEnabled}</p>
          <p>Policies: {dbAudit.summary.policies}</p>
          <p>Anon write grants: {dbAudit.summary.anonymousWriteGrants}</p>
        </div>
        <div className="connectWizardFindingSummary">
          {['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(level => <span key={level}>{level}: <b>{counts[level] || 0}</b></span>)}
        </div>
        {dbAudit.findings.length > 0 && <div className="connectWizardFindings">
          {dbAudit.findings.slice(0,5).map(f => <div key={f.key}><span>{f.severity}</span><div><b>{f.title}</b><small>{f.category}</small></div></div>)}
        </div>}
        <div className="refActions">
          <button className="refPrimary" type="button" onClick={() => setStep(6)}>Continue →</button>
          <Link href={adminBase + '/database-security'}>Open Full Database Security</Link>
        </div>
      </> : <>
        <p className="connectWizardStatus">{dbAuditError || 'Audit result is not available yet.'}</p>
        <div className="refActions">
          <button className="refPrimary" type="button" disabled={busy || !dbConnection} onClick={() => void runDatabaseAudit()}>{busy ? 'Auditing…' : 'Retry Audit'}</button>
          <Link href={adminBase + '/database-security'}>Open Database Security</Link>
        </div>
      </>}
    </div>}

    {step === 6 && site && <div className="connectWizardBody">
      <div className="connectWizardSuccess"><b>✓</b><div><h3>WebShield Setup Complete</h3><p>{site.domain} is linked to your WebShield admin workspace.</p></div></div>
      <div className="connectWizardReadiness">
        <div className="done"><b>✓</b><span>Website Registered<small>{site.domain}</small></span></div>
        <div className="done"><b>✓</b><span>Collector Connected<small>{site.last_event_at ? 'Telemetry received' : 'Verified'}</small></span></div>
        <div className={dbSkipped ? 'pending' : 'done'}><b>{dbSkipped ? '!' : '✓'}</b><span>Database Security<small>{dbSkipped ? 'Not connected — pending' : dbConnection?.project_ref || 'Connected'}</small></span></div>
        <div className={dbAudit ? 'done' : 'pending'}><b>{dbAudit ? '✓' : '!'}</b><span>Database Audit<small>{dbAudit ? `Score ${dbAudit.summary.securityScore}/100 · ${dbAudit.summary.overallRisk}` : 'Pending'}</small></span></div>
        <div className="pending"><b>5</b><span>WAF / Traffic Enforcement<small>Provider connection required for blocking/challenge/rate-limit enforcement</small></span></div>
        <div className="pending"><b>6</b><span>Auto Protection<small>Enable only after supported enforcement provider is connected</small></span></div>
      </div>
      <div className="refActions">
        <Link className="refPrimary" href={adminBase + '/dashboard'}>Open Security Dashboard →</Link>
        <Link href={adminBase + '/live-traffic'}>View Live Traffic</Link>
        <Link href={adminBase + '/database-security'}>{dbSkipped ? 'Connect Database Security' : 'Database Security'}</Link>
      </div>
      <p className="studioHint">Collector monitoring and database auditing are active only for the layers shown as connected. WAF enforcement and automatic blocking require a supported traffic-path provider.</p>
    </div>}

    {status && <p className="connectWizardStatus" role="status">{status}</p>}
  </div>;
}
