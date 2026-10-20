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

function normalizeDomain(input: string) {
  const raw = input.trim();
  if (!raw) return '';
  try {
    return new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`).hostname.replace(/^www\./, '').toLowerCase();
  } catch {
    return '';
  }
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
  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);
  const [platform, setPlatform] = useState<Platform>('universal');
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
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
    if (platform === 'nextjs') {
      return `Add this once in app/layout.tsx inside <head> (or your root layout):\n\n${snippet}`;
    }
    if (platform === 'react') {
      return `Paste this once inside <head> in index.html, then redeploy:\n\n${snippet}`;
    }
    if (platform === 'wordpress') {
      return `Add this once to the site-wide header before </head> using your theme/header custom code area:\n\n${snippet}`;
    }
    if (platform === 'shopify') {
      return `Add this once in theme.liquid before </head>, then save the theme:\n\n${snippet}`;
    }
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
      setStatus('Connected. This website is now linked to the WebShield admin workspace.');
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

  return <div className="connectWizard">
    <div className="connectWizardSteps" aria-label="Website connection progress">
      {[
        ['1','Website'],
        ['2','Install'],
        ['3','Verify'],
        ['4','Connected']
      ].map(([n,label],i) => <div key={n} className={(step >= i + 1 ? 'active ' : '') + (step === i + 1 ? 'current' : '')}>
        <b>{step > i + 1 ? '✓' : n}</b><span>{label}</span>
      </div>)}
    </div>

    {step === 1 && <form onSubmit={register} className="connectWizardBody">
      <div className="connectWizardIntro"><Icon name="globe" size={32}/><div><h3>Connect any website</h3><p>Enter the website URL. WebShield will register it in your workspace and prepare a unique collector connection.</p></div></div>
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
      <p className="studioHint">The collector only sends WebShield telemetry for this registered domain. It does not expose your website database credentials.</p>
    </div>}

    {step === 3 && site && <div className="connectWizardBody">
      <div className="connectWizardIntro"><Icon name="chart" size={32}/><div><h3>Verify Connection</h3><p>WebShield is waiting for the first page event from {site.domain}.</p></div></div>
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

    {step === 4 && site && <div className="connectWizardBody">
      <div className="connectWizardSuccess"><b>✓</b><div><h3>Website Connected</h3><p>{site.domain} is linked to the WebShield database and admin workspace.</p></div></div>
      <div className="moduleDetail">
        <p>Status: {site.status || 'CONNECTED'}</p>
        <p>Verification: {site.verified_at ? 'Verified' : 'Connected'}</p>
        <p>Collector: {site.collector_enabled ? 'Enabled' : 'Disabled'}</p>
        <p>Last event: {site.last_event_at ? new Date(site.last_event_at).toLocaleString() : 'Received'}</p>
      </div>
      <div className="refActions">
        <Link className="refPrimary" href={adminBase + '/live-traffic'}>View Live Traffic →</Link>
        <Link href={adminBase + '/websites'}>Manage Websites</Link>
        <Link href={adminBase + '/database-security'}>Connect Database Security</Link>
      </div>
      <p className="studioHint">Database Security is a separate, explicit provider connection. A website URL alone does not grant database access.</p>
    </div>}

    {status && <p className="connectWizardStatus" role="status">{status}</p>}
  </div>;
}
