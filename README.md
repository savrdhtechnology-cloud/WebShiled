# WebShield

Website and database security monitoring by Savrdh Technologies. Next.js 16 app
served under `/webshield`, backed by the WebShield Supabase project
(`szvxrgbshmmsvujkusdm`).

## What runs where

| Module | What it actually does | Needs |
| --- | --- | --- |
| **Websites & Scan** | Passive posture scan (HTTPS, redirects, security headers, cookies, CORS, exposed `.env`/`.git`, SPF/DMARC). Results are saved per website (`security_scan_runs`, `websites.security_score`). | — |
| **Continuous monitoring** | Every 15 min (GitHub Actions → `/api/cron/monitor`, plus a daily Vercel Cron): uptime + response time, TLS certificate validity/expiry, posture re-scan when due (default daily). Alerts: website down (2 failed checks), SSL invalid / expiring ≤14 days, new HIGH/CRITICAL finding, score drop ≥10. Auto-resolves when fixed. | `WEBSHIELD_SUPABASE_SECRET_KEY` |
| **Browser collector** | `<script src=".../webshield.js" data-site-key>` — page views, visitors, bots → Live Traffic. | — |
| **Server protection + Firewall** | Website middleware calls `POST /api/ingest` per request. WebShield detects SQL injection, XSS, path traversal, command injection, secret-file probes, scanner tools, request floods and login brute force; applies IP rules and custom firewall rules; returns `ALLOW / RATE_LIMIT / BLOCK`, which the middleware enforces. Attacks create threat events and alerts. | `WEBSHIELD_SUPABASE_SECRET_KEY`; server key per site |
| **Database Security** | Audits a Supabase project through a scoped Management API token: RLS coverage, anonymous write grants, broad anon policies, public SECURITY DEFINER functions, public buckets. Re-audits daily; new HIGH/CRITICAL findings alert. | Management API token |
| **Fix Center** | Reviewed, approved fixes: enable RLS, revoke anon writes, revoke public EXECUTE. Every change is a recorded remediation job. | Token with remediation access |
| **Data Guard** | Installs an audit trigger on chosen tables of the monitored database. Records who changed which row (logged-in user id, anon key, backend key or direct DB login) and client IP — never row data. Alerts on: writes without login, direct database edits outside the app (SQL editor / leaked DB password), privilege/credential column changes (`role`, `is_admin`, `password`…), mass deletes (≥25 in a window), mass updates, TRUNCATE. | Token with remediation access (installs trigger) |
| **Alerts** | Deduplicated alerts (same issue = one open alert with an occurrence count). Delivery by email (Resend) and/or signed HTTPS webhook; defaults to emailing workspace owners/admins for HIGH+. | `RESEND_API_KEY`, `ALERT_EMAIL_FROM` (optional `WEBHOOK_SECRET`) |

## Setup

1. **Database.** In the WebShield Supabase project SQL editor run, in order, any
   migration not yet applied: `supabase/migrations/0001` … `0006`. `0006` is
   safe to re-run and stops with a clear message if an earlier one is missing.
2. **Environment variables (Vercel → webshield project):**

   | Variable | Purpose |
   | --- | --- |
   | `WEBSHIELD_SUPABASE_SECRET_KEY` | Supabase **secret** API key of the WebShield project (Settings → API Keys). Server only; used by cron, ingest and alert delivery. |
   | `CRON_SECRET` | Optional. Random string ≥16 chars for the daily Vercel Cron. |
   | `WEBSHIELD_ENCRYPTION_KEY` | ≥32 chars, encrypts stored database tokens. Must stay stable. |
   | `RESEND_API_KEY`, `ALERT_EMAIL_FROM` | Email alerts, e.g. `WebShield <alerts@your-verified-domain>`. |
   | `WEBHOOK_SECRET` | Optional; signs webhook bodies (`x-webshield-signature: sha256=…`). |
   | `NEXT_PUBLIC_APP_URL` | e.g. `https://savrdhtechnologies.com/webshield` (links in emails). |

   Scheduling: `.github/workflows/monitor.yml` runs the cycle every 15 minutes
   and authenticates with a GitHub-signed OIDC token (no GitHub secret needed;
   only `main` of this repository is accepted — override the list with
   `WEBSHIELD_MONITOR_REPOSITORIES`). `vercel.json` adds a daily Vercel Cron,
   which needs `CRON_SECRET`; without it the daily run is simply rejected.
3. **Add your websites** (Websites & Scan → Add Website). Monitoring starts
   automatically. Use **Run checks** for an immediate check.
4. **Server protection** (recommended for every site you own): open a website →
   **Create server key** → add `WEBSHIELD_SITE_KEY` / `WEBSHIELD_SERVER_KEY` to
   that site's env and save the shown snippet as `proxy.ts` (Next.js 16) or
   `middleware.ts` (Next.js 13–15). It fails open: if WebShield is unreachable
   the site keeps working.

   Other stacks call the same endpoint:

   ```http
   POST https://savrdhtechnologies.com/webshield/api/ingest
   x-webshield-site: <site key>
   authorization: Bearer <server key>
   content-type: application/json

   {"ip":"203.0.113.7","method":"GET","path":"/login","query":"?a=1","userAgent":"…","country":"IN"}
   → {"ok":true,"action":"ALLOW|RATE_LIMIT|CHALLENGE|BLOCK","riskScore":0,"signals":[]}
   ```
5. **Database / CRM protection:** Database Security → Connect Database with a
   project-scoped Management API token. Choose *Audit + approved remediation* to
   use Fix Center and Data Guard. Run the audit, then **Choose tables to
   protect** → **Install Data Guard**. List public-form tables (lead/inquiry
   forms) under "Tables where public forms may insert without login", so normal
   form submissions are not flagged.

## Development

```bash
npm install
npm run dev        # http://localhost:3000/webshield
npm run typecheck
npm test           # unit tests + Data Guard SQL + migrations on PGlite
npm run build
```

## Reference dashboard preview

Run `npm install` and `npm run dev`, then visit `/demo` for the responsive
Next.js reference interface. Dedicated screens: `/demo/websites`,
`/demo/database-security`, and `/demo/live-traffic`.

The preview uses labelled sample telemetry. Website additions and finding
reviews are session-local; they do not modify the backend. Search, pending-site
filtering, dialogs, and mobile navigation are interactive. Real scan,
database, and authenticated monitoring workflows remain under `/app`.

### Appearance Studio

Open `/demo/appearance` or use the floating Appearance Studio button on any
preview page. Four presets and individual controls adjust background, accent,
animation speed/intensity, glow, hover/click feedback, card opacity/radius and
density. Preferences persist locally in `webshield:appearance:v1`; reset restores
the defaults. This customisation applies to the demo interface, not `/app`.
Device reduced-motion preferences override animated effects. Background layers
ignore pointer input, and the studio drawer supports Escape and focus trapping.

### Connected modules and animated telemetry

The authenticated `/app` workspace uses the same responsive shell and Appearance
Studio as `/demo`. Dashboard and Live Traffic poll the tenant-scoped dashboard
API every 15 seconds, with pause/resume, time-window filtering, interactive
charts, country selection, map zoom, visitor details and CSV export. The UI shows
an explicit empty state until real collector records arrive. Current detail
queries are capped at 1,000 visitors and 5,000 recent sessions; aggregate totals
are queried separately. Map markers use country-centre approximations for known
countries, not precise visitor coordinates.

Websites use existing add/connect/verify/remove APIs; database security and Fix
Center retain the existing audit and approval workflow. Threats support reviewed
status changes, alerts can be acknowledged, support tickets can be created and
resolved, and reports export CSV. Writes require an authenticated workspace and
existing RLS permissions. Status updates require OWNER, ADMIN or SECURITY_ANALYST.
The demo counterparts operate only on explicitly labelled session-local samples.
A public passive scan is available from the demo scan dialog.

World map coastlines: Natural Earth public-domain data, distributed by
[world-atlas](https://github.com/topojson/world-atlas), bundled as
`public/world-land.svg`. No external map API or paid key is needed.

Local database-provider credentials use a generated, ignored `.env.local`
encryption key. Keep that key stable to decrypt saved provider tokens. Advanced
RLS audits require an explicit scoped Management API token in Database Security;
regular Supabase authentication and publishable API keys do not grant schema
introspection or remediation privileges. No new provider token is created by
this implementation.
