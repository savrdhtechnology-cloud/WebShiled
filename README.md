# WebShield V1

**Monitor. Detect. Protect.**

WebShield is a website protection and visitor security platform by **Savrdh Technologies**. The V1 repository provides a scalable SaaS application foundation for website monitoring, visitor visibility, threat investigation, firewall policy management, analytics, alerts, reporting, API integrations, billing, team access, administration and security-provider integration.

> **Important:** V1 does **not** claim to be a live WAF, DDoS mitigation network, IP reputation service or bot-management network. The default deployment uses a clearly labelled **DEMO MODE** provider. Real enforcement only exists after a production edge/WAF provider is connected.

## Product

- Product: WebShield
- Company: Savrdh Technologies
- Founder: Shailendra Choudhary
- Tagline: Monitor. Detect. Protect.
- Company website: https://www.savrdhtechnology.com

## Technology

- Next.js 16.3.4 App Router
- React 19.2.8
- TypeScript
- Supabase Auth + PostgreSQL integration foundation
- Supabase SSR cookie sessions
- Server Components and Route Handlers
- Vercel-compatible deployment
- Custom lightweight CSS/SVG charts (no heavy chart/UI dependency)

## Application areas

### Public website

`/`, `/product`, `/features`, `/how-it-works`, `/pricing`, `/security`, `/documentation`, `/contact`, `/login`, `/register`, `/forgot-password`, `/reset-password`

### Client application

`/app/dashboard`, `/app/live-visitors`, `/app/visitor-history`, `/app/threat-center`, `/app/firewall`, `/app/websites`, `/app/analytics`, `/app/reports`, `/app/alerts`, `/app/api-integrations`, `/app/billing`, `/app/team`, `/app/settings`, `/app/support`

### Admin application

`/admin/dashboard`, `/admin/clients`, `/admin/websites`, `/admin/security-events`, `/admin/threat-events`, `/admin/users`, `/admin/plans`, `/admin/subscriptions`, `/admin/system-logs`, `/admin/support-tickets`, `/admin/system-settings`

## Architecture

```text
Public / Auth UI
       |
       v
Server-side session + RBAC
       |
       +----------------------+----------------------+
       |                      |                      |
       v                      v                      v
Client routes             API routes             Admin routes
       |                      |                      |
       +----------------------+----------------------+
                              |
                              v
                    Provider / Service boundary
                              |
       +----------------------+----------------------+
       |                      |                      |
       v                      v                      v
Demo telemetry       Supabase/Postgres       Security providers
(default V1)         (integration-ready)      (integration-ready)
```

## Security engine

The provider-neutral security engine lives in `lib/security-engine/index.ts`.

```text
Incoming Request
      ↓
Request Collector
      ↓
Normalizer
      ↓
Threat Detection Engine
      ↓
Risk Scoring
      ↓
Security Rules
      ↓
Decision Engine
      ↓
ALLOW / BLOCK / CHALLENGE / RATE_LIMIT
      ↓
Event Processor
      ↓
Dashboard / Alerts / Analytics
```

Interfaces are provided for IP reputation, bot detection, request analysis, rate limiting, custom rules and event processing. `DemoSignalProvider` is intentionally non-enforcing.

## Authentication and RBAC

Production auth is designed for Supabase Auth using cookie-based SSR sessions. Protected pages validate server-side claims; authorization roles are read from trusted `app_metadata`, not user-editable profile metadata.

Roles:

- `OWNER`
- `ADMIN`
- `SECURITY_ANALYST`
- `MEMBER`
- `VIEWER`

`/admin/*` requires `OWNER` or `ADMIN` in the current V1 route guard. More granular admin permissions can be added without changing the overall tenant model.

When Supabase is not configured and `WEB_SHIELD_DEMO_MODE=true`, a demo-only signed cookie enables UI exploration. This session must not be treated as production authentication.

## Database

The initial schema is in:

`supabase/migrations/0001_webshield_v1.sql`

It includes:

- organizations
- profiles
- team_members
- websites
- visitors
- visitor_sessions
- threat_events
- security_events
- firewall_rules
- ip_rules
- country_rules
- alerts
- notifications
- api_keys
- webhooks
- plans
- subscriptions
- invoices
- audit_logs
- support_tickets

All public application tables have RLS enabled. Organization access is tenant-scoped through `team_members`. Secret hashes for API keys/webhooks are separated into the non-exposed `private` schema.

Do **not** apply this migration blindly to an existing database. Review it against the dedicated production project first, run Supabase security/performance advisors, then apply through the normal migration workflow.

## Demo mode

Set:

```env
WEB_SHIELD_DEMO_MODE=true
```

Demo mode supplies simulated visitors, threats, metrics, analytics, alerts and firewall configuration from `lib/demo.ts`. Every main application page displays **DEMO MODE**. Demo API responses also include `meta.demo=true`.

When demo mode is disabled without a production provider, protected data API routes return `501 PROVIDER_NOT_CONNECTED` instead of inventing live data.

## API boundary

Current normalized endpoints are represented beneath `/api/*`:

- `/api/dashboard`
- `/api/websites`
- `/api/visitors`
- `/api/threats`
- `/api/firewall`
- `/api/analytics`
- `/api/reports`
- `/api/alerts`
- `/api/api-keys`
- `/api/webhooks`
- `/api/billing`
- `/api/admin`
- `/api/support`

Authenticated `GET` requests return demo provider data while demo mode is enabled. Write operations intentionally return `501 INTEGRATION_READY` until a real database/provider command layer is configured, preventing fake state mutation.

## Local development

1. Copy the example environment file:

```bash
cp .env.example .env.local
```

2. Install exact dependencies:

```bash
npm install
```

3. Run checks:

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

4. Start development:

```bash
npm run dev
```

Open `http://localhost:3000`.

### Demo sign-in

When production Supabase variables are absent and demo mode is enabled, the login UI accepts a valid-looking email plus an 8+ character password for demo exploration. Emails beginning with `admin@` can preview the demo admin shell. These are **not** real production accounts or credentials.

## Environment variables

See `.env.example`.

| Variable | Scope | Purpose |
|---|---|---|
| `NEXT_PUBLIC_APP_URL` | public | canonical application URL |
| `WEB_SHIELD_DEMO_MODE` | server | enable/disable demo provider |
| `NEXT_PUBLIC_SUPABASE_URL` | public | Supabase project URL |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | public | Supabase publishable key |
| `AUTH_SECRET` | server | server session signing / internal auth secret |
| `API_SECRET` | server | reserved for trusted internal API authentication |
| `WEBHOOK_SECRET` | server | reserved for webhook signing |

Never expose a Supabase secret/service-role key with a `NEXT_PUBLIC_` prefix. Never commit production credentials.

## Security controls included in V1

- Server-side protected client/admin layouts
- Role-based authorization guard
- Supabase `getClaims()` production validation path
- Cookie-based SSR auth integration
- RLS-ready tenant schema
- Secret material separated from public schema
- Secure response headers
- API content-type/body validation
- Consistent API response envelope
- Audit log entity model
- Explicit demo/production provider boundary
- Masked API key UI
- No real secret committed to the repository
- `robots.txt` blocks application/admin/API crawling

## Integration-ready, not falsely implemented

The following require real infrastructure before they can be described as production functionality:

- DDoS mitigation
- Edge WAF enforcement
- IP reputation provider
- Bot challenge provider
- distributed rate limiting
- real-time collector / streaming telemetry
- email notification delivery
- webhook delivery/signing worker
- PDF report generation
- payment gateway / invoices
- production API key issuance/revocation command layer

## Vercel deployment

Recommended project name: `webshield`

1. Create a **new** Vercel project linked only to `savrdhtechnology-cloud/WebShiled`.
2. Use the detected Next.js framework defaults.
3. Configure environment variables in Vercel, never in source control.
4. For the initial demo deployment set `WEB_SHIELD_DEMO_MODE=true`.
5. Set `NEXT_PUBLIC_APP_URL` to the final production domain after the first deployment.
6. When Supabase is ready, add its project URL and publishable key, configure allowed auth redirect URLs, apply/review the migration, then disable demo mode only after production telemetry providers are connected.

## Production checklist

- [ ] Dedicated Supabase project selected
- [ ] Migration reviewed before application
- [ ] Supabase security advisor clean
- [ ] Supabase performance advisor reviewed
- [ ] Auth email and recovery redirect URLs configured
- [ ] `AUTH_SECRET` generated securely
- [ ] Production security provider connected
- [ ] Provider enforcement tested before using `PROTECTED` status
- [ ] Real-time collector authenticated and rate-limited
- [ ] Audit events emitted for sensitive writes
- [ ] API keys stored hashed; raw keys displayed once only
- [ ] Webhook secrets stored server-side only
- [ ] Payment provider configured before enabling paid checkout
- [ ] PDF provider configured before enabling PDF download
- [ ] Lint, typecheck, tests and production build passing
- [ ] Mobile/tablet/desktop smoke tests complete
- [ ] Runtime logs reviewed after deployment

## Repository safety

This repository started empty. WebShield V1 is the initial application foundation; no prior application code or database schema was deleted or overwritten.
