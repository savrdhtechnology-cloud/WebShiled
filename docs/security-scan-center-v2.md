# WebShield Security Scan Center V2 — implementation contract

Status: design specification, NOT a completed scanner. Work on feature/security-scan-center-v2 only; do not merge or deploy without tested approval.

## User experience
- Scan Center: choose owned/verified website, run Quick Passive Scan, browse category-level findings with severity, timestamp, affected resource, observed evidence, impact, fix guidance, remediation ownership, and verification.
- Display scan coverage honestly: PASSED, FINDING, INCONCLUSIVE, NOT_RUN, REQUIRES_INTEGRATION. Never present untested targets as secure.
- Record scan runs and findings in Supabase by organization and website; show history and diffs. Existing localStorage scan is not sufficient for organization-level records.
- Fix Center: create remediation tasks; actions affecting infrastructure require preflight, authenticated provider integrations, granular permission, explicit confirmation, audit log, rollback guidance. Never advertise one-click fixes for findings without supported APIs.
- Verify Fix: targeted rescans with fresh evidence; a fix can only be marked verified when checked.

## Eight modules and evidence
1. SSL & HTTPS: current passive TLS/redirect checks, plus real leaf certificate expiry, chain and hostname verification with a dedicated safe TLS inspector.
2. Security Headers: CSP/HSTS/framing/nosniff/referrer/permissions/cookies; inspect values, not merely presence. Honor CSP frame-ancestors over deprecated X-Frame-Options.
3. Website Security: public posture, exposed dotfiles, configuration leaks, unsafe caching and CORS context; suppress false positives and avoid collecting secrets.
4. DNS Security: TXT SPF/DMARC, DKIM for selectors supplied by the owner/provider, relevant DNS hygiene; DNSSEC optional. DKIM cannot be reliably discovered generically.
5. Database Security: authenticated, read-only provider audits (Supabase/Postgres RLS, public exposure, grants, sensitive configuration); never run against arbitrary website URLs or store database passwords in browser.
6. Malware Detection: consented content/reputation checks using licensed feeds or configured integrations; flag suspected indicators, never promise universal detection.
7. Vulnerabilities: source/SBOM/dependency advisories on connected GitHub repo; non-destructive configuration checks only. Active dynamic scans are out of scope without separate authorization and execution environment.
8. Monitoring: uptime, SSL expiry and configuration drift via scheduled jobs; rate-limits, bounded timeouts, false-positive suppression and incident alerts.

## Safety and operations
- Require verified ownership and explicit authorized scope for deep/connected checks.
- Passive public scanning: restrict targets to HTTP/S on public resolvers; harden SSRF handling against DNS rebinding and restricted IP classes, redirects, IPv4-mapped IPv6, exotic hosts, and custom ports.
- Never perform destructive testing, credential attacks, traffic floods, automatic network exposure, or modify client sites without a recorded confirmation.
- Jobs should run in a proper worker/queue, not long-running Vercel requests. Per-target concurrency ceilings and cancellation required.
- Findings evidence should be redacted; avoid persisting Set-Cookie values, secrets, raw auth headers, or sensitive response bodies.
- Authz and org isolation enforced with RLS. Handle scan history retention and data deletion.
- Tests: scanner unit tests for true/false positives; mocked network integration tests; SSRF/redirect tests; CI build/typecheck/test; manual acceptance test on owner-provided staging site.
- Existing features must remain intact: Dashboard, collector telemetry, appearance, domain registration and reports.

## Milestones
M1: scan history schema, results UX, robust passive scan evidence and SSL certificate checks.
M2: DNS and connected read-only database/source-code checks.
M3: malware reputation, dependency CVE checks, monitoring and alert jobs.
M4: remediation workflow with gated provider actions, per-fix verification, audit logs.

No change in this document constitutes a production implementation.
