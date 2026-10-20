import { runReadOnlyQuery } from "@/lib/database-security/supabase-management";
import type { DatabaseAuditResult, DatabaseFinding, DatabaseFixType, DatabaseSeverity } from "@/lib/database-security/types";

type Row = Record<string, unknown>;

const TABLES_SQL = `
select
  n.nspname as schema_name,
  c.relname as table_name,
  c.relrowsecurity as rls_enabled,
  c.relforcerowsecurity as rls_forced
from pg_catalog.pg_class c
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r','p')
  and n.nspname = 'public'
order by c.relname;
`;

const POLICIES_SQL = `
select schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
from pg_catalog.pg_policies
where schemaname = 'public'
order by tablename, policyname;
`;

const GRANTS_SQL = `
select table_schema, table_name, grantee, privilege_type
from information_schema.table_privileges
where table_schema = 'public'
  and grantee in ('anon','authenticated','PUBLIC')
order by table_name, grantee, privilege_type;
`;

const FUNCTIONS_SQL = `
select
  n.nspname as schema_name,
  p.proname as function_name,
  pg_catalog.pg_get_function_identity_arguments(p.oid) as identity_arguments,
  p.prosecdef as security_definer,
  p.proconfig as function_config,
  pg_catalog.has_function_privilege('public', p.oid, 'EXECUTE') as public_execute
from pg_catalog.pg_proc p
join pg_catalog.pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public'
order by p.proname;
`;

const BUCKETS_SQL = `
select id, name, public
from storage.buckets
where public = true
order by name;
`;

function bool(value: unknown) {
  return value === true || value === "true" || value === "t";
}

function text(value: unknown) {
  return value == null ? "" : String(value);
}

function roles(value: unknown) {
  if (Array.isArray(value)) return value.map(String);
  const raw = text(value).replace(/[{}]/g, "");
  return raw ? raw.split(",").map(x => x.trim()) : [];
}

function severityWeight(value: DatabaseSeverity) {
  return value === "CRITICAL" ? 30 : value === "HIGH" ? 16 : value === "MEDIUM" ? 8 : value === "LOW" ? 3 : 0;
}

function finding(input: {
  key: string;
  category: string;
  severity: DatabaseSeverity;
  title: string;
  description: string;
  impact: string;
  evidence?: Record<string, unknown>;
  recommendedFix: string;
  fixType?: DatabaseFixType;
}): DatabaseFinding {
  return { evidence: {}, fixType: "MANUAL", ...input };
}

async function safeQuery(projectRef: string, token: string, sql: string) {
  try { return await runReadOnlyQuery(projectRef, token, sql); }
  catch { return [] as Row[]; }
}

export async function runSupabaseDatabaseAudit(projectRef: string, token: string): Promise<DatabaseAuditResult> {
  const [tables, policies, grants, functions, buckets] = await Promise.all([
    safeQuery(projectRef, token, TABLES_SQL),
    safeQuery(projectRef, token, POLICIES_SQL),
    safeQuery(projectRef, token, GRANTS_SQL),
    safeQuery(projectRef, token, FUNCTIONS_SQL),
    safeQuery(projectRef, token, BUCKETS_SQL)
  ]);

  const findings: DatabaseFinding[] = [];
  const policyByTable = new Map<string, Row[]>();
  for (const policy of policies) {
    const name = text(policy.tablename);
    policyByTable.set(name, [...(policyByTable.get(name) || []), policy]);
  }

  const grantsByTable = new Map<string, Row[]>();
  for (const grant of grants) {
    const name = text(grant.table_name);
    grantsByTable.set(name, [...(grantsByTable.get(name) || []), grant]);
  }

  for (const table of tables) {
    const schema = text(table.schema_name) || "public";
    const name = text(table.table_name);
    const tableGrants = grantsByTable.get(name) || [];
    const anonWrite = tableGrants.some(g => text(g.grantee) === "anon" && ["INSERT","UPDATE","DELETE","TRUNCATE","TRIGGER","REFERENCES"].includes(text(g.privilege_type).toUpperCase()));

    if (!bool(table.rls_enabled)) {
      findings.push(finding({
        key: `rls-disabled:${schema}.${name}`,
        category: "RLS",
        severity: anonWrite ? "HIGH" : "MEDIUM",
        title: `RLS disabled on ${schema}.${name}`,
        description: "Row Level Security is not enabled on this table.",
        impact: anonWrite
          ? "The table also has anonymous write privileges, which can create a direct data-integrity risk."
          : "If this table is exposed through the Data API, access can rely only on database grants instead of row-level policies.",
        evidence: { schema, table: name, anonymousWrite: anonWrite },
        recommendedFix: "Review application access requirements, create the required policies, then enable RLS.",
        fixType: "ENABLE_RLS"
      }));
    }

    const tablePolicies = policyByTable.get(name) || [];
    for (const policy of tablePolicies) {
      const policyRoles = roles(policy.roles);
      const condition = text(policy.qual).replace(/[()\s]/g, "").toLowerCase();
      const check = text(policy.with_check).replace(/[()\s]/g, "").toLowerCase();
      const command = text(policy.cmd).toUpperCase();
      if (policyRoles.includes("anon") && (condition === "true" || check === "true")) {
        findings.push(finding({
          key: `broad-policy:${schema}.${name}:${text(policy.policyname)}`,
          category: "RLS Policy",
          severity: ["ALL","INSERT","UPDATE","DELETE"].includes(command) ? "HIGH" : "MEDIUM",
          title: `Broad anonymous policy on ${name}`,
          description: `Policy ${text(policy.policyname)} allows an anonymous role with an unconditional expression.`,
          impact: "Anonymous clients may receive broader row access than intended.",
          evidence: { schema, table: name, policy: text(policy.policyname), command, roles: policyRoles, qual: policy.qual, withCheck: policy.with_check },
          recommendedFix: "Replace unconditional anonymous access with the narrowest policy required by the application."
        }));
      }
    }
  }

  const anonWrites = grants.filter(g =>
    text(g.grantee) === "anon" &&
    ["INSERT","UPDATE","DELETE","TRUNCATE","TRIGGER","REFERENCES"].includes(text(g.privilege_type).toUpperCase())
  );
  const groupedWrites = new Map<string, string[]>();
  for (const grant of anonWrites) {
    const key = `${text(grant.table_schema)}.${text(grant.table_name)}`;
    groupedWrites.set(key, [...(groupedWrites.get(key) || []), text(grant.privilege_type).toUpperCase()]);
  }
  for (const [resource, privileges] of groupedWrites) {
    const [schema, table] = resource.split(".");
    findings.push(finding({
      key: `anon-write:${resource}`,
      category: "Privileges",
      severity: "HIGH",
      title: `Anonymous write privileges on ${resource}`,
      description: `The anon database role has ${[...new Set(privileges)].join(", ")} privilege(s).`,
      impact: "Unauthenticated requests may be able to change data when combined with exposed API access or permissive RLS.",
      evidence: { schema, table, privileges: [...new Set(privileges)] },
      recommendedFix: "Confirm that anonymous writes are intentional. Revoke unnecessary write grants and use authenticated/RLS-controlled access.",
      fixType: "REVOKE_ANON_WRITE"
    }));
  }

  for (const fn of functions) {
    if (!bool(fn.security_definer) || !bool(fn.public_execute)) continue;
    const config = Array.isArray(fn.function_config) ? fn.function_config.map(String) : [];
    const hasSearchPath = config.some(x => x.toLowerCase().startsWith("search_path="));
    findings.push(finding({
      key: `public-security-definer:${text(fn.schema_name)}.${text(fn.function_name)}:${text(fn.identity_arguments)}`,
      category: "Database Functions",
      severity: hasSearchPath ? "MEDIUM" : "HIGH",
      title: `Public EXECUTE on SECURITY DEFINER function ${text(fn.function_name)}`,
      description: "A SECURITY DEFINER function is executable by PUBLIC.",
      impact: hasSearchPath
        ? "Any caller can invoke privileged function logic. The function should be intentionally exposed and tightly validated."
        : "Privileged function logic is publicly callable and its search_path is not pinned, increasing privilege-escalation risk if the function is unsafe.",
      evidence: {
        schema: text(fn.schema_name),
        function: text(fn.function_name),
        identityArguments: text(fn.identity_arguments),
        searchPathPinned: hasSearchPath
      },
      recommendedFix: "Review callers and function body. Revoke PUBLIC execution unless public invocation is explicitly required.",
      fixType: "REVOKE_PUBLIC_EXECUTE"
    }));
  }

  for (const bucket of buckets) {
    findings.push(finding({
      key: `public-bucket:${text(bucket.id || bucket.name)}`,
      category: "Storage",
      severity: "LOW",
      title: `Public storage bucket: ${text(bucket.name || bucket.id)}`,
      description: "This Supabase Storage bucket is configured as public.",
      impact: "Objects can be publicly retrievable by URL. This is safe only for content intentionally meant to be public.",
      evidence: { bucketId: bucket.id, name: bucket.name },
      recommendedFix: "Confirm the bucket contains public assets only. Use a private bucket and signed URLs for sensitive files."
    }));
  }

  const counts: Record<DatabaseSeverity, number> = { INFO:0, LOW:0, MEDIUM:0, HIGH:0, CRITICAL:0 };
  findings.forEach(f => counts[f.severity]++);
  const score = Math.max(0, Math.min(100, 100 - findings.reduce((sum, f) => sum + severityWeight(f.severity), 0)));
  const overallRisk: DatabaseSeverity = counts.CRITICAL ? "CRITICAL" : counts.HIGH ? "HIGH" : counts.MEDIUM ? "MEDIUM" : counts.LOW ? "LOW" : "INFO";
  const rlsEnabled = tables.filter(t => bool(t.rls_enabled)).length;

  return {
    findings,
    summary: {
      securityScore: score,
      overallRisk,
      findingCounts: counts,
      tables: tables.length,
      rlsEnabled,
      rlsCoverage: tables.length ? Math.round((rlsEnabled / tables.length) * 100) : 100,
      policies: policies.length,
      anonymousWriteGrants: groupedWrites.size,
      publicSecurityDefinerFunctions: functions.filter(f => bool(f.security_definer) && bool(f.public_execute)).length,
      publicStorageBuckets: buckets.length
    },
    scannedAt: new Date().toISOString()
  };
}

function quoteIdent(value: string) {
  if (!value || value.includes("\u0000")) throw new Error("Invalid database identifier.");
  return '"' + value.replace(/"/g, '""') + '"';
}

export function remediationSql(finding: { fix_type?: string; fixType?: string; evidence?: Record<string, unknown> }) {
  const type = String(finding.fix_type || finding.fixType || "MANUAL");
  const evidence = finding.evidence || {};
  const schema = String(evidence.schema || "public");

  if (type === "ENABLE_RLS") {
    const table = String(evidence.table || "");
    if (!table) throw new Error("Finding does not include a table.");
    return `alter table ${quoteIdent(schema)}.${quoteIdent(table)} enable row level security;`;
  }

  if (type === "REVOKE_ANON_WRITE") {
    const table = String(evidence.table || "");
    if (!table) throw new Error("Finding does not include a table.");
    return `revoke insert, update, delete, truncate, references, trigger on table ${quoteIdent(schema)}.${quoteIdent(table)} from anon;`;
  }

  if (type === "REVOKE_PUBLIC_EXECUTE") {
    const fn = String(evidence.function || "");
    const args = String(evidence.identityArguments || "");
    if (!fn) throw new Error("Finding does not include a function.");
    return `revoke execute on function ${quoteIdent(schema)}.${quoteIdent(fn)}(${args}) from public;`;
  }

  throw new Error("This finding requires a manual fix.");
}
