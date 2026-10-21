// Real request analysis used by the server ingest endpoint.
// Pure functions only (no I/O) so they can be unit tested.

import type { FirewallAction, Severity } from "@/lib/types";

export type RequestFacts = {
  ip: string;
  method: string;
  path: string;
  query?: string;
  userAgent?: string;
};

export type Signal = { code: string; score: number; severity: Severity; explanation: string };

export type IpRule = { id: string; ip_cidr: string; action: FirewallAction; website_id?: string | null; expires_at?: string | null };

const PATTERNS: Array<{ code: string; score: number; severity: Severity; test: RegExp; explanation: string }> = [
  { code: "SQL_INJECTION", score: 60, severity: "HIGH", explanation: "SQL injection pattern in the request.",
    test: /(\bunion\b[\s\S]{0,40}\bselect\b|\bselect\b[\s\S]{0,40}\bfrom\b[\s\S]{0,40}\b(information_schema|pg_catalog|mysql\.user)\b|'\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+|\bor\s+1\s*=\s*1\b|;\s*(drop|truncate|delete|update|insert)\s+\w+|\b(sleep|pg_sleep|benchmark)\s*\(\s*\d|\bwaitfor\s+delay\b|\bxp_cmdshell\b|--\s*$|\/\*\*\/)/i },
  { code: "XSS_ATTEMPT", score: 50, severity: "HIGH", explanation: "Cross-site scripting payload in the request.",
    test: /(<\s*script|<\s*\/\s*script|javascript\s*:|\bon(error|load|mouseover|focus|click)\s*=|<\s*svg[^>]*\bon\w+\s*=|<\s*iframe|document\.cookie|\balert\s*\(|\bprompt\s*\(|String\.fromCharCode)/i },
  { code: "PATH_TRAVERSAL", score: 60, severity: "HIGH", explanation: "Directory traversal attempt.",
    test: /(\.\.\/|\.\.\\|\/etc\/(passwd|shadow|hosts)|\bwin\.ini\b|\/proc\/self\/|boot\.ini)/i },
  { code: "COMMAND_INJECTION", score: 60, severity: "HIGH", explanation: "Operating-system command injection pattern.",
    test: /((;|\|\|?|&&|`|\$\()\s*(cat|ls|id|whoami|uname|wget|curl|bash|sh|nc|ncat|powershell|cmd)\b)/i },
  { code: "SENSITIVE_FILE_PROBE", score: 45, severity: "MEDIUM", explanation: "Probe for secrets or source files.",
    test: /\/(?:(?:\.git|\.svn|\.hg|\.aws|\.ssh)\/|(?:\.env(?:\.\w+)?|id_rsa|\.DS_Store|wp-config\.php(?:\.\w+)?|config\.(?:php|json|yml|yaml)\.(?:bak|old|save)|database\.yml|\.htpasswd|phpinfo\.php|server-status|backup\.(?:zip|sql|tar\.gz)|dump\.sql)(?:\/|$|\?))/i },
  { code: "SCANNER_PROBE", score: 30, severity: "MEDIUM", explanation: "Common vulnerability-scanner path.",
    test: /\/(wp-login\.php|xmlrpc\.php|wp-admin\/(install|setup-config)\.php|phpmyadmin|pma\/|adminer\.php|cgi-bin\/|actuator\/|vendor\/phpunit|solr\/admin|\.well-known\/(?!security\.txt|acme-challenge|apple-app-site-association|assetlinks\.json))/i },
  { code: "SSRF_PROBE", score: 40, severity: "MEDIUM", explanation: "Internal address or metadata endpoint in parameters.",
    test: /(169\.254\.169\.254|metadata\.google\.internal|(?:https?|gopher|file|dict):\/\/(?:127\.|localhost|0\.0\.0\.0|\[::1\]))/i }
];

const ATTACK_TOOLS = /(sqlmap|nikto|nmap|masscan|zgrab|nuclei|acunetix|netsparker|wpscan|dirbuster|gobuster|ffuf|feroxbuster|hydra|havij|w3af|openvas|jaeles|whatweb)/i;
const SCRIPT_CLIENTS = /^(curl|wget|python-requests|python-urllib|go-http-client|libwww-perl|java\/|okhttp|axios|node-fetch|httpclient)/i;
const LOGIN_PATH = /(login|signin|sign-in|auth|session|otp|password|wp-login\.php|token)/i;

function safeDecode(value: string) {
  let out = value;
  for (let i = 0; i < 2; i++) {
    try { const next = decodeURIComponent(out.replace(/\+/g, " ")); if (next === out) break; out = next; } catch { break; }
  }
  return out;
}

export function analyzeRequest(facts: RequestFacts): Signal[] {
  const target = safeDecode(`${facts.path || "/"}${facts.query || ""}`).slice(0, 4000);
  const signals: Signal[] = [];
  for (const pattern of PATTERNS) {
    if (pattern.test.test(target)) signals.push({ code: pattern.code, score: pattern.score, severity: pattern.severity, explanation: pattern.explanation });
  }
  const ua = String(facts.userAgent || "").trim();
  if (ATTACK_TOOLS.test(ua)) signals.push({ code: "ATTACK_TOOL", score: 60, severity: "HIGH", explanation: `Known attack tool user-agent (${ua.slice(0, 40)}).` });
  else if (!ua) signals.push({ code: "EMPTY_USER_AGENT", score: 10, severity: "LOW", explanation: "Request without a user-agent." });
  else if (SCRIPT_CLIENTS.test(ua)) signals.push({ code: "SCRIPT_CLIENT", score: 10, severity: "LOW", explanation: "Scripted HTTP client." });
  return signals;
}

export function isLoginAttempt(facts: RequestFacts) {
  return String(facts.method).toUpperCase() === "POST" && LOGIN_PATH.test(facts.path || "");
}

/** Rate signals from counters supplied by the caller. */
export function rateSignals(requestsLastMinute: number, loginPostsLastFiveMinutes: number): Signal[] {
  const signals: Signal[] = [];
  if (requestsLastMinute > 300) signals.push({ code: "RATE_FLOOD", score: 70, severity: "HIGH", explanation: `${requestsLastMinute} requests from this IP in the last minute.` });
  else if (requestsLastMinute > 120) signals.push({ code: "RATE_SPIKE", score: 40, severity: "MEDIUM", explanation: `${requestsLastMinute} requests from this IP in the last minute.` });
  if (loginPostsLastFiveMinutes > 20) signals.push({ code: "BRUTE_FORCE", score: 70, severity: "CRITICAL", explanation: `${loginPostsLastFiveMinutes} login attempts in 5 minutes.` });
  else if (loginPostsLastFiveMinutes > 8) signals.push({ code: "BRUTE_FORCE", score: 50, severity: "HIGH", explanation: `${loginPostsLastFiveMinutes} login attempts in 5 minutes.` });
  return signals;
}

export function decide(score: number): FirewallAction {
  if (score >= 90) return "BLOCK";
  if (score >= 70) return "CHALLENGE";
  if (score >= 50) return "RATE_LIMIT";
  return "ALLOW";
}

// ---------------------------------------------------------------------------
// IP / CIDR matching (IPv4 and IPv6)
// ---------------------------------------------------------------------------
function ipv4ToBigInt(ip: string): bigint | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = (value << 8n) + BigInt(n);
  }
  return value;
}

function ipv6ToBigInt(ip: string): bigint | null {
  let address = ip.toLowerCase();
  if (address.includes(".")) {
    const lastColon = address.lastIndexOf(":");
    const v4 = ipv4ToBigInt(address.slice(lastColon + 1));
    if (v4 === null) return null;
    address = address.slice(0, lastColon + 1) + ((v4 >> 16n) & 0xffffn).toString(16) + ":" + (v4 & 0xffffn).toString(16);
  }
  const halves = address.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  if (groups.length !== 8) return null;
  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    value = (value << 16n) + BigInt(parseInt(group, 16));
  }
  return value;
}

function parseIp(ip: string): { bits: 32 | 128; value: bigint } | null {
  const clean = ip.trim().replace(/^\[|\]$/g, "");
  const v4 = ipv4ToBigInt(clean);
  if (v4 !== null) return { bits: 32, value: v4 };
  const v6 = ipv6ToBigInt(clean);
  if (v6 === null) return null;
  // IPv4-mapped IPv6 (::ffff:a.b.c.d) compares as IPv4.
  if (v6 >> 32n === 0xffffn) return { bits: 32, value: v6 & 0xffffffffn };
  return { bits: 128, value: v6 };
}

export function isValidCidr(value: string) {
  const [ip, prefixRaw] = String(value || "").trim().split("/");
  const parsed = parseIp(ip || "");
  if (!parsed) return false;
  if (prefixRaw === undefined) return true;
  if (!/^\d{1,3}$/.test(prefixRaw)) return false;
  return Number(prefixRaw) <= parsed.bits;
}

export function ipInCidr(ip: string, cidr: string) {
  const [network, prefixRaw] = String(cidr || "").trim().split("/");
  const a = parseIp(ip), b = parseIp(network || "");
  if (!a || !b || a.bits !== b.bits) return false;
  const prefix = prefixRaw === undefined ? a.bits : Number(prefixRaw);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > a.bits) return false;
  const shift = BigInt(a.bits - prefix);
  return (a.value >> shift) === (b.value >> shift);
}

/** First matching active rule. ALLOW rules win over BLOCK when both match (explicit allowlist). */
export function matchIpRule(ip: string, rules: IpRule[], websiteId: string, now = Date.now()) {
  const active = rules.filter(r => (!r.website_id || r.website_id === websiteId) && (!r.expires_at || new Date(r.expires_at).getTime() > now) && ipInCidr(ip, r.ip_cidr));
  return active.find(r => r.action === "ALLOW") || active.find(r => r.action === "BLOCK") || active[0] || null;
}

export type Evaluation = { action: FirewallAction; riskScore: number; signals: Signal[]; matchedRule: IpRule | null };

export function evaluateRequest(facts: RequestFacts, context: { rules: IpRule[]; websiteId: string; requestsLastMinute: number; loginPostsLastFiveMinutes: number }): Evaluation {
  const rule = facts.ip ? matchIpRule(facts.ip, context.rules, context.websiteId) : null;
  if (rule?.action === "ALLOW") return { action: "ALLOW", riskScore: 0, signals: [], matchedRule: rule };
  const signals = [...analyzeRequest(facts), ...rateSignals(context.requestsLastMinute, context.loginPostsLastFiveMinutes)];
  if (rule) signals.push({ code: `IP_RULE_${rule.action}`, score: rule.action === "BLOCK" ? 100 : rule.action === "CHALLENGE" ? 70 : 50, severity: rule.action === "BLOCK" ? "HIGH" : "MEDIUM", explanation: `Matched firewall rule for ${rule.ip_cidr}.` });
  const riskScore = Math.min(100, signals.reduce((sum, s) => sum + s.score, 0));
  const rank: FirewallAction[] = ["ALLOW", "RATE_LIMIT", "CHALLENGE", "BLOCK"];
  const decided = decide(riskScore);
  const action = rule && rank.indexOf(rule.action) > rank.indexOf(decided) ? rule.action : decided;
  return { action, riskScore, signals, matchedRule: rule };
}

// ---------------------------------------------------------------------------
// Custom firewall rules (firewall_rules.conditions), evaluated after scoring.
// Supported fields: risk_score, path, method, country, ip, user_agent.
// Operators: greater_than, less_than, equals, not_equals, contains, starts_with.
// ---------------------------------------------------------------------------
export type PolicyRule = { id: string; name: string; priority: number; enabled: boolean; action: FirewallAction; website_id?: string | null; conditions: Array<{ field?: string; operator?: string; value?: unknown }> };

function fieldValue(field: string, facts: RequestFacts & { country?: string }, riskScore: number): string | number {
  switch (field) {
    case "risk_score": return riskScore;
    case "path": return facts.path || "";
    case "method": return String(facts.method || "").toUpperCase();
    case "country": return String(facts.country || "").toUpperCase();
    case "ip": return facts.ip || "";
    case "user_agent": return facts.userAgent || "";
    default: return "";
  }
}

export function ruleMatches(rule: PolicyRule, facts: RequestFacts & { country?: string }, riskScore: number) {
  if (!rule.enabled || !Array.isArray(rule.conditions) || !rule.conditions.length) return false;
  return rule.conditions.every(condition => {
    const field = String(condition.field || "");
    const actual = fieldValue(field, facts, riskScore);
    const expected = condition.value;
    switch (String(condition.operator || "")) {
      case "greater_than": return Number(actual) > Number(expected);
      case "less_than": return Number(actual) < Number(expected);
      case "equals": return String(actual).toLowerCase() === String(expected).toLowerCase();
      case "not_equals": return String(actual).toLowerCase() !== String(expected).toLowerCase();
      case "contains": return String(actual).toLowerCase().includes(String(expected).toLowerCase());
      case "starts_with": return String(actual).toLowerCase().startsWith(String(expected).toLowerCase());
      default: return false;
    }
  });
}

export function applyPolicyRules(evaluation: Evaluation, facts: RequestFacts & { country?: string }, rules: PolicyRule[], websiteId: string): Evaluation & { policyRule: PolicyRule | null } {
  if (evaluation.matchedRule?.action === "ALLOW") return { ...evaluation, policyRule: null };
  const rule = [...rules]
    .filter(r => !r.website_id || r.website_id === websiteId)
    .sort((a, b) => a.priority - b.priority)
    .find(r => ruleMatches(r, facts, evaluation.riskScore));
  if (!rule) return { ...evaluation, policyRule: null };
  if (rule.action === "ALLOW") return { ...evaluation, action: "ALLOW", policyRule: rule };
  const rank: FirewallAction[] = ["ALLOW", "RATE_LIMIT", "CHALLENGE", "BLOCK"];
  const action = rank.indexOf(rule.action) > rank.indexOf(evaluation.action) ? rule.action : evaluation.action;
  return { ...evaluation, action, policyRule: rule, signals: [...evaluation.signals, { code: "POLICY_RULE", score: 0, severity: "MEDIUM", explanation: `Matched firewall rule "${rule.name}".` }] };
}
