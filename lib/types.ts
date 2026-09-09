export type Role = "OWNER" | "ADMIN" | "SECURITY_ANALYST" | "MEMBER" | "VIEWER";
export type VisitorStatus = "SAFE" | "SUSPICIOUS" | "THREAT" | "BLOCKED";
export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type FirewallAction = "ALLOW" | "BLOCK" | "CHALLENGE" | "RATE_LIMIT";

export interface AppUser {
  id: string;
  email: string;
  name: string;
  role: Role;
  organizationId: string;
  demo: boolean;
}

export interface Visitor {
  id: string;
  ip: string;
  country: string;
  city: string;
  device: string;
  browser: string;
  os: string;
  referrer: string;
  url: string;
  method: string;
  timestamp: string;
  riskScore: number;
  status: VisitorStatus;
}

export interface ThreatEvent {
  id: string;
  type: string;
  severity: Severity;
  sourceIp: string;
  targetUrl: string;
  timestamp: string;
  riskScore: number;
  status: string;
  action: FirewallAction;
}
