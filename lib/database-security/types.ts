export type DatabaseSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type DatabaseFixType = "MANUAL" | "ENABLE_RLS" | "REVOKE_ANON_WRITE" | "REVOKE_PUBLIC_EXECUTE";

export type DatabaseFinding = {
  key: string;
  category: string;
  severity: DatabaseSeverity;
  title: string;
  description: string;
  impact: string;
  evidence: Record<string, unknown>;
  recommendedFix: string;
  fixType: DatabaseFixType;
};

export type DatabaseAuditSummary = {
  securityScore: number;
  overallRisk: DatabaseSeverity;
  findingCounts: Record<DatabaseSeverity, number>;
  tables: number;
  rlsEnabled: number;
  rlsCoverage: number;
  policies: number;
  anonymousWriteGrants: number;
  publicSecurityDefinerFunctions: number;
  publicStorageBuckets: number;
};

export type DatabaseAuditResult = {
  findings: DatabaseFinding[];
  summary: DatabaseAuditSummary;
  scannedAt: string;
};
