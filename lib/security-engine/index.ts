import type { FirewallAction, Severity } from "@/lib/types";

export interface NormalizedRequest {
  requestId: string;
  websiteId: string;
  ip: string;
  method: string;
  path: string;
  headers: Record<string,string>;
  userAgent?: string;
  country?: string;
  receivedAt: string;
}

export interface SecuritySignal {
  source: "ip_reputation" | "bot_detection" | "request_analysis" | "rate_limit" | "custom_rule";
  code: string;
  score: number;
  severity: Severity;
  explanation: string;
}

export interface SecurityDecision {
  requestId: string;
  riskScore: number;
  action: FirewallAction;
  signals: SecuritySignal[];
  provider: string;
  enforcementConnected: boolean;
}

export interface IpReputationProvider { evaluate(request: NormalizedRequest): Promise<SecuritySignal[]>; }
export interface BotDetectionProvider { evaluate(request: NormalizedRequest): Promise<SecuritySignal[]>; }
export interface RequestAnalysisProvider { evaluate(request: NormalizedRequest): Promise<SecuritySignal[]>; }
export interface RateLimitProvider { evaluate(request: NormalizedRequest): Promise<SecuritySignal[]>; }
export interface SecurityRuleProvider { evaluate(request: NormalizedRequest, score: number): Promise<SecuritySignal[]>; }
export interface EventProcessor { persist(request: NormalizedRequest, decision: SecurityDecision): Promise<void>; }

export class RiskScorer {
  score(signals: SecuritySignal[]) {
    const raw = signals.reduce((sum, signal) => sum + Math.max(0, signal.score), 0);
    return Math.min(100, Math.round(raw));
  }
}

export class DecisionEngine {
  decide(score: number): FirewallAction {
    if (score >= 90) return "BLOCK";
    if (score >= 70) return "CHALLENGE";
    if (score >= 50) return "RATE_LIMIT";
    return "ALLOW";
  }
}

export class WebShieldSecurityEngine {
  constructor(
    private providers: Array<IpReputationProvider | BotDetectionProvider | RequestAnalysisProvider | RateLimitProvider>,
    private rules: SecurityRuleProvider,
    private events: EventProcessor,
    private scorer = new RiskScorer(),
    private decision = new DecisionEngine(),
    private providerName = "unconfigured",
    private enforcementConnected = false
  ) {}

  async evaluate(request: NormalizedRequest): Promise<SecurityDecision> {
    const baseSignals = (await Promise.all(this.providers.map(provider => provider.evaluate(request)))).flat();
    const initialScore = this.scorer.score(baseSignals);
    const ruleSignals = await this.rules.evaluate(request, initialScore);
    const signals = [...baseSignals, ...ruleSignals];
    const riskScore = this.scorer.score(signals);
    const result: SecurityDecision = {
      requestId: request.requestId,
      riskScore,
      action: this.decision.decide(riskScore),
      signals,
      provider: this.providerName,
      enforcementConnected: this.enforcementConnected
    };
    await this.events.persist(request, result);
    return result;
  }
}

/**
 * Development-only provider. It demonstrates replaceable service boundaries and never claims enforcement.
 * Real IP reputation, edge WAF, bot management and rate limiting providers plug into the same interfaces.
 */
export class DemoSignalProvider implements RequestAnalysisProvider {
  async evaluate(request: NormalizedRequest): Promise<SecuritySignal[]> {
    const signals: SecuritySignal[] = [];
    if (request.path.includes("/wp-login")) signals.push({ source: "request_analysis", code: "DEMO_LOGIN_PROBE", score: 34, severity: "MEDIUM", explanation: "Demo signal: commonly probed authentication path." });
    if (request.method === "POST" && request.path.includes("/api/auth")) signals.push({ source: "request_analysis", code: "DEMO_AUTH_BURST", score: 24, severity: "MEDIUM", explanation: "Demo signal: authentication endpoint activity." });
    return signals;
  }
}
