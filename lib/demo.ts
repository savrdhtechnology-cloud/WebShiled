import type { ThreatEvent, Visitor } from "@/lib/types";

export const demoMetrics = [
  ["Total Visitors", "48,291", "+12.8%"],
  ["Active Visitors", "184", "Live"],
  ["Blocked Threats", "1,284", "+8.2%"],
  ["Requests Blocked", "3,942", "+17.1%"],
  ["Threat Score", "28 / 100", "Low"],
  ["Website Uptime", "99.98%", "30d"]
] as const;

export const demoVisitors: Visitor[] = [
  { id: "VIS-88421", ip: "103.21.55.18", country: "India", city: "New Delhi", device: "Desktop", browser: "Chrome", os: "Windows 11", referrer: "google.com", url: "/pricing", method: "GET", timestamp: "12:29:42", riskScore: 8, status: "SAFE" },
  { id: "VIS-88420", ip: "45.83.64.17", country: "Germany", city: "Frankfurt", device: "Server", browser: "Unknown", os: "Linux", referrer: "Direct", url: "/wp-login.php", method: "POST", timestamp: "12:29:38", riskScore: 91, status: "BLOCKED" },
  { id: "VIS-88419", ip: "198.51.100.44", country: "United States", city: "Austin", device: "Mobile", browser: "Safari", os: "iOS", referrer: "linkedin.com", url: "/features", method: "GET", timestamp: "12:29:31", riskScore: 14, status: "SAFE" },
  { id: "VIS-88418", ip: "203.0.113.88", country: "Singapore", city: "Singapore", device: "Bot", browser: "Headless", os: "Linux", referrer: "Direct", url: "/api/auth", method: "POST", timestamp: "12:29:25", riskScore: 73, status: "SUSPICIOUS" },
  { id: "VIS-88417", ip: "192.0.2.31", country: "Brazil", city: "Sao Paulo", device: "Desktop", browser: "Firefox", os: "Ubuntu", referrer: "Direct", url: "/search?q=%27", method: "GET", timestamp: "12:29:12", riskScore: 96, status: "THREAT" }
];

export const demoThreats: ThreatEvent[] = [
  { id: "THR-2048", type: "SQL Injection Attempt", severity: "CRITICAL", sourceIp: "192.0.2.31", targetUrl: "/search", timestamp: "12:29:12", riskScore: 96, status: "Mitigated", action: "BLOCK" },
  { id: "THR-2047", type: "Brute Force", severity: "HIGH", sourceIp: "45.83.64.17", targetUrl: "/wp-login.php", timestamp: "12:28:47", riskScore: 91, status: "Blocked", action: "RATE_LIMIT" },
  { id: "THR-2046", type: "Bot Traffic", severity: "MEDIUM", sourceIp: "203.0.113.88", targetUrl: "/api/auth", timestamp: "12:27:03", riskScore: 73, status: "Challenged", action: "CHALLENGE" },
  { id: "THR-2045", type: "Abnormal Traffic", severity: "LOW", sourceIp: "198.51.100.77", targetUrl: "/assets", timestamp: "12:25:14", riskScore: 38, status: "Observed", action: "ALLOW" }
];

export const trafficSeries = [42, 58, 47, 71, 66, 83, 72, 96, 88, 105, 91, 118, 110, 128];
export const threatSeries = [12, 18, 9, 22, 16, 28, 19, 36, 31, 41, 25, 38, 33, 47];

export const demoWebsites = [
  { domain: "savrdhtechnology.com", status: "PROTECTED", ssl: "Valid", integration: "Demo Provider", risk: "Low" },
  { domain: "portal.example.in", status: "PENDING", ssl: "Valid", integration: "Verification required", risk: "—" },
  { domain: "shop.example.com", status: "CONNECTED", ssl: "Valid", integration: "Collector ready", risk: "Medium" }
];

export const demoAlerts = [
  ["Critical Threat", "SQL injection signature detected on /search", "2 min ago", "CRITICAL"],
  ["Traffic Spike", "Requests increased 180% over 5-minute baseline", "18 min ago", "HIGH"],
  ["SSL Issue", "Certificate renewal window begins in 21 days", "1 hr ago", "MEDIUM"]
] as const;
