export const consolePages = [
  "dashboard", "websites", "live-traffic", "threat-center", "database-security",
  "fix-center", "firewall", "analytics", "reports", "alerts", "appearance", "settings", "support"
] as const;
export function consolePage(slug: string) {
  return slug === "live-visitors" || slug === "visitor-history" ? "live-traffic" : slug;
}
export function isConsolePage(slug: string) {
  return (consolePages as readonly string[]).includes(consolePage(slug));
}
