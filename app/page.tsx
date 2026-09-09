import Link from "next/link";
import { Icon } from "@/components/icons";
import { Logo } from "@/components/logo";

const features = [
  ["Real-Time Monitoring", "See visitor activity, request context and risk signals from a single operations view.", "visitors"],
  ["Threat Detection", "Normalize security events into clear categories, severity and risk scores.", "threat"],
  ["Smart Protection", "Build modular IP, country, bot, rate-limit and custom security rules.", "firewall"],
  ["Security Analytics", "Understand traffic, threat trends, geographies, devices and attack categories.", "chart"],
  ["Multi-Site Control", "Manage verification, integration status and security posture across websites.", "globe"],
  ["Alerts & Integrations", "Route high-priority events to dashboard, email and webhook integrations.", "bell"]
];

export default function HomePage() {
  return (
    <main className="marketing">
      <header className="publicNav container">
        <Logo />
        <nav aria-label="Primary navigation">
          <a href="#features">Features</a><a href="#how">How it works</a><a href="#pricing">Pricing</a><a href="#security">Security</a><a href="#docs">Docs</a>
        </nav>
        <div className="navActions"><Link className="linkBtn" href="/login">Login</Link><Link className="btn small" href="/register">Get Started</Link></div>
      </header>

      <section className="hero container">
        <div className="eyebrow"><span className="pulseDot"/> Website Security Operations Platform</div>
        <h1>Monitor. Detect. <span>Protect.</span></h1>
        <p>Advanced Website Protection & Visitor Security Platform built to help businesses understand traffic, investigate suspicious activity and manage website security from one command center.</p>
        <div className="heroActions"><Link className="btn" href="/register">Get Started <Icon name="chevron"/></Link><Link className="ghostBtn" href="/login?demo=1">Explore WebShield</Link></div>
        <div className="trustLine"><Icon name="shield"/><span>Built by <strong>Savrdh Technologies</strong></span><i/> <span>V1 demo providers clearly separated from production telemetry</span></div>
      </section>

      <section className="heroDashboard container" aria-label="WebShield dashboard preview">
        <div className="previewTop"><div><span className="windowDot"/><span className="windowDot"/><span className="windowDot"/></div><span>webshield / security-overview</span><span className="demoBadge">DEMO MODE</span></div>
        <div className="previewGrid">
          <aside><div className="miniBrand">W</div>{["Overview","Live Visitors","Threat Center","Firewall","Websites","Analytics"].map((x,i)=><div key={x} className={i===0?"miniNav active":"miniNav"}><span/>{x}</div>)}</aside>
          <div className="previewBody"><div className="previewHeading"><div><small>Security Overview</small><h3>Protected & monitored</h3></div><span className="statusPill safe">● Operational</span></div><div className="previewStats">{[["Visitors","48.2K"],["Active","184"],["Threats blocked","1,284"],["Uptime","99.98%"]].map(([a,b])=><div className="previewStat" key={a}><small>{a}</small><strong>{b}</strong><em/></div>)}</div><div className="previewChart"><div className="chartTitle"><span>Traffic & threat activity</span><small>Last 24 hours</small></div><svg viewBox="0 0 800 180" preserveAspectRatio="none"><defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="currentColor" stopOpacity=".28"/><stop offset="1" stopColor="currentColor" stopOpacity="0"/></linearGradient></defs><path className="area" d="M0 150 C80 120 80 130 140 95 S250 130 300 80 S400 100 470 45 S610 100 690 55 S760 50 800 25 L800 180 L0 180Z"/><path className="line" d="M0 150 C80 120 80 130 140 95 S250 130 300 80 S400 100 470 45 S610 100 690 55 S760 50 800 25"/></svg></div></div>
        </div>
      </section>

      <section id="features" className="section container"><div className="sectionHead"><span>WHY WEBSHIELD</span><h2>One security workspace for your websites</h2><p>Designed for visibility first, with modular services that can grow from demo telemetry to production-grade providers without rebuilding the dashboard.</p></div><div className="featureGrid">{features.map(([title,desc,icon])=><article className="featureCard" key={title}><div className="featureIcon"><Icon name={icon}/></div><h3>{title}</h3><p>{desc}</p><a href="#how">Learn more <Icon name="chevron" size={14}/></a></article>)}</div></section>

      <section id="how" className="section container split"><div><div className="sectionHead left"><span>HOW IT WORKS</span><h2>From request signal to security decision</h2></div><div className="pipeline">{["Request Collector","Normalizer","Threat Detection","Risk Scoring","Rules Engine","Decision + Event Log"].map((x,i)=><div className="pipeStep" key={x}><b>{String(i+1).padStart(2,"0")}</b><span><strong>{x}</strong><small>{i===5?"ALLOW / BLOCK / CHALLENGE / RATE LIMIT":"Modular, replaceable service boundary"}</small></span></div>)}</div></div><div className="codeCard"><div className="codeTop"><span>Security decision</span><em>DEMO PROVIDER</em></div><pre>{`{
  "request_id": "req_8f21...",
  "risk_score": 91,
  "signals": [
    "brute_force_pattern",
    "suspicious_ip"
  ],
  "decision": "RATE_LIMIT",
  "event_logged": true
}`}</pre><div className="codeFoot"><Icon name="lock"/> Production enforcement requires a connected security provider.</div></div></section>

      <section id="security" className="section securityStrip"><div className="container"><div><span className="eyebrow"><Icon name="shield"/> SECURITY BY DESIGN</span><h2>Serious foundations, accurate claims.</h2><p>WebShield V1 separates simulated telemetry from real infrastructure. The architecture includes RBAC, server-side validation boundaries, RLS-ready database models, audit logs, secure headers and secret management.</p></div><div className="securityChecks">{["RBAC foundation","Audit logging model","RLS-ready schema","Secure headers","No frontend secrets","Demo data labels"].map(x=><span key={x}><Icon name="check"/>{x}</span>)}</div></div></section>

      <section id="pricing" className="section container"><div className="sectionHead"><span>PRICING</span><h2>Start small. Scale with protection needs.</h2><p>Payment processing is integration-ready and intentionally not simulated as a real transaction system.</p></div><div className="pricingGrid">{[
        ["FREE","₹0","1 website","10K monthly visitors","7-day retention"],
        ["STARTER","Coming soon","3 websites","100K monthly visitors","30-day retention"],
        ["BUSINESS","Coming soon","10 websites","Advanced reports","API + team access"],
        ["ENTERPRISE","Contact us","Custom websites","Custom retention","Priority integration"]
      ].map((p,i)=><article key={p[0]} className={i===2?"priceCard featured":"priceCard"}>{i===2&&<small className="popular">POPULAR</small>}<h3>{p[0]}</h3><strong>{p[1]}</strong><ul>{p.slice(2).map(x=><li key={x}><Icon name="check" size={15}/>{x}</li>)}</ul><Link className={i===2?"btn full":"ghostBtn full"} href="/register">Choose {p[0]}</Link></article>)}</div></section>

      <section id="docs" className="section faq container"><div className="sectionHead"><span>FAQ</span><h2>Built transparently for V1</h2></div><div className="faqGrid">{[
        ["Is WebShield already a full WAF or DDoS mitigation network?","No. V1 provides the SaaS application foundation, event model, rule engine interfaces and demo providers. Real enforcement must be connected to actual edge/WAF infrastructure."],
        ["Can I manage multiple websites?","Yes. The V1 application includes website onboarding, verification states, integration status, API key architecture and per-site security views."],
        ["Is visitor data real in demo mode?","No. Every simulated visitor, threat and analytics dataset is visibly labeled DEMO MODE and kept separate from production provider interfaces."],
        ["Who owns WebShield?","WebShield is a Savrdh Technologies product. Founder: Shailendra Choudhary — Founder & Visionary, Technology Entrepreneur and Product Strategist."]
      ].map(([q,a])=><article key={q}><h3>{q}</h3><p>{a}</p></article>)}</div></section>

      <section className="cta"><div className="container"><div><span>WEBSHIELD V1</span><h2>See your website security picture clearly.</h2></div><Link className="btn" href="/register">Create workspace <Icon name="chevron"/></Link></div></section>
      <footer className="footer container"><Logo/><p>WebShield © 2026 Savrdh Technologies. Monitor. Detect. Protect.</p><a href="https://www.savrdhtechnology.com">savrdhtechnology.com</a></footer>
    </main>
  );
}
