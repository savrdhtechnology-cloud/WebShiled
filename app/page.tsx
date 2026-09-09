import Link from "next/link";
import { Icon } from "@/components/icons";
import { Logo } from "@/components/logo";
import { PublicScanner } from "@/components/public-scanner";

const features = [
  ["Real-Time Visitor Monitoring", "Track visitors, IP, country, device, browser, operating system, pages and sessions after WebShield integration is connected.", "visitors"],
  ["Threat & Suspicious Activity Detection", "Normalize suspicious requests into threat categories, severity, risk scores and investigation timelines.", "threat"],
  ["Website Protection & Security", "Apply IP, country, rate-limit and custom policies through a connected edge/WAF or supported hosting integration.", "firewall"],
  ["Bot & Malicious Traffic Detection", "Detect automated and abnormal traffic patterns using connected request telemetry and provider signals.", "shield"],
  ["Detailed Visitor & Security Analytics", "Understand traffic, visitor behavior, geographies, devices, threats and security trends from one workspace.", "chart"],
  ["Attack & Threat Alerts", "Surface critical, high and medium risk events in the dashboard and route supported notifications after setup.", "bell"],
  ["Easy Website Integration", "Start with a free external scan, verify ownership, then connect the website traffic path to WebShield.", "globe"],
  ["Security Reports & Insights", "Generate posture findings, remediation guidance and connected-site security reporting for customers.", "chart"]
];

export default function HomePage() {
  return (
    <main className="marketing">
      <header className="publicNav container">
        <Logo />
        <nav aria-label="Primary navigation">
          <a href="#scan">Scan</a><a href="#features">Features</a><a href="#how">How it works</a><a href="#pricing">Pricing</a><a href="#security">Security</a>
        </nav>
        <div className="navActions"><Link className="linkBtn" href="/login">Login</Link><Link className="btn small" href="/register">Get Started</Link></div>
      </header>

      <section className="hero container">
        <div className="eyebrow"><span className="pulseDot"/> Website Security Monitoring & Protection Platform</div>
        <h1>Scan. Monitor. <span>Protect.</span></h1>
        <p>Enter a website to check its external security posture. Then connect WebShield to monitor real traffic, detect suspicious activity, receive alerts and enforce supported protection rules.</p>
        <div className="heroActions"><a className="btn" href="#scan">Scan Website Free <Icon name="chevron"/></a><Link className="ghostBtn" href="/login?demo=1">Explore Dashboard</Link></div>
        <div className="trustLine"><Icon name="shield"/><span>Built by <strong>Savrdh Technologies</strong></span><i/><span>Passive scan is real · Live protection requires website integration</span></div>
      </section>

      <PublicScanner />

      <section className="heroDashboard container" aria-label="WebShield dashboard preview">
        <div className="previewTop"><div><span className="windowDot"/><span className="windowDot"/><span className="windowDot"/></div><span>webshield / security-overview</span><span className="demoBadge">CONNECTED VIEW PREVIEW</span></div>
        <div className="previewGrid">
          <aside><div className="miniBrand">W</div>{["Overview","Live Visitors","Threat Center","Firewall","Websites","Analytics"].map((x,i)=><div key={x} className={i===0?"miniNav active":"miniNav"}><span/>{x}</div>)}</aside>
          <div className="previewBody"><div className="previewHeading"><div><small>Security Overview</small><h3>Monitor · Detect · Protect</h3></div><span className="statusPill safe">● Integration aware</span></div><div className="previewStats">{[["Visitors","48.2K"],["Active","184"],["Threat signals","1,284"],["Uptime","99.98%"]].map(([a,b])=><div className="previewStat" key={a}><small>{a}</small><strong>{b}</strong><em/></div>)}</div><div className="previewChart"><div className="chartTitle"><span>Traffic & threat activity</span><small>Connected-site preview</small></div><svg viewBox="0 0 800 180" preserveAspectRatio="none"><defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="currentColor" stopOpacity=".28"/><stop offset="1" stopColor="currentColor" stopOpacity="0"/></linearGradient></defs><path className="area" d="M0 150 C80 120 80 130 140 95 S250 130 300 80 S400 100 470 45 S610 100 690 55 S760 50 800 25 L800 180 L0 180Z"/><path className="line" d="M0 150 C80 120 80 130 140 95 S250 130 300 80 S400 100 470 45 S610 100 690 55 S760 50 800 25"/></svg></div></div>
        </div>
      </section>

      <section id="features" className="section container"><div className="sectionHead"><span>WHAT CUSTOMERS PAY FOR</span><h2>Eight security capabilities in one customer workspace</h2><p>The free scan shows external posture immediately. Connected protection unlocks continuous visitor telemetry, threat signals, alerts and provider-backed enforcement.</p></div><div className="featureGrid">{features.map(([title,desc,icon])=><article className="featureCard" key={title}><div className="featureIcon"><Icon name={icon}/></div><h3>{title}</h3><p>{desc}</p><a href="#how">How it works <Icon name="chevron" size={14}/></a></article>)}</div></section>

      <section id="how" className="section container split"><div><div className="sectionHead left"><span>CUSTOMER FLOW</span><h2>Free scan first. Protection after integration.</h2></div><div className="pipeline">{[
        ["Paste website URL","Real passive posture scan"],
        ["Review findings","Score, missing controls and remediation guidance"],
        ["Verify website","Confirm the customer controls the site"],
        ["Connect WebShield","Edge / WAF / reverse-proxy / supported hosting adapter"],
        ["Monitor & detect","Visitors, bots, suspicious requests, risk and analytics"],
        ["Enforce & alert","Provider-backed BLOCK / CHALLENGE / RATE LIMIT plus alerts"]
      ].map(([x,y],i)=><div className="pipeStep" key={x}><b>{String(i+1).padStart(2,"0")}</b><span><strong>{x}</strong><small>{y}</small></span></div>)}</div></div><div className="codeCard"><div className="codeTop"><span>Protection decision model</span><em>CONNECTED PROVIDER REQUIRED</em></div><pre>{`{
  "website": "customer.example",
  "risk_score": 91,
  "signals": [
    "automation_pattern",
    "suspicious_request_rate"
  ],
  "decision": "RATE_LIMIT",
  "provider_enforcement": "required"
}`}</pre><div className="codeFoot"><Icon name="lock"/> URL scan alone cannot block visitors; enforcement starts after the customer connects a supported traffic-path provider.</div></div></section>

      <section id="security" className="section securityStrip"><div className="container"><div><span className="eyebrow"><Icon name="shield"/> SECURITY BY DESIGN</span><h2>Useful security without fake protection claims.</h2><p>WebShield keeps external scan data separate from connected traffic telemetry. A site is never labelled automatically protected until a real edge/WAF/hosting enforcement integration is verified and active.</p></div><div className="securityChecks">{["Public-host SSRF safeguards","Ownership verification flow","RBAC foundation","Audit logging model","RLS-ready schema","No frontend secrets"].map(x=><span key={x}><Icon name="check"/>{x}</span>)}</div></div></section>

      <section id="pricing" className="section container"><div className="sectionHead"><span>SAAS MODEL</span><h2>Scan for free. Charge for continuous protection.</h2><p>The commercial product should bill for connected websites, traffic volume, retention, alerts, reporting and supported protection integrations—not for fake scan numbers.</p></div><div className="pricingGrid">{[
        ["SCAN","₹0","External posture scan","Prioritized findings","Remediation guidance"],
        ["STARTER","Coming soon","1 connected website","Monitoring + alerts","Basic protection rules"],
        ["BUSINESS","Coming soon","Multiple websites","Advanced analytics","Reports + team access"],
        ["ENTERPRISE","Contact us","Custom traffic volume","Provider integrations","Priority support"]
      ].map((p,i)=><article key={p[0]} className={i===2?"priceCard featured":"priceCard"}>{i===2&&<small className="popular">POPULAR</small>}<h3>{p[0]}</h3><strong>{p[1]}</strong><ul>{p.slice(2).map(x=><li key={x}><Icon name="check" size={15}/>{x}</li>)}</ul><Link className={i===2?"btn full":"ghostBtn full"} href={i===0?"/#scan":"/register"}>{i===0?"Scan Website":"Start Setup"}</Link></article>)}</div></section>

      <section className="cta"><div className="container"><div><span>WEBSHIELD</span><h2>Find the problem. Fix the posture. Connect protection.</h2></div><a className="btn" href="#scan">Scan Website <Icon name="chevron"/></a></div></section>
      <footer className="footer container"><Logo/><p>WebShield © 2026 Savrdh Technologies. Scan. Monitor. Protect.</p><a href="https://www.savrdhtechnology.com">savrdhtechnology.com</a></footer>
    </main>
  );
}
