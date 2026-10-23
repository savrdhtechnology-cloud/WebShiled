import Link from "next/link";
import { Icon } from "@/components/icons";
import { LandingDemoForm } from "@/components/landing-demo-form";
import { createClient } from "@/lib/supabase/server";
import "./landing.css";

export const dynamic = "force-dynamic";

const SITE = "https://savrdhtechnologies.com";
const CATALOG_API = "https://ldffgetuzoeupuhoaubn.supabase.co/functions/v1/product-catalog";

type Product = { slug: string; name: string; tagline?: string; description?: string; website_path?: string };

// Used only if the live catalog cannot be reached.
const FALLBACK: Product[] = [
  { slug: "autoos", name: "Savrdh AutoOS", tagline: "Run your dealership and workshop in one system", website_path: "/savrdhautoos" },
  { slug: "jarvis", name: "Savrdh AI JARVIS", tagline: "Your AI assistant for business work", website_path: "/jarvis" },
  { slug: "fieldsure", name: "FieldSure", tagline: "Field verification you can trust", website_path: "/products/fieldsure" },
  { slug: "engagex", name: "EngageX", tagline: "Customer communication that converts", website_path: "/products/engagex" },
  { slug: "intelsight", name: "SAVRDH IntelSight", tagline: "Business intelligence at a glance", website_path: "/products/intelsight" },
  { slug: "fintech-os", name: "SAVRDH FinTech OS", tagline: "Finance operations, organised", website_path: "/fintech-os" }
];

async function loadProducts(): Promise<Product[]> {
  try {
    const res = await fetch(CATALOG_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "public_list" }),
      next: { revalidate: 60 },
      signal: AbortSignal.timeout(6000)
    });
    if (!res.ok) throw new Error("catalog");
    const data = await res.json();
    const list: Product[] = Array.isArray(data.products) ? data.products : [];
    return list.filter((p) => p.slug && p.slug !== "webshield" && p.name);
  } catch {
    return FALLBACK;
  }
}

function productHref(p: Product) {
  const path = String(p.website_path || "");
  if (path.startsWith("/") && !path.startsWith("//")) return SITE + path;
  try {
    const u = new URL(path);
    return u.protocol === "https:" ? u.href : SITE + "/products";
  } catch {
    return SITE + "/products";
  }
}

async function signedIn() {
  try {
    const supabase = await createClient();
    const { data } = await supabase.auth.getClaims();
    return Boolean(data?.claims?.sub);
  } catch {
    return false;
  }
}

const FEATURES = [
  ["globe", "Website & scan", "Add a website and scan it for SSL, security headers, DNS, malware and known vulnerabilities."],
  ["visitors", "Live traffic", "Watch visitors, countries and blocked requests as they happen, with no guesswork."],
  ["threat", "Threat centre", "Suspicious activity is grouped by risk, so you see what needs attention first."],
  ["database", "Database security", "Check how your connected database is protected and fix weak settings."],
  ["bell", "Instant alerts", "Get told the moment an issue appears and see which site has which problem."],
  ["report", "Fix steps & reports", "Every issue comes with clear fix steps. Share reports with your team or clients."]
] as const;

export default async function HomePage() {
  const [products, isIn] = await Promise.all([loadProducts(), signedIn()]);
  const loop = products.length ? [...products, ...products] : [];
  return (
    <main className="lp">
      <div className="lpBg" aria-hidden="true"><i /><i /><i /></div>
      <header className="lpNav">
        <Link href="/" className="lpBrand" aria-label="WebShield home"><span>W</span><b>WebShield</b><small>by Savrdh Technologies</small></Link>
        <nav aria-label="Main">
          <a href="#features">Features</a>
          <a href="#products">Other products</a>
          <a href="#demo">Free trial</a>
          {isIn ? <Link className="lpBtn ghost" href="/app/dashboard">Open dashboard</Link> : <><Link className="lpBtn ghost" href="/login">Login</Link><a className="lpBtn" href="#demo">Request free trial</a></>}
        </nav>
      </header>

      <section className="lpHero">
        <div className="lpHeroText">
          <span className="lpEyebrow"><i />WEBSITE PROTECTION & VISITOR SECURITY</span>
          <h1>Monitor. <em>Detect.</em> Protect.</h1>
          <p>WebShield scans any website for SSL, security headers, DNS, malware and vulnerabilities, alerts you the moment an issue appears, and shows on one dashboard which site has which problem.</p>
          <div className="lpActions">
            <a className="lpBtn big" href="#demo">Request free trial</a>
            {isIn ? <Link className="lpBtn ghost big" href="/app/dashboard">Open dashboard</Link> : <a className="lpBtn ghost big" href="#demo">Request free trial</a>}
          </div>
          <small className="lpNote">{isIn ? "You are signed in." : <>Already have an account? <Link href="/login">Login</Link></>}</small>
        </div>
        <div className="lpShield" aria-hidden="true">
          <div className="lpRing r1" /><div className="lpRing r2" /><div className="lpRing r3" /><div className="lpSweep" />
          <div className="lpCore"><Icon name="shield" size={64} /></div>
          <span className="lpChip c1"><b>84</b> security score</span>
          <span className="lpChip c2"><b>0</b> critical issues</span>
          <span className="lpChip c3"><b>24/7</b> monitoring</span>
          <span className="lpDot d1" /><span className="lpDot d2" /><span className="lpDot d3" /><span className="lpDot d4" />
        </div>
      </section>

      <section id="features" className="lpSection">
        <div className="lpHead"><span>WHAT YOU GET</span><h2>One dashboard for every website you run</h2></div>
        <div className="lpGrid">
          {FEATURES.map(([icon, title, text], i) => (
            <article key={title} className="lpCard" style={{ animationDelay: `${i * 80}ms` }}>
              <span className="lpIcon"><Icon name={icon} size={20} /></span>
              <h3>{title}</h3>
              <p>{text}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="lpSection lpSteps">
        <div className="lpHead"><span>HOW IT WORKS</span><h2>Protected in three steps</h2></div>
        <ol>
          <li><b>1</b><h3>Request your trial</h3><p>Tell us about your website. The Savrdh team reviews your request.</p></li>
          <li><b>2</b><h3>Get your activation link</h3><p>We email you a personal link that activates your trial workspace.</p></li>
          <li><b>3</b><h3>Add your website and scan</h3><p>Connect it with one line of code, then follow the fix steps.</p></li>
        </ol>
      </section>

      {loop.length > 0 && (
        <section id="products" className="lpSection lpProducts">
          <div className="lpHead"><span>MORE FROM SAVRDH TECHNOLOGIES</span><h2>Software built to run your business</h2></div>
          <div className="lpTrack" aria-label="Other Savrdh products">
            <div className="lpRail">
              {loop.map((p, i) => (
                <a key={p.slug + i} className="lpProd" href={productHref(p)} aria-hidden={i >= products.length ? true : undefined} tabIndex={i >= products.length ? -1 : undefined}>
                  <span className="lpProdIcon">{p.name.split(/\s+/).map((w) => w[0]).join("").slice(0, 2)}</span>
                  <h3>{p.name}</h3>
                  <p>{p.tagline || p.description || ""}</p>
                  <em>View details →</em>
                </a>
              ))}
            </div>
          </div>
          <p className="lpMore"><a href={SITE + "/products"}>See all products →</a></p>
        </section>
      )}

      <section id="demo" className="lpSection lpDemo">
        <div className="lpDemoCopy">
          <span>FREE TRIAL</span>
          <h2>Try WebShield on your own website</h2>
          <ul>
            <li><Icon name="check" size={16} />A guided walkthrough from the Savrdh product team</li>
            <li><Icon name="check" size={16} />Scan a real website and see the fix steps</li>
            <li><Icon name="check" size={16} />Your trial is activated by our team and sent to you by email</li>
          </ul>
        </div>
        <LandingDemoForm />
      </section>

      <footer className="lpFoot">
        <span>© Savrdh Technologies. WebShield, Monitor. Detect. Protect.</span>
        <span><a href={SITE}>savrdhtechnologies.com</a> · <Link href="/login">Login</Link></span>
      </footer>
    </main>
  );
}
