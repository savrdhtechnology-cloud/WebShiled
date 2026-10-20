import Link from "next/link";
import {NotificationBell} from "./notification-bell";
import {WebsiteMonitoring} from "./website-monitoring";
import { logoutAction } from "@/app/actions";
import { Icon } from "@/components/icons";
import { AppearanceProvider } from "@/components/appearance-studio";
import type { AppUser } from "@/lib/types";

function navIcon(slug: string) {
  if (slug.includes("database") || slug.includes("fix-center")) return "lock";
  if (slug.includes("visitor") || slug.includes("client") || slug === "users" || slug === "team" || slug.includes("device") || slug.includes("browser") || slug.includes("session")) return "visitors";
  if (slug.includes("threat") || slug.includes("security") || slug.includes("suspicious") || slug.includes("brute") || slug.includes("xss") || slug.includes("sql") || slug.includes("ddos")) return "threat";
  if (slug.includes("firewall") || slug.includes("rule") || slug.includes("block") || slug.includes("rate") || slug.includes("filter") || slug.includes("bot-protection")) return "firewall";
  if (slug.includes("website") || slug.includes("domain") || slug.includes("ssl") || slug.includes("dns") || slug.includes("geographic") || slug.includes("country") || slug.includes("location")) return "globe";
  if (slug.includes("analytic") || slug.includes("report") || slug.includes("subscription") || slug.includes("plan") || slug.includes("export") || slug === "billing") return "chart";
  if (slug.includes("alert") || slug.includes("notification") || slug.includes("support")) return "bell";
  if (slug.includes("api") || slug.includes("reputation")) return "key";
  if (slug.includes("setting") || slug.includes("log")) return "settings";
  return "dashboard";
}

export function AppShell({
  children, user, nav, area
}: {
  children: React.ReactNode;
  user: AppUser;
  nav: readonly (readonly [string,string])[];
  area: "app" | "admin";
}) {
  const base = area === "admin" ? "/admin" : "/app";
  return <AppearanceProvider><div className="referenceApp adminReferenceApp">
    <input id="mobile-nav" className="navToggleInput" type="checkbox" />
    <aside className="refSidebar">
      <Link href={`${base}/dashboard`} className="refBrand"><b>W</b><span><strong>WebShield</strong><small>SAVRDH TECHNOLOGIES</small></span></Link>
      <nav aria-label={`${area} navigation`}>
        <p className="refNavLabel">{area === "admin" ? "PLATFORM CONTROL" : "WORKSPACE"}</p>
        {nav.map(([slug,label])=>slug.startsWith("#")?<p className="refNavLabel" key={slug}>{label}</p>:<Link key={slug} href={`${base}/${slug}`}><Icon name={navIcon(slug)} size={23}/><span>{label}</span></Link>)}
      </nav>
      <div className="refEnterprise"><Icon name="shield" size={30}/><div>Enterprise Security<small>Web & Database Protection</small></div></div>
    </aside>
    <label className="sidebarBackdrop" htmlFor="mobile-nav"/>
    <section className="refMain">
      <header className="refTopbar"><label htmlFor="mobile-nav" className="refMobileButton" aria-label="Toggle navigation"><Icon name="menu"/></label><span className="refOperational">● Systems operational</span><NotificationBell/><Link href="/demo/dashboard">Design dashboard</Link><Link href="/app/dashboard">Connected workspace</Link><form action={logoutAction}><button type="submit" className="refProfile"><b>{user.name.slice(0,2).toUpperCase()}</b><span>{user.name}<small>{user.role.replaceAll("_"," ")}</small></span><Icon name="logout" size={17}/></button></form></header>
      <main className="refContent"><WebsiteMonitoring/>{children}</main>
    </section>
  </div></AppearanceProvider>;
}
