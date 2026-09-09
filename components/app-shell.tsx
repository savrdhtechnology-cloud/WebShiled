import Link from "next/link";
import { logoutAction } from "@/app/actions";
import { Icon } from "@/components/icons";
import { Logo } from "@/components/logo";
import type { AppUser } from "@/lib/types";

function navIcon(slug: string) {
  if (slug.includes("visitor") || slug.includes("client") || slug === "users" || slug === "team") return "visitors";
  if (slug.includes("threat") || slug.includes("security")) return "threat";
  if (slug.includes("firewall") || slug.includes("rule")) return "firewall";
  if (slug.includes("website")) return "globe";
  if (slug.includes("analytic") || slug.includes("report") || slug.includes("subscription") || slug.includes("plan") || slug === "billing") return "chart";
  if (slug.includes("alert") || slug.includes("support")) return "bell";
  if (slug.includes("api")) return "key";
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
  return (
    <div className="appShell">
      <input id="mobile-nav" className="navToggleInput" type="checkbox" />
      <aside className="sidebar">
        <div className="sidebarHead"><Logo /><label className="mobileClose" htmlFor="mobile-nav">×</label></div>
        <div className="workspaceSelect"><span className="workspaceLogo">S</span><span><small>Workspace</small><strong>{area === "admin" ? "WebShield Admin" : "Savrdh Technologies"}</strong></span><Icon name="chevron" size={14}/></div>
        <nav className="sideNav" aria-label={`${area} navigation`}>
          <small className="navLabel">{area === "admin" ? "PLATFORM CONTROL" : "SECURITY OPERATIONS"}</small>
          {nav.map(([slug,label])=><Link key={slug} href={`${base}/${slug}`}><Icon name={navIcon(slug)} size={17}/><span>{label}</span></Link>)}
        </nav>
        <div className="sidebarFoot">
          {user.demo && <div className="demoPanel"><span className="demoBadge">DEMO MODE</span><p>Simulated telemetry only. No live WAF enforcement.</p></div>}
          <form action={logoutAction}><button type="submit" className="userChip"><span>{user.name.slice(0,2).toUpperCase()}</span><b>{user.name}<small>{user.role.replaceAll("_"," ")}</small></b><Icon name="logout" size={17}/></button></form>
        </div>
      </aside>
      <label className="sidebarBackdrop" htmlFor="mobile-nav"/>
      <section className="appMain">
        <header className="topbar">
          <div className="topbarLeft"><label htmlFor="mobile-nav" className="mobileMenu"><Icon name="menu"/></label><span className="statusPill safe"><i/> Systems operational</span><span className="topSep"/><span className="topSite"><Icon name="globe" size={15}/>{area === "admin" ? "Platform overview" : "savrdhtechnology.com"}</span></div>
          <div className="topbarRight"><button className="iconButton" aria-label="Search"><Icon name="search"/></button><button className="iconButton alertDot" aria-label="Notifications"><Icon name="bell"/></button>{area === "app" && (["OWNER","ADMIN"].includes(user.role)) && <Link href="/admin/dashboard" className="adminSwitch">Admin</Link>}</div>
        </header>
        {children}
      </section>
    </div>
  );
}
