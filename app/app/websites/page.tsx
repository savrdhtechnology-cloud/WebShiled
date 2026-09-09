import { WebsiteScanner } from "@/components/website-scanner";
import { Icon } from "@/components/icons";
import { demoWebsites } from "@/lib/demo";

export const dynamic = "force-dynamic";

export default function WebsitesPage() {
  return (
    <div className="pageWrap">
      <div className="pageHeader">
        <div>
          <div className="breadcrumbs">WebShield <span>/</span> Websites</div>
          <h1>Websites</h1>
          <p>Connect websites and run a real passive security posture check.</p>
        </div>
        <div className="headerActions">
          <span className="demoBadge large">DEMO DATA + LIVE SCAN</span>
        </div>
      </div>

      <WebsiteScanner />

      <div className="websiteGrid">
        {demoWebsites.map((w) => (
          <article className="websiteCard" key={w.domain}>
            <div className="siteIcon"><Icon name="globe" /></div>
            <div>
              <h3>{w.domain}</h3>
              <p>SSL: {w.ssl} · Risk: {w.risk}</p>
              <span className={`statusTag ${w.status === "PROTECTED" ? "safe" : "medium"}`}>{w.status}</span>
              <p>Integration: <b>{w.integration}</b></p>
              <p style={{ fontSize: 10 }}>The card above is demo inventory. Use the scanner to obtain a live external posture result.</p>
            </div>
          </article>
        ))}
      </div>

      <article className="panel" style={{ marginTop: 16 }}>
        <div className="panelHead">
          <div>
            <h3>Integration setup</h3>
            <p>A website is never labelled protected before ownership verification and a real protection provider connection.</p>
          </div>
        </div>
        <div className="steps">
          {[["1","Enter domain"],["2","Run passive scan"],["3","Verify ownership"],["4","Install integration"],["5","Activate real protection provider"]].map(([n,a]) => (
            <div className="step" key={n}><span>{n}</span><b>{a}</b></div>
          ))}
        </div>
      </article>
    </div>
  );
}
