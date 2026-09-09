import { WebsiteScanner } from "@/components/website-scanner";
import { BackendWebsites } from "@/components/backend-websites";

export const dynamic = "force-dynamic";

export default function WebsitesPage() {
  return (
    <div className="pageWrap">
      <div className="pageHeader">
        <div>
          <div className="breadcrumbs">WebShield <span>/</span> Websites</div>
          <h1>Websites & Security Scan</h1>
          <p>Run a live passive scan and manage websites stored in the WebShield backend.</p>
        </div>
        <div className="headerActions"><span className="statusTag safe">LIVE SCAN + DATABASE</span></div>
      </div>

      <WebsiteScanner />
      <BackendWebsites />

      <article className="panel" style={{ marginTop: 16 }}>
        <div className="panelHead"><div><h3>Protection activation</h3><p>A website is only labelled protected after ownership verification and a real traffic-path/WAF integration.</p></div></div>
        <div className="steps">
          {[["1","Add domain"],["2","Run passive scan"],["3","Verify ownership"],["4","Connect traffic provider"],["5","Activate protection rules"]].map(([n,a]) => <div className="step" key={n}><span>{n}</span><b>{a}</b></div>)}
        </div>
      </article>
    </div>
  );
}
