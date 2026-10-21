import { notFound, redirect } from "next/navigation";
import { featureCatalog } from "@/lib/feature-catalog";
import { ReferenceConsole } from "@/components/reference-console";
import { requireUser } from "@/lib/auth";
import { consolePage, isConsolePage } from "@/lib/console-pages";
import { withBasePath } from "@/lib/base-path";



export default async function ClientPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  if (!isConsolePage(slug)) {
    const feature = featureCatalog[slug];
    if (!feature) notFound();
    const group = feature.group.toLowerCase();
    const destination = group.includes("threat") ? "threat-center" :
      group.includes("firewall") ? "firewall" :
      group.includes("alert") ? "alerts" :
      group.includes("website") ? "websites" :
      group.includes("analytic") ? "analytics" :
      group.includes("report") ? "reports" :
      group.includes("visitor") ? "live-traffic" : "dashboard";
    redirect(withBasePath("/app/" + destination));
  }
  const user = await requireUser();
  return <ReferenceConsole page={consolePage(slug)} connected appearanceScope="workspace" account={{ name: user.name, role: user.role }} />;
}
