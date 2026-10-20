import { notFound, redirect } from "next/navigation";
import { featureCatalog } from "@/lib/feature-catalog";
import { ReferenceConsole } from "@/components/reference-console";
import { requireUser } from "@/lib/auth";
import { withBasePath } from "@/lib/base-path";

const supported = [
  "dashboard","websites","database-security","fix-center","live-traffic","live-visitors",
  "threat-center","firewall","analytics","reports","alerts","appearance","settings","support"
] as const;

export default async function ClientPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  if (!supported.includes(slug as (typeof supported)[number])) {
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
  return <ReferenceConsole page={slug === "live-visitors" ? "live-traffic" : slug} connected account={{ name: user.name, role: user.role }} />;
}
