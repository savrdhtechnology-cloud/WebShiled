import { redirect } from "next/navigation";
import { ClientDashboard } from "@/components/dashboard";
import { ClientModule } from "@/components/module-page";
import { CapabilityPage } from "@/components/capability-page";
import { featureCatalog } from "@/lib/feature-catalog";

export default async function ClientPage({ params }: { params: Promise<{ slug?: string[] }> }) {
  const { slug } = await params;
  if (!slug?.length) redirect("/app/dashboard");
  const current = slug[0];
  if (current === "dashboard") return <ClientDashboard/>;
  const feature = featureCatalog[current];
  if (feature) return <CapabilityPage feature={feature}/>;
  return <div className="pageWrap"><ClientModule slug={current}/></div>;
}
