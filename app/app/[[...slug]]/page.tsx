import { redirect } from "next/navigation";
import { ClientDashboard } from "@/components/dashboard";
import { ClientModule } from "@/components/module-page";
export default async function ClientPage({ params }: { params: Promise<{ slug?: string[] }> }) {
  const { slug } = await params;
  if (!slug?.length) redirect("/app/dashboard");
  const current = slug[0];
  if (current === "dashboard") return <ClientDashboard/>;
  return <div className="pageWrap"><ClientModule slug={current}/></div>;
}
