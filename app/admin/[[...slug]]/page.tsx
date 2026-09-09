import { redirect } from "next/navigation";
import { AdminDashboard } from "@/components/dashboard";
import { AdminModule } from "@/components/module-page";
export default async function AdminPage({ params }: { params: Promise<{ slug?: string[] }> }) {
  const { slug } = await params;
  if (!slug?.length) redirect("/admin/dashboard");
  const current = slug[0];
  if (current === "dashboard") return <AdminDashboard/>;
  return <AdminModule slug={current}/>;
}
