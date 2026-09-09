import { redirect } from "next/navigation";
import { AdminDashboard } from "@/components/dashboard";
import { AdminModule } from "@/components/module-page";
import { WebsiteScanner } from "@/components/website-scanner";

export default async function AdminPage({ params }: { params: Promise<{ slug?: string[] }> }) {
  const { slug } = await params;
  if (!slug?.length) redirect("/admin/dashboard");
  const current = slug[0];

  if (current === "dashboard") {
    return (
      <>
        <div className="pageWrap" style={{ paddingBottom: 0 }}>
          <WebsiteScanner />
        </div>
        <AdminDashboard />
      </>
    );
  }

  return <AdminModule slug={current}/>;
}
