import { notFound, redirect } from "next/navigation";
import { ReferenceConsole } from "@/components/reference-console";
import { requireAdmin } from "@/lib/auth";
import { withBasePath } from "@/lib/base-path";

const supported = [
  "dashboard",
  "websites",
  "live-traffic",
  "threat-center",
  "database-security",
  "fix-center",
  "firewall",
  "analytics",
  "reports",
  "alerts",
  "appearance",
  "settings",
  "support"
] as const;

export default async function AdminPage({ params }: { params: Promise<{ slug?: string[] }> }) {
  const { slug } = await params;
  if (!slug?.length) redirect(withBasePath("/admin/dashboard"));
  const current = slug[0];
  if (!supported.includes(current as (typeof supported)[number])) notFound();

  const user = await requireAdmin();
  return (
    <ReferenceConsole
      page={current}
      connected
      area="admin"
      account={{ name: user.name, role: user.role }}
    />
  );
}
