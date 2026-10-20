import { notFound, redirect } from "next/navigation";
import { ReferenceConsole } from "@/components/reference-console";
import { requireAdmin } from "@/lib/auth";

const supported = [
  "dashboard",
  "websites",
  "database-security",
  "fix-center",
  "security-events",
  "plans",
  "support-tickets",
  "system-settings"
] as const;

export default async function AdminPage({ params }: { params: Promise<{ slug?: string[] }> }) {
  const { slug } = await params;
  if (!slug?.length) redirect("/admin/dashboard");

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
