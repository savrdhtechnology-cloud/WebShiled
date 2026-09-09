import { AppShell } from "@/components/app-shell";
import { adminNav } from "@/lib/navigation";
import { requireAdmin } from "@/lib/auth";
export const dynamic = "force-dynamic";
export default async function AdminLayout({ children }: { children: React.ReactNode }) {
  const user = await requireAdmin();
  return <AppShell user={user} nav={adminNav} area="admin">{children}</AppShell>;
}
