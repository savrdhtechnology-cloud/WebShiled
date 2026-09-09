import { AppShell } from "@/components/app-shell";
import { clientNav } from "@/lib/navigation";
import { requireUser } from "@/lib/auth";
export const dynamic = "force-dynamic";
export default async function ClientLayout({ children }: { children: React.ReactNode }) {
  const user = await requireUser();
  return <AppShell user={user} nav={clientNav} area="app">{children}</AppShell>;
}
