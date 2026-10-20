import { notFound } from "next/navigation";
import { ReferenceConsole } from "@/components/reference-console";
import { requireAdmin } from "@/lib/auth";

const supported = [
  "dashboard","websites","live-traffic","threat-center","database-security","fix-center",
  "firewall","analytics","reports","alerts","appearance","settings","support"
] as const;

export default async function AdminPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  if (!supported.includes(slug as (typeof supported)[number])) notFound();
  const user = await requireAdmin();
  return (
    <ReferenceConsole
      page={slug}
      account={{ name: user.name, role: user.role }}
      baseOverride="/admin"
      appearanceScope="admin"
    />
  );
}
