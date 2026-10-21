import { consolePage, isConsolePage } from "@/lib/console-pages";
import { notFound } from "next/navigation";
import { ReferenceConsole } from "@/components/reference-console";
import { requireAdmin } from "@/lib/auth";



export default async function AdminPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  if (!isConsolePage(slug)) notFound();
  const user = await requireAdmin();
  return (
    <ReferenceConsole
      page={consolePage(slug)}
      account={{ name: user.name, role: user.role }}
      baseOverride="/admin"
      appearanceScope="admin"
    />
  );
}
