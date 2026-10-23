import { notFound, redirect } from "next/navigation";
import { consolePage, isConsolePage } from "@/lib/console-pages";

// The sample-data preview is no longer public. Every demo URL now goes to the real workspace page,
// which requires a login (see app/app/layout.tsx).
export default async function DemoPage({params}:{params:Promise<{slug?:string[]}>}) {
  const {slug}=await params;
  const page=consolePage(slug?.[0]||"dashboard");
  if(!isConsolePage(page)||Number(slug?.length)>1)notFound();
  redirect("/app/"+page);
}
