import { notFound } from "next/navigation";
import { ReferenceConsole } from "@/components/reference-console";
import { consolePage, isConsolePage } from "@/lib/console-pages";

export default async function DemoPage({params}:{params:Promise<{slug?:string[]}>}) {
  const {slug}=await params;
  const page=consolePage(slug?.[0]||"dashboard");
  if(!isConsolePage(page)||Number(slug?.length)>1)notFound();
  return <ReferenceConsole page={page} baseOverride="/demo" appearanceScope="demo"/>;
}
