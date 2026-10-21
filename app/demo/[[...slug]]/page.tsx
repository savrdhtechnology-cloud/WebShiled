import { redirect } from "next/navigation";
import { consolePage, isConsolePage } from "@/lib/console-pages";
import { withBasePath } from "@/lib/base-path";

export default async function DemoPage({params}:{params:Promise<{slug?:string[]}>}) {
  const {slug}=await params;
  const page=slug?.[0]&&isConsolePage(slug[0])?consolePage(slug[0]):"dashboard";
  redirect(withBasePath("/app/"+page));
}
