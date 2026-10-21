import { notFound, redirect } from "next/navigation";
import { withBasePath } from "@/lib/base-path";

const retiredPages = ["product", "features", "how-it-works", "pricing", "security", "documentation", "contact"];
export default async function PublicPage({params}:{params:Promise<{slug:string}>}) {
  const {slug}=await params;
  if(!retiredPages.includes(slug))notFound();
  redirect(withBasePath("/demo/dashboard"));
}
