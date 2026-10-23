import { notFound, redirect } from "next/navigation";

const retiredPages = ["product", "features", "how-it-works", "pricing", "security", "documentation", "contact"];
export default async function PublicPage({params}:{params:Promise<{slug:string}>}) {
  const {slug}=await params;
  if(!retiredPages.includes(slug))notFound();
  redirect("/app/dashboard");
}
