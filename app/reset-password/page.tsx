import type { Metadata } from "next";
import { AuthForm } from "@/components/auth-form";
export const metadata: Metadata = { title: "Reset password" };
export default async function Reset({ searchParams }: { searchParams: Promise<Record<string,string|undefined>> }) { const q=await searchParams; return <AuthForm mode="reset" error={q.error} />; }
