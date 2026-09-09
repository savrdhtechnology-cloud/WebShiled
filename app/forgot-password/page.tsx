import type { Metadata } from "next";
import { AuthForm } from "@/components/auth-form";
export const metadata: Metadata = { title: "Forgot password" };
export default async function Forgot({ searchParams }: { searchParams: Promise<Record<string,string|undefined>> }) { const q=await searchParams; return <AuthForm mode="forgot" message={q.message} />; }
