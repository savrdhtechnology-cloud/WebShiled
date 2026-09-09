import type { Metadata } from "next";
import { AuthForm } from "@/components/auth-form";
export const metadata: Metadata = { title: "Register" };
export default async function Register({ searchParams }: { searchParams: Promise<Record<string,string|undefined>> }) { const q=await searchParams; return <AuthForm mode="register" error={q.error} />; }
