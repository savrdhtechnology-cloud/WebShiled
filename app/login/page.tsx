import type { Metadata } from "next";
import { AuthForm } from "@/components/auth-form";
export const metadata: Metadata = { title: "Login" };
export default async function Login({ searchParams }: { searchParams: Promise<Record<string,string|undefined>> }) {
  const q = await searchParams;
  return <AuthForm mode="login" error={q.error} message={q.message} next={q.next} />;
}
