import type { Metadata } from "next";
import Link from "next/link";
import { AuthForm } from "@/components/auth-form";
import { Logo } from "@/components/logo";
import { verifyTrialToken } from "@/lib/trial";

export const metadata: Metadata = { title: "Activate your trial" };
export const dynamic = "force-dynamic";

export default async function Register({ searchParams }: { searchParams: Promise<Record<string,string|undefined>> }) {
  const q = await searchParams;
  const trial = String(q.trial || "");
  if (!(await verifyTrialToken(trial))) {
    return (
      <main className="authPage">
        <section className="authPanel" style={{ gridColumn: "1 / -1" }}>
          <div className="authCard">
            <div className="mobileAuthLogo" style={{ display: "block", marginBottom: 18 }}><Logo /></div>
            <span className="authKicker">WEBSHIELD</span>
            <h2>Trial access is by invitation</h2>
            <p>WebShield is activated by the Savrdh team. Request a free trial and we will email you a personal activation link. If you already have a link and see this message, it may have expired, so please request a new one.</p>
            <div className="authForm" style={{ marginTop: 18 }}>
              <Link className="btn full" href="/#demo">Request a free trial</Link>
            </div>
            <div className="authMeta center">Already activated? <Link href="/login">Sign in</Link></div>
          </div>
        </section>
      </main>
    );
  }
  return <AuthForm mode="register" error={q.error} trial={trial} />;
}
