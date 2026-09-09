import Link from "next/link";
import { Icon } from "@/components/icons";
import { Logo } from "@/components/logo";
import { forgotPasswordAction, loginAction, registerAction, resetPasswordAction } from "@/app/actions";

type Mode = "login" | "register" | "forgot" | "reset";

export function AuthForm({ mode, error, message, next }: { mode: Mode; error?: string; message?: string; next?: string }) {
  const copy = {
    login: ["Welcome back", "Sign in to your WebShield security workspace."],
    register: ["Create your workspace", "Start with the WebShield V1 security operations foundation."],
    forgot: ["Reset access", "Request a secure password recovery email."],
    reset: ["Choose a new password", "Use at least 10 characters for your new password."]
  }[mode];
  const action = mode === "login" ? loginAction : mode === "register" ? registerAction : mode === "forgot" ? forgotPasswordAction : resetPasswordAction;
  const messages: Record<string,string> = {
    invalid: "Please check the fields and try again.", credentials: "The email or password is incorrect.",
    "not-configured": "Production authentication is integration-ready. Configure Supabase environment variables to activate it.",
    signup: "Registration could not be completed.", "verify-email": "Check your email to verify the new account.",
    "integration-ready": "Password recovery is ready to activate when Supabase Auth is configured.",
    sent: "If an account exists, a password recovery email has been requested.",
    weak: "Password must contain at least 10 characters.", failed: "Password update failed. Request a new recovery link.",
    "password-updated": "Password updated. You can now sign in."
  };
  return (
    <main className="authPage">
      <section className="authVisual">
        <Logo />
        <div className="authPitch"><span className="eyebrow"><span className="pulseDot"/> SECURITY OPERATIONS</span><h1>Visibility before vulnerability.</h1><p>Monitor traffic, investigate risk and manage website security from a unified workspace.</p><div className="authFeature"><Icon name="shield"/><span><b>Security-first foundation</b><small>RBAC · audit logs · secure sessions · RLS-ready data model</small></span></div><div className="authFeature"><Icon name="chart"/><span><b>Clear telemetry boundaries</b><small>Demo providers never masquerade as production security data</small></span></div></div>
        <small className="authCopyright">© 2026 Savrdh Technologies</small>
      </section>
      <section className="authPanel">
        <div className="authCard">
          <div className="mobileAuthLogo"><Logo /></div>
          <span className="authKicker">WEBSHIELD</span><h2>{copy[0]}</h2><p>{copy[1]}</p>
          {(error || message) && <div className={error ? "formNotice error" : "formNotice"}>{messages[error || message || ""] || "Request received."}</div>}
          <form action={action} className="authForm">
            {mode === "register" && <label>Full name<input name="name" autoComplete="name" required placeholder="Your name" /></label>}
            {(mode === "login" || mode === "register" || mode === "forgot") && <label>Email address<input name="email" type="email" autoComplete="email" required placeholder="you@company.com" /></label>}
            {(mode === "login" || mode === "register" || mode === "reset") && <label>Password<input name="password" type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} minLength={mode === "login" ? 8 : 10} required placeholder="••••••••••" /></label>}
            {mode === "login" && <input type="hidden" name="next" value={next || "/app/dashboard"} />}
            <button className="btn full" type="submit">{mode === "login" ? "Sign in" : mode === "register" ? "Create account" : mode === "forgot" ? "Send recovery email" : "Update password"}<Icon name="chevron"/></button>
          </form>
          {mode === "login" && <><div className="authMeta"><Link href="/forgot-password">Forgot password?</Link><span>New to WebShield? <Link href="/register">Create account</Link></span></div><div className="demoLogin"><b>Demo mode</b><p>Use any valid-looking email and an 8+ character password. Use an email beginning with <code>admin@</code> only to preview the demo admin workspace.</p></div></>}
          {mode === "register" && <div className="authMeta center">Already have an account? <Link href="/login">Sign in</Link></div>}
          {(mode === "forgot" || mode === "reset") && <div className="authMeta center"><Link href="/login">Back to sign in</Link></div>}
        </div>
      </section>
    </main>
  );
}
