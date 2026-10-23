import { redirect } from "next/navigation";

// The product opens straight into the signed-in workspace; requireUser() in app/app/layout.tsx sends
// anyone without a session to /login first, so nothing is visible without logging in.
export default function HomePage() {
  redirect("/app/dashboard");
}
