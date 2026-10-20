import { redirect } from "next/navigation";

export default function DemoPage() {
  redirect("/login?next=/app/dashboard");
}
