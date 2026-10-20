import { redirect } from "next/navigation";
import { withBasePath } from "@/lib/base-path";

export default function AppIndex() {
  redirect(withBasePath("/app/dashboard"));
}
