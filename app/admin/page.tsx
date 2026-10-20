import { redirect } from "next/navigation";
import { withBasePath } from "@/lib/base-path";

export default function AdminIndex() {
  redirect(withBasePath("/admin/dashboard"));
}
