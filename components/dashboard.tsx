import { BackendDashboard } from "@/components/backend-dashboard";

export function ClientDashboard() {
  return <BackendDashboard />;
}

export function AdminDashboard() {
  return <BackendDashboard admin />;
}
