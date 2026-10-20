import { requireUser } from '@/lib/auth';
export const dynamic = 'force-dynamic';
export default async function ClientLayout({children}:{children:React.ReactNode}){await requireUser();return children;}
