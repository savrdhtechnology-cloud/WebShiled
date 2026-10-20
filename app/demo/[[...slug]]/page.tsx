import {redirect} from 'next/navigation';
import {getCurrentUser} from '@/lib/auth';
import {ReferenceConsole} from '@/components/reference-console';
export default async function Page({params}:{params:Promise<{slug?:string[]}>}) {
 const {slug}=await params;const page=slug?.[0]||'dashboard';
 if(!['dashboard','appearance'].includes(page))redirect('/app/'+(slug||[]).map(encodeURIComponent).join('/'));
 const user=await getCurrentUser();
 return <ReferenceConsole page={page} connected={Boolean(user)} account={user?{name:user.name,role:user.role}:undefined}/>;
}
