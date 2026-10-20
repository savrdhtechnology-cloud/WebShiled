import { ReferenceConsole } from '@/components/reference-console';
export default async function Page({params}:{params:Promise<{slug?:string[]}>}) { const {slug}=await params; return <ReferenceConsole page={slug?.[0] || 'dashboard'}/>; }
