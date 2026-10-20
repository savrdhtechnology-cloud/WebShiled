import {redirect,notFound} from 'next/navigation';
import {featureCatalog} from '@/lib/feature-catalog';
import {ReferenceConsole} from '@/components/reference-console';
import {requireUser} from '@/lib/auth';
export default async function ClientPage({params}:{params:Promise<{slug?:string[]}>}){
 const {slug}=await params;if(!slug?.length)redirect('/app/dashboard');
 const supported=['dashboard','websites','database-security','fix-center','live-traffic','live-visitors','threat-center','firewall','analytics','reports','alerts','appearance','settings','support'];
 if(!supported.includes(slug[0])){const feature=featureCatalog[slug[0]];if(!feature)notFound();const group=feature.group.toLowerCase();const destination=group.includes('threat')?'threat-center':group.includes('firewall')?'firewall':group.includes('alert')?'alerts':group.includes('website')?'websites':group.includes('analytic')?'analytics':group.includes('report')?'reports':group.includes('visitor')?'live-traffic':'dashboard';redirect('/app/'+destination);}
 const user=await requireUser();
 return <ReferenceConsole page={slug[0]==='live-visitors'?'live-traffic':slug[0]} connected account={{name:user.name,role:user.role}}/>;
}
