import {ReferenceConsole} from '@/components/reference-console';
import {requireUser} from '@/lib/auth';
export const dynamic='force-dynamic';
export default async function WebsitesPage(){const user=await requireUser();return <ReferenceConsole page="websites" appearanceScope="workspace" connected account={{name:user.name,role:user.role}}/>}
