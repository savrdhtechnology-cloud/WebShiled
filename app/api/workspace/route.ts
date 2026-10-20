import {NextResponse} from 'next/server';
import {getCurrentUser} from '@/lib/auth';
export async function GET(){const user=await getCurrentUser();if(!user)return NextResponse.json({ok:false,error:{message:'Authentication required.'}},{status:401});return NextResponse.json({ok:true,data:{name:user.name,role:user.role,organizationId:user.organizationId,project:'szvxrgbshmmsvujkusdm',access:'Tenant-isolated by Row Level Security'}},{headers:{'cache-control':'no-store'}})}
