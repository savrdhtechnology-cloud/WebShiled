import {NextRequest,NextResponse} from 'next/server';
import {createClient} from '@/lib/supabase/server';
import {validSettings} from '@/lib/appearance';
export async function GET(){
 const client=await createClient();const {data:{user},error}=await client.auth.getUser();
 if(error||!user)return NextResponse.json({error:'Sign in to apply appearance across your account.'},{status:401});
 return NextResponse.json({data:user.user_metadata?.webshield_appearance??null},{headers:{'Cache-Control':'no-store'}});
}
export async function PUT(request:NextRequest){
 if(request.headers.get('origin')!==request.nextUrl.origin)return NextResponse.json({error:'Invalid request origin.'},{status:403});
 const client=await createClient();const {data:{user},error}=await client.auth.getUser();
 if(error||!user)return NextResponse.json({error:'Sign in to apply appearance across your account.'},{status:401});
 let input;try{input=await request.json()}catch{return NextResponse.json({error:'Invalid appearance settings.'},{status:400})}
 if(!input||typeof input!=='object'||Array.isArray(input))return NextResponse.json({error:'Invalid appearance settings.'},{status:400});
 const appearance=validSettings(input);const result=await client.auth.updateUser({data:{webshield_appearance:appearance}});
 if(result.error)return NextResponse.json({error:'Appearance could not be applied. Please try again.'},{status:500});
 return NextResponse.json({data:appearance},{headers:{'Cache-Control':'no-store'}});
}
