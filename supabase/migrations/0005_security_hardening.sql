-- Harden WebShield SECURITY DEFINER function execution.
revoke all on function public.handle_webshield_new_user() from public, anon, authenticated;
revoke all on function public.rls_auto_enable() from public, anon, authenticated;

-- Collector must remain callable by the public WebShield script, but no broader PUBLIC/authenticated grant is needed.
revoke all on function public.webshield_ingest_event(text,text,text,text,text,text,text,text,text,text,text,boolean) from public, authenticated;
grant execute on function public.webshield_ingest_event(text,text,text,text,text,text,text,text,text,text,text,boolean) to anon;
