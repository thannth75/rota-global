-- Rota Global: espaços familiares independentes
-- migration_plans.plan_data permanece privado por owner_user_id (RLS já existente).
-- Cada grupo representa um único núcleo familiar; somente adultos convidados entram nele.
drop policy if exists "users join own new family group" on public.group_members;
create policy "users join own new family group"
on public.group_members for insert to authenticated
with check (
  user_id = (select auth.uid())
  and role = 'owner'
  and exists (
    select 1 from public.migration_groups mg
    where mg.id = group_id and mg.created_by = (select auth.uid())
  )
);

create or replace function public.create_family_workspace(
  p_group_name text,
  p_family_name text
)
returns table(group_id uuid, family_unit_id uuid)
language plpgsql
security invoker
set search_path = public, private
as $$
declare
  v_user uuid := auth.uid();
  v_group uuid;
  v_family uuid;
begin
  if v_user is null then raise exception 'Autenticação necessária'; end if;
  if nullif(trim(p_group_name), '') is null or nullif(trim(p_family_name), '') is null then
    raise exception 'Informe o nome do espaço e da família';
  end if;
  insert into public.migration_groups(name, created_by)
  values (trim(p_group_name), v_user)
  returning id into v_group;
  insert into public.group_members(group_id, user_id, role)
  values (v_group, v_user, 'owner');
  insert into public.family_units(group_id, name)
  values (v_group, trim(p_family_name))
  returning id into v_family;
  return query select v_group, v_family;
end;
$$;

revoke all on function public.create_family_workspace(text, text) from public, anon;
grant execute on function public.create_family_workspace(text, text) to authenticated;

-- Desativa o antigo bootstrap que criava dois núcleos dentro do mesmo grupo,
-- impedindo que as duas famílias sejam misturadas por engano.
revoke all on function public.initialize_rota_global_group(text) from public, anon, authenticated;
