-- CHALLENGE: Supabase schema. Run once in Supabase > SQL Editor.

create table if not exists docs (
  col text not null,
  id text not null,
  data jsonb not null default '{}',
  owner uuid not null default auth.uid(),
  primary key (col, id)
);
create table if not exists userdata (
  uid uuid primary key default auth.uid(),
  data jsonb not null default '{}',
  updated timestamptz default now()
);
create table if not exists admins (uid uuid primary key);

alter table docs enable row level security;
alter table userdata enable row level security;
alter table admins enable row level security;

create or replace function is_admin() returns boolean
language sql security definer stable set search_path = public as $$
  select exists (select 1 from admins where uid = auth.uid())
$$;

create or replace function is_creator() returns boolean
language sql security definer stable set search_path = public as $$
  select is_admin() or coalesce(
    (select data->'ids' ? auth.uid()::text from docs where col = 'meta' and id = 'creators'), false)
$$;

-- everyone logged in can read shared content
create policy docs_read on docs for select to authenticated using (true);

-- insert: own rows only; members row id = your user id; only creators make challenges; only admins write meta
create policy docs_ins on docs for insert to authenticated with check (
  owner = auth.uid()
  and (col <> 'members' or id = auth.uid()::text)
  and (col not like 'challenges/%/people' or id = auth.uid()::text)
  and (col <> 'challenges' or is_creator())
  and (col <> 'meta' or is_admin())
);
create policy docs_upd on docs for update to authenticated
  using (owner = auth.uid())
  with check (owner = auth.uid() and (col <> 'meta' or is_admin()));
create policy docs_del on docs for delete to authenticated
  using (owner = auth.uid() or is_admin());

-- private user data (goals, habits, finance): only the owner
create policy ud_all on userdata for all to authenticated
  using (uid = auth.uid()) with check (uid = auth.uid());
create policy adm_self on admins for select to authenticated using (uid = auth.uid());

-- likes: anyone logged in can toggle only their own like
create or replace function like_post(pid text) returns void
language plpgsql security definer set search_path = public as $$
declare u text := auth.uid()::text;
begin
  update docs set data = jsonb_set(data, '{likes}',
    case when coalesce(data->'likes','[]'::jsonb) ? u
         then (data->'likes') - u
         else coalesce(data->'likes','[]'::jsonb) || to_jsonb(u) end)
  where col = 'posts' and id = pid;
end $$;
revoke execute on function like_post(text) from public, anon;
grant execute on function like_post(text) to authenticated;

-- make yourself admin (after you sign up in the app), replace the email:
-- insert into admins select id from auth.users where email = 'you@example.com';
