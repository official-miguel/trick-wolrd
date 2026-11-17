-- =====================================================================
-- Trick World — Supabase setup
-- Run this whole file once: Supabase dashboard → SQL Editor → New query → Run.
-- It is safe to run again later (everything is "create or replace" / "if not exists").
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------
create table if not exists public.profiles (
  id            uuid primary key references auth.users(id) on delete cascade,
  email         text,
  full_name     text,
  phone         text,
  is_active     boolean not null default false,
  is_admin      boolean not null default false,
  session_id    uuid,          -- the ONE login session allowed for this user
  device_info   text,          -- e.g. "Chrome on Android"
  last_seen     timestamptz,
  last_login    timestamptz,
  activated_at  timestamptz,
  created_at    timestamptz not null default now()
);

-- Codes live in their own table so users can never read their own code.
create table if not exists public.activation_codes (
  user_id    uuid primary key references public.profiles(id) on delete cascade,
  code       text not null,
  used       boolean not null default false,
  attempts   int not null default 0,
  issued_at  timestamptz not null default now()
);

-- Paid plans: when an account is activated it gets an end date.
-- When that date passes the account is switched off and the user must recharge.
alter table public.profiles         add column if not exists expires_at  timestamptz;
alter table public.profiles         add column if not exists plan_months int;
alter table public.activation_codes add column if not exists plan_months int not null default 1;

alter table public.profiles         enable row level security;
alter table public.activation_codes enable row level security;

drop policy if exists "tw: read own profile" on public.profiles;
create policy "tw: read own profile" on public.profiles
  for select to authenticated using (id = (select auth.uid()));

-- No direct writes from the browser. Every change goes through the functions below.
revoke all on public.profiles from anon;
revoke insert, update, delete on public.profiles from authenticated;
revoke all on public.activation_codes from anon, authenticated;

-- ---------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------

-- 8-character code like "K7QM-2XPA" (no 0/O/1/I to avoid confusion).
create or replace function public.tw_gen_code()
returns text language plpgsql volatile set search_path = '' as $$
declare
  alphabet constant text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  b bytea := extensions.gen_random_bytes(8);
  r text := '';
begin
  for i in 0..7 loop
    r := r || substr(alphabet, (get_byte(b, i) % 32) + 1, 1);
    if i = 3 then r := r || '-'; end if;
  end loop;
  return r;
end $$;

-- The login session id Supabase puts in every access token.
create or replace function public.tw_current_session()
returns uuid language sql stable set search_path = '' as $$
  select nullif(auth.jwt() ->> 'session_id', '')::uuid
$$;

create or replace function public.tw_is_admin()
returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce((select is_admin from public.profiles where id = auth.uid()), false)
$$;

-- Switches off any account whose plan end date has passed. Pass a user id to
-- check just that user, or null to sweep everyone.
create or replace function public.tw_expire_due(p_user uuid default null)
returns void language sql volatile security definer set search_path = '' as $$
  update public.profiles
     set is_active = false
   where is_active
     and not is_admin
     and expires_at is not null
     and expires_at <= now()
     and (p_user is null or id = p_user)
$$;

-- Use this in RLS policies on YOUR content tables:
--   create policy "members only" on public.videos for select to authenticated
--   using (public.tw_session_ok());
-- It is true only for an active user on their current (single) device.
create or replace function public.tw_session_ok()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.profiles p
    where p.id = auth.uid()
      and (p.is_admin or (p.is_active and (p.expires_at is null or p.expires_at > now())))
      and p.session_id = public.tw_current_session()
  )
$$;

-- ---------------------------------------------------------------------
-- New sign-ups get a profile + an activation code automatically
-- ---------------------------------------------------------------------
create or replace function public.tw_handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, email, full_name, phone)
  values (new.id, new.email, new.raw_user_meta_data ->> 'full_name', new.raw_user_meta_data ->> 'phone')
  on conflict (id) do nothing;

  insert into public.activation_codes (user_id, code)
  values (new.id, public.tw_gen_code())
  on conflict (user_id) do nothing;

  return new;
end $$;

drop trigger if exists tw_on_auth_user_created on auth.users;
create trigger tw_on_auth_user_created
  after insert on auth.users
  for each row execute function public.tw_handle_new_user();

-- Backfill users that existed before this script ran.
insert into public.profiles (id, email, full_name, phone)
select u.id, u.email, u.raw_user_meta_data ->> 'full_name', u.raw_user_meta_data ->> 'phone'
from auth.users u
on conflict (id) do nothing;

insert into public.activation_codes (user_id, code)
select p.id, public.tw_gen_code() from public.profiles p
on conflict (user_id) do nothing;

-- ---------------------------------------------------------------------
-- One device at a time
-- ---------------------------------------------------------------------

-- Called right after login. This device becomes the only allowed one,
-- and every other login for the user is revoked.
create or replace function public.tw_claim_session(p_device_info text default null)
returns json language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := auth.uid();
  v_sid uuid := public.tw_current_session();
  p public.profiles;
begin
  if v_uid is null or v_sid is null then
    raise exception 'Not signed in' using errcode = '28000';
  end if;

  perform public.tw_expire_due(v_uid);

  update public.profiles
     set session_id  = v_sid,
         device_info = left(coalesce(nullif(trim(p_device_info), ''), 'Unknown device'), 120),
         last_seen   = now(),
         last_login  = now()
   where id = v_uid
  returning * into p;

  if not found then
    raise exception 'Profile missing. Run supabase/schema.sql again.';
  end if;

  -- Kill other sessions so the old device can't refresh its token.
  begin
    delete from auth.sessions where user_id = v_uid and id <> v_sid;
  exception when others then null;  -- the client-side check still logs them out
  end;

  return json_build_object('ok', true, 'is_active', p.is_active or p.is_admin,
    'is_admin', p.is_admin, 'full_name', p.full_name, 'email', p.email,
    'expires_at', p.expires_at, 'plan_months', p.plan_months,
    'expired', not p.is_active and not p.is_admin and p.expires_at is not null and p.expires_at <= now());
end $$;

-- Called on every protected page and every ~20s as a heartbeat.
create or replace function public.tw_check_session()
returns json language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := auth.uid();
  v_sid uuid := public.tw_current_session();
  p public.profiles;
begin
  if v_uid is null then
    return json_build_object('ok', false, 'reason', 'signed_out');
  end if;

  perform public.tw_expire_due(v_uid);

  select * into p from public.profiles where id = v_uid;
  if not found then
    return json_build_object('ok', false, 'reason', 'no_profile');
  end if;
  if p.session_id is null then
    return json_build_object('ok', false, 'reason', 'session_ended');
  end if;
  if p.session_id is distinct from v_sid then
    return json_build_object('ok', false, 'reason', 'other_device');
  end if;

  -- Throttled so the heartbeat doesn't spam realtime updates.
  if p.last_seen is null or p.last_seen < now() - interval '60 seconds' then
    update public.profiles set last_seen = now() where id = v_uid;
  end if;

  return json_build_object('ok', true, 'is_active', p.is_active or p.is_admin,
    'is_admin', p.is_admin, 'full_name', p.full_name, 'email', p.email,
    'expires_at', p.expires_at, 'plan_months', p.plan_months,
    'expired', not p.is_active and not p.is_admin and p.expires_at is not null and p.expires_at <= now());
end $$;

-- Called on normal "Log out".
create or replace function public.tw_release_session()
returns void language sql security definer set search_path = '' as $$
  update public.profiles set session_id = null
  where id = auth.uid() and session_id = public.tw_current_session()
$$;

-- ---------------------------------------------------------------------
-- Activation
-- ---------------------------------------------------------------------
create or replace function public.tw_activate(p_code text)
returns json language plpgsql security definer set search_path = '' as $$
declare
  v_uid  uuid := auth.uid();
  c      public.activation_codes;
  v_norm text := upper(regexp_replace(coalesce(p_code, ''), '[^A-Za-z0-9]', '', 'g'));
begin
  if v_uid is null then
    raise exception 'Not signed in' using errcode = '28000';
  end if;

  perform public.tw_expire_due(v_uid);

  if exists (select 1 from public.profiles where id = v_uid and is_active) then
    return json_build_object('ok', true);
  end if;

  select * into c from public.activation_codes where user_id = v_uid for update;
  if not found then
    return json_build_object('ok', false, 'reason', 'no_code');
  end if;
  if c.attempts >= 10 then
    return json_build_object('ok', false, 'reason', 'locked');
  end if;
  if c.used then
    return json_build_object('ok', false, 'reason', 'used');
  end if;
  if replace(c.code, '-', '') <> v_norm then
    update public.activation_codes set attempts = attempts + 1 where user_id = v_uid;
    return json_build_object('ok', false, 'reason', 'invalid', 'left', greatest(0, 9 - c.attempts));
  end if;

  update public.activation_codes set used = true, attempts = 0 where user_id = v_uid;
  update public.profiles
     set is_active    = true,
         activated_at = now(),
         plan_months  = c.plan_months,
         expires_at   = now() + make_interval(months => c.plan_months)
   where id = v_uid;
  return json_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- Admin
-- ---------------------------------------------------------------------
drop function if exists public.tw_admin_list_users();
create or replace function public.tw_admin_list_users()
returns table (
  id uuid, email text, full_name text, phone text,
  is_active boolean, is_admin boolean, has_session boolean, device_info text,
  last_seen timestamptz, last_login timestamptz, activated_at timestamptz, created_at timestamptz,
  code text, code_used boolean, attempts int, code_issued_at timestamptz,
  expires_at timestamptz, plan_months int, code_plan_months int
)
language plpgsql security definer set search_path = '' as $$
#variable_conflict use_column
begin
  if not public.tw_is_admin() then
    raise exception 'Admins only' using errcode = '42501';
  end if;
  perform public.tw_expire_due(null);
  return query
    select p.id, p.email, p.full_name, p.phone,
           p.is_active, p.is_admin, p.session_id is not null, p.device_info,
           p.last_seen, p.last_login, p.activated_at, p.created_at,
           c.code, c.used, c.attempts, c.issued_at,
           p.expires_at, p.plan_months, c.plan_months
    from public.profiles p
    left join public.activation_codes c on c.user_id = p.id
    order by p.created_at desc;
end $$;

drop function if exists public.tw_admin_set_active(uuid, boolean);
-- p_months: how long the plan lasts (1 month = KSh 300, 2 months = KSh 500).
-- If the user still has time left, the new months are added on top of it.
create or replace function public.tw_admin_set_active(p_user uuid, p_active boolean, p_months int default 1)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.tw_is_admin() then
    raise exception 'Admins only' using errcode = '42501';
  end if;
  if p_active and (p_months is null or p_months < 1 or p_months > 12) then
    raise exception 'Choose a plan between 1 and 12 months';
  end if;
  perform public.tw_expire_due(p_user);
  update public.profiles
     set is_active    = p_active,
         activated_at = case when p_active and not is_active then now() else activated_at end,
         plan_months  = case when p_active then p_months else plan_months end,
         expires_at   = case
                          when p_active and is_active and expires_at > now()
                            then expires_at + make_interval(months => p_months)
                          when p_active
                            then now() + make_interval(months => p_months)
                          else expires_at
                        end
   where id = p_user;
  if not found then raise exception 'User not found'; end if;
  -- Activating by hand burns the current code. Deactivating leaves it burned,
  -- so the user needs a NEW code to come back.
  if p_active then
    update public.activation_codes set used = true where user_id = p_user;
  end if;
end $$;

drop function if exists public.tw_admin_new_code(uuid);
-- The code carries the plan: when the user enters it they get p_months of access.
create or replace function public.tw_admin_new_code(p_user uuid, p_months int default 1)
returns text language plpgsql security definer set search_path = '' as $$
declare
  v_code text := public.tw_gen_code();
begin
  if not public.tw_is_admin() then
    raise exception 'Admins only' using errcode = '42501';
  end if;
  if p_months is null or p_months < 1 or p_months > 12 then
    raise exception 'Choose a plan between 1 and 12 months';
  end if;
  if not exists (select 1 from public.profiles where id = p_user) then
    raise exception 'User not found';
  end if;
  insert into public.activation_codes (user_id, code, plan_months) values (p_user, v_code, p_months)
  on conflict (user_id) do update
    set code = excluded.code, plan_months = excluded.plan_months,
        used = false, attempts = 0, issued_at = now();
  return v_code;
end $$;

create or replace function public.tw_admin_logout_device(p_user uuid)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.tw_is_admin() then
    raise exception 'Admins only' using errcode = '42501';
  end if;
  update public.profiles set session_id = null where id = p_user;
  begin
    delete from auth.sessions where user_id = p_user;
  exception when others then null;
  end;
end $$;

-- ---------------------------------------------------------------------
-- Permissions
-- ---------------------------------------------------------------------
revoke execute on function public.tw_gen_code()        from public, anon, authenticated;
revoke execute on function public.tw_handle_new_user() from public, anon, authenticated;
revoke execute on function public.tw_expire_due(uuid)  from public, anon, authenticated;

revoke execute on function
  public.tw_current_session(), public.tw_is_admin(), public.tw_session_ok(),
  public.tw_claim_session(text), public.tw_check_session(), public.tw_release_session(),
  public.tw_activate(text),
  public.tw_admin_list_users(), public.tw_admin_set_active(uuid, boolean, int),
  public.tw_admin_new_code(uuid, int), public.tw_admin_logout_device(uuid)
from public, anon;

grant execute on function
  public.tw_current_session(), public.tw_is_admin(), public.tw_session_ok(),
  public.tw_claim_session(text), public.tw_check_session(), public.tw_release_session(),
  public.tw_activate(text),
  public.tw_admin_list_users(), public.tw_admin_set_active(uuid, boolean, int),
  public.tw_admin_new_code(uuid, int), public.tw_admin_logout_device(uuid)
to authenticated;

-- Realtime: lets a device react instantly when it's activated, deactivated or logged out.
do $$
begin
  alter publication supabase_realtime add table public.profiles;
exception when duplicate_object or undefined_object then null;
end $$;

-- Tell the API to pick up the new/changed functions straight away.
notify pgrst, 'reload schema';

-- ---------------------------------------------------------------------
-- LAST STEP: make yourself admin (sign up on the site first, then run):
-- update public.profiles set is_admin = true where email = 'your-email@example.com';
-- ---------------------------------------------------------------------
