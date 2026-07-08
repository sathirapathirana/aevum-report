-- ============================================================
-- Aevum Protocol — Patient Portal Database Setup (v2)
-- Covers Phase 1–3 (+ supports Phase 4 in the app layer)
-- Run this in Supabase: Project → SQL Editor → New Query
-- Safe to run even if you already ran the original measurements-only script.
-- ============================================================

-- ── Phase 1: Profiles & tiering ──────────────────────────────

create table if not exists profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  subscription_tier text not null default 'free' check (subscription_tier in ('free','paid')),
  next_visit_date date,
  created_at timestamptz not null default now()
);

alter table profiles enable row level security;

-- Staff table: lists which auth users are clinicians (you / Dr. Kawya)
create table if not exists staff (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  role text not null default 'clinician',
  created_at timestamptz not null default now()
);

alter table staff enable row level security;

-- Helper function: is the currently logged-in user a staff member?
create or replace function is_staff()
returns boolean as $$
  select exists (select 1 from staff where staff.id = auth.uid());
$$ language sql security definer stable;

-- Auto-create a profile row the moment someone signs up
create or replace function handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, full_name)
  values (new.id, new.raw_user_meta_data->>'full_name')
  on conflict (id) do nothing;
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function handle_new_user();

-- Guard: only staff can change subscription_tier or next_visit_date,
-- even if a patient's own row-update request slips through.
create or replace function prevent_patient_tier_change()
returns trigger as $$
begin
  if not is_staff() then
    new.subscription_tier := old.subscription_tier;
    new.next_visit_date := old.next_visit_date;
  end if;
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists guard_profile_update on profiles;
create trigger guard_profile_update
  before update on profiles
  for each row execute function prevent_patient_tier_change();

drop policy if exists "Staff can view own staff row" on staff;
create policy "Staff can view own staff row" on staff for select using (auth.uid() = id);

drop policy if exists "Patients and staff can view profiles" on profiles;
create policy "Patients and staff can view profiles" on profiles
  for select using (auth.uid() = id or is_staff());

drop policy if exists "Patients can update own profile" on profiles;
create policy "Patients can update own profile" on profiles
  for update using (auth.uid() = id or is_staff());
-- (tier & next_visit_date are still protected by the trigger above
--  even though this policy allows the row-level update)

-- ── Phase 2: Plans & visit notes ─────────────────────────────

create table if not exists plans (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references auth.users(id) on delete cascade,
  content text not null default '',
  status text not null default 'ai_draft' check (status in ('ai_draft','reviewed')),
  reviewed_by uuid references auth.users(id),
  updated_at timestamptz not null default now()
);

alter table plans enable row level security;

drop policy if exists "View own plan" on plans;
create policy "View own plan" on plans for select using (auth.uid() = patient_id or is_staff());
drop policy if exists "Staff manage plans" on plans;
create policy "Staff manage plans" on plans for all using (is_staff());

create table if not exists visit_notes (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references auth.users(id) on delete cascade,
  visit_date date not null default current_date,
  content text not null,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);

alter table visit_notes enable row level security;

drop policy if exists "Paid patients view own notes" on visit_notes;
create policy "Paid patients view own notes" on visit_notes for select
  using (
    is_staff()
    or (auth.uid() = patient_id and exists (
      select 1 from profiles p where p.id = auth.uid() and p.subscription_tier = 'paid'
    ))
  );
drop policy if exists "Staff manage notes" on visit_notes;
create policy "Staff manage notes" on visit_notes for all using (is_staff());

-- ── Phase 3: Blood work & medications ────────────────────────

create table if not exists blood_work (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references auth.users(id) on delete cascade,
  test_name text not null,
  value numeric not null,
  unit text,
  test_date date not null default current_date,
  entered_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);

alter table blood_work enable row level security;

drop policy if exists "Paid patients manage own blood work" on blood_work;
create policy "Paid patients manage own blood work" on blood_work for all
  using (
    auth.uid() = patient_id and exists (
      select 1 from profiles p where p.id = auth.uid() and p.subscription_tier = 'paid'
    )
  )
  with check (
    auth.uid() = patient_id and exists (
      select 1 from profiles p where p.id = auth.uid() and p.subscription_tier = 'paid'
    )
  );
drop policy if exists "Staff manage all blood work" on blood_work;
create policy "Staff manage all blood work" on blood_work for all using (is_staff());

create table if not exists medications (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  dosage text,
  frequency text,
  active boolean not null default true,
  added_at timestamptz not null default now()
);

alter table medications enable row level security;

drop policy if exists "Paid patients manage own medications" on medications;
create policy "Paid patients manage own medications" on medications for all
  using (
    auth.uid() = patient_id and exists (
      select 1 from profiles p where p.id = auth.uid() and p.subscription_tier = 'paid'
    )
  )
  with check (
    auth.uid() = patient_id and exists (
      select 1 from profiles p where p.id = auth.uid() and p.subscription_tier = 'paid'
    )
  );
drop policy if exists "Staff manage all medications" on medications;
create policy "Staff manage all medications" on medications for all using (is_staff());

-- ── Measurements (from the original setup — included so this
--    single script is enough on its own) ─────────────────────

create table if not exists measurements (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid references auth.users(id) not null,
  metric text not null,
  value numeric not null,
  recorded_at date not null default current_date,
  created_at timestamptz not null default now()
);

create index if not exists idx_measurements_patient_metric
  on measurements (patient_id, metric, recorded_at);

alter table measurements enable row level security;

drop policy if exists "Patients can view own measurements" on measurements;
create policy "Patients can view own measurements" on measurements for select
  using (auth.uid() = patient_id or is_staff());
drop policy if exists "Patients can insert own measurements" on measurements;
create policy "Patients can insert own measurements" on measurements for insert
  with check (auth.uid() = patient_id);
drop policy if exists "Patients can delete own measurements" on measurements;
create policy "Patients can delete own measurements" on measurements for delete
  using (auth.uid() = patient_id);

-- ============================================================
-- ONE-TIME MANUAL STEP: making yourself (and Dr. Kawya) staff
-- Run this AFTER you've both signed up once via the normal login
-- page, so your auth.users rows already exist. Replace the emails.
-- ============================================================
-- insert into staff (id, full_name, role)
-- select id, 'Dr. Sathira', 'clinician' from auth.users where email = 'you@example.com';
-- insert into staff (id, full_name, role)
-- select id, 'Dr. Kawya', 'clinician' from auth.users where email = 'kawya@example.com';
