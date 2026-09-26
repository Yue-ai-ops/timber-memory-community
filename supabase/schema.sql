-- Timber Collab initial schema (Supabase PostgreSQL)
-- Apply only to a new project or after reviewing a clean backup. This file does not
-- connect to Supabase and contains no real user, location, or credential data.

begin;

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

create type public.member_role as enum ('member', 'admin');
create type public.submission_kind as enum ('photo', 'story', 'correction', 'shoot');
create type public.submission_privacy as enum ('team', 'private');
create type public.submission_status as enum ('pending', 'needs_info', 'approved', 'rejected');

create table public.members (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null check (char_length(display_name) between 1 and 100),
  role public.member_role not null default 'member',
  active boolean not null default false,
  created_at timestamptz not null default pg_catalog.now()
);

-- Invite tokens are 256-bit random secrets. Only their SHA-256 hashes are stored.
create table public.invite_codes (
  id uuid primary key default gen_random_uuid(),
  label text not null check (char_length(label) between 1 and 100),
  token_hash bytea not null unique,
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default pg_catalog.now(),
  expires_at timestamptz not null,
  use_limit integer not null check (use_limit between 1 and 1000),
  use_count integer not null default 0 check (use_count >= 0 and use_count <= use_limit),
  revoked_at timestamptz,
  constraint invite_codes_future_expiry check (expires_at > created_at)
);

-- Private throttle state. It has no client policies or grants.
create table public.invite_attempts (
  user_id uuid primary key references auth.users(id) on delete cascade,
  window_started_at timestamptz not null,
  attempt_count integer not null check (attempt_count between 1 and 6)
);

create table public.submissions (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null default auth.uid() references auth.users(id) on delete restrict,
  author text not null check (char_length(author) between 1 and 100),
  title text not null check (char_length(title) between 1 and 150),
  story text not null default '' check (char_length(story) <= 10000),
  captured_year text check (captured_year is null or char_length(captured_year) <= 30),
  building_id text check (building_id is null or char_length(building_id) <= 120),
  x real,
  y real,
  kind public.submission_kind not null,
  privacy public.submission_privacy not null default 'team',
  status public.submission_status not null default 'pending',
  review_note text check (review_note is null or char_length(review_note) <= 2000),
  created_at timestamptz not null default pg_catalog.now(),
  updated_at timestamptz not null default pg_catalog.now(),
  revision integer not null default 1 check (revision >= 1),
  constraint submissions_xy_pair check ((x is null) = (y is null)),
  constraint submissions_x_bounds check (x is null or (x >= 0 and x <= 1058)),
  constraint submissions_y_bounds check (y is null or (y >= 0 and y <= 1186))
);

create index submissions_owner_created_idx on public.submissions (owner_id, created_at desc);
create index submissions_team_status_created_idx on public.submissions (status, created_at desc)
  where privacy = 'team';

create table public.submission_reviews (
  id uuid primary key default gen_random_uuid(),
  submission_id uuid not null references public.submissions(id) on delete restrict,
  reviewer_id uuid not null references auth.users(id) on delete restrict,
  prior_status public.submission_status not null,
  new_status public.submission_status not null check (new_status in ('needs_info', 'approved', 'rejected')),
  note text check (note is null or char_length(note) <= 2000),
  submission_revision integer not null check (submission_revision >= 2),
  created_at timestamptz not null default pg_catalog.now()
);
create index submission_reviews_submission_created_idx
  on public.submission_reviews (submission_id, created_at desc);

create table public.assets (
  id uuid primary key default gen_random_uuid(),
  submission_id uuid not null references public.submissions(id) on delete restrict,
  owner_id uuid not null default auth.uid() references auth.users(id) on delete restrict,
  object_path text not null unique,
  filename text not null check (char_length(filename) between 1 and 255),
  mime text not null check (mime in (
    'image/jpeg', 'image/png', 'image/webp', 'image/heic', 'image/heif',
    'video/mp4', 'video/quicktime', 'model/gltf-binary', 'model/gltf+json'
  )),
  bytes bigint not null check (bytes between 1 and 52428800),
  sha256 text not null check (sha256 ~ '^[0-9a-fA-F]{64}$'),
  created_at timestamptz not null default pg_catalog.now(),
  constraint assets_path_matches_owner_submission check (
    object_path like owner_id::text || '/' || submission_id::text || '/%'
    and cardinality(pg_catalog.string_to_array(object_path, '/')) = 3
    and char_length(pg_catalog.split_part(object_path, '/', 3)) > 0
  )
);
create index assets_submission_idx on public.assets (submission_id);
create unique index assets_submission_sha256_uniq on public.assets (submission_id, pg_catalog.lower(sha256));

create table public.map_versions (
  id uuid primary key default gen_random_uuid(),
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default pg_catalog.now(),
  payload jsonb not null check (pg_catalog.jsonb_typeof(payload) = 'object'),
  previous_id uuid references public.map_versions(id) on delete restrict,
  note text check (note is null or char_length(note) <= 2000)
);
create index map_versions_created_idx on public.map_versions (created_at desc);
-- A version chain has at most one child per prior snapshot.
create unique index map_versions_previous_uniq on public.map_versions (previous_id)
  where previous_id is not null;

-- Boolean-only SECURITY DEFINER helpers avoid member-table RLS recursion. The
-- fixed search_path plus qualified object references prevent caller object shadowing.
create or replace function public.is_active_member()
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, pg_temp
as $$
  select exists (
    select 1 from public.members m
    where m.user_id = auth.uid() and m.active
  );
$$;

create or replace function public.is_active_admin()
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, pg_temp
as $$
  select exists (
    select 1 from public.members m
    where m.user_id = auth.uid() and m.active and m.role = 'admin'::public.member_role
  );
$$;

-- Used by storage policies; it reveals only authorization for the caller's object.
create or replace function public.can_read_submission(p_submission_id uuid)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, pg_temp
as $$
  select exists (
    select 1 from public.submissions s
    where s.id = p_submission_id
      and public.is_active_member()
      and (s.privacy = 'team'::public.submission_privacy
           or s.owner_id = auth.uid()
           or public.is_active_admin())
  );
$$;

create or replace function public.can_upload_submission_asset(p_submission_id uuid)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, pg_temp
as $$
  select exists (
    select 1 from public.submissions s
    where s.id = p_submission_id
      and s.owner_id = auth.uid()
      and s.status in ('pending'::public.submission_status, 'needs_info'::public.submission_status)
      and public.is_active_member()
  );
$$;

create or replace function public.can_delete_submission_asset(p_submission_id uuid)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, pg_temp
as $$
  select exists (
    select 1 from public.submissions s
    where s.id = p_submission_id
      and s.owner_id = auth.uid()
      and s.status = 'pending'::public.submission_status
      and public.is_active_member()
  );
$$;

-- The direct submissions UPDATE grant is intentionally absent. All edits pass
-- through this row-locking RPC so a stale client cannot overwrite a newer revision.
create or replace function public.update_submission(
  p_id uuid,
  p_expected_revision integer,
  p_author text,
  p_title text,
  p_story text,
  p_captured_year text,
  p_building_id text,
  p_x real,
  p_y real,
  p_kind public.submission_kind,
  p_privacy public.submission_privacy
)
returns public.submissions
language plpgsql
security definer
set search_path = pg_catalog, pg_temp
as $$
declare
  v_row public.submissions;
begin
  if auth.uid() is null or not public.is_active_member() then
    raise exception using errcode = '42501', message = 'active member required';
  end if;
  select s.* into v_row from public.submissions s where s.id = p_id for update;
  if not found then
    raise exception using errcode = 'P0002', message = 'submission not found';
  end if;
  if v_row.owner_id <> auth.uid() then
    raise exception using errcode = '42501', message = 'owner required';
  end if;
  if v_row.status not in ('pending'::public.submission_status, 'needs_info'::public.submission_status) then
    raise exception using errcode = '42501', message = 'submission is not editable';
  end if;
  if v_row.revision is distinct from p_expected_revision then
    raise exception using errcode = '40001', message = 'revision conflict';
  end if;

  update public.submissions s set
    author = p_author,
    title = p_title,
    story = p_story,
    captured_year = p_captured_year,
    building_id = p_building_id,
    x = p_x,
    y = p_y,
    kind = p_kind,
    privacy = p_privacy,
    updated_at = pg_catalog.now(),
    revision = s.revision + 1
  where s.id = p_id
  returning s.* into v_row;
  return v_row;
end;
$$;

create or replace function public.review_submission(
  p_id uuid,
  p_expected_revision integer,
  p_status public.submission_status,
  p_review_note text
)
returns public.submissions
language plpgsql
security definer
set search_path = pg_catalog, pg_temp
as $$
declare
  v_row public.submissions;
  v_old_status public.submission_status;
begin
  if auth.uid() is null or not public.is_active_admin() then
    raise exception using errcode = '42501', message = 'active admin required';
  end if;
  if p_status not in ('needs_info'::public.submission_status, 'approved'::public.submission_status, 'rejected'::public.submission_status) then
    raise exception using errcode = '22023', message = 'invalid review status';
  end if;
  if p_review_note is not null and char_length(p_review_note) > 2000 then
    raise exception using errcode = '22023', message = 'review note too long';
  end if;

  select s.* into v_row from public.submissions s where s.id = p_id for update;
  if not found then
    raise exception using errcode = 'P0002', message = 'submission not found';
  end if;
  if v_row.revision is distinct from p_expected_revision then
    raise exception using errcode = '40001', message = 'revision conflict';
  end if;
  if v_row.status not in ('pending'::public.submission_status, 'needs_info'::public.submission_status) then
    raise exception using errcode = '42501', message = 'submission is not reviewable';
  end if;

  v_old_status := v_row.status;
  update public.submissions s set
    status = p_status,
    review_note = p_review_note,
    updated_at = pg_catalog.now(),
    revision = s.revision + 1
  where s.id = p_id
  returning s.* into v_row;

  insert into public.submission_reviews (
    submission_id, reviewer_id, prior_status, new_status, note, submission_revision
  ) values (
    v_row.id, auth.uid(), v_old_status, v_row.status, p_review_note, v_row.revision
  );
  return v_row;
end;
$$;

create or replace function public.register_asset(
  p_submission_id uuid,
  p_object_path text,
  p_filename text,
  p_mime text,
  p_bytes bigint,
  p_sha256 text
)
returns public.assets
language plpgsql
security definer
set search_path = pg_catalog, pg_temp
as $$
declare
  v_row public.assets;
  v_submission public.submissions;
  v_existing public.assets;
begin
  if auth.uid() is null or not public.is_active_member() then
    raise exception using errcode = '42501', message = 'active member required';
  end if;
  -- Serialize asset registration with review/edit RPCs on the submission row.
  select s.* into v_submission
  from public.submissions s
  where s.id = p_submission_id
  for update;
  if not found then
    raise exception using errcode = 'P0002', message = 'submission not found';
  end if;
  if v_submission.owner_id <> auth.uid()
     or v_submission.status not in ('pending'::public.submission_status, 'needs_info'::public.submission_status) then
    raise exception using errcode = '42501', message = 'owner of editable submission required';
  end if;
  if p_object_path is null
     or p_object_path not like auth.uid()::text || '/' || p_submission_id::text || '/%'
     or cardinality(pg_catalog.string_to_array(p_object_path, '/')) <> 3 then
    raise exception using errcode = '22023', message = 'object path must be uid/submission_id/file';
  end if;

  if not exists (
    select 1 from storage.objects o
    where o.bucket_id = 'timber-private' and o.name = p_object_path
  ) then
    raise exception using errcode = 'P0002', message = 'uploaded storage object not found';
  end if;

  -- Retries of the same registration are idempotent. A path/hash collision with
  -- different metadata is rejected instead of silently changing the record.
  select a.* into v_existing
  from public.assets a
  where a.object_path = p_object_path
     or (a.submission_id = p_submission_id and pg_catalog.lower(a.sha256) = pg_catalog.lower(p_sha256))
  for update;
  if found then
    if v_existing.submission_id = p_submission_id
       and v_existing.owner_id = auth.uid()
       and v_existing.object_path = p_object_path
       and v_existing.filename = p_filename
       and v_existing.mime = p_mime
       and v_existing.bytes = p_bytes
       and pg_catalog.lower(v_existing.sha256) = pg_catalog.lower(p_sha256) then
      return v_existing;
    end if;
    raise exception using errcode = '23505', message = 'asset path or submission hash already registered';
  end if;

  insert into public.assets (submission_id, owner_id, object_path, filename, mime, bytes, sha256)
  values (p_submission_id, auth.uid(), p_object_path, p_filename, p_mime, p_bytes, pg_catalog.lower(p_sha256))
  returning * into v_row;
  return v_row;
end;
$$;

create or replace function public.create_map_version(
  p_payload jsonb,
  p_note text,
  p_previous_id uuid default null
)
returns public.map_versions
language plpgsql
security definer
set search_path = pg_catalog, pg_temp
as $$
declare
  v_row public.map_versions;
  v_head uuid;
  v_head_count integer;
begin
  if auth.uid() is null or not public.is_active_admin() then
    raise exception using errcode = '42501', message = 'active admin required';
  end if;
  -- Serialize head selection and prevent concurrent admins from forking the
  -- version chain. The partial unique index is a second line of defense.
  perform pg_catalog.pg_advisory_xact_lock(741926001::bigint);
  select pg_catalog.count(*), pg_catalog.min(m.id::text)::uuid
    into v_head_count, v_head
  from public.map_versions m
  where not exists (
    select 1 from public.map_versions child where child.previous_id = m.id
  );
  if v_head_count > 1 then
    raise exception using errcode = '55000', message = 'map version chain has multiple heads';
  end if;
  if p_previous_id is distinct from v_head then
    raise exception using errcode = '40001', message = 'map version head conflict';
  end if;
  insert into public.map_versions (created_by, payload, previous_id, note)
  values (auth.uid(), p_payload, p_previous_id, p_note)
  returning * into v_row;
  return v_row;
end;
$$;

-- Admin-only invite creation. The plaintext is returned once and never persisted.
create or replace function public.create_invite(
  p_label text,
  p_days integer default 7,
  p_max_uses integer default 20
)
returns text
language plpgsql
security definer
set search_path = pg_catalog, pg_temp
as $$
declare
  v_code text;
begin
  if auth.uid() is null or not public.is_active_admin() then
    raise exception using errcode = '42501', message = 'active admin required';
  end if;
  if p_label is null or char_length(p_label) not between 1 and 100
     or p_days is null or p_days not between 1 and 90
     or p_max_uses is null or p_max_uses not between 1 and 1000 then
    raise exception using errcode = '22023', message = 'invalid invite parameters';
  end if;
  v_code := pg_catalog.encode(extensions.gen_random_bytes(32), 'hex');
  insert into public.invite_codes (label, token_hash, created_by, expires_at, use_limit)
  values (
    p_label,
    extensions.digest(pg_catalog.convert_to(v_code, 'UTF8'), 'sha256'),
    auth.uid(),
    pg_catalog.now() + pg_catalog.make_interval(days => p_days),
    p_max_uses
  );
  return v_code;
end;
$$;

-- Failures return JSON rather than raising so the per-user attempt counter commits.
-- The invite row is locked while checking and consuming a use to prevent overuse.
create or replace function public.redeem_invite(
  p_code text,
  p_display_name text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, pg_temp
as $$
declare
  v_uid uuid := auth.uid();
  v_attempt_count integer;
  v_invite public.invite_codes;
  v_code text;
  v_member public.members;
begin
  if v_uid is null then
    return pg_catalog.jsonb_build_object('success', false, 'reason', 'authentication_required');
  end if;

  -- Serialize two simultaneous redemptions from the same device UID as well as
  -- serializing on the invite row below. Hash collisions only cause extra waiting.
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext(v_uid::text)::bigint);
  select m.* into v_member from public.members m where m.user_id = v_uid for update;
  if found and v_member.active then
    return pg_catalog.jsonb_build_object('success', true, 'already_member', true, 'display_name', v_member.display_name);
  end if;

  insert into public.invite_attempts as ia (user_id, window_started_at, attempt_count)
  values (v_uid, pg_catalog.now(), 1)
  on conflict (user_id) do update set
    window_started_at = case
      when ia.window_started_at <= pg_catalog.now() - interval '15 minutes' then pg_catalog.now()
      else ia.window_started_at
    end,
    attempt_count = case
      when ia.window_started_at <= pg_catalog.now() - interval '15 minutes' then 1
      else least(6, ia.attempt_count + 1)
    end
  returning attempt_count into v_attempt_count;

  if v_attempt_count > 5 then
    return pg_catalog.jsonb_build_object('success', false, 'reason', 'rate_limited');
  end if;
  if p_display_name is null or char_length(p_display_name) not between 1 and 100 then
    return pg_catalog.jsonb_build_object('success', false, 'reason', 'invalid_input');
  end if;
  v_code := pg_catalog.lower(pg_catalog.btrim(coalesce(p_code, '')));
  if v_code !~ '^[0-9a-f]{64}$' then
    return pg_catalog.jsonb_build_object('success', false, 'reason', 'invalid_or_expired');
  end if;

  select i.* into v_invite
  from public.invite_codes i
  where i.token_hash = extensions.digest(pg_catalog.convert_to(v_code, 'UTF8'), 'sha256')
  for update;
  if not found or v_invite.revoked_at is not null
     or v_invite.expires_at <= pg_catalog.now()
     or v_invite.use_count >= v_invite.use_limit then
    return pg_catalog.jsonb_build_object('success', false, 'reason', 'invalid_or_expired');
  end if;
  if v_member.user_id is not null and v_member.role = 'admin'::public.member_role then
    return pg_catalog.jsonb_build_object('success', false, 'reason', 'contact_admin');
  end if;

  update public.invite_codes set use_count = use_count + 1 where id = v_invite.id;
  if v_member.user_id is null then
    insert into public.members (user_id, display_name, role, active)
    values (v_uid, p_display_name, 'member', true);
  else
    -- Existing inactive rows may only be reactivated as members; never preserve
    -- an inactive admin role when joining through an invitation.
    update public.members set display_name = p_display_name, active = true, role = 'member'
    where user_id = v_uid;
  end if;
  return pg_catalog.jsonb_build_object('success', true, 'already_member', false, 'display_name', p_display_name);
end;
$$;

create or replace function public.revoke_invite(p_invite_id uuid)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, pg_temp
as $$
begin
  if auth.uid() is null or not public.is_active_admin() then
    raise exception using errcode = '42501', message = 'active admin required';
  end if;
  update public.invite_codes set revoked_at = pg_catalog.now()
  where id = p_invite_id and revoked_at is null;
  return found;
end;
$$;

-- Append-only records are protected even from accidental privileged UPDATE/DELETE.
create or replace function public.reject_append_only_mutation()
returns trigger
language plpgsql
set search_path = pg_catalog, pg_temp
as $$
begin
  raise exception using errcode = '42501', message = 'append-only table';
end;
$$;
create trigger submission_reviews_append_only
  before update or delete on public.submission_reviews
  for each row execute function public.reject_append_only_mutation();
create trigger map_versions_append_only
  before update or delete on public.map_versions
  for each row execute function public.reject_append_only_mutation();

alter table public.members enable row level security;
alter table public.invite_codes enable row level security;
alter table public.invite_attempts enable row level security;
alter table public.submissions enable row level security;
alter table public.submission_reviews enable row level security;
alter table public.assets enable row level security;
alter table public.map_versions enable row level security;

create policy members_read_self on public.members
  for select to authenticated using (user_id = auth.uid());
create policy invite_codes_read_admin on public.invite_codes
  for select to authenticated using (public.is_active_admin());
create policy submissions_read_visible on public.submissions
  for select to authenticated using (
    public.is_active_member()
    and (privacy = 'team'::public.submission_privacy or owner_id = auth.uid() or public.is_active_admin())
  );
create policy submissions_insert_own_pending on public.submissions
  for insert to authenticated with check (
    public.is_active_member() and owner_id = auth.uid()
    and status = 'pending'::public.submission_status and revision = 1
  );
create policy reviews_read_visible_submission on public.submission_reviews
  for select to authenticated using (public.can_read_submission(submission_id));
create policy assets_read_visible_submission on public.assets
  for select to authenticated using (public.can_read_submission(submission_id));
create policy assets_delete_own_pending on public.assets
  for delete to authenticated using (
    owner_id = auth.uid() and public.can_delete_submission_asset(submission_id)
  );
create policy map_versions_read_member on public.map_versions
  for select to authenticated using (public.is_active_member());

-- No table access for anon. Authenticated receives only the operations needed by
-- the app. In particular, no direct UPDATE on submissions and no direct writes to
-- membership, review history, or map snapshots.
revoke all on table public.members, public.submissions, public.submission_reviews,
  public.assets, public.map_versions from anon, authenticated;
revoke all on table public.invite_codes, public.invite_attempts from anon, authenticated;
grant select on public.members, public.submissions, public.submission_reviews,
  public.assets, public.map_versions to authenticated;
grant select on public.invite_codes to authenticated;
grant insert (id, author, title, story, captured_year, building_id, x, y, kind, privacy)
  on public.submissions to authenticated;
grant delete on public.assets to authenticated;

-- PostgreSQL grants EXECUTE on new functions to PUBLIC by default. Revoke that
-- default explicitly; authenticated access is limited to application RPCs and
-- boolean helpers needed by RLS. Internal trigger function remains uncallable.
revoke all on function public.is_active_member() from public, anon, authenticated;
revoke all on function public.is_active_admin() from public, anon, authenticated;
revoke all on function public.can_read_submission(uuid) from public, anon, authenticated;
revoke all on function public.can_upload_submission_asset(uuid) from public, anon, authenticated;
revoke all on function public.can_delete_submission_asset(uuid) from public, anon, authenticated;
revoke all on function public.update_submission(uuid, integer, text, text, text, text, text, real, real, public.submission_kind, public.submission_privacy) from public, anon, authenticated;
revoke all on function public.review_submission(uuid, integer, public.submission_status, text) from public, anon, authenticated;
revoke all on function public.register_asset(uuid, text, text, text, bigint, text) from public, anon, authenticated;
revoke all on function public.create_map_version(jsonb, text, uuid) from public, anon, authenticated;
revoke all on function public.create_invite(text, integer, integer) from public, anon, authenticated;
revoke all on function public.redeem_invite(text, text) from public, anon, authenticated;
revoke all on function public.revoke_invite(uuid) from public, anon, authenticated;
revoke all on function public.reject_append_only_mutation() from public, anon, authenticated;
grant execute on function public.is_active_member() to authenticated;
grant execute on function public.is_active_admin() to authenticated;
grant execute on function public.can_read_submission(uuid) to authenticated;
grant execute on function public.can_upload_submission_asset(uuid) to authenticated;
grant execute on function public.can_delete_submission_asset(uuid) to authenticated;
grant execute on function public.update_submission(uuid, integer, text, text, text, text, text, real, real, public.submission_kind, public.submission_privacy) to authenticated;
grant execute on function public.review_submission(uuid, integer, public.submission_status, text) to authenticated;
grant execute on function public.register_asset(uuid, text, text, text, bigint, text) to authenticated;
grant execute on function public.create_map_version(jsonb, text, uuid) to authenticated;
grant execute on function public.create_invite(text, integer, integer) to authenticated;
grant execute on function public.redeem_invite(text, text) to authenticated;
grant execute on function public.revoke_invite(uuid) to authenticated;

-- Private storage. The project Storage API enforces the 50 MiB object limit and
-- MIME allowlist. Object name must be exactly uid/submission_uuid/one_filename.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'timber-private', 'timber-private', false, 52428800,
  array['image/jpeg','image/png','image/webp','image/heic','image/heif',
        'video/mp4','video/quicktime','model/gltf-binary','model/gltf+json']
)
on conflict (id) do update set
  name = excluded.name,
  public = false,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

create policy timber_storage_read_visible on storage.objects
  for select to authenticated using (
    bucket_id = 'timber-private'
    and cardinality(storage.foldername(name)) = 2
    and case
      when pg_catalog.split_part(name, '/', 2) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
      then public.can_read_submission(pg_catalog.split_part(name, '/', 2)::uuid)
      else false
    end
  );
create policy timber_storage_upload_owner_editable on storage.objects
  for insert to authenticated with check (
    bucket_id = 'timber-private'
    and cardinality(storage.foldername(name)) = 2
    and (storage.foldername(name))[1] = auth.uid()::text
    and case
      when pg_catalog.split_part(name, '/', 2) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
      then public.can_upload_submission_asset(pg_catalog.split_part(name, '/', 2)::uuid)
      else false
    end
  );
create policy timber_storage_delete_owner_pending on storage.objects
  for delete to authenticated using (
    bucket_id = 'timber-private'
    and cardinality(storage.foldername(name)) = 2
    and (storage.foldername(name))[1] = auth.uid()::text
    and case
      when pg_catalog.split_part(name, '/', 2) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
      then public.can_delete_submission_asset(pg_catalog.split_part(name, '/', 2)::uuid)
      else false
    end
  );

commit;
