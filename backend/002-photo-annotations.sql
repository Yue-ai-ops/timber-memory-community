begin;
-- Each contributor owns a separate account of a photo. No shared last-writer-wins.
create table public.photo_annotations (
 asset_id uuid not null references public.assets(id) on delete cascade,
 annotator_id uuid not null references public.members(user_id),
 annotator_name text not null,
 title text not null check(char_length(title) between 1 and 150),
 category text not null check(category in ('building','road','people','life','aerial','other','unknown')),
 captured_year text not null default '' check(char_length(captured_year)<=30),
 place text not null default '' check(char_length(place)<=120),
 x real, y real,
 source text not null default '' check(char_length(source)<=200),
 confidence text not null check(confidence in ('certain','approximate','unknown')),
 notes text not null default '' check(char_length(notes)<=4000),
 revision integer not null default 1,
 updated_at timestamptz not null default now(),
 primary key(asset_id,annotator_id),
 check((x is null)=(y is null)),
 check(x is null or (x>=0 and x<=1058 and y>=0 and y<=1186))
);
alter table public.photo_annotations enable row level security;
create policy annotation_read on public.photo_annotations for select to authenticated using (
 exists(select 1 from public.assets a where a.id=asset_id and public.can_read_submission(a.submission_id))
);
revoke all on public.photo_annotations from anon,authenticated;
grant select on public.photo_annotations to authenticated;
create function public.save_photo_annotation(p_asset_id uuid,p_expected_revision integer,p_value jsonb)
returns public.photo_annotations language plpgsql security definer set search_path=pg_catalog,public as $$
declare n text; r public.photo_annotations;
begin
 if not public.is_active_member() or not exists(select 1 from public.assets a where a.id=p_asset_id and public.can_read_submission(a.submission_id)) then raise exception '没有这张资料的访问权限'; end if;
 select display_name into n from public.members where user_id=auth.uid();
 -- Lock the asset, including the first annotation, to prevent concurrent insert races.
 perform 1 from public.assets where id=p_asset_id for update;
 select * into r from public.photo_annotations where asset_id=p_asset_id and annotator_id=auth.uid() for update;
 if coalesce(r.revision,0)<>p_expected_revision then raise exception '标注已更新，请重新打开照片后再保存'; end if;
 insert into public.photo_annotations(asset_id,annotator_id,annotator_name,title,category,captured_year,place,x,y,source,confidence,notes,revision)
 values(p_asset_id,auth.uid(),n,btrim(p_value->>'title'),p_value->>'category',coalesce(p_value->>'captured_year',''),coalesce(p_value->>'place',''),(p_value->>'x')::real,(p_value->>'y')::real,coalesce(p_value->>'source',''),p_value->>'confidence',coalesce(p_value->>'notes',''),1)
 on conflict(asset_id,annotator_id) do update set title=excluded.title,category=excluded.category,captured_year=excluded.captured_year,place=excluded.place,x=excluded.x,y=excluded.y,source=excluded.source,confidence=excluded.confidence,notes=excluded.notes,annotator_name=n,revision=photo_annotations.revision+1,updated_at=now()
 returning * into r; return r;
end $$;
create function public.bind_submission_author() returns trigger language plpgsql security definer set search_path=pg_catalog,public as $$
begin
 select display_name into new.author from public.members where user_id=new.owner_id;
 if new.author is null then raise exception '请先加入共创'; end if;
 return new;
end $$;
create trigger bind_submission_author before insert or update of author on public.submissions for each row execute function public.bind_submission_author();
create function public.community_storage_usage() returns jsonb language plpgsql security definer set search_path=pg_catalog,public as $$
begin
 if not public.is_active_admin() then raise exception '仅整理者可查看容量'; end if;
 return (select jsonb_build_object('files',count(*),'bytes',coalesce(sum((metadata->>'size')::bigint),0),'checked_at',now()) from storage.objects where bucket_id='timber-private');
end $$;
revoke all on function public.save_photo_annotation(uuid,integer,jsonb),public.bind_submission_author(),public.community_storage_usage() from public,anon,authenticated;
grant execute on function public.save_photo_annotation(uuid,integer,jsonb),public.community_storage_usage() to authenticated;
notify pgrst,'reload schema';
commit;
