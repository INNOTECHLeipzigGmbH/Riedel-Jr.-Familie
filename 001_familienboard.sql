-- Familienboard: Tabellen + Funktionen (Supabase-Projekt "Protokoll", Praefix fb_)
-- Zugriff ausschliesslich ueber SECURITY-DEFINER-Funktionen mit persoenlichem Zugangscode (Token).
-- RLS ist aktiv und es gibt bewusst KEINE Policies: anon kann Tabellen nicht direkt lesen/schreiben.

create table if not exists fb_personen (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  rolle text not null check (rolle in ('inhaber','bearbeiten','mitmachen','ansehen')),
  token_hash text not null unique,
  aktiv boolean not null default true,
  erstellt timestamptz not null default now()
);

create table if not exists fb_bereiche (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  icon text not null default 'haus',
  pos int not null default 0,
  erstellt timestamptz not null default now()
);

create table if not exists fb_zugriff (
  person_id uuid not null references fb_personen(id) on delete cascade,
  bereich_id uuid not null references fb_bereiche(id) on delete cascade,
  primary key (person_id, bereich_id)
);

create table if not exists fb_themen (
  id uuid primary key default gen_random_uuid(),
  bereich_id uuid not null references fb_bereiche(id) on delete cascade,
  titel text not null,
  status text not null default 'laeuft' check (status in ('dringend','wartet','laeuft','erledigt')),
  naechster_schritt text,
  faellig date,
  zustaendig_id uuid references fb_personen(id) on delete set null,
  firma text,
  wiederholung text check (wiederholung in ('monatlich','vierteljaehrlich','halbjaehrlich','jaehrlich')),
  notiz text,
  links jsonb not null default '[]'::jsonb,
  erledigt_am date,
  erstellt_von uuid references fb_personen(id) on delete set null,
  erstellt timestamptz not null default now(),
  geaendert timestamptz not null default now()
);
create index if not exists fb_themen_bereich_idx on fb_themen(bereich_id);

create table if not exists fb_verlauf (
  id uuid primary key default gen_random_uuid(),
  thema_id uuid not null references fb_themen(id) on delete cascade,
  person_id uuid references fb_personen(id) on delete set null,
  text text not null,
  erstellt timestamptz not null default now()
);
create index if not exists fb_verlauf_thema_idx on fb_verlauf(thema_id, erstellt desc);

alter table fb_personen enable row level security;
alter table fb_bereiche enable row level security;
alter table fb_zugriff enable row level security;
alter table fb_themen enable row level security;
alter table fb_verlauf enable row level security;
revoke all on fb_personen, fb_bereiche, fb_zugriff, fb_themen, fb_verlauf from anon, authenticated, public;

-- ---------- Hilfsfunktionen (nicht direkt aufrufbar) ----------
create or replace function fb_hash(p_token text) returns text
language sql immutable set search_path = public as
$$ select encode(sha256(convert_to(coalesce(p_token,''), 'utf8')), 'hex') $$;

create or replace function fb_auth(p_token text) returns fb_personen
language plpgsql security definer set search_path = public as $$
declare p fb_personen;
begin
  select * into p from fb_personen where token_hash = fb_hash(p_token) and aktiv;
  if not found then raise exception 'unauthorized'; end if;
  return p;
end $$;

create or replace function fb_darf(p fb_personen, b uuid) returns boolean
language sql security definer stable set search_path = public as
$$ select p.rolle = 'inhaber' or exists (select 1 from fb_zugriff z where z.person_id = p.id and z.bereich_id = b) $$;

create or replace function fb_neues_token() returns text
language sql volatile set search_path = public as
$$ select replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '') $$;

create or replace function fb_status_label(s text) returns text
language sql immutable set search_path = public as
$$ select case s when 'dringend' then 'Handlungsbedarf' when 'wartet' then 'Wartet' when 'laeuft' then 'Läuft' when 'erledigt' then 'Erledigt' else s end $$;

-- ---------- Laden ----------
create or replace function fb_laden(p_token text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare p fb_personen; res jsonb;
begin
  p := fb_auth(p_token);
  select jsonb_build_object(
    'me', jsonb_build_object('id', p.id, 'name', p.name, 'rolle', p.rolle),
    'bereiche', coalesce((select jsonb_agg(to_jsonb(b) order by b.pos, b.name) from fb_bereiche b where fb_darf(p, b.id)), '[]'::jsonb),
    'themen', coalesce((select jsonb_agg(to_jsonb(t) order by t.faellig nulls last, t.titel) from fb_themen t where fb_darf(p, t.bereich_id)), '[]'::jsonb),
    'personen', coalesce((select jsonb_agg(jsonb_build_object(
        'id', x.id, 'name', x.name,
        'rolle', case when p.rolle = 'inhaber' then x.rolle else null end,
        'bereiche', case when p.rolle = 'inhaber' then coalesce((select jsonb_agg(z.bereich_id) from fb_zugriff z where z.person_id = x.id), '[]'::jsonb) else null end
      ) order by x.erstellt) from fb_personen x where x.aktiv), '[]'::jsonb)
  ) into res;
  return res;
end $$;

-- ---------- Themen ----------
create or replace function fb_thema_speichern(p_token text, p_id uuid, p_data jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  p fb_personen; t fb_themen; v_new text; v_next date; v_iv interval; n int := 0; res jsonb;
begin
  p := fb_auth(p_token);
  if p_id is null then
    if p.rolle not in ('inhaber','bearbeiten') then raise exception 'forbidden'; end if;
    if not fb_darf(p, (p_data->>'bereich_id')::uuid) then raise exception 'forbidden'; end if;
    insert into fb_themen(bereich_id, titel, status, naechster_schritt, faellig, zustaendig_id, firma, wiederholung, notiz, links, erstellt_von)
    values ((p_data->>'bereich_id')::uuid,
            coalesce(nullif(trim(p_data->>'titel'), ''), 'Neues Thema'),
            coalesce(nullif(p_data->>'status', ''), 'laeuft'),
            nullif(p_data->>'naechster_schritt', ''),
            nullif(p_data->>'faellig', '')::date,
            nullif(p_data->>'zustaendig_id', '')::uuid,
            nullif(p_data->>'firma', ''),
            nullif(p_data->>'wiederholung', ''),
            nullif(p_data->>'notiz', ''),
            coalesce(p_data->'links', '[]'::jsonb),
            p.id)
    returning * into t;
    insert into fb_verlauf(thema_id, person_id, text) values (t.id, p.id, 'Thema angelegt');
    return to_jsonb(t);
  end if;

  select * into t from fb_themen where id = p_id;
  if not found or not fb_darf(p, t.bereich_id) then raise exception 'forbidden'; end if;
  if p.rolle = 'ansehen' then raise exception 'forbidden'; end if;

  if p.rolle in ('inhaber','bearbeiten') then
    update fb_themen set
      titel             = case when p_data ? 'titel' then coalesce(nullif(trim(p_data->>'titel'), ''), titel) else titel end,
      naechster_schritt = case when p_data ? 'naechster_schritt' then nullif(p_data->>'naechster_schritt', '') else naechster_schritt end,
      faellig           = case when p_data ? 'faellig' then nullif(p_data->>'faellig', '')::date else faellig end,
      zustaendig_id     = case when p_data ? 'zustaendig_id' then nullif(p_data->>'zustaendig_id', '')::uuid else zustaendig_id end,
      firma             = case when p_data ? 'firma' then nullif(p_data->>'firma', '') else firma end,
      wiederholung      = case when p_data ? 'wiederholung' then nullif(p_data->>'wiederholung', '') else wiederholung end,
      notiz             = case when p_data ? 'notiz' then nullif(p_data->>'notiz', '') else notiz end,
      links             = case when p_data ? 'links' then coalesce(p_data->'links', '[]'::jsonb) else links end,
      geaendert         = now()
    where id = p_id returning * into t;
  end if;

  v_new := nullif(p_data->>'status', '');
  if v_new is not null and v_new <> t.status then
    if v_new = 'erledigt' and t.wiederholung is not null then
      v_iv := case t.wiederholung when 'monatlich' then interval '1 month' when 'vierteljaehrlich' then interval '3 months'
                                  when 'halbjaehrlich' then interval '6 months' else interval '1 year' end;
      v_next := coalesce(t.faellig, current_date);
      loop
        v_next := (v_next + v_iv)::date; n := n + 1;
        exit when v_next >= current_date or n > 240;
      end loop;
      update fb_themen set status = 'laeuft', faellig = v_next, erledigt_am = null, geaendert = now() where id = p_id returning * into t;
      insert into fb_verlauf(thema_id, person_id, text)
        values (p_id, p.id, 'Erledigt, wiederholt sich: nächste Fälligkeit ' || to_char(v_next, 'DD.MM.YYYY'));
    else
      update fb_themen set status = v_new,
        erledigt_am = case when v_new = 'erledigt' then current_date else null end,
        geaendert = now()
      where id = p_id returning * into t;
      insert into fb_verlauf(thema_id, person_id, text)
        values (p_id, p.id, 'Status auf „' || fb_status_label(v_new) || '“ gesetzt');
    end if;
  end if;
  return to_jsonb(t);
end $$;

create or replace function fb_thema_loeschen(p_token text, p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
declare p fb_personen; t fb_themen;
begin
  p := fb_auth(p_token);
  select * into t from fb_themen where id = p_id;
  if not found or not fb_darf(p, t.bereich_id) or p.rolle not in ('inhaber','bearbeiten') then raise exception 'forbidden'; end if;
  delete from fb_themen where id = p_id;
end $$;

create or replace function fb_verlauf_laden(p_token text, p_thema uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare p fb_personen; t fb_themen;
begin
  p := fb_auth(p_token);
  select * into t from fb_themen where id = p_thema;
  if not found or not fb_darf(p, t.bereich_id) then raise exception 'forbidden'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('text', v.text, 'wer', pe.name, 'erstellt', v.erstellt) order by v.erstellt desc)
                   from (select * from fb_verlauf where thema_id = p_thema order by erstellt desc limit 60) v
                   left join fb_personen pe on pe.id = v.person_id), '[]'::jsonb);
end $$;

create or replace function fb_kommentar(p_token text, p_thema uuid, p_text text) returns void
language plpgsql security definer set search_path = public as $$
declare p fb_personen; t fb_themen;
begin
  p := fb_auth(p_token);
  select * into t from fb_themen where id = p_thema;
  if not found or not fb_darf(p, t.bereich_id) or p.rolle = 'ansehen' then raise exception 'forbidden'; end if;
  if nullif(trim(p_text), '') is null then return; end if;
  insert into fb_verlauf(thema_id, person_id, text) values (p_thema, p.id, left(trim(p_text), 1000));
  update fb_themen set geaendert = now() where id = p_thema;
end $$;

-- ---------- Bereiche (nur Inhaber) ----------
create or replace function fb_bereich_speichern(p_token text, p_id uuid, p_name text, p_icon text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare p fb_personen; b fb_bereiche;
begin
  p := fb_auth(p_token);
  if p.rolle <> 'inhaber' then raise exception 'forbidden'; end if;
  if p_id is null then
    insert into fb_bereiche(name, icon, pos)
    values (coalesce(nullif(trim(p_name), ''), 'Neuer Bereich'), coalesce(nullif(p_icon, ''), 'haus'), coalesce((select max(pos) + 1 from fb_bereiche), 0))
    returning * into b;
  else
    update fb_bereiche set name = coalesce(nullif(trim(p_name), ''), name), icon = coalesce(nullif(p_icon, ''), icon)
    where id = p_id returning * into b;
  end if;
  return to_jsonb(b);
end $$;

create or replace function fb_bereich_loeschen(p_token text, p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
declare p fb_personen;
begin
  p := fb_auth(p_token);
  if p.rolle <> 'inhaber' then raise exception 'forbidden'; end if;
  delete from fb_bereiche where id = p_id;
end $$;

-- ---------- Personen und Zugang (nur Inhaber) ----------
create or replace function fb_person_speichern(p_token text, p_id uuid, p_name text, p_rolle text, p_bereiche uuid[]) returns jsonb
language plpgsql security definer set search_path = public as $$
declare p fb_personen; x fb_personen; v_token text;
begin
  p := fb_auth(p_token);
  if p.rolle <> 'inhaber' then raise exception 'forbidden'; end if;
  if p_id is distinct from p.id and p_rolle not in ('bearbeiten','mitmachen','ansehen') then raise exception 'invalid role'; end if;
  if p_id is null then
    v_token := fb_neues_token();
    insert into fb_personen(name, rolle, token_hash) values (coalesce(nullif(trim(p_name), ''), 'Person'), p_rolle, fb_hash(v_token)) returning * into x;
  else
    update fb_personen set name = coalesce(nullif(trim(p_name), ''), name),
                           rolle = case when id = p.id then rolle else p_rolle end
    where id = p_id and aktiv returning * into x;
    if not found then raise exception 'not found'; end if;
  end if;
  if x.rolle <> 'inhaber' then
    delete from fb_zugriff where person_id = x.id;
    insert into fb_zugriff(person_id, bereich_id)
      select x.id, b from unnest(coalesce(p_bereiche, '{}'::uuid[])) b where exists (select 1 from fb_bereiche where id = b);
  end if;
  return jsonb_build_object('id', x.id, 'token', v_token);
end $$;

create or replace function fb_person_token_neu(p_token text, p_id uuid) returns text
language plpgsql security definer set search_path = public as $$
declare p fb_personen; v_token text;
begin
  p := fb_auth(p_token);
  if p.rolle <> 'inhaber' then raise exception 'forbidden'; end if;
  v_token := fb_neues_token();
  update fb_personen set token_hash = fb_hash(v_token) where id = p_id and aktiv;
  if not found then raise exception 'not found'; end if;
  return v_token;
end $$;

create or replace function fb_person_loeschen(p_token text, p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
declare p fb_personen;
begin
  p := fb_auth(p_token);
  if p.rolle <> 'inhaber' or p_id = p.id then raise exception 'forbidden'; end if;
  delete from fb_personen where id = p_id;
end $$;

-- ---------- Rechte: nur die Schnittstellenfunktionen sind fuer anon aufrufbar ----------
revoke execute on function fb_hash(text), fb_auth(text), fb_darf(fb_personen, uuid), fb_neues_token(), fb_status_label(text) from public, anon, authenticated;
revoke execute on function
  fb_laden(text), fb_thema_speichern(text, uuid, jsonb), fb_thema_loeschen(text, uuid), fb_verlauf_laden(text, uuid),
  fb_kommentar(text, uuid, text), fb_bereich_speichern(text, uuid, text, text), fb_bereich_loeschen(text, uuid),
  fb_person_speichern(text, uuid, text, text, uuid[]), fb_person_token_neu(text, uuid), fb_person_loeschen(text, uuid)
  from public;
grant execute on function
  fb_laden(text), fb_thema_speichern(text, uuid, jsonb), fb_thema_loeschen(text, uuid), fb_verlauf_laden(text, uuid),
  fb_kommentar(text, uuid, text), fb_bereich_speichern(text, uuid, text, text), fb_bereich_loeschen(text, uuid),
  fb_person_speichern(text, uuid, text, text, uuid[]), fb_person_token_neu(text, uuid), fb_person_loeschen(text, uuid)
  to anon, authenticated;
