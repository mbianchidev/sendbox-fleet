-- Least-privilege PostgreSQL roles for sendbox-fleet.
--
-- sendbox_fleet_owner owns the schema and runs `sendbox-fleet admin migrate`.
-- sendbox_fleet_app runs the server with FLEET_MIGRATE=false. It can read and
-- write operational tables but can only SELECT and INSERT audit events, and
-- cannot touch the migration ledger.
--
-- Run as a superuser (or the database owner) in the fleet database:
--   1. psql -v ON_ERROR_STOP=1 -f deploy/postgres/roles.sql   (creates roles)
--   2. set passwords: ALTER ROLE ... PASSWORD '...';
--   3. FLEET_DATABASE_URL=postgres://sendbox_fleet_owner@... sendbox-fleet admin migrate
--   4. psql -v ON_ERROR_STOP=1 -f deploy/postgres/roles.sql   (grants)
-- Rerun step 4 after every upgrade that ships a migration. Safe to rerun.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sendbox_fleet_owner') THEN
        CREATE ROLE sendbox_fleet_owner LOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sendbox_fleet_app') THEN
        CREATE ROLE sendbox_fleet_app LOGIN;
    END IF;
END
$$;

GRANT CREATE, USAGE ON SCHEMA public TO sendbox_fleet_owner;
GRANT USAGE ON SCHEMA public TO sendbox_fleet_app;
REVOKE CREATE ON SCHEMA public FROM sendbox_fleet_app;

DO $$
DECLARE
    table_name text;
BEGIN
    IF to_regclass('public._sqlx_migrations') IS NULL THEN
        RAISE NOTICE 'schema not migrated yet; rerun after `sendbox-fleet admin migrate`';
        RETURN;
    END IF;
    FOR table_name IN
        SELECT tablename FROM pg_tables
        WHERE schemaname = 'public' AND tableowner = 'sendbox_fleet_owner'
    LOOP
        EXECUTE format('REVOKE ALL ON public.%I FROM sendbox_fleet_app', table_name);
        IF table_name = '_sqlx_migrations' THEN
            EXECUTE format('GRANT SELECT ON public.%I TO sendbox_fleet_app', table_name);
        ELSIF table_name = 'audit_events' THEN
            EXECUTE format('GRANT SELECT, INSERT ON public.%I TO sendbox_fleet_app', table_name);
        ELSE
            EXECUTE format(
                'GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO sendbox_fleet_app',
                table_name
            );
        END IF;
    END LOOP;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sendbox_fleet_app;
END
$$;
