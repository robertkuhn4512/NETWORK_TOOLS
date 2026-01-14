BEGIN;

DO $$
DECLARE
  r record;
  dbname text;
BEGIN
  SELECT current_database() INTO dbname;

  IF dbname <> 'network_tools' THEN
    RAISE EXCEPTION
      'Refusing to run: current_database() = %, expected network_tools',
      dbname;
  END IF;

  RAISE NOTICE 'Dropping tables in database: %', dbname;

  FOR r IN
    SELECT schemaname, tablename
    FROM pg_tables
    WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
      -- Optional: restrict to specific schemas only:
      -- AND schemaname IN ('public', 'network_tools')
    ORDER BY schemaname, tablename
  LOOP
    RAISE NOTICE 'Dropping table: %.%', r.schemaname, r.tablename;
    EXECUTE format('DROP TABLE IF EXISTS %I.%I CASCADE;', r.schemaname, r.tablename);
  END LOOP;

  RAISE NOTICE 'Done.';

END $$;

COMMIT;