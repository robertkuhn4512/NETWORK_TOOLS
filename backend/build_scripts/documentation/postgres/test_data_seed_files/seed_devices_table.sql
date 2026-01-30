-- Seed test data into the devices table. This should allow you to test cisco api endpoints
-- so you have some data to work with.
BEGIN;

-- Optional wipe:
-- TRUNCATE TABLE public.devices RESTART IDENTITY;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
DECLARE
  -- ===== CONFIG =====
  v_schema text := 'public';
  v_table  text := 'devices';
  v_count  int  := 2000;


  v_on_conflict_do_nothing boolean := TRUE;
  v_cols text[];

  -- inferred columns
  os_col text;
  ver_col text;
  dtype_col text;
  hostname_col text;
  ip_col text;
  loop_col text;
  vendor_col text;
  model_col text;
  serial_col text;
  is_deleted_col text;
  created_col text;
  updated_col text;

  col_list  text := '';
  expr_list text := '';
  first     boolean := TRUE;

  r record;
  cand text;
  include_col boolean;
  expr text;

  q_schema text;
  q_table  text;
  sql text;
BEGIN
  SELECT array_agg(column_name::text ORDER BY ordinal_position)
    INTO v_cols
  FROM information_schema.columns
  WHERE table_schema = v_schema
    AND table_name   = v_table;

  IF v_cols IS NULL THEN
    RAISE EXCEPTION 'Table %.% not found', v_schema, v_table;
  END IF;

  -- infer OS column
  FOR cand IN SELECT unnest(ARRAY['os','os_name','device_os','platform_os','os_type']) LOOP
    IF cand = ANY(v_cols) THEN os_col := cand; EXIT; END IF;
  END LOOP;

  -- infer VERSION column
  FOR cand IN SELECT unnest(ARRAY['version','os_version','software_version','device_version']) LOOP
    IF cand = ANY(v_cols) THEN ver_col := cand; EXIT; END IF;
  END LOOP;

  -- infer DEVICE_TYPE column (netmiko device_type values go here)
  FOR cand IN SELECT unnest(ARRAY['device_type','netmiko_device_type','driver','platform','type']) LOOP
    IF cand = ANY(v_cols) THEN dtype_col := cand; EXIT; END IF;
  END LOOP;

  -- other common columns
  FOR cand IN SELECT unnest(ARRAY['hostname','device_name','name']) LOOP
    IF cand = ANY(v_cols) THEN hostname_col := cand; EXIT; END IF;
  END LOOP;

  FOR cand IN SELECT unnest(ARRAY['management_ip','mgmt_ip','ip_address','ipv4_address','ipv4']) LOOP
    IF cand = ANY(v_cols) THEN ip_col := cand; EXIT; END IF;
  END LOOP;


  -- infer LOOPBACK IPv4 column (unique constraint often lives here)
  FOR cand IN SELECT unnest(ARRAY['ipv4_loopback','loopback_ip','loopback_ipv4','lo0_ip','lo0']) LOOP
    IF cand = ANY(v_cols) THEN loop_col := cand; EXIT; END IF;
  END LOOP;

  FOR cand IN SELECT unnest(ARRAY['vendor','manufacturer','make']) LOOP
    IF cand = ANY(v_cols) THEN vendor_col := cand; EXIT; END IF;
  END LOOP;

  FOR cand IN SELECT unnest(ARRAY['model','platform_model','device_model']) LOOP
    IF cand = ANY(v_cols) THEN model_col := cand; EXIT; END IF;
  END LOOP;

  FOR cand IN SELECT unnest(ARRAY['serial_number','serial']) LOOP
    IF cand = ANY(v_cols) THEN serial_col := cand; EXIT; END IF;
  END LOOP;

  FOR cand IN SELECT unnest(ARRAY['is_deleted','deleted']) LOOP
    IF cand = ANY(v_cols) THEN is_deleted_col := cand; EXIT; END IF;
  END LOOP;

  FOR cand IN SELECT unnest(ARRAY['created_at','created','created_on']) LOOP
    IF cand = ANY(v_cols) THEN created_col := cand; EXIT; END IF;
  END LOOP;

  FOR cand IN SELECT unnest(ARRAY['updated_at','updated','updated_on']) LOOP
    IF cand = ANY(v_cols) THEN updated_col := cand; EXIT; END IF;
  END LOOP;

  IF os_col IS NULL OR ver_col IS NULL OR dtype_col IS NULL THEN
    RAISE EXCEPTION
      'Could not infer required columns. Found os=% version=% device_type=%',
      os_col, ver_col, dtype_col;
  END IF;

  q_schema := quote_ident(v_schema);
  q_table  := quote_ident(v_table);

  -- Build INSERT column list + SELECT expression list
  FOR r IN
    SELECT
      column_name::text AS column_name,
      data_type::text   AS data_type,
      udt_name::text    AS udt_name,
      is_nullable::text AS is_nullable,
      column_default::text AS column_default,
      is_identity::text AS is_identity,
      COALESCE(is_generated::text, 'NEVER') AS is_generated
    FROM information_schema.columns
    WHERE table_schema = v_schema
      AND table_name   = v_table
    ORDER BY ordinal_position
  LOOP
    -- skip identity / generated
    IF r.is_identity = 'YES' OR upper(r.is_generated) <> 'NEVER' THEN
      CONTINUE;
    END IF;

    include_col := FALSE;

    -- include inferred / known columns
    IF r.column_name = os_col
       OR r.column_name = ver_col
       OR r.column_name = dtype_col
       OR (hostname_col   IS NOT NULL AND r.column_name = hostname_col)
       OR (ip_col         IS NOT NULL AND r.column_name = ip_col)
       OR (loop_col       IS NOT NULL AND r.column_name = loop_col)
       OR (vendor_col     IS NOT NULL AND r.column_name = vendor_col)
       OR (model_col      IS NOT NULL AND r.column_name = model_col)
       OR (serial_col     IS NOT NULL AND r.column_name = serial_col)
       OR (is_deleted_col IS NOT NULL AND r.column_name = is_deleted_col)
       OR (created_col    IS NOT NULL AND r.column_name = created_col)
       OR (updated_col    IS NOT NULL AND r.column_name = updated_col)
    THEN
      include_col := TRUE;
    END IF;

    -- include required NOT NULL w/out default
    IF r.is_nullable = 'NO' AND (r.column_default IS NULL OR r.column_default = '') THEN
      include_col := TRUE;
    END IF;

    IF NOT include_col THEN
      CONTINUE;
    END IF;

    -- map known columns
    IF r.column_name = os_col THEN
      expr := 'data.os';
    ELSIF r.column_name = ver_col THEN
      expr := 'data.version';
    ELSIF r.column_name = dtype_col THEN
      expr := 'data.netmiko_device_type';
    ELSIF hostname_col IS NOT NULL AND r.column_name = hostname_col THEN
      expr := 'data.hostname';
    ELSIF ip_col IS NOT NULL AND r.column_name = ip_col THEN
      IF r.data_type IN ('inet','cidr') THEN
        expr := '(data.management_ip::inet)';
      ELSE
        expr := 'data.management_ip';
      END IF;
    ELSIF loop_col IS NOT NULL AND r.column_name = loop_col THEN
      -- populate ipv4_loopback (or equivalent) so unique constraints don't collide
      IF r.data_type IN ('inet','cidr') THEN
        expr := '(data.management_ip::inet)';
      ELSE
        expr := 'data.management_ip';
      END IF;
    ELSIF vendor_col IS NOT NULL AND r.column_name = vendor_col THEN
      expr := 'data.vendor';
    ELSIF model_col IS NOT NULL AND r.column_name = model_col THEN
      expr := 'data.model';
    ELSIF serial_col IS NOT NULL AND r.column_name = serial_col THEN
      expr := 'data.serial_number';
    ELSIF is_deleted_col IS NOT NULL AND r.column_name = is_deleted_col THEN
      expr := 'FALSE';
    ELSIF created_col IS NOT NULL AND r.column_name = created_col THEN
      expr := 'NOW()';
    ELSIF updated_col IS NOT NULL AND r.column_name = updated_col THEN
      expr := 'NOW()';
    ELSE
      -- best-effort generic values for extra required columns
      IF r.data_type IN ('integer','smallint','bigint') THEN
        expr := '((data.i % 1000) + 1)';
      ELSIF r.data_type IN ('numeric','decimal','real','double precision') THEN
        expr := '0';
      ELSIF r.data_type = 'boolean' THEN
        expr := 'FALSE';
      ELSIF r.data_type = 'uuid' THEN
        expr := 'gen_random_uuid()';
      ELSIF r.data_type LIKE 'timestamp%' THEN
        expr := 'NOW()';
      ELSIF r.data_type = 'date' THEN
        expr := 'CURRENT_DATE';
      ELSIF r.data_type = 'jsonb' THEN
        expr := format('jsonb_build_object(''seed'',true,''i'',data.i,''col'',%L)', r.column_name);
      ELSIF r.data_type = 'json' THEN
        expr := format('json_build_object(''seed'',true,''i'',data.i,''col'',%L)', r.column_name);
      ELSIF r.data_type IN ('inet','cidr') THEN
        expr := '(data.management_ip::inet)';
      ELSIF r.data_type = 'ARRAY' THEN
        -- minimal empty arrays for common types
        IF r.udt_name = '_text' THEN
          expr := 'ARRAY[]::text[]';
        ELSIF r.udt_name = '_varchar' THEN
          expr := 'ARRAY[]::varchar[]';
        ELSIF r.udt_name = '_int4' THEN
          expr := 'ARRAY[]::int[]';
        ELSIF r.udt_name = '_uuid' THEN
          expr := 'ARRAY[]::uuid[]';
        ELSIF r.udt_name = '_bool' THEN
          expr := 'ARRAY[]::boolean[]';
        ELSIF r.udt_name = '_inet' THEN
          expr := 'ARRAY[]::inet[]';
        ELSE
          expr := 'ARRAY[]::text[]';
        END IF;
      ELSE
        expr := format('%L || data.i', 'seed_' || r.column_name || '_');
      END IF;
    END IF;

    IF first THEN
      col_list  := quote_ident(r.column_name);
      expr_list := expr;
      first     := FALSE;
    ELSE
      col_list  := col_list  || ', ' || quote_ident(r.column_name);
      expr_list := expr_list || ', ' || expr;
    END IF;
  END LOOP;

  IF first THEN
    RAISE EXCEPTION 'No insertable columns selected for %.%', v_schema, v_table;
  END IF;

  -- Netmiko-focused dataset generator
  sql := format($fmt$
WITH gs AS (
  SELECT generate_series(1, %s) AS i
),
profile AS (
  SELECT
    i,
    -- Weighted-ish selection by i%%100
    CASE
      WHEN (i %% 100) < 22 THEN 'cisco_xe'
      WHEN (i %% 100) < 38 THEN 'cisco_ios'
      WHEN (i %% 100) < 48 THEN 'cisco_asr'
      WHEN (i %% 100) < 60 THEN 'cisco_xr'
      WHEN (i %% 100) < 78 THEN 'cisco_nxos'
      WHEN (i %% 100) < 88 THEN 'cisco_asa'
      WHEN (i %% 100) < 96 THEN 'cisco_ftd'
      ELSE 'cisco_wlc'
    END AS netmiko_device_type
  FROM gs
),
data AS (
  SELECT
    i,
    netmiko_device_type,
    CASE netmiko_device_type
      WHEN 'cisco_ios'  THEN 'ios'
      WHEN 'cisco_xe'   THEN 'iosxe'
      WHEN 'cisco_asr'  THEN 'iosxe'
      WHEN 'cisco_xr'   THEN 'iosxr'
      WHEN 'cisco_nxos' THEN 'nxos'
      WHEN 'cisco_asa'  THEN 'asa'
      WHEN 'cisco_ftd'  THEN 'ftd'
      ELSE 'aireos'
    END AS os,
    CASE netmiko_device_type
      WHEN 'cisco_xe' THEN (ARRAY['16.9.5','16.12.10','17.3.6','17.6.5','17.9.3','17.10.1','17.12.3'])[(i %% 7)+1]
      WHEN 'cisco_ios' THEN (ARRAY['15.2(4)M7','15.7(3)M5','12.4(25d)','12.2(55)SE12','15.0(2)SE11'])[(i %% 5)+1]
      WHEN 'cisco_asr' THEN (ARRAY['16.12.10','17.3.6','17.6.5','17.9.4','17.10.1'])[(i %% 5)+1]
      WHEN 'cisco_xr' THEN (ARRAY['6.5.3','7.1.2','7.3.2','7.5.1','7.7.1'])[(i %% 5)+1]
      WHEN 'cisco_nxos' THEN (ARRAY['7.0(3)I7(8)','7.0(3)I7(9)','9.3(8)','9.3(10)','10.2(3)','10.3(1)'])[(i %% 6)+1]
      WHEN 'cisco_asa' THEN (ARRAY['9.12(4)','9.14(4)','9.16(3)','9.18(2)','9.20(1)'])[(i %% 5)+1]
      WHEN 'cisco_ftd' THEN (ARRAY['6.7.0','7.0.6','7.1.0','7.2.5','7.4.1'])[(i %% 5)+1]
      ELSE (ARRAY['8.5.171.0','8.10.185.0','8.10.190.0'])[(i %% 3)+1]
    END AS version,
    -- deterministic private IPv4 as text
    ('10.' || (((i/65536) %% 20) + 1) || '.' || ((i/256) %% 256) || '.' || (i %% 256)) AS management_ip,
    -- hostname based on netmiko type
    (replace(netmiko_device_type, 'cisco_', '') || '-' ||
     CASE netmiko_device_type
       WHEN 'cisco_ios'  THEN 'ios'
       WHEN 'cisco_xe'   THEN 'iosxe'
       WHEN 'cisco_asr'  THEN 'iosxe'
       WHEN 'cisco_xr'   THEN 'iosxr'
       WHEN 'cisco_nxos' THEN 'nxos'
       WHEN 'cisco_asa'  THEN 'asa'
       WHEN 'cisco_ftd'  THEN 'ftd'
       ELSE 'aireos'
     END || '-' || lpad(i::text, 4, '0')) AS hostname,
    'cisco' AS vendor,
    CASE
      WHEN netmiko_device_type='cisco_nxos'
        THEN (ARRAY['N9K-C93180YC-FX','N9K-C9372PX','N7K-C7010','N5K-C5548UP'])[(i %% 4)+1]
      WHEN netmiko_device_type IN ('cisco_xe','cisco_ios')
        THEN (ARRAY['C9300-48P','C9200-24T','ISR4431','ISR4451','WS-C3560X-24P-L','WS-C2960X-48FPS-L'])[(i %% 6)+1]
      WHEN netmiko_device_type='cisco_asr'
        THEN (ARRAY['ASR1001-X','ASR1002-X','ASR1006'])[(i %% 3)+1]
      WHEN netmiko_device_type='cisco_xr'
        THEN (ARRAY['NCS-540','ASR-9001','NCS-5501'])[(i %% 3)+1]
      WHEN netmiko_device_type='cisco_asa'
        THEN (ARRAY['ASA5516-X','ASA5525-X','ASA5508-X'])[(i %% 3)+1]
      WHEN netmiko_device_type='cisco_ftd'
        THEN (ARRAY['FPR1010','FPR2110','FPR2140'])[(i %% 3)+1]
      ELSE (ARRAY['AIR-CT3504','AIR-CT5520','C9800-L-C-K9'])[(i %% 3)+1]
    END AS model,
    ('FTX' || lpad(i::text, 9, '0')) AS serial_number
  FROM profile
)
INSERT INTO %s.%s (%s)
SELECT %s
FROM data
%s;
$fmt$,
    v_count,
    q_schema, q_table,
    col_list,
    expr_list,
    CASE WHEN v_on_conflict_do_nothing THEN 'ON CONFLICT DO NOTHING' ELSE '' END
  );

  RAISE NOTICE 'Seeding %.% with % rows. Insert columns: %', v_schema, v_table, v_count, col_list;
  EXECUTE sql;
END $$;

COMMIT;
