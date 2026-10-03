import duckdb

con = duckdb.connect()

print("Loading web table...")
con.execute("""
    CREATE TABLE web AS 
    SELECT endpoint_id, endpoint_name, mac, unit, 
           event_time as ts,
           message as dest
    FROM read_csv_auto('data/web_activity.csv');
""")

print("\n--- 1. Night-time activity (01:00 to 05:00) ---")
night_activity = con.execute("""
    SELECT endpoint_id, endpoint_name, unit, count(*) as hits, count(distinct dest) as unique_dest,
           count(distinct date_trunc('day', ts)) as active_days
    FROM web
    WHERE extract('hour' from ts) BETWEEN 1 AND 4
      AND NOT regexp_matches(dest, '(clamav|google|mozilla|ubuntu|debian|canonical|ntp)')
    GROUP BY endpoint_id, endpoint_name, unit
    ORDER BY hits DESC
    LIMIT 25
""").fetchdf()
print(night_activity.to_string())

print("\n--- 2. Internal / Lateral Movement connections (private IPs) ---")
internal_conns = con.execute("""
    SELECT endpoint_id, endpoint_name, unit, count(*) as hits, count(distinct dest) as unique_internal_ips
    FROM web
    WHERE regexp_matches(dest, '^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)')
    GROUP BY endpoint_id, endpoint_name, unit
    ORDER BY unique_internal_ips DESC
    LIMIT 25
""").fetchdf()
print(internal_conns.to_string())
