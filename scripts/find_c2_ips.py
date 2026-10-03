import duckdb
import re

con = duckdb.connect()

print("Loading web activity...")
con.execute("""
    CREATE TABLE web AS 
    SELECT endpoint_id, endpoint_name, mac, unit, 
           event_time as ts,
           event_time, received_time, message as dest
    FROM read_csv_auto('data/web_activity.csv');
""")

# Let's check for IP destinations vs domain destinations
print("\n--- Identifying Raw External IPs contacted ---")
raw_ips = con.execute("""
    SELECT dest, count(distinct endpoint_id) as ep_count, count(*) as hit_count, 
           min(ts) as first_ts, max(ts) as last_ts
    FROM web
    WHERE regexp_matches(dest, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$')
      AND NOT regexp_matches(dest, '^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|127\\.|198\\.18\\.|198\\.19\\.)')
    GROUP BY dest
    HAVING ep_count = 1 AND hit_count >= 50
    ORDER BY hit_count DESC
""").fetchdf()
print(raw_ips.head(40).to_string())

print("\n--- Endpoints contacting those raw external IPs with high hit counts ---")
high_ip_eps = con.execute("""
    WITH susp_ips AS (
        SELECT dest
        FROM web
        WHERE regexp_matches(dest, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$')
          AND NOT regexp_matches(dest, '^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|127\\.|198\\.18\\.|198\\.19\\.)')
        GROUP BY dest
        HAVING count(distinct endpoint_id) = 1 AND count(*) >= 50
    )
    SELECT w.endpoint_id, w.endpoint_name, w.unit, w.dest, count(*) as hits, min(w.ts) as start_t, max(w.ts) as end_t
    FROM web w
    JOIN susp_ips s ON w.dest = s.dest
    GROUP BY w.endpoint_id, w.endpoint_name, w.unit, w.dest
    ORDER BY hits DESC
""").fetchdf()
print(high_ip_eps.head(40).to_string())
