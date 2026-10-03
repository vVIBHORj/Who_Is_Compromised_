import duckdb

con = duckdb.connect()

q_files = con.execute("""
    SELECT 
        endpoint_id,
        endpoint_name,
        unit,
        min(event_time) as first_seen,
        max(event_time) as last_seen,
        count(*) as count,
        message
    FROM read_csv_auto('data/endpoint_security.csv', ignore_errors=true)
    WHERE log_type = 'quarantine'
      AND message NOT ILIKE '%No Malicious files found%'
      AND message NOT ILIKE '%No suspicious file found%'
    GROUP BY endpoint_id, endpoint_name, unit, message
    ORDER BY first_seen
""").fetchdf()

print(f"Total quarantined file records: {len(q_files)}")
for idx, r in q_files.iterrows():
    print(f"{r['first_seen']} -> {r['last_seen']} ({r['count']}x) | {r['endpoint_id']} ({r['endpoint_name']}, {r['unit']}) | {r['message']}")
