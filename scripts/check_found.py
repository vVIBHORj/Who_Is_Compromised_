import duckdb

con = duckdb.connect()

print("=== AV SCANS WITH FOUND ===")
res_found = con.execute("""
    SELECT endpoint_id, endpoint_name, unit, event_time, message
    FROM read_csv_auto('data/endpoint_security.csv', ignore_errors=true)
    WHERE log_type = 'av_scan'
      AND message ILIKE '%FOUND%'
    ORDER BY event_time
""").fetchdf()
for idx, r in res_found.iterrows():
    print(f"{r['event_time']} | {r['endpoint_id']} ({r['endpoint_name']}, {r['unit']}): {r['message']}")

print("\n=== AV SCANS WITH Infectedfiles > 0 ===")
res_inf = con.execute("""
    SELECT endpoint_id, endpoint_name, unit, event_time, message
    FROM read_csv_auto('data/endpoint_security.csv', ignore_errors=true)
    WHERE log_type = 'av_scan'
      AND message ILIKE '%Infectedfiles:%'
      AND message NOT ILIKE '%Infectedfiles: 0%'
      AND message NOT ILIKE '%Infectedfiles:0%'
    ORDER BY event_time
""").fetchdf()
for idx, r in res_inf.iterrows():
    print(f"{r['event_time']} | {r['endpoint_id']} ({r['endpoint_name']}, {r['unit']}): {r['message']}")
