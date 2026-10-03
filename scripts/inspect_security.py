import duckdb

con = duckdb.connect()

print("--- Log Types in endpoint_security.csv ---")
df_types = con.execute("""
    SELECT log_type, count(*) as cnt
    FROM read_csv_auto('data/endpoint_security.csv', ignore_errors=true)
    GROUP BY log_type
""").fetchdf()
print(df_types)

print("\n--- Quarantine / AV detections / Suspicious messages ---")
df_alerts = con.execute("""
    SELECT endpoint_id, endpoint_name, unit, log_type, event_time, message
    FROM read_csv_auto('data/endpoint_security.csv', ignore_errors=true)
    WHERE message ILIKE '%FOUND%' 
       OR message ILIKE '%Malicious%'
       OR (message ILIKE '%Infected file is %' AND message NOT ILIKE '%System Scan Completed%')
""").fetchdf()
print(df_alerts.to_string())

print("\n--- Quarantine records with actual files ---")
df_quar = con.execute("""
    SELECT endpoint_id, endpoint_name, unit, event_time, message
    FROM read_csv_auto('data/endpoint_security.csv', ignore_errors=true)
    WHERE log_type = 'quarantine'
      AND message NOT ILIKE '%No Malicious files found%'
      AND message NOT ILIKE '%No suspicious file found%'
""").fetchdf()
print(df_quar.to_string())

print("\n--- Web blocks in endpoint_security.csv ---")
df_web_blocks = con.execute("""
    SELECT endpoint_id, endpoint_name, unit, count(*) as block_count, min(event_time) as first_block, max(event_time) as last_block
    FROM read_csv_auto('data/endpoint_security.csv', ignore_errors=true)
    WHERE log_type = 'web_block'
    GROUP BY endpoint_id, endpoint_name, unit
    ORDER BY block_count DESC
""").fetchdf()
print(df_web_blocks.head(20))
