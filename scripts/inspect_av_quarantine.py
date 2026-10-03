import duckdb

con = duckdb.connect()

print("=== ALL UNIQUE QUARANTINED FILES (EXCLUDING NO MALICIOUS FOUND) ===")
res_q = con.execute("""
    SELECT DISTINCT endpoint_id, endpoint_name, unit, message
    FROM read_csv_auto('data/endpoint_security.csv', ignore_errors=true)
    WHERE log_type = 'quarantine'
      AND message NOT ILIKE '%No Malicious files found%'
      AND message NOT ILIKE '%No suspicious file found%'
    ORDER BY endpoint_id
""").fetchdf()
for idx, row in res_q.iterrows():
    print(f"{row['endpoint_id']} | {row['endpoint_name']} | {row['unit']} | {row['message']}")

print("\n=== ALL AV SCAN INFECTION / DETECTION ALERTS ===")
res_av = con.execute("""
    SELECT DISTINCT endpoint_id, endpoint_name, unit, message
    FROM read_csv_auto('data/endpoint_security.csv', ignore_errors=true)
    WHERE log_type = 'av_scan'
      AND (
          message ILIKE '%FOUND%'
          OR message ILIKE '%Quarantined and deleted%'
          OR message ILIKE '%Attempting to handle%'
          OR message ILIKE '%Processing:%'
          OR (message ILIKE '%Infected file is %' AND message NOT ILIKE '%System Scan Completed%')
      )
    ORDER BY endpoint_id
""").fetchdf()
for idx, row in res_av.iterrows():
    print(f"{row['endpoint_id']} | {row['endpoint_name']} | {row['unit']} | {row['message']}")
