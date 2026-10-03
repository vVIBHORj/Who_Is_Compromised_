import duckdb

con = duckdb.connect()

q_files = con.execute("""
    SELECT 
        endpoint_id,
        endpoint_name,
        unit,
        message
    FROM read_csv_auto('data/endpoint_security.csv', ignore_errors=true)
    WHERE log_type = 'quarantine'
      AND message NOT ILIKE '%No Malicious files found%'
      AND message NOT ILIKE '%No suspicious file found%'
    GROUP BY endpoint_id, endpoint_name, unit, message
""").fetchdf()

for idx, r in q_files.iterrows():
    print(f"{r['endpoint_id']} ({r['endpoint_name']}, {r['unit']}) -> {r['message']}")
