import duckdb

con = duckdb.connect()

xbel_eps = ['EPJYEC7F', 'EPOC6Y4R', 'EPMQTKSL', 'EPC2L3UH', 'EPFQSCDV', 'EPR4BEDS', 'EPDRB236', 'EPLDM6PE', 'EP3GALVS']

print("=== AV SCAN LOGS FOR XBEL ENDPOINTS ===")
for ep in xbel_eps:
    res = con.execute(f"""
        SELECT event_time, message
        FROM read_csv_auto('data/endpoint_security.csv')
        WHERE endpoint_id = '{ep}' AND log_type = 'av_scan'
          AND message NOT ILIKE '%Infected file is ----- System Scan Completed ------%'
          AND message NOT ILIKE '%Knownviruses:%'
        ORDER BY event_time
    """).fetchdf()
    print(f"\n--- {ep} ({len(res)} messages) ---")
    for idx, r in res.iterrows():
        print(f"{r['event_time']} | {r['message']}")
