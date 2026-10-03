import duckdb

con = duckdb.connect()

df = con.execute("""
    SELECT event_time, message
    FROM read_csv_auto('data/web_activity.csv')
    WHERE endpoint_id = 'EP67QOYP'
      AND event_time >= '2026-09-12 10:50:00'
      AND event_time <= '2026-09-12 10:58:15'
    ORDER BY event_time
""").fetchdf()

for idx, r in df.iterrows():
    print(f"{r['event_time']} | {r['message']}")
