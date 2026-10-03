import duckdb

con = duckdb.connect()

endpoints = [
    'EP67QOYP', 'EPGSQVEB', 'EPLFOXSS', 'EPD24DBC', 'EPVSWBNA', 
    'EPSES7ZK', 'EP4YIFHV', 'EPQKOBYG', 'EPAJI3E5', 'EPJ76RZV', 
    'EPSJWX5J', 'EPRD7FJT', 'EPQBJBDX', 'EPWZ7L6L'
]

con.execute("""
    CREATE TABLE web AS 
    SELECT endpoint_id, endpoint_name, unit, 
           event_time as ts,
           event_time, message as dest
    FROM read_csv_auto('data/web_activity.csv');
""")

con.execute("""
    CREATE TABLE dest_pop AS
    SELECT dest, count(distinct endpoint_id) as ep_count
    FROM web
    GROUP BY dest;
""")

for ep in endpoints:
    rows = con.execute(f"""
        SELECT w.event_time, w.dest, d.ep_count
        FROM web w
        JOIN dest_pop d ON w.dest = d.dest
        WHERE w.endpoint_id = '{ep}'
          AND d.ep_count <= 3
          AND NOT regexp_matches(w.dest, '(google|gstatic|youtube|googlevideo|mozilla|clamav|cloudfront|akamai|windowsupdate|microsoft|digicert|sectigo|letsencrypt|criteo|doubleclick|adnxs|pubmatic|rubiconproject|openx|taboola|outbrain|casalemedia|smartadserver|adroll|indiatimes|timesofindia|hindu|ndtv|livemint|indianexpress|moneycontrol|groww|zerodha|bsnl|airtel|jio|gov\\.example|\\.local|\\.bbrouter|\\.hgu_lan)')
        ORDER BY w.ts
    """).fetchdf()
    
    print(f"\n==================== Endpoint: {ep} (Filtered: {len(rows)}) ====================")
    if len(rows) > 0:
        dest_summary = rows.groupby('dest').agg(hits=('ep_count', 'count'), first_seen=('event_time', 'min'), last_seen=('event_time', 'max')).reset_index()
        dest_summary = dest_summary.sort_values(by='hits', ascending=False)
        print(dest_summary.head(10).to_string())
