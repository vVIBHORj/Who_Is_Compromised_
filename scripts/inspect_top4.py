import duckdb

con = duckdb.connect()

con.execute("""
    CREATE TABLE web AS 
    SELECT endpoint_id, endpoint_name, unit, event_time, message as dest
    FROM read_csv_auto('data/web_activity.csv');
""")

con.execute("""
    CREATE TABLE dest_pop AS
    SELECT dest, count(distinct endpoint_id) as ep_count
    FROM web
    GROUP BY dest;
""")

for ep in ['EP67QOYP', 'EPGSQVEB', 'EPLFOXSS', 'EPD24DBC']:
    df = con.execute(f"""
        SELECT w.dest, count(*) as hits, min(w.event_time) as min_t, max(w.event_time) as max_t
        FROM web w
        JOIN dest_pop d ON w.dest = d.dest
        WHERE w.endpoint_id = '{ep}'
          AND d.ep_count <= 2
          AND NOT regexp_matches(w.dest, '(google|mozilla|clamav|cloudfront|akamai|gov\\.example|\\.local|\\.bbrouter)')
        GROUP BY w.dest
        ORDER BY hits DESC
        LIMIT 20
    """).fetchdf()
    print(f"\n=== {ep} ===")
    print(df.to_string())
