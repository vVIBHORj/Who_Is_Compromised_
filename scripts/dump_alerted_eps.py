import duckdb

con = duckdb.connect()

con.execute("""
    CREATE TABLE web AS 
    SELECT endpoint_id, endpoint_name, mac, unit, event_time, received_time, message as dest
    FROM read_csv_auto('data/web_activity.csv');
""")

con.execute("""
    CREATE TABLE dest_pop AS
    SELECT dest, count(distinct endpoint_id) as ep_count, count(*) as hit_count
    FROM web
    GROUP BY dest;
""")

targets = [
    'EP4YIFHV', 'EPSES7ZK', 'EPVSWBNA', 'EPQKOBYG', 'EPLFOXSS',
    'EPAJI3E5', 'EPJ76RZV', 'EPSJWX5J', 'EPRD7FJT', 'EPGSQVEB',
    'EPD24DBC', 'EP7UYCXM', 'EPWZ7L6L', 'EPQIWPBQ', 'EPNPX6VY'
]

with open(r'scripts/alerted_eps_traffic.txt', 'w', encoding='utf-8') as f:
    for ep in targets:
        f.write(f"\n==================== Endpoint: {ep} ====================\n")
        rare_dest = con.execute(f"""
            SELECT w.event_time, w.dest, d.ep_count, d.hit_count
            FROM web w
            JOIN dest_pop d ON w.dest = d.dest
            WHERE w.endpoint_id = '{ep}' AND d.ep_count = 1
            ORDER BY w.event_time
        """).fetchdf()
        f.write(f"Total rare single-endpoint destinations: {len(rare_dest)}\n")
        f.write(rare_dest.head(50).to_string() + "\n")

print("Written to scripts/alerted_eps_traffic.txt")
