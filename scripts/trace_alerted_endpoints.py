import duckdb

con = duckdb.connect()

print("Creating in-memory table for web_activity...")
con.execute("""
    CREATE TABLE web AS 
    SELECT endpoint_id, endpoint_name, mac, unit, event_time, received_time, message as dest
    FROM read_csv_auto('data/web_activity.csv');
""")

print("Calculating destination popularity across endpoints...")
con.execute("""
    CREATE TABLE dest_pop AS
    SELECT dest, count(distinct endpoint_id) as ep_count, count(*) as hit_count
    FROM web
    GROUP BY dest;
""")

print("Done index/prep. Now running queries.")

endpoints_of_interest = [
    'EP4YIFHV', 'EPSES7ZK', 'EPVSWBNA', 'EPQKOBYG', 'EPLFOXSS',
    'EPAJI3E5', 'EPJ76RZV', 'EPSJWX5J', 'EPRD7FJT', 'EPGSQVEB',
    'EPD24DBC', 'EP7UYCXM', 'EPWZ7L6L', 'EPQIWPBQ', 'EPNPX6VY',
    'EPVC2P55', 'EPPGWIOF', 'EPZRAPEL', 'EPFQSCDV', 'EPF4AJCM',
    'EP2SJ6NE', 'EPQBJBDX', 'EPEEHWSG', 'EPUJL36T'
]

for ep in endpoints_of_interest:
    print(f"\n==================== Endpoint: {ep} ====================")
    rare_dest = con.execute(f"""
        SELECT w.event_time, w.dest, d.ep_count, d.hit_count
        FROM web w
        JOIN dest_pop d ON w.dest = d.dest
        WHERE w.endpoint_id = '{ep}' AND d.ep_count = 1
        ORDER BY w.event_time
        LIMIT 30
    """).fetchdf()
    print(rare_dest.to_string())
