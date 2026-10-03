import duckdb

con = duckdb.connect()

print("--- Distinct Web Blocks ---")
blocks = con.execute("""
    SELECT DISTINCT message
    FROM read_csv_auto('data/endpoint_security.csv', ignore_errors=true)
    WHERE log_type = 'web_block'
""").fetchall()

print(f"Total distinct web block messages: {len(blocks)}")
for b in blocks[:30]:
    print(b[0])

# Check if blocked domains appear in web_activity.csv
print("\n--- Checking overlap between web_block messages and web_activity.csv ---")
overlap = con.execute("""
    WITH blocked AS (
        SELECT DISTINCT message as dest
        FROM read_csv_auto('data/endpoint_security.csv', ignore_errors=true)
        WHERE log_type = 'web_block'
    ),
    web AS (
        SELECT endpoint_id, endpoint_name, unit, event_time, message as dest
        FROM read_csv_auto('data/web_activity.csv', ignore_errors=true)
    )
    SELECT w.endpoint_id, w.endpoint_name, w.unit, w.event_time, w.dest
    FROM web w
    JOIN blocked b ON w.dest = b.dest
    ORDER BY w.event_time
""").fetchdf()
print(f"Overlap count: {len(overlap)}")
print(overlap.head(50))
