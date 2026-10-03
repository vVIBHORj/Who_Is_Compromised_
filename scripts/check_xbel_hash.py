import duckdb

con = duckdb.connect()

print("--- Checking 5e10b349... occurrences ---")
df = con.execute("""
    SELECT endpoint_id, endpoint_name, unit, event_time, message
    FROM read_csv_auto('data/endpoint_security.csv')
    WHERE message ILIKE '%5e10b3490160cca0fc872f2b026d4b40bafc236852f83d30c9031899e50adc9c%'
    ORDER BY event_time
""").fetchdf()
print(f"Total rows: {len(df)}")
print(df.drop_duplicates(subset=['endpoint_id', 'message']).to_string())
