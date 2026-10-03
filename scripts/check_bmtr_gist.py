import duckdb

con = duckdb.connect()

print("--- Endpoints contacting bmtr.org ---")
bmtr = con.execute("""
    SELECT endpoint_id, endpoint_name, unit, count(*) as hits, min(event_time) as min_t, max(event_time) as max_t
    FROM read_csv_auto('data/web_activity.csv')
    WHERE message ILIKE '%bmtr.org%'
    GROUP BY endpoint_id, endpoint_name, unit
""").fetchdf()
print(bmtr)

print("\n--- Endpoints contacting gist.githubusercontent.com ---")
gist = con.execute("""
    SELECT endpoint_id, endpoint_name, unit, count(*) as hits, min(event_time) as min_t, max(event_time) as max_t
    FROM read_csv_auto('data/web_activity.csv')
    WHERE message ILIKE '%gist.githubusercontent.com%'
    GROUP BY endpoint_id, endpoint_name, unit
""").fetchdf()
print(gist)
