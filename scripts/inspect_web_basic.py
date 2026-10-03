import duckdb

con = duckdb.connect()

print("Checking schema and sample from web_activity.csv...")
sample = con.execute("SELECT * FROM read_csv_auto('data/web_activity.csv') LIMIT 5").fetchdf()
print(sample)

# Check distinct endpoints in web_activity vs usb vs endpoint_security
print("\nChecking distinct endpoints count...")
eps_web = con.execute("SELECT count(distinct endpoint_id) FROM read_csv_auto('data/web_activity.csv')").fetchone()[0]
print(f"Distinct endpoints in web_activity: {eps_web}")

# Check USB endpoint EPD24DBC and EP7FZ2XY in web_activity
print("\nChecking USB endpoints activity in web_activity...")
usb_web = con.execute("""
    SELECT endpoint_id, count(*) as cnt, min(event_time) as min_t, max(event_time) as max_t
    FROM read_csv_auto('data/web_activity.csv')
    WHERE endpoint_id IN ('EPD24DBC', 'EP7FZ2XY')
    GROUP BY endpoint_id
""").fetchdf()
print(usb_web)

# Check EPLFOXSS (the mail infection endpoint) in web_activity
print("\nChecking EPLFOXSS activity in web_activity...")
mail_web = con.execute("""
    SELECT count(*) as cnt, min(event_time) as min_t, max(event_time) as max_t
    FROM read_csv_auto('data/web_activity.csv')
    WHERE endpoint_id = 'EPLFOXSS'
""").fetchdf()
print(mail_web)
