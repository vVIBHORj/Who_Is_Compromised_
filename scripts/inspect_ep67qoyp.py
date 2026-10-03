import duckdb

con = duckdb.connect()

print("=== EP67QOYP in endpoint_security.csv ===")
sec = con.execute("""
    SELECT * FROM read_csv_auto('data/endpoint_security.csv')
    WHERE endpoint_id = 'EP67QOYP'
""").fetchdf()
print(f"Count: {len(sec)}")
print(sec.to_string())

print("\n=== EP67QOYP in usb_events.csv ===")
usb = con.execute("""
    SELECT * FROM read_csv_auto('data/usb_events.csv')
    WHERE endpoint_id = 'EP67QOYP'
""").fetchdf()
print(f"Count: {len(usb)}")

print("\n=== EP67QOYP web activity summary ===")
web_summary = con.execute("""
    SELECT message, count(*) as cnt, min(event_time) as first_seen, max(event_time) as last_seen
    FROM read_csv_auto('data/web_activity.csv')
    WHERE endpoint_id = 'EP67QOYP'
    GROUP BY message
    ORDER BY cnt DESC
""").fetchdf()
print(f"Total distinct destinations: {len(web_summary)}")
print(web_summary.head(40).to_string())
