import duckdb

con = duckdb.connect()

print("Loading web table...")
con.execute("""
    CREATE TABLE web AS 
    SELECT endpoint_id, endpoint_name, mac, unit, 
           event_time as ts,
           event_time, received_time, message as dest
    FROM read_csv_auto('data/web_activity.csv');
""")

print("\n--- Remote Access Tools / Tunnels / C2 Keywords ---")
rat_keywords = ['anydesk', 'teamviewer', 'ngrok', 'torproject', 'pastebin', 'discord', 'telegram', 'duckdns', 'no-ip', 'hopto', 'ddns', 'localtunnel', 'portmap', 'serveo', 'pagekite', 'remotedesktop', 'vnc', 'rustdesk']

for kw in rat_keywords:
    df_kw = con.execute(f"""
        SELECT endpoint_id, endpoint_name, unit, count(*) as hits, min(ts) as first_seen, max(ts) as last_seen, count(distinct dest) as unique_dest
        FROM web
        WHERE dest ILIKE '%{kw}%'
        GROUP BY endpoint_id, endpoint_name, unit
    """).fetchdf()
    if len(df_kw) > 0:
        print(f"\nKeyword: {kw} ({len(df_kw)} endpoints):")
        print(df_kw.to_string())

print("\n--- Suspicious TLDs (.xyz, .top, .ru, .su, .tk, .cc, .pw, .buzz, .club) ---")
susp_tlds = con.execute("""
    SELECT endpoint_id, endpoint_name, unit, dest, count(*) as hits, min(ts) as first_seen, max(ts) as last_seen
    FROM web
    WHERE regexp_matches(dest, '\\.(xyz|top|ru|su|tk|cc|pw|buzz|club|online|site|space|fun|icu|monster|click)$')
    GROUP BY endpoint_id, endpoint_name, unit, dest
    ORDER BY hits DESC
""").fetchdf()
print(f"Total matching suspicious TLD entries: {len(susp_tlds)}")
print(susp_tlds.head(50).to_string())
