import duckdb

con = duckdb.connect()

print("Loading web table...")
con.execute("""
    CREATE TABLE web AS 
    SELECT endpoint_id, endpoint_name, unit, 
           event_time as ts,
           event_time, message as dest
    FROM read_csv_auto('data/web_activity.csv');
""")

# 1. Remote management / tunnels
print("--- 1. Testing for Remote Access / Tunnels ---")
rats = [
    'teamviewer', 'splashtop', 'logmein', 'meshcentral', 'dwservice', 
    'zerotier', 'tailscale', 'trycloudflare', 'ngrok', 'localtunnel', 
    'portmap', 'serveo', 'pagekite', 'rustdesk', 'ultraviewer', 'ammyy'
]
pattern = '|'.join(rats)
res_rats = con.execute(f"""
    SELECT endpoint_id, endpoint_name, unit, dest, count(*) as cnt
    FROM web
    WHERE regexp_matches(dest, '({pattern})')
    GROUP BY endpoint_id, endpoint_name, unit, dest
""").fetchdf()
print(f"Rats/Tunnels hits: {len(res_rats)}")
print(res_rats)

# 2. Dynamic DNS
print("\n--- 2. Testing for Dynamic DNS Providers ---")
ddns = ['duckdns', 'no-ip', 'ddns\\.net', 'hopto\\.org', 'zapto\\.org', 'dynu\\.com', 'afraid\\.org', 'freeddns', 'sytes\\.net']
ddns_pattern = '|'.join(ddns)
res_ddns = con.execute(f"""
    SELECT endpoint_id, endpoint_name, unit, dest, count(*) as cnt
    FROM web
    WHERE regexp_matches(dest, '({ddns_pattern})')
    GROUP BY endpoint_id, endpoint_name, unit, dest
""").fetchdf()
print(f"Dynamic DNS hits: {len(res_ddns)}")
print(res_ddns)

# 3. Abnormally long domain names (DNS tunneling / C2)
print("\n--- 3. Testing for Very Long Domains (length > 60 chars) ---")
res_long = con.execute("""
    SELECT endpoint_id, endpoint_name, unit, dest, length(dest) as len, count(*) as cnt
    FROM web
    WHERE length(dest) > 60
      AND NOT regexp_matches(dest, '(google|amazonaws|cloudfront|akamaized|windowsupdate|googlevideo|safeframe|azure|livemint)')
    GROUP BY endpoint_id, endpoint_name, unit, dest, len
    ORDER BY cnt DESC
""").fetchdf()
print(f"Long domain hits: {len(res_long)}")
print(res_long.head(20).to_string())

# 4. Check for Pastebin, Discord Webhook, Telegram, Github Raw exfil/C2
print("\n--- 4. Testing for Webhook/Pastebin/Telegram/File sharing C2 ---")
webhooks = ['pastebin', 'hastebin', 'ghostbin', 'rentry', 'telegram\\.org', 'api\\.telegram', 'discordapp\\.com', 'discord\\.com/api', 'transfer\\.sh', 'file\\.io', 'anonfiles', 'gofile\\.io', 'mega\\.nz', 'mega\\.co\\.nz', 'mediafire']
wh_pattern = '|'.join(webhooks)
res_wh = con.execute(f"""
    SELECT endpoint_id, endpoint_name, unit, dest, count(*) as cnt
    FROM web
    WHERE regexp_matches(dest, '({wh_pattern})')
    GROUP BY endpoint_id, endpoint_name, unit, dest
""").fetchdf()
print(f"File share / Webhook hits: {len(res_wh)}")
print(res_wh)
