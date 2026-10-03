#!/usr/bin/env python3
"""
Organisation X - Endpoint Telemetry Compromise Investigation Script
Analyzes data/web_activity.csv, data/endpoint_security.csv, and data/usb_events.csv
to identify compromised endpoints, attack vectors, and malicious infrastructure.
"""

import sys
import duckdb
import pandas as pd

def get_connection():
    return duckdb.connect()

def analyze_usb_events(con):
    print("=" * 70)
    print("1. USB HARDWARE TELEMETRY ANALYSIS")
    print("=" * 70)
    df = con.execute("""
        SELECT endpoint_id, endpoint_name, mac, unit, event_time, received_time, message
        FROM read_csv_auto('data/usb_events.csv')
        ORDER BY event_time
    """).fetchdf()
    print(df.to_string())
    print("\n[!] Finding: EPD24DBC (host-7394, unit-foxtrot) plugged in an unauthorized")
    print("    'General -UDisk' Mass Storage flash drive (abcd:1234) on 22-09-2026.\n")

def analyze_endpoint_security(con):
    print("=" * 70)
    print("2. ENDPOINT SECURITY LOGS (ANTIVIRUS & QUARANTINE)")
    print("=" * 70)
    
    # 2.1 Quarantined files (excluding clean scans)
    print("--- 2.1 Genuine Quarantined Malicious Files ---")
    quarantine_df = con.execute("""
        SELECT endpoint_id, endpoint_name, unit, min(event_time) as first_seen, max(event_time) as last_seen, count(*) as count, message
        FROM read_csv_auto('data/endpoint_security.csv', ignore_errors=true)
        WHERE log_type = 'quarantine'
          AND message NOT ILIKE '%No Malicious files found%'
          AND message NOT ILIKE '%No suspicious file found%'
          AND message NOT ILIKE '%recently-used.xbel%'
        GROUP BY endpoint_id, endpoint_name, unit, message
        ORDER BY first_seen
    """).fetchdf()
    for idx, r in quarantine_df.iterrows():
        print(f"[{r['first_seen']}] {r['endpoint_id']} ({r['endpoint_name']}, {r['unit']}) -> {r['message']}")

    # 2.2 Scanner Permission Failure (EPLFOXSS)
    print("\n--- 2.2 Antivirus Permission Failures (Unremediated Mail Infection) ---")
    perm_df = con.execute("""
        SELECT endpoint_id, endpoint_name, unit, min(event_time) as first_seen, max(event_time) as last_seen, count(*) as count, message
        FROM read_csv_auto('data/endpoint_security.csv', ignore_errors=true)
        WHERE log_type = 'av_scan'
          AND message ILIKE '%File not found or no permissions%'
        GROUP BY endpoint_id, endpoint_name, unit, message
    """).fetchdf()
    for idx, r in perm_df.iterrows():
        print(f"[RECURRING {r['count']}x] {r['endpoint_id']} ({r['endpoint_name']}, {r['unit']}) -> {r['message']}")

    # 2.3 Staged Trojan Detections (EPVSWBNA, EPSES7ZK, EPQKOBYG, EPGSQVEB)
    print("\n--- 2.3 Non-Clean AV Scan Detections & Staging ---")
    av_df = con.execute("""
        SELECT endpoint_id, endpoint_name, unit, min(event_time) as first_seen, max(event_time) as last_seen, message
        FROM read_csv_auto('data/endpoint_security.csv', ignore_errors=true)
        WHERE log_type = 'av_scan'
          AND (message ILIKE '%Processing:%' OR message ILIKE '%Quarantined and deleted%')
          AND message NOT ILIKE '%recently-used.xbel%'
        GROUP BY endpoint_id, endpoint_name, unit, message
        ORDER BY endpoint_id, first_seen
    """).fetchdf()
    for idx, r in av_df.iterrows():
        print(f"[{r['first_seen']}] {r['endpoint_id']} ({r['endpoint_name']}, {r['unit']}) -> {r['message']}")

    # 2.4 Antivirus False Positive Analysis (recently-used.xbel)
    print("\n--- 2.4 AV False Positive: GNOME recently-used.xbel Identical Hash ---")
    xbel_df = con.execute("""
        SELECT count(distinct endpoint_id) as affected_endpoints, count(*) as total_alerts,
               min(event_time) as start_date, max(event_time) as end_date
        FROM read_csv_auto('data/endpoint_security.csv', ignore_errors=true)
        WHERE message ILIKE '%recently-used.xbel%'
    """).fetchdf()
    print(f"Alert count: {xbel_df.iloc[0]['total_alerts']} across {xbel_df.iloc[0]['affected_endpoints']} endpoints (Identical SHA256: 5e10b3490160cca0fc872f2b026d4b40bafc236852f83d30c9031899e50adc9c)")

def analyze_web_activity(con):
    print("\n" + "=" * 70)
    print("3. WEB ACTIVITY TELEMETRY ANALYSIS (C2, DGA & REMOTE ACCESS)")
    print("=" * 70)

    # Ingest web table once for fast processing
    print("[*] Indexing web activity telemetry...")
    con.execute("""
        CREATE TEMPORARY TABLE web AS 
        SELECT endpoint_id, endpoint_name, unit, 
               event_time as ts,
               message as dest
        FROM read_csv_auto('data/web_activity.csv');
    """)

    # 3.1 EP67QOYP: DGA Bot & C2 Evasion
    print("\n--- 3.1 Critical C2 & DGA Bot Investigation: EP67QOYP ---")
    dga_df = con.execute("""
        SELECT dest, count(*) as hits, min(ts) as first_seen, max(ts) as last_seen
        FROM web
        WHERE endpoint_id = 'EP67QOYP'
          AND (
              dest ILIKE '%bmtr.org%' 
              OR dest ILIKE '%gh-proxy.com%' 
              OR dest ILIKE '%gist.githubusercontent.com%'
              OR regexp_matches(dest, '\\.(xyz|fun|space|click|live)$')
              OR dest IN ('92.243.67.229', '192.71.166.50', '45.153.124.106', '192.121.87.94', '212.52.16.207', 'api.seeip.org')
          )
        GROUP BY dest
        ORDER BY hits DESC
    """).fetchdf()
    print(dga_df.head(25).to_string())

    # 3.2 EPGSQVEB: AnyDesk Remote Desktop Persistence
    print("\n--- 3.2 Remote Desktop Persistence (AnyDesk RAT): EPGSQVEB ---")
    anydesk_df = con.execute("""
        SELECT dest, count(*) as hits, min(ts) as first_seen, max(ts) as last_seen
        FROM web
        WHERE endpoint_id = 'EPGSQVEB'
          AND (dest ILIKE '%anydesk.com%' OR dest LIKE '148.113.%')
        GROUP BY dest
        ORDER BY hits DESC
    """).fetchdf()
    print(anydesk_df.to_string())

    # 3.3 EPSES7ZK: Malvertising & Search Hijacker
    print("\n--- 3.3 Malvertising Search Hijacker: EPSES7ZK ---")
    hijack_df = con.execute("""
        SELECT dest, count(*) as hits, min(ts) as first_seen, max(ts) as last_seen
        FROM web
        WHERE endpoint_id = 'EPSES7ZK'
          AND (dest ILIKE '%freshysearch%' OR dest ILIKE '%searchtabnew%' OR dest ILIKE '%frompdftodoc%' OR dest ILIKE '%manualsearch%')
        GROUP BY dest
        ORDER BY hits DESC
    """).fetchdf()
    print(hijack_df.to_string())

def print_master_verdict():
    print("\n" + "=" * 70)
    print("4. MASTER COMPROMISE DIRECTORY (CONFIDENCE-BASED CLASSIFICATION)")
    print("=" * 70)
    
    categories = {
        "CONFIRMED (Active Compromise / Policy Violation)": [
            ("EP67QOYP", "host-de52", "unit-lima", "Evidence: 230+ bmtr.org & DGA queries, gh-proxy.com, VPS IPs (92.243.67.229, 45.153.124.106) | Inferred: Active C2 botnet node evading AV"),
            ("EPGSQVEB", "host-9a4f", "unit-bravo", "Evidence: Final_Documents.zip quarantined Sep 10; AnyDesk relays (relay-*.net.anydesk.com) Sep 13-19 | Inferred: Interactive remote access persistence"),
            ("EPLFOXSS", "host-423b", "unit-romeo", "Evidence: Nightly AV permission errors on cur/1773731387.41169_0.EPLFOXSS (Sep 1-19) | Inferred: Unquarantined live malicious email in active spool"),
            ("EPVSWBNA", "host-e103", "unit-delta", "Evidence: Extracted trojan binaries (launcher.exe, Strings.dll, zshp1020s.dll) in ~/Desktop/printer/ | Inferred: Fake printer driver trojan unpacked on desktop"),
            ("EPSES7ZK", "host-4c8d", "unit-papa", "Evidence: 100+ visits to freshysearch/searchtabnew; 5 downloaded fake hp_LJ1020 driver copies | Inferred: Adware/browser hijacker driving trojan downloads"),
            ("EP4YIFHV", "host-a616", "unit-lima", "Evidence: 22 quarantined JS files (wallet_donation_driver.js, shopping_iframe_driver.js) | Inferred: Malicious browser extension targeting crypto/forms"),
            ("EPD24DBC", "host-7394", "unit-foxtrot", "Evidence: Generic USB Mass Storage 'General -UDisk' (abcd:1234) connected Sep 22 18:23 | Inferred: Physical removable media policy violation")
        ],
        "SUSPECTED (Malware Staged / Prevented on Disk)": [
            ("EPWZ7L6L", "host-a61e", "unit-sierra", "Evidence: Quarantined ops-electron-app.desktop (FileType: Malicious) | Inferred: Trojanized Linux desktop entry staged for execution"),
            ("EP2SJ6NE", "host-a976", "unit-bravo", "Evidence: Quarantined libreoffice-calc.desktop (FileType: Malicious, SHA256: 93ffd79...) | Inferred: Trojanized spreadsheet application launcher"),
            ("EPF4AJCM", "host-e53b", "unit-golf", "Evidence: Quarantined identical libreoffice-calc.desktop (SHA256: 93ffd79...) | Inferred: Multi-host trojanized launcher distribution"),
            ("EPQIWPBQ", "host-93eb", "unit-quebec", "Evidence: Quarantined Approve Booking.desktop (ASCII text executable) | Inferred: Phishing/social engineering desktop launcher"),
            ("EPQKOBYG", "host-d29a", "unit-romeo", "Evidence: Quarantined win-lbp623-621-fw-v1301(1).exe in Downloads | Inferred: Fake Windows firmware binary downloaded on Linux workstation"),
            ("EP7UYCXM", "host-2c1e", "unit-alpha", "Evidence: Quarantined libeToken.so.10.7.77 (FileType: Malicious) & anydesk.com traffic | Inferred: Rogue PKCS#11 shared library potentially paired with remote tool"),
            ("EPNPX6VY", "host-6ef6", "unit-juliett", "Evidence: Quarantined Microsoft.Practices.EnterpriseLibrary.Common.dll | Inferred: Staged rogue Windows assembly targeting mono/cross-platform runtime"),
            ("EPVC2P55", "host-aca0", "unit-alpha", "Evidence: Quarantined Data1.cab (FileType: Malicious) | Inferred: Compressed archive carrier containing malicious payload"),
            ("EPPGWIOF", "host-a656", "unit-india", "Evidence: Quarantined brprintconflsr3 and rawtobr3 | Inferred: Malicious printer filter binaries staged in local system paths"),
            ("EPZRAPEL", "host-d14b", "unit-foxtrot", "Evidence: Quarantined binary hash blob 53EDA42869D426262B752F088EA605187284ACE8 | Inferred: Raw malware payload or encrypted dropper component")
        ],
        "NEEDS VERIFICATION (Lure Documents & Unconfirmed Launchers)": [
            ("EPMVZYZO", "host-ba01", "unit-quebec", "Evidence: Quarantined 4 files (mydoc.pdf, mydoc-9.pdf, mydoc-10.pdf, mydoc-75.pdf) | Inferred: Repeated document downloads; requires verifying if exploit or FP"),
            ("EPAJI3E5", "host-f6a4", "unit-oscar", "Evidence: Quarantined Lakeside traders.pdf & Lakeside traders.docx | Inferred: Targeted spear-phishing attachments; exploit unconfirmed"),
            ("EPJ76RZV", "host-aedd", "unit-alpha", "Evidence: Quarantined COMPRESSED FINAL COMPARISION RETIREES WELFARE1.xlsx | Inferred: Personnel-themed lure spreadsheet; exploit unconfirmed"),
            ("EPSJWX5J", "host-0982", "unit-golf", "Evidence: Quarantined Staff_Library_Payment_Final.docx | Inferred: Payment-themed lure document; exploit unconfirmed"),
            ("EPRD7FJT", "host-916a", "unit-romeo", "Evidence: Quarantined 12th Plan Works Dashboard.pdf | Inferred: Planning lure PDF; exploit unconfirmed"),
            ("EPQBJBDX", "host-19e6", "unit-golf", "Evidence: Quarantined dash cam.pdf | Inferred: Lure PDF matching dash cam procurement theme; exploit unconfirmed"),
            ("EPT3KTUL", "host-ad7a", "unit-quebec", "Evidence: Quarantined Dash Camera-49600.00.pdf | Inferred: Procurement lure document; requires content verification"),
            ("EPAGTKNF", "host-227c", "unit-quebec", "Evidence: Quarantined Buy CP PLUS Dashboard Camera...pdf | Inferred: GeM / public procurement lure PDF matching EPT3KTUL"),
            ("EPJ42VCZ", "host-56a6", "unit-india", "Evidence: Quarantined RAGHAV STNC STNA.pdf and RAGHAV STNA STNB.pdf | Inferred: Personal document lure PDFs; exploit unconfirmed"),
            ("EPEEHWSG", "host-4724", "unit-kilo", "Evidence: Quarantined Library Books.xlsx and xsane.desktop | Inferred: Spreadsheet lure and scanner shortcut; exploit unconfirmed"),
            ("EPFFTO5T", "host-508b", "unit-delta", "Evidence: Quarantined Journey Request.desktop | Inferred: Potential phishing application launcher; requires content inspection"),
            ("EPGW2NY4", "host-ceff", "unit-bravo", "Evidence: Quarantined webex.desktop (xdg-open script) | Inferred: Flagged for script structure; requires confirming if benign shortcut"),
            ("EPQISY6K", "host-5281", "unit-bravo", "Evidence: Quarantined veracrypt.desktop | Inferred: Flagged by extension policy; requires confirming legitimate tool"),
            ("EPUJL36T", "host-9ce1", "unit-delta", "Evidence: Quarantined org.gnome.Screenshot.desktop, org.kde.k3b.desktop, veracrypt.desktop | Inferred: Quarantined for desktop extension type rather than threat"),
            ("EPR4BEDS", "host-fe94", "unit-romeo", "Evidence: Quarantined chromium.desktop and veracrypt.desktop | Inferred: Quarantined for desktop extension type; requires inspection"),
            ("EPFQSCDV", "host-2fe4", "unit-juliett", "Evidence: Quarantined simple-scan.desktop | Inferred: Quarantined for desktop extension type; requires inspection")
        ],
        "LIKELY FALSE POSITIVE (Antivirus Signature FP)": [
            ("EPC2L3UH", "host-b4da", "unit-india", "Evidence: Nightly quarantine (18x) of recently-used.xbel (hash: 5e10b349...) | Inferred: Signature FP on GNOME recent files XML metadata"),
            ("EPJYEC7F", "host-38aa", "unit-romeo", "Evidence: Nightly quarantine (10x) of recently-used.xbel (hash: 5e10b349...) | Inferred: Signature FP on GNOME recent files XML metadata"),
            ("EPOC6Y4R", "host-e783", "unit-charlie", "Evidence: Nightly quarantine (5x) of recently-used.xbel (hash: 5e10b349...) | Inferred: Signature FP on GNOME recent files XML metadata"),
            ("EPMQTKSL", "host-942d", "unit-charlie", "Evidence: Nightly quarantine of recently-used.xbel (hash: 5e10b349...) | Inferred: Signature FP on GNOME recent files XML metadata"),
            ("EPFQSCDV", "host-2fe4", "unit-juliett", "Evidence: Nightly quarantine of recently-used.xbel (hash: 5e10b349...) | Inferred: Signature FP on GNOME recent files XML metadata"),
            ("EPR4BEDS", "host-fe94", "unit-romeo", "Evidence: Nightly quarantine of recently-used.xbel (hash: 5e10b349...) | Inferred: Signature FP on GNOME recent files XML metadata"),
            ("EPDRB236", "host-b3df", "unit-hotel", "Evidence: Nightly quarantine of recently-used.xbel (hash: 5e10b349...) | Inferred: Signature FP on GNOME recent files XML metadata"),
            ("EPLDM6PE", "host-2d83", "unit-foxtrot", "Evidence: Nightly quarantine of recently-used.xbel (hash: 5e10b349...) | Inferred: Signature FP on GNOME recent files XML metadata"),
            ("EP3GALVS", "host-58bb", "unit-golf", "Evidence: Nightly quarantine of recently-used.xbel (hash: 5e10b349...) | Inferred: Signature FP on GNOME recent files XML metadata"),
            ("EPAX5P5D", "host-0b21", "unit-bravo", "Evidence: AV scan processing recently-used.xbel (hash: 5e10b349...) | Inferred: Signature FP on GNOME recent files XML metadata"),
            ("EPMDU6L5", "host-b05e", "unit-oscar", "Evidence: Pre-existing quarantine of recently-used.xbel (hash: 5dd59e8...) | Inferred: Signature FP on GNOME recent files XML metadata")
        ]
    }

    fmt = "{:<10} {:<12} {:<14} {:<80}"
    for cat_name, hosts in categories.items():
        print(f"\n>>> {cat_name} ({len(hosts)} Hosts):")
        print(fmt.format("Endpoint", "Hostname", "Unit", "Summary (Evidence & Inferred)"))
        print("-" * 125)
        for h in hosts:
            summary = h[3] if len(h[3]) <= 78 else h[3][:75] + "..."
            print(fmt.format(h[0], h[1], h[2], summary))

    print("\n" + "=" * 70)
    print("5. LIMITATIONS & NEXT STEPS")
    print("=" * 70)
    print("[-] Limitations:")
    print("    1. Network telemetry lacks HTTP paths/headers (cannot verify exfiltrated data volume).")
    print("    2. Missing endpoint process lineage (cannot confirm execution of quarantined attachments).")
    print("    3. Scanner permission deficit prevented remediation of infected mail spool on host-423b.")
    print("[-] Immediate Next Steps:")
    print("    1. Check all 20 unique SHA256 hashes against VirusTotal and threat intel feeds.")
    print("    2. Isolate host-de52 (EP67QOYP) and host-9a4f (EPGSQVEB); collect live memory and process sockets.")
    print("    3. Elevate privileges on host-423b (EPLFOXSS) to inspect and scrub the unquarantined Evolution spool.")
    print("    4. Audit all user .desktop entries in ~/.local/share/applications/ and ~/Desktop/ across the fleet.")

def main():
    print("\nStarting Organisation X Telemetry Forensic Investigation...")
    con = get_connection()
    analyze_usb_events(con)
    analyze_endpoint_security(con)
    analyze_web_activity(con)
    print_master_verdict()
    print("\n[+] Full report available at: COMPROMISE_ANALYSIS_FINDINGS_AND_OUTCOME.md\n")

if __name__ == "__main__":
    main()
