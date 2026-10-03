# Forensic Investigation Scripts Directory

This directory contains the complete set of modular Python scripts used during the investigation of Organisation X's endpoint telemetry (`data/web_activity.csv`, `data/endpoint_security.csv`, `data/usb_events.csv`).

## Master Script
* **`../investigate.py`**: The unified, end-to-end investigation runner that executes all key forensic checks and prints the master compromise verdict.

---

## Modular Investigation Scripts

### 1. Antivirus, Quarantine & Security Logs
| Script | Purpose |
| :--- | :--- |
| **`inspect_security.py`** | Analyzes distribution of log types, quarantine records, and web-filter blocks in `endpoint_security.csv`. |
| **`inspect_av_quarantine.py`** | Queries all genuine quarantined files and ClamAV infection messages across endpoints. |
| **`check_found.py`** | Inspects antivirus scan messages for detections, infected file counts, and signatures. |
| **`dump_quarantine.py`** | Extracts chronological quarantine events, hit counts, and first/last seen timestamps. |
| **`dump_quarantine_all.py`** | Dumps distinct quarantined file names, local quarantine timestamps, file types, and SHA256 hashes. |
| **`check_xbel_hash.py`** | Analyzes the recurring `5e10b349...` SHA256 hash to prove the `recently-used.xbel` false positive. |
| **`check_xbel_av.py`** | Cross-references AV scan logs for all endpoints affected by the `recently-used.xbel` quarantine loop. |

### 2. C2, DGA & Threat Actor Infrastructure
| Script | Purpose |
| :--- | :--- |
| **`inspect_ep67qoyp.py`** | Full forensic profile of `EP67QOYP` across web and security logs (DGA, foreign VPS IPs, clean AV evasion). |
| **`trace_ep67qoyp_start.py`** | Minute-by-minute breakdown of the initial infection on `EP67QOYP` (Sep 12 10:55–11:05, Gist, IP lookups). |
| **`check_bmtr_gist.py`** | Verifies that `bmtr.org` C2 and `gist.githubusercontent.com` were contacted solely by `EP67QOYP`. |
| **`find_c2_ips.py`** | Detects raw external IP connections and single-endpoint high-frequency outbound targets. |
| **`find_rats_tlds.py`** | Searches the entire web dataset for remote access tools (AnyDesk, TeamViewer) and suspicious TLDs (`.xyz`, `.space`, `.fun`). |
| **`comprehensive_compromise_hunt.py`** | Scans for reverse tunnels, dynamic DNS, webhook exfiltration (Discord, Pastebin), and DNS tunneling. |

### 3. Suspicious Traffic & Alerted Endpoints Deep-Dive
| Script | Purpose |
| :--- | :--- |
| **`trace_alerted_endpoints.py`** | Fast in-memory indexed query mapping rare single-endpoint destinations for all flagged workstations. |
| **`inspect_suspect_destinations.py`** | Filters out benign CDNs, search engines, and OS telemetry to isolate suspicious external domains. |
| **`inspect_suspects_batch1.py`** | Detailed domain breakdown for suspect endpoints. |
| **`inspect_top4.py`** | Destination and frequency analysis for top suspects (`EP67QOYP`, `EPGSQVEB`, `EPLFOXSS`, `EPD24DBC`). |
| **`check_night_internal.py`** | Detects off-hours network connections (01:00–05:00) and internal private IP communications. |
| **`inspect_web_blocks.py`** | Analyzes web filter blocks and cross-references them against actual traffic in `web_activity.csv`. |
| **`dump_alerted_eps.py`** | Generates `alerted_eps_traffic.txt` containing rare external traffic for all candidate hosts. |

---

## Output Data Artifacts
* **`alerted_eps_traffic.txt`**: Complete text dump of single-endpoint external destinations contacted by alerted workstations.
