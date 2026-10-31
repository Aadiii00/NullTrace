# DATA_FINDINGS.md — KillChain Phase 0 Dataset Analysis

**Generated:** 2026-10-31  
**Dataset:** `edr_10000_logs.json`  
**Analysis method:** PowerShell streaming enumeration — no data loaded into memory as a whole  

---

## 1. FILE PROPERTIES

| Property | Value |
|---|---|
| Full path | `f:\killchain\edr_10000_logs.json` |
| File format | **JSONL** — one JSON object per line, no wrapping array |
| File size | **8,382,999 bytes (7.99 MB)** |
| Total lines | **10,000** |
| Empty lines | 0 |
| Malformed lines | **0** |
| Duplicate `event.id` records | **0** |
| Unique `event.id` values | 10,000 |

---

## 2. TIMESTAMP ANALYSIS

| Property | Value |
|---|---|
| Format | ISO 8601 UTC — `@timestamp` field, millisecond precision |
| First event | `2026-10-31T02:07:40.438Z` |
| Last event | `2026-10-31T02:07:40.972Z` |
| Span | **~534 milliseconds** |
| Resolution concern | **CRITICAL** — all 10,000 events fall within a sub-second window |

> **⚠ IMPORTANT IMPLICATION:** Because all events share essentially the same timestamp, **time-based correlation windows are useless** for this dataset. Correlation must rely on **sequence numbers (line position)**, **process entity IDs**, **parent-process chains**, **authentication source-destination pairs**, and **shared host/user/IP combinations**. Out-of-order detection is irrelevant — all timestamps are effectively simultaneous.

---

## 3. EVENT DISTRIBUTION

### By Category (ECS `event.category[0]`)

| Category | Count | % of total |
|---|---:|---:|
| network | 4,384 | 43.8% |
| process | 2,972 | 29.7% |
| file | 1,257 | 12.6% |
| authentication | 850 | 8.5% |
| registry | 537 | 5.4% |

### By Kind (ECS `event.kind`)

| Kind | Count |
|---|---:|
| event (normal telemetry) | 9,496 |
| alert (pre-flagged by generator) | 504 |

### By Action (ECS `event.action`)

| Action | Count |
|---|---:|
| process_created | 2,972 |
| network_connection | 2,520 |
| dns_query | 1,864 |
| file_modified | 1,169 |
| user_logon | 850 |
| registry_value_set | 537 |
| file_rename | 88 |

### By Dataset (ECS `event.dataset`)

| Dataset | Count |
|---|---:|
| edr.network | 4,384 |
| edr.process | 2,972 |
| edr.file | 1,257 |
| edr.authentication | 850 |
| edr.registry | 537 |

### By Severity

| Severity | Count | Meaning |
|---|---:|---|
| 0 | 9,496 | Normal/benign telemetry |
| 5 | 97 | Medium — brute force alerts |
| 8 | 319 | High — execution + C2 + persistence alerts |
| 10 | 88 | Critical — ransomware/impact alerts |

---

## 4. INFRASTRUCTURE ENTITIES

### Hosts — 28 unique

| Hostname | Events | Role |
|---|---:|---|
| SRV-DC-01 | 441 | Domain Controller |
| SRV-FILE-01 | 368 | File Server |
| SRV-DB-01 | 360 | Database Server (Linux RHEL 9.3) |
| SRV-WEB-01 | 332 | Web Server (Linux) |
| WS-ENG-010 to WS-ENG-015 | ~341–381 each | Engineering workstations |
| WS-FIN-010 to WS-FIN-015 | ~319–376 each | Finance workstations |
| WS-HR-010 to WS-HR-015 | ~332–381 each | HR workstations |
| WS-SALES-010 to WS-SALES-015 | ~341–399 each | Sales workstations |

**Network subnets inferred:**
- `10.10.0.x` — Servers (DC, File, DB, Web)
- `10.10.1.x` — Finance workstations
- `10.10.2.x` — HR workstations
- `10.10.3.x` — Engineering workstations
- `10.10.4.x` — Sales workstations

### OS Types

| OS | Events |
|---|---:|
| Windows (Win11 Enterprise / Server 2022) | 9,308 |
| Linux (RHEL 9.3) | 692 |

### Users — 12 unique

| Username | Event count | Notes |
|---|---:|---|
| vreddy | 881 | Most active |
| nverma | 879 | — |
| rkumar | 863 | — |
| dnair | 856 | — |
| pmehta | 844 | — |
| kiyer | 835 | — |
| sgupta | 834 | — |
| asharma | 814 | — |
| jdsouza | 810 | — |
| svc_sql | 810 | Service account |
| mkhan | 793 | — |
| svc_backup | 781 | Service account |

All users appear on domain `CORP`.

### Agent IDs

- 28 unique `agent.id` values — one per host, confirming one EDR agent per endpoint.

---

## 5. PROCESS TELEMETRY

### Process names — 21 unique

| Process | Count |
|---|---:|
| chrome.exe | 2,698 |
| svchost.exe | 2,016 |
| winword.exe | 614 |
| excel.exe | 580 |
| MsMpEng.exe | 496 |
| explorer.exe | 393 |
| powershell.exe | 319 |
| notepad.exe | 278 |
| teams.exe | 275 |
| msedge.exe | 267 |
| outlook.exe | 252 |
| OneDrive.exe | 252 |
| curl | 198 |
| systemd-resolved | 117 |
| unknown.exe | 88 |
| nginx | 84 |
| python3 | 72 |
| cron | 41 |
| vim | 38 |
| postgres | 37 |

### Parent process names

| Parent | Count |
|---|---:|
| explorer.exe | 2,140 |
| services.exe | 536 |
| systemd | 154 |
| winword.exe | 98 |
| bash | 44 |

### Process entity IDs

- **2,972 unique `process.entity_id` values** — one per process-creation event
- Every process event has a `process.entity_id` present — **no missing entity IDs**
- Every process event has `process.name` — **no missing process names**

### Key parent-child relationships detected

| Parent | Child | Count | Significance |
|---|---|---:|---|
| winword.exe | powershell.exe | 98 | **MALICIOUS — Office macro spawning PowerShell** |
| explorer.exe | winword/excel/chrome/etc | 2,140 | Normal user-launched processes |
| services.exe | svchost.exe/MsMpEng.exe | 536 | Normal Windows service processes |
| systemd | nginx/postgres/python3 | 154 | Normal Linux daemons |

---

## 6. AUTHENTICATION TELEMETRY

| Metric | Value |
|---|---:|
| Total auth events | 850 |
| Successful logons (4624) | 689 |
| Failed logons (4625) | 161 |
| Success rate | 81% |

### Windows Event IDs present

| Event ID | Description | Count |
|---|---:|---:|
| 4624 | Successful logon | 689 |
| 4625 | Failed logon | 161 |
| 4720 | Account created | **0 — NOT PRESENT** |

### Logon types

| Type | Count |
|---|---:|
| Network | 373 |
| Interactive | 254 |
| RemoteInteractive (RDP) | 223 |

### Failed logon source IPs

| Source IP | Failed count | Nature |
|---|---:|---|
| 203.0.113.57 | 38 | External (TEST-NET-3 per RFC 5737) |
| 192.0.2.88 | 36 | External (TEST-NET-1 per RFC 5737) |
| 198.51.100.23 | 23 | External (TEST-NET-2 per RFC 5737) |
| Internal IPs (10.x.x.x) | ~64 total | Internal lateral movement attempts |

> **Note:** The three external IPs (192.0.2.x, 198.51.100.x, 203.0.113.x) are RFC 5737 documentation addresses used as simulation placeholders. They represent attacker-controlled external IPs.

### Brute-force telemetry (labels_extra field)

- 97 authentication alert events carry `labels_extra.failed_count_5min` (range: 33–114)
- All target **SRV-DC-01** (the domain controller)
- Source IPs: 192.0.2.88, 203.0.113.57, 198.51.100.23

### Cross-host authentication (lateral movement evidence)

- **689 successful logons** with internal source IPs present
- Confirmed cross-host access patterns (sample):
  - `10.10.1.12` → `WS-FIN-015` as `jdsouza` (Network)
  - `10.10.3.11` → `SRV-DB-01` as `rkumar` (Network)
  - `10.10.3.14` → `SRV-DC-01` as `sgupta` (Network)
  - `10.10.1.11` → `SRV-WEB-01` as `svc_sql` (Interactive)

---

## 7. NETWORK TELEMETRY

### Total network events: 4,384

| Sub-type | Count |
|---|---:|
| network_connection | 2,520 |
| dns_query | 1,864 |

### Destination domains — 12 unique

| Domain | Connection count | Nature |
|---|---:|---|
| www.google.com | 303 | Legitimate |
| zoom.us | 275 | Legitimate |
| outlook.office365.com | 272 | Legitimate |
| teams.microsoft.com | 270 | Legitimate |
| login.microsoftonline.com | 268 | Legitimate |
| slack.com | 264 | Legitimate |
| update.microsoft.com | 262 | Legitimate |
| s3.amazonaws.com | 244 | Legitimate / potential exfil |
| github.com | 244 | Legitimate |
| **suspicious-example-c2.invalid** | 41 | **MALICIOUS — C2 domain** |
| **sim-exfil.example** | 41 | **MALICIOUS — Exfiltration simulation domain** |
| **bad-domain-demo.test** | 36 | **MALICIOUS — Demonstration bad domain** |

### Suspicious domain connections (beaconing alerts)

- 118 alert events for beaconing to `suspicious-example-c2.invalid`, `sim-exfil.example`, `bad-domain-demo.test`
- All involve **powershell.exe** as the connecting process
- Rule: `34eb26ba` — "Beaconing to low-reputation destination"
- Technique: T1071.001 (Web Protocols)
- Bytes: 3,638 per connection (low, consistent with beaconing)

### Large outbound transfers

- **No single connection >= 1 MB** in the dataset
- Maximum bytes observed: ~899,849 bytes (~878 KB) via `curl` from SRV-DB-01 to s3.amazonaws.com
- `curl` processes: 198 events on SRV-WEB-01 and SRV-DB-01 (Linux servers), connecting to legitimate and suspicious domains

### DNS query domains — 9 unique

All 9 DNS domains match the legitimate/suspicious destination list above (same domains).

---

## 8. FILE TELEMETRY

### Total file events: 1,257

| Action | Count |
|---|---:|
| file_modified | 1,169 |
| file_rename | 88 |

### File rename events — ransomware signature

- **88 file rename alert events**, all `event.kind = "alert"`
- Rule: `8476ceb0` — "Rapid mass file rename to uniform extension"
- Technique: T1486 (Data Encrypted for Impact)
- All renames use `.locked` extension
- Process: `unknown.exe` (no hash, no entity_id for the rename events)
- `labels_extra.files_renamed_60s`: values up to 3,976
- Affected hosts: 25 of 28 hosts
- File paths: `C:\Users\<user>\Documents\<many>.locked` and `/home/<user>/<many>.locked`
- **No `file.target_path` field present** — only `file.path` showing the renamed-to name

### File modification events

- 1,169 normal file modification events
- Processes: excel.exe, explorer.exe, winword.exe, outlook.exe
- Files: Q3_Report_*.xlsx, .tmp files, various documents

---

## 9. REGISTRY TELEMETRY

### Total registry events: 537

### Registry key paths — 3 unique base paths

| Base path | Count | Nature |
|---|---:|---|
| `HKCU\Software\Microsoft\Office\16.0\Common\General\` | 234 | Normal Office recent files |
| `HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates\` | 200 | Normal Defender updates |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\` | 103 | **MALICIOUS — Autorun persistence** |

### Persistence via Run key

- 103 alert events writing to `HKCU\...\CurrentVersion\Run\<SUSPECT_ENTRY>`
- Rule: `1581c4a4` — "Autorun key created by scripting engine"
- Technique: T1547.001 (Registry Run Keys / Startup Folder)
- All written by `powershell.exe`
- Process parent not recorded in these events (no parent.name field)
- `<SUSPECT_ENTRY>` is a placeholder — actual value not present in dataset

---

## 10. ALERT SUMMARY (PRE-LABELED BY GENERATOR)

All 504 alert events carry `labels.synthetic = "true"` and `labels.simulated_detection = "true"`.

**No `labels.ground_truth` field is present** — the dataset uses embedded alert classifications instead of a separate ground-truth index.

### Five distinct alert rules

| Rule ID | Rule Name | Count | Technique | Tactic | Severity |
|---|---|---:|---|---|---|
| 34eb26ba | Beaconing to low-reputation destination | 118 | T1071.001 | Command and Control | 8 |
| 1581c4a4 | Autorun key created by scripting engine | 103 | T1547.001 | Persistence | 8 |
| 5cb93fae | Office application spawned a scripting engine | 98 | T1059.001 | Execution | 8 |
| ccb7b967 | High rate of failed logons from single source | 97 | T1110 | Credential Access | 5 |
| 8476ceb0 | Rapid mass file rename to uniform extension | 88 | T1486 | Impact | 10 |

**Total alert events: 504**  
**Normal telemetry events: 9,496**  
**Alert rate: 5.04%**

---

## 11. MISSING AND UNAVAILABLE DATA

| Field / Evidence | Status |
|---|---|
| Account creation (Windows Event 4720) | **NOT PRESENT** |
| Privilege assignment events | **NOT PRESENT** |
| Group membership changes | **NOT PRESENT** |
| `file.target_path` for renames | **NOT PRESENT** (only renamed-to path shown) |
| Registry `data.strings` for Run key | Placeholder `<SUSPECT_ENTRY>` — not actual value |
| Process hash on `unknown.exe` | **NOT PRESENT** |
| Process `entity_id` on file rename events | **NOT PRESENT** |
| Process parent on autorun/beaconing alerts | **NOT PRESENT** |
| External exfiltration byte totals | No single event > 1MB |
| Ground-truth incident IDs | **NOT PRESENT** (alerts embedded instead) |
| Original sequence numbers | **NOT PRESENT** as field — use line number (0-based) |

---

## 12. DATA QUALITY OBSERVATIONS

| Check | Result |
|---|---|
| Malformed JSON records | 0 |
| Duplicate `event.id` | 0 |
| Missing `event.id` | 0 |
| Missing `host.name` | 0 |
| Missing `user.name` | 0 |
| Missing `process.name` (process events) | 0 |
| Missing `process.entity_id` (process events) | 0 |
| Schema consistency | High — ECS 1.x format throughout |

---

## 13. FIELDS CRITICAL FOR ATTACK PATH RECONSTRUCTION

| Field | Path | Use |
|---|---|---|
| Event ID | `event.id` | Unique event reference |
| Timestamp | `@timestamp` | Ordering (sequence takes priority) |
| Sequence | Line number (0–9999) | Ordering when timestamps tie |
| Host | `host.name` | Entity pivot |
| User | `user.name` | Entity pivot |
| Source IP | `source.ip` | Auth origin / network source |
| Dest IP | `destination.ip` | Network target |
| Dest domain | `destination.domain` | C2 / exfil identification |
| Process name | `process.name` | Process identity |
| Process entity ID | `process.entity_id` | Unique process instance |
| Parent process name | `process.parent.name` | Lineage |
| Parent PID | `process.parent.pid` | Lineage |
| Command line | `process.command_line` | Encoded PS detection |
| Auth outcome | `event.outcome` | Success vs failure |
| Winlog event ID | `winlog.event_id` | 4624/4625 classification |
| Logon type | `winlog.logon.type` | Network/RDP/Interactive |
| Registry path | `registry.path` | Persistence artifacts |
| File path | `file.path` | Ransomware artifacts |
| Network bytes | `network.bytes` | Transfer volume |
| Alert rule ID | `rule.id` | Pre-labeled detection |
| MITRE technique | `threat.technique.id` | ATT&CK mapping |
| MITRE tactic | `threat.tactic.name` | Kill-chain stage |
| Labels extra | `labels_extra.*` | Augmented counters |
| Kind | `event.kind` | event vs alert |

---

## 14. INGESTION STRATEGY IMPLICATIONS

1. **Format:** JSONL — read line-by-line, one JSON object per line. No array wrapper.
2. **Memory:** Each line is ~838 bytes average. Can stream without loading all into memory.
3. **Sequence numbers:** Assign 0-based line number as stable sequence — timestamps are not usable for ordering.
4. **Timestamp deduplication:** Cannot use timestamp alone to deduplicate — all are within 534ms. Use `event.id` (guaranteed unique).
5. **Schema normalization:** ECS 1.x format. All fields are nested objects. Use JSONPath extraction in DuckDB.
6. **Chunk size:** 1,000 records per batch is safe for memory-bounded ingestion.
7. **Entity ID coverage:** Process events have 100% entity_id coverage. Correlation on entity_id is reliable.
