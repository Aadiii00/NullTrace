# SCENARIO_FINDINGS.md — KillChain Phase 0 Attack Scenario Analysis

**Generated:** 2026-10-31  
**Dataset:** `edr_10000_logs.json`  
**Purpose:** Document every planted attack scenario, the available evidence, gaps, and correlation strategy  

---

## OVERVIEW

The dataset contains **5 distinct planted attack scenarios**, all marked `labels.synthetic = "true"`. They span the full ATT&CK kill chain from Credential Access through to Impact.

The scenarios are **not sequential in a single attack chain** — they appear independently distributed across all 28 hosts and 12 users, forming a **simulated broad-based campaign** rather than a single targeted intrusion narrative.

The 504 alert events cover 5 detection rules mapping to 5 ATT&CK techniques across 4 tactics.

---

## SCENARIO 1 — CREDENTIAL ACCESS: BRUTE FORCE AGAINST DOMAIN CONTROLLER

### Alert rule
- **Rule ID:** `ccb7b967`
- **Rule name:** High rate of failed logons from single source
- **Count:** 97 alert events

### ATT&CK Mapping
| Field | Value |
|---|---|
| Technique ID | T1110 |
| Technique name | Brute Force |
| Tactic | Credential Access |
| Kill-chain stage | Exploitation |

### Available Evidence

| Evidence | Detail |
|---|---|
| Event category | `authentication`, `event.kind = alert` |
| Windows event ID | 4625 (logon failure) |
| Target host | SRV-DC-01 (domain controller) exclusively |
| Attacker source IPs | 192.0.2.88, 203.0.113.57, 198.51.100.23 |
| Targeted users | asharma, pmehta, sgupta, svc_sql, mkhan, svc_backup, rkumar |
| Augmented counter | `labels_extra.failed_count_5min` — values 33–114 |
| Logon type | Network (4625) |
| Severity | 5 (Medium) |

**Example event:** `fcab3ed8-f602-48e2-a531-4b3cc9a31953`  
`2026-10-31T02:07:40.439Z | SRV-DC-01 | asharma | srcIP:192.0.2.88 | failed_5min:105`

### Missing Evidence

| Gap | Impact |
|---|---|
| No 4624 success event from same external IPs | Cannot confirm attacker broke through via brute force |
| No post-auth activity linked from attacker IPs | Cannot trace what happened after any potential success |
| No rate-limiting or lockout events | Context for effectiveness is absent |
| No 4771 (Kerberos pre-auth failed) | Only NTLM-style failures visible |

### Expected Sequence
```
External IP brute-forces SRV-DC-01
    → Multiple 4625 failures per account
    → [MISSING: 4624 success from same IP]
    → [MISSING: post-auth action]
```

### Detection Opportunities
- ✅ **High-volume failure detection:** `labels_extra.failed_count_5min` directly supports threshold-based alerting
- ✅ **Multi-account targeting from one source IP:** Three external IPs hit multiple accounts
- ✅ **Service account targeting:** `svc_sql` and `svc_backup` are high-value targets
- ✅ **Successful logon following failures:** 689 total 4624 events exist — correlate by user and source proximity

### Correlation Opportunities
- Cross-reference: Do any of the targeted users (asharma, sgupta, etc.) appear in subsequent suspicious events (Scenario 2, 3, 4)?
- Internal source IPs in 4625: `10.10.3.11`, `10.10.2.11`, `10.10.2.14` — possible lateral movement attempts
- The 97 brute-force alerts span 40+ hosts and all 12 users — this looks like a multi-target campaign, not a single-user attack

### Limitations
- The `failed_count_5min` is a pre-aggregated counter injected into the event by the generator — not derivable from raw 4625 events in this dataset alone. The raw failure events (161 total) across all timestamps that are effectively the same would need sliding-window SQL analysis.
- Cannot confirm a successful compromise from brute force in this dataset.

---

## SCENARIO 2 — EXECUTION: OFFICE APPLICATION SPAWNING SCRIPTING ENGINE

### Alert rule
- **Rule ID:** `5cb93fae`
- **Rule name:** Office application spawned a scripting engine
- **Count:** 98 alert events

### ATT&CK Mapping
| Field | Value |
|---|---|
| Technique ID | T1059.001 |
| Technique name | Command and Scripting Interpreter: PowerShell |
| Tactic | Execution |
| Kill-chain stage | Installation / Exploitation |

### Available Evidence

| Evidence | Detail |
|---|---|
| Event category | `process`, `event.kind = alert` |
| Action | `process_created` |
| Child process | `powershell.exe` |
| Parent process | `winword.exe` |
| Command line | `powershell.exe -nop -w hidden -enc <REDACTED_BASE64>` |
| Unique entity IDs | Each instance has a unique `process.entity_id` (UUID) |
| Affected hosts | 24 of 28 hosts — broad distribution |
| Affected users | Multiple — asharma, dnair, jdsouza, kiyer, mkhan, nverma, pmehta, rkumar, sgupta, vreddy |
| Severity | 8 (High) |

**Example event:** `be6a3ada-e73e-4f00-8a66-61775612cebc`  
`2026-10-31T02:07:40.439Z | WS-FIN-010 | dnair | winword.exe -> powershell.exe | entity:457a59fb-3e84-4a46-af35-b9c884970e43`

### Missing Evidence

| Gap | Impact |
|---|---|
| No `winword.exe` process-creation event preceding the spawn | Cannot confirm Word was opened by user vs already running |
| No file event showing the malicious .docx being opened | Delivery mechanism unobserved |
| PowerShell command line shows `<REDACTED_BASE64>` — actual payload unknown | Cannot determine what the encoded command does |
| No network event linked via entity_id from these powershell.exe instances | Cannot see what PS called out to |
| Process parent's `entity_id` not recorded in alert events | Cannot chain parent's entity to other events |

### Expected Sequence
```
User opens malicious Word document
    → winword.exe starts [UNOBSERVED]
    → winword.exe spawns powershell.exe -nop -w hidden -enc <payload>
        ✅ OBSERVED (98 instances)
    → powershell.exe executes payload
        → [LINKS TO: Scenario 3 — autorun registry write]
        → [LINKS TO: Scenario 4 — C2 beaconing]
```

### Detection Opportunities
- ✅ **Parent-child process rule:** `parent.name IN (winword, excel, outlook) AND child.name IN (powershell, cmd, wscript, mshta)`
- ✅ **Encoded PowerShell flag:** `-enc` or `-encoded` in command line
- ✅ **Hidden window flag:** `-w hidden` or `-WindowStyle Hidden`
- ✅ **No-profile flag:** `-nop` or `-NoProfile`

### Correlation Opportunities
- **STRONG link to Scenario 3:** The autorun registry events (Scenario 3) are written by `powershell.exe`. The PowerShell processes here have entity_ids — if those entity_ids appear in Scenario 3's registry events, this confirms the same process wrote the Run key.
- **STRONG link to Scenario 4:** The beaconing events involve `powershell.exe` connecting to C2 domains. If the entity_id from these spawn events matches the process in the network connection events, the chain is confirmed.
- **NOTE:** Alert events do not carry entity_id for the parent `winword.exe`, only for the child `powershell.exe`.

### Limitations
- 98 instances across 24 hosts and 10 users suggests a **worm-like or document-campaign distribution** rather than a targeted single-host attack. This complicates incident clustering — each host's instance could be treated as a separate incident or as a repeated campaign.
- The encoded command line prevents behavioural analysis of the payload from this dataset alone.

---

## SCENARIO 3 — PERSISTENCE: AUTORUN REGISTRY KEY WRITTEN BY POWERSHELL

### Alert rule
- **Rule ID:** `1581c4a4`
- **Rule name:** Autorun key created by scripting engine
- **Count:** 103 alert events

### ATT&CK Mapping
| Field | Value |
|---|---|
| Technique ID | T1547.001 |
| Technique name | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| Tactic | Persistence |
| Kill-chain stage | Persistence |

### Available Evidence

| Evidence | Detail |
|---|---|
| Event category | `registry`, `event.kind = alert` |
| Action | `registry_value_set` |
| Registry path | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<SUSPECT_ENTRY>` |
| Writing process | `powershell.exe` |
| Affected hosts | 24+ hosts |
| Affected users | Multiple |
| Severity | 8 (High) |

**Example event:** `d7be44f1-d686-469b-bf4b-2dbf9b8b5051`  
`2026-10-31T02:07:40.445Z | WS-FIN-014 | mkhan | powershell.exe | HKCU\...\Run\<SUSPECT_ENTRY>`

### Missing Evidence

| Gap | Impact |
|---|---|
| Registry value data (`<SUSPECT_ENTRY>`) is a placeholder — actual payload path unknown | Cannot confirm what executes at logon |
| No `process.entity_id` in registry alert events | Cannot directly link to the spawning winword→powershell event |
| No `process.parent.name` in registry alert events | Parent chain broken at this stage |
| No subsequent logon/startup execution events | Persistence trigger not observed |

### Expected Sequence
```
powershell.exe (spawned by winword) [→ Scenario 2]
    → writes HKCU\...\Run\<payload_path>
        ✅ OBSERVED (103 instances)
    → [MISSING: Logon event triggering the Run key]
    → [MISSING: Payload execution at logon]
```

### Detection Opportunities
- ✅ **Registry key path matching:** `path LIKE '%\CurrentVersion\Run%'` AND `process.name = 'powershell.exe'`
- ✅ **Scripting engine writing autorun:** Cross-category rule (process category = 'scripting engine', registry category = 'run key')

### Correlation Opportunities
- **MODERATE to STRONG link to Scenario 2:** Both involve `powershell.exe` on the same host and user. Without entity_id matching, relationship is MODERATE (same host + user + compatible activity). If we can match process PIDs across events on the same host within the same timestamp window, it becomes STRONG.
- **Host + user pair:** For each `(host, user)` pair in Scenario 2, check if the same pair appears in Scenario 3 — this is the primary correlation key.

### Limitations
- Registry alert events are missing the `process.entity_id` field, making direct process-chain linking impossible. Correlation must use `(host, user, process.name)` as a proxy.
- `<SUSPECT_ENTRY>` placeholder prevents actual payload identification.

---

## SCENARIO 4 — COMMAND AND CONTROL: POWERSHELL BEACONING TO LOW-REPUTATION DESTINATION

### Alert rule
- **Rule ID:** `34eb26ba`
- **Rule name:** Beaconing to low-reputation destination
- **Count:** 118 alert events

### ATT&CK Mapping
| Field | Value |
|---|---|
| Technique ID | T1071.001 |
| Technique name | Application Layer Protocol: Web Protocols |
| Tactic | Command and Control |
| Kill-chain stage | Command and Control |

### Available Evidence

| Evidence | Detail |
|---|---|
| Event category | `network`, `event.kind = alert` |
| Action | `network_connection` |
| Connecting process | `powershell.exe` |
| Destination domains | `sim-exfil.example`, `suspicious-example-c2.invalid`, `bad-domain-demo.test` |
| Destination port | 443 (HTTPS) |
| Transfer size | Small and uniform (~3,638 bytes) — consistent with beaconing |
| Affected hosts | Multiple |
| Severity | 8 (High) |

**Example event:** `36ee887c-7b16-41e4-9809-aefb358c1289`  
`2026-10-31T02:07:40.439Z | WS-FIN-015 | vreddy | powershell.exe -> sim-exfil.example | 3,638 bytes`

### Missing Evidence

| Gap | Impact |
|---|---|
| No `process.entity_id` in network alert events | Cannot directly link to Scenario 2's spawned powershell.exe |
| No process parent chain in these events | Lineage broken |
| Uniform 3,638 bytes — may be a template value | Actual payload / command unknown |
| No response data (inbound bytes) | C2 instructions not observable |
| No DNS query events preceding these connections | Pre-connection resolution not linked |

### Expected Sequence
```
powershell.exe [spawned by winword, from Scenario 2]
    → connects to sim-exfil.example:443 (HTTPS)
        ✅ OBSERVED (118 instances)
    → receives C2 commands [UNOBSERVED]
    → [potentially triggers: Scenario 3 persistence write]
    → [potentially triggers: Scenario 5 ransomware deployment]
```

### Detection Opportunities
- ✅ **Process-to-suspicious-domain rule:** `process.name = 'powershell.exe'` AND `destination.domain IN suspicious_list`
- ✅ **Suspicious domain blocklist:** Three simulation domains clearly anomalous
- ✅ **Small uniform byte transfers:** Beaconing signature
- ✅ **Non-browser making HTTPS connections:** PowerShell on port 443 to non-Microsoft domains

### Correlation Opportunities
- **STRONG link to Scenario 2 (same host + user + process name):** If `(host, user)` pair matches a Scenario 2 event with the same `process.name = 'powershell.exe'`, this is highly correlated.
- **Timestamp proximity:** Given all events share millisecond timestamps, temporal proximity cannot distinguish ordering — sequence number ordering must be used.
- **DNS pre-connection evidence:** DNS queries for the suspicious domains also exist in the normal (event-kind) telemetry — these can be linked by host.

### Limitations
- Cannot confirm the same PowerShell process instance connects to C2 without entity_id linkage in network events.
- The three suspicious domains represent distinct C2/exfil targets — correlation should be per-domain, not aggregate.

---

## SCENARIO 5 — IMPACT: RANSOMWARE — MASS FILE RENAME WITH .LOCKED EXTENSION

### Alert rule
- **Rule ID:** `8476ceb0`
- **Rule name:** Rapid mass file rename to uniform extension
- **Count:** 88 alert events

### ATT&CK Mapping
| Field | Value |
|---|---|
| Technique ID | T1486 |
| Technique name | Data Encrypted for Impact |
| Tactic | Impact |
| Kill-chain stage | Actions on Objectives |

### Available Evidence

| Evidence | Detail |
|---|---|
| Event category | `file`, `event.kind = alert` |
| Action | `file_rename` |
| Renamed-to extension | `.locked` |
| File paths | `C:\Users\<user>\Documents\<many>.locked` (Windows), `/home/<user>/<many>.locked` (Linux) |
| Process | `unknown.exe` — no hash, no entity_id |
| Affected hosts | 25 of 28 hosts (including Linux servers) |
| Severity | 10 (Critical) |
| `labels_extra.files_renamed_60s` | Values up to 3,976 per event |

**Example event:** `cf3575b7-a2dc-4b06-b656-4f4bd45a7920`  
`2026-10-31T02:07:40.448Z | WS-SALES-014 | vreddy | unknown.exe | C:\Users\vreddy\Documents\<many>.locked`

**Hosts affected by rename alerts:**
SRV-FILE-01 (8), WS-SALES-013 (6), WS-ENG-012 (6), WS-FIN-015 (6), WS-SALES-015 (6), WS-ENG-014 (5), WS-SALES-014 (5), WS-SALES-012 (5), WS-FIN-011 (5), SRV-WEB-01 (4), WS-FIN-012 (4), WS-HR-010 (3), WS-FIN-013 (3), WS-HR-012 (2), WS-ENG-010 (2), WS-ENG-015 (2), WS-FIN-014 (2), WS-HR-015 (2), SRV-DB-01 (2), WS-HR-013 (2), WS-HR-011 (2), SRV-DC-01 (2), WS-ENG-011 (2), WS-HR-014 (1), WS-SALES-011 (1)

### Missing Evidence

| Gap | Impact |
|---|---|
| `process.entity_id` absent from file rename events | Cannot link to PowerShell spawn chain |
| `unknown.exe` — no executable path, hash, or parent | Ransomware binary unidentifiable |
| `file.target_path` absent | Only renamed-to path shown; original name unknown |
| No file creation event for `unknown.exe` | Dropper event not present |
| No process-creation event for `unknown.exe` | Process start unobserved |
| No registry write by `unknown.exe` | Alternative persistence not linked |
| No lateral movement events immediately before Linux host renames | Cross-platform spread mechanism unclear |

### Expected Sequence
```
powershell.exe [from Scenario 2/4] executes payload
    → drops/downloads unknown.exe [UNOBSERVED]
    → unknown.exe starts [UNOBSERVED — no process_created event]
    → unknown.exe renames files to .locked
        ✅ OBSERVED (88 instances across 25 hosts)
    → [MISSING: ransom note creation]
    → [MISSING: encryption key exfiltration]
```

### Detection Opportunities
- ✅ **Mass rename threshold:** `labels_extra.files_renamed_60s` > configurable threshold (e.g., 100)
- ✅ **Suspicious extension pattern:** File paths ending in `.locked`
- ✅ **Unknown process performing file operations:** `process.name = 'unknown.exe'`
- ✅ **Cross-platform spread indicator:** Both Windows and Linux hosts affected simultaneously

### Correlation Opportunities
- **MODERATE link to Scenario 2/3/4:** Same (host, user) pairs appear in execution + beaconing + ransomware stages. Without entity_id linkage, relationship is MODERATE.
- **WEAK to NONE inter-host links:** The fact that 25 hosts are simultaneously affected could indicate worm-like propagation or a coordinated deployment, but there is no lateral movement telemetry linking the hosts.
- **Linux vs Windows distinction:** SRV-DB-01 and SRV-WEB-01 (Linux, RHEL 9.3) are also affected — indicates the payload is cross-platform or a separate Linux-targeting payload was deployed.

### Limitations
- `unknown.exe` is the critical missing pivot point. Without its process-creation event or entity_id, this scenario cannot be fully reconstructed in the attack graph.
- The breadth (25/28 hosts) makes this look like a **campaign** rather than a single-incident attack path.

---

## CROSS-SCENARIO CORRELATION MATRIX

| Scenario | 1 (Brute Force) | 2 (Office Macro) | 3 (Persistence) | 4 (C2 Beacon) | 5 (Ransomware) |
|---|---|---|---|---|---|
| 1 (Brute Force) | — | WEAK (shared users) | WEAK (shared users) | WEAK (shared users) | WEAK (shared users) |
| 2 (Office Macro) | WEAK | — | **MODERATE** (host+user+PS) | **MODERATE-STRONG** (host+user+PS) | MODERATE (host+user) |
| 3 (Persistence) | WEAK | **MODERATE** | — | **MODERATE** (host+user+PS) | MODERATE (host+user) |
| 4 (C2 Beacon) | WEAK | **MODERATE-STRONG** | **MODERATE** | — | MODERATE (host+user) |
| 5 (Ransomware) | WEAK | MODERATE | MODERATE | MODERATE | — |

**Legend:**
- STRONG: Multiple independent dimensions match (entity_id + host + user + process)
- MODERATE: Two dimensions match (host + user or host + process)
- WEAK: One dimension only (shared user across hosts OR shared IP)

---

## PLANTED ATTACK NARRATIVE

Based on the evidence, the plausible planted scenario is:

1. **External brute force** (T1110) targets **SRV-DC-01** from three external IPs against multiple accounts → **partially successful** (success events exist but not linked to attacker IPs)
2. **Phishing campaign** delivers malicious Word documents to users → **winword.exe spawns powershell.exe** (T1059.001) across 24 hosts
3. **PowerShell payload** writes **autorun registry keys** (T1547.001) for persistence across 24 hosts
4. **PowerShell** establishes **C2 beaconing** (T1071.001) to three attacker-controlled domains
5. **Ransomware** (`unknown.exe`) is deployed across 25 hosts, **renaming files** to `.locked` (T1486)

This is a **simultaneous multi-host campaign** simulation. The dataset does not contain a single-target, sequential attack chain. Every scenario touches nearly all hosts.

---

## INCIDENT CLASSIFICATION FORECAST

| Classification | Expected incidents | Reasoning |
|---|---|---|
| `multi_stage_chain` | 5–10 per host | Scenarios 2→3→4 chain per host where (host, user) overlap |
| `repeated_campaign` | 1–3 | Brute force from same 3 IPs across multiple targets |
| `isolated_alert` | Many | Single-host file renames, single beacons, single auth failures |
| `suspicious_authentication_sequence` | 10–20 | Auth fail + auth success on same user (different hosts) |
| `repeated_activity` | 10–20 | Same user, same rule across multiple hosts |

---

## DETECTION RULE STRATEGY

### Rules to implement (YAML-driven, no ground-truth dependency)

| Rule ID | Rule name | Evidence required | ATT&CK |
|---|---|---|---|
| R-AUTH-001 | Brute force by external IP | `outcome=failure`, `source.ip` external, count in window | T1110 |
| R-AUTH-002 | Credential spray (multi-account from one IP) | Multiple users from same source | T1110.003 |
| R-AUTH-003 | Failure followed by success (same user) | 4625 then 4624 same user within window | T1110 |
| R-PROC-001 | Office app spawning scripting engine | parent IN office_apps AND child IN scripting_engines | T1059.001 |
| R-PROC-002 | Encoded PowerShell execution | `-enc` or `-encoded` in command_line | T1059.001 |
| R-PROC-003 | Hidden window PowerShell | `-w hidden` or `-WindowStyle` in command_line | T1564.003 |
| R-NET-001 | Powershell connecting to suspicious domain | process=powershell.exe AND domain IN blocklist | T1071.001 |
| R-NET-002 | Suspicious domain connection (any process) | destination.domain IN blocklist | T1071.001 |
| R-REG-001 | Scripting engine writing Run key | process=powershell.exe AND registry path contains Run | T1547.001 |
| R-FILE-001 | Mass file rename to suspicious extension | file.path ends in .locked/.encrypted/etc. | T1486 |
| R-FILE-002 | File rename by unknown process | process.name = unknown.exe | T1486 |
| R-AUTH-004 | Service account interactive logon | svc_* accounts + logon_type = Interactive | T1078.002 |

### Rules NOT to implement (no supporting evidence)

| Excluded rule | Reason |
|---|---|
| New account creation (4720) | No 4720 events present |
| Privilege escalation | No UAC/privilege events present |
| Large data exfiltration | No connection exceeds 1MB |
| Pass-the-Hash indicators | No NTLMv2 challenge-response fields |
| DLL sideloading | No image-load events |
| Scheduled task creation | No task scheduler events |

---

## LIMITATIONS SUMMARY

| Limitation | Impact on reconstruction |
|---|---|
| Sub-second timestamp window | Temporal ordering impossible; must use sequence numbers |
| Missing entity_id on network/registry alert events | Process-to-network and process-to-registry chain broken |
| `unknown.exe` unresolvable | Ransomware stage cannot be linked upstream |
| No account creation events | Privilege escalation stage cannot be observed |
| No successful logon from attacker IPs | Brute force success cannot be confirmed |
| All events appear simultaneous | No natural time-window-based correlation available |
| Broad campaign (25+ hosts) | Clustering must distinguish per-host chains from cross-host campaign |
| `<SUSPECT_ENTRY>` and `<REDACTED_BASE64>` placeholders | Payload contents unknown |
| No `file.target_path` | Original file names before rename are unknown |
