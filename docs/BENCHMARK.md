# BENCHMARK.md — KillChain Performance & Latency Metrics

**Benchmark Date:** 2026-10-31T03:41:08.338913+00:00  
**Dataset:** `edr_10000_logs.json` (10,000 events, 8.38 MB)  
**Database:** DuckDB in-process columnar database  

---

## 1. PIPELINE LATENCY & THROUGHPUT

| Stage | Operations | Latency (s) | Throughput | Status |
|---|---|---:|---:|---|
| **Streaming Ingestion** | 10,000 events, schema validation, entity resolution | Ingested | ~2,500 events/s | PASS |
| **Detection Engine** | 7 rules evaluated against 10,000 events | 3.748 s | 2,668 events/s | PASS |
| **Incident Correlation** | Multi-stage graph clustering, 610 detections correlated | 2.489 s | 245 alerts/s | PASS |
| **Attack Graph & Blast Radius** | 100 nodes, 819 edges, BFS reachability | 0.071 s | Sub-second | PASS |
| **Ground Truth Evaluation** | Confusion matrix & metric computation | 0.046 s | Sub-second | PASS |

---

## 2. DETECTION ACCURACY METRICS

| Metric | Target | Achieved | Status |
|---|---|---:|---|
| **Recall (Sensitivity)** | ≥ 95.0% | **100.00%** | **PASS** (Zero Missed Attacks) |
| **Accuracy** | ≥ 95.0% | **98.94%** | **PASS** |
| **Specificity** | ≥ 95.0% | **98.88%** | **PASS** |
| **F1 Score** | ≥ 85.0% | **90.48%** | **PASS** |
| **Precision** | ≥ 80.0% | **82.62%** | **PASS** |

---

## 3. ATTACK SCENARIO VERIFICATION

| Planted Scenario | Technique | Ground Truth | Detected | Result |
|---|---|---:|---:|---|
| Ransomware Rapid Mass File Rename | T1486 | 88 | 88 | **PASS (100%)** |
| Command & Control Beaconing | T1071.001 | 118 | 118 | **PASS (100%)** |
| Autorun Registry Run Key Persistence | T1547.001 | 103 | 103 | **PASS (100%)** |
| Office Macro Spawning Scripting Engine | T1059.001 | 98 | 98 | **PASS (100%)** |
| Password Spraying & Brute Force Logons | T1110 | 97 | 161 | **PASS (100% Recall)** |
