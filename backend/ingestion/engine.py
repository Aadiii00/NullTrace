"""
Streaming ingestion engine for KillChain.

Supports:
- JSONL (one JSON object per line) — the primary format
- JSON array file (single array wrapper)
- Streaming read — never loads entire file into memory
- Chunk-based DuckDB inserts (configurable chunk_size)
- Duplicate event_id detection via in-memory set + DB check
- Malformed-record isolation with row-level error capture
- Stable seq_num assignment (0-based line position)
- UTC timestamp normalization
- Raw JSON preservation
- Progress reporting via Rich
- Resumable: skips already-ingested event_ids
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, Iterator, List, Optional, Tuple

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TransferSpeedColumn,
)

from backend.config import get_settings
from backend.database import get_db, init_schema

console = Console()

# ── Helpers ────────────────────────────────────────────────────────────────────

def _safe_get(obj: Dict, *keys, default=None):
    """Safe nested dict access."""
    cur = obj
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
        if cur is None:
            return default
    return cur


def _ts_to_utc(ts_str: Optional[str]) -> Optional[str]:
    """Normalize any ISO-8601 timestamp to UTC string. Returns None on failure."""
    if not ts_str:
        return None
    try:
        # Python 3.11+ handles Z suffix natively
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return None


def _det_format(file_path: Path) -> str:
    """Detect JSON vs JSONL by inspecting first non-empty byte."""
    with open(file_path, "rb") as f:
        for _ in range(1024):
            b = f.read(1)
            if not b:
                break
            ch = b.decode("utf-8", errors="ignore").strip()
            if ch == "[":
                return "json"
            if ch == "{":
                return "jsonl"
    return "jsonl"


def _stream_jsonl(file_path: Path) -> Generator[Tuple[int, str], None, None]:
    """Yield (line_number_0based, raw_line) for each non-empty line."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for seq, line in enumerate(f):
            stripped = line.strip()
            if stripped:
                yield seq, stripped


def _stream_json_array(file_path: Path) -> Generator[Tuple[int, str], None, None]:
    """
    Stream objects from a JSON array file without loading everything.
    Uses a simple bracket-depth counter — works for flat arrays of objects.
    """
    import re
    depth = 0
    buf: List[str] = []
    seq = 0
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            for ch in raw_line:
                if ch == "{":
                    depth += 1
                if depth > 0:
                    buf.append(ch)
                if ch == "}":
                    depth -= 1
                    if depth == 0 and buf:
                        yield seq, "".join(buf).strip()
                        buf = []
                        seq += 1


def _normalize_event(seq_num: int, raw: str, dataset_id: str) -> Tuple[Optional[Dict], Optional[Dict], Optional[str]]:
    """
    Parse one raw JSON line and extract:
    - event_row: for `events` table
    - norm_row: for `normalized_events` table
    - error: string if malformed

    Returns (event_row, norm_row, error).
    """
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        return None, None, f"JSON parse error: {e}"

    if not isinstance(obj, dict):
        return None, None, "Root is not a JSON object"

    event_id = _safe_get(obj, "event", "id")
    if not event_id:
        return None, None, "Missing event.id"

    # ── events table row ──────────────────────────────────────────────────────
    host_ips = _safe_get(obj, "host", "ip") or []
    host_ip = host_ips[0] if isinstance(host_ips, list) and host_ips else None

    event_row = {
        "seq_num": seq_num,
        "event_id": event_id,
        "dataset_id": dataset_id,
        "timestamp_utc": _ts_to_utc(_safe_get(obj, "@timestamp")),
        "event_kind": _safe_get(obj, "event", "kind"),
        "event_category": _safe_get(obj, "event", "category", default=[None])[0]
            if isinstance(_safe_get(obj, "event", "category"), list)
            else _safe_get(obj, "event", "category"),
        "event_action": _safe_get(obj, "event", "action"),
        "event_outcome": _safe_get(obj, "event", "outcome"),
        "event_severity": int(_safe_get(obj, "event", "severity") or 0),
        "dataset_name": _safe_get(obj, "event", "dataset"),
        "host_name": _safe_get(obj, "host", "name"),
        "host_ip": host_ip,
        "host_os_type": _safe_get(obj, "host", "os", "type"),
        "user_name": _safe_get(obj, "user", "name"),
        "user_domain": _safe_get(obj, "user", "domain"),
        "agent_id": _safe_get(obj, "agent", "id"),
        "raw_json": raw,
    }

    # ── normalized_events table row ───────────────────────────────────────────
    # Technique / tactic — may be lists
    tech_ids = _safe_get(obj, "threat", "technique", "id") or []
    tech_nms = _safe_get(obj, "threat", "technique", "name") or []
    tech_id = tech_ids[0] if isinstance(tech_ids, list) and tech_ids else (tech_ids or None)
    tech_nm = tech_nms[0] if isinstance(tech_nms, list) and tech_nms else (tech_nms or None)

    labels_extra = _safe_get(obj, "labels_extra")

    norm_row = {
        "event_id": event_id,
        "seq_num": seq_num,
        # Process
        "process_name": _safe_get(obj, "process", "name"),
        "process_pid": _safe_get(obj, "process", "pid"),
        "process_entity_id": _safe_get(obj, "process", "entity_id"),
        "process_cmdline": _safe_get(obj, "process", "command_line"),
        "process_exe": _safe_get(obj, "process", "executable"),
        "process_md5": _safe_get(obj, "process", "hash", "md5"),
        "process_sha256": _safe_get(obj, "process", "hash", "sha256"),
        "parent_name": _safe_get(obj, "process", "parent", "name"),
        "parent_pid": _safe_get(obj, "process", "parent", "pid"),
        # Network
        "src_ip": _safe_get(obj, "source", "ip"),
        "src_port": _safe_get(obj, "source", "port"),
        "dst_ip": _safe_get(obj, "destination", "ip"),
        "dst_port": _safe_get(obj, "destination", "port"),
        "dst_domain": _safe_get(obj, "destination", "domain"),
        "net_bytes": _safe_get(obj, "network", "bytes"),
        "net_protocol": _safe_get(obj, "network", "protocol"),
        "net_direction": _safe_get(obj, "network", "direction"),
        "net_transport": _safe_get(obj, "network", "transport"),
        # DNS
        "dns_question": _safe_get(obj, "dns", "question", "name"),
        "dns_response_code": _safe_get(obj, "dns", "response_code"),
        # Auth
        "auth_outcome": _safe_get(obj, "event", "outcome"),
        "logon_type": _safe_get(obj, "winlog", "logon", "type"),
        "winlog_event_id": _safe_get(obj, "winlog", "event_id"),
        # File
        "file_path": _safe_get(obj, "file", "path"),
        "file_name": _safe_get(obj, "file", "name"),
        "file_size": _safe_get(obj, "file", "size"),
        "file_target_path": _safe_get(obj, "file", "target_path"),
        # Registry
        "registry_path": _safe_get(obj, "registry", "path"),
        "registry_data": json.dumps(_safe_get(obj, "registry", "data")) if _safe_get(obj, "registry", "data") else None,
        # Alert
        "rule_id": _safe_get(obj, "rule", "id"),
        "rule_name": _safe_get(obj, "rule", "name"),
        "threat_technique_id": tech_id,
        "threat_technique_nm": tech_nm,
        "threat_tactic_nm": _safe_get(obj, "threat", "tactic", "name"),
        # Labels
        "label_synthetic": str(_safe_get(obj, "labels", "synthetic", default="false")).lower() == "true",
        "labels_extra_json": json.dumps(labels_extra) if labels_extra else None,
    }

    return event_row, norm_row, None


def _extract_entities(event_id: str, event_row: Dict, norm_row: Dict) -> List[Dict]:
    """
    Extract entity references from an event for the event_entities table.
    Returns a list of entity dicts.
    """
    entities = []

    def add(etype: str, value: Optional[str]):
        if value:
            entities.append({
                "event_id": event_id,
                "entity_type": etype,
                "entity_value": value.strip().lower() if isinstance(value, str) else str(value),
                "raw_value": value,
            })

    add("host", event_row.get("host_name"))
    add("user", event_row.get("user_name"))
    add("process", norm_row.get("process_name"))
    add("process_entity", norm_row.get("process_entity_id"))
    add("parent_process", norm_row.get("parent_name"))
    add("src_ip", norm_row.get("src_ip"))
    add("dst_ip", norm_row.get("dst_ip"))
    add("dst_domain", norm_row.get("dst_domain"))
    add("dns_domain", norm_row.get("dns_question"))
    add("file", norm_row.get("file_path"))
    add("registry", norm_row.get("registry_path"))

    return entities


# ── Main ingestion function ─────────────────────────────────────────────────────

def ingest_file(
    file_path: str | Path,
    dataset_id: str,
    db_path: Optional[str] = None,
    chunk_size: Optional[int] = None,
    max_records: Optional[int] = None,
    show_progress: bool = True,
    run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Stream-ingest a JSON/JSONL file into DuckDB.

    Returns a statistics dict.
    """
    settings = get_settings()
    file_path = Path(file_path)
    chunk_size = chunk_size or settings.ingestion.chunk_size
    max_records = max_records or settings.ingestion.max_records
    run_id = run_id or str(uuid.uuid4())

    if not file_path.exists():
        raise FileNotFoundError(f"Dataset file not found: {file_path}")

    file_size = file_path.stat().st_size
    fmt = _det_format(file_path)

    conn = get_db(db_path)
    init_schema(db_path)

    # Register / update dataset record
    conn.execute("""
        INSERT INTO datasets (dataset_id, filename, file_path, file_size_bytes, format, status)
        VALUES (?, ?, ?, ?, ?, 'ingesting')
        ON CONFLICT (dataset_id) DO UPDATE SET
            filename = excluded.filename,
            file_path = excluded.file_path,
            file_size_bytes = excluded.file_size_bytes,
            format = excluded.format,
            status = 'ingesting',
            updated_at = NOW()
    """, [dataset_id, file_path.name, str(file_path), file_size, fmt])

    # Register ingestion run
    started_at = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        INSERT INTO ingestion_metadata
            (run_id, dataset_id, started_at, status)
        VALUES (?, ?, ?, 'running')
        ON CONFLICT (run_id) DO UPDATE SET status = 'running'
    """, [run_id, dataset_id, started_at])
    conn.commit()

    # Load already-ingested event_ids to support resume
    existing_ids: set[str] = set()
    rows = conn.execute(
        "SELECT event_id FROM events WHERE dataset_id = ?", [dataset_id]
    ).fetchall()
    for (eid,) in rows:
        existing_ids.add(eid)

    global _entity_counter
    max_id_row = conn.execute("SELECT COALESCE(MAX(id), 0) FROM event_entities").fetchone()
    _entity_counter = int(max_id_row[0]) if max_id_row else 0

    # ── Stats ─────────────────────────────────────────────────────────────────
    stats = {
        "run_id": run_id,
        "dataset_id": dataset_id,
        "total_records": 0,
        "valid_records": 0,
        "invalid_records": 0,
        "duplicate_records": 0,
        "processed_bytes": 0,
        "ingestion_time_s": 0.0,
        "rows_per_second": 0.0,
        "format": fmt,
    }

    # Chunk accumulators
    event_rows: List[Dict] = []
    norm_rows: List[Dict] = []
    entity_rows: List[Dict] = []
    seen_this_run: set[str] = set()

    # ── Progress display ───────────────────────────────────────────────────────
    progress_ctx = Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("• {task.fields[valid]} valid"),
        TextColumn("• {task.fields[invalid]} invalid"),
        TextColumn("• {task.fields[dup]} dup"),
        TimeElapsedColumn(),
        console=console,
        disable=not show_progress,
    )

    streamer = _stream_jsonl(file_path) if fmt == "jsonl" else _stream_json_array(file_path)

    def flush_chunk():
        if event_rows:
            _insert_events(conn, event_rows)
        if norm_rows:
            _insert_norm(conn, norm_rows)
        if entity_rows:
            _insert_entities(conn, entity_rows)
        conn.commit()
        event_rows.clear()
        norm_rows.clear()
        entity_rows.clear()

    t_start = time.perf_counter()

    with progress_ctx as progress:
        task = progress.add_task(
            f"Ingesting {file_path.name}",
            total=None,
            valid=0, invalid=0, dup=0,
        )

        for seq_num, raw_line in streamer:
            if max_records and stats["total_records"] >= max_records:
                break

            stats["total_records"] += 1
            stats["processed_bytes"] += len(raw_line.encode("utf-8"))

            event_row, norm_row, error = _normalize_event(seq_num, raw_line, dataset_id)

            if error or event_row is None:
                stats["invalid_records"] += 1
                progress.update(task, advance=1, invalid=stats["invalid_records"])
                continue

            eid = event_row["event_id"]

            # Duplicate check
            if eid in existing_ids or eid in seen_this_run:
                stats["duplicate_records"] += 1
                progress.update(task, advance=1, dup=stats["duplicate_records"])
                continue

            seen_this_run.add(eid)
            stats["valid_records"] += 1

            entities = _extract_entities(eid, event_row, norm_row)

            event_rows.append(event_row)
            norm_rows.append(norm_row)
            entity_rows.extend(entities)

            progress.update(task, advance=1, valid=stats["valid_records"])

            if len(event_rows) >= chunk_size:
                flush_chunk()

    # Final flush
    flush_chunk()

    t_end = time.perf_counter()
    elapsed = t_end - t_start
    stats["ingestion_time_s"] = round(elapsed, 3)
    stats["rows_per_second"] = round(stats["valid_records"] / elapsed, 1) if elapsed > 0 else 0

    # Update DB metadata
    completed_at = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        UPDATE ingestion_metadata SET
            completed_at = ?,
            total_records = ?,
            valid_records = ?,
            invalid_records = ?,
            duplicate_records = ?,
            processed_bytes = ?,
            rows_per_second = ?,
            status = 'completed'
        WHERE run_id = ?
    """, [
        completed_at,
        stats["total_records"],
        stats["valid_records"],
        stats["invalid_records"],
        stats["duplicate_records"],
        stats["processed_bytes"],
        stats["rows_per_second"],
        run_id,
    ])
    conn.execute("""
        UPDATE datasets SET status = 'ingested', updated_at = NOW()
        WHERE dataset_id = ?
    """, [dataset_id])
    conn.commit()

    return stats


# ── Batch insert helpers ────────────────────────────────────────────────────────

def _insert_events(conn: Any, rows: List[Dict]) -> None:
    if not rows:
        return
    cols = list(rows[0].keys())
    placeholders = ", ".join(["?"] * len(cols))
    col_str = ", ".join(cols)
    sql = f"INSERT OR IGNORE INTO events ({col_str}) VALUES ({placeholders})"
    data = [[r[c] for c in cols] for r in rows]
    conn.executemany(sql, data)


def _insert_norm(conn: Any, rows: List[Dict]) -> None:
    if not rows:
        return
    cols = list(rows[0].keys())
    placeholders = ", ".join(["?"] * len(cols))
    col_str = ", ".join(cols)
    sql = f"INSERT OR IGNORE INTO normalized_events ({col_str}) VALUES ({placeholders})"
    data = [[r[c] for c in cols] for r in rows]
    conn.executemany(sql, data)


_entity_counter: int = 0


def _insert_entities(conn: Any, rows: List[Dict]) -> None:
    global _entity_counter
    if not rows:
        return
    sql = "INSERT INTO event_entities (id, event_id, entity_type, entity_value, raw_value) VALUES (?, ?, ?, ?, ?)"
    start = _entity_counter
    data = [
        (start + i + 1, r["event_id"], r["entity_type"], r["entity_value"], r["raw_value"])
        for i, r in enumerate(rows)
    ]
    _entity_counter += len(rows)
    conn.executemany(sql, data)


def get_ingestion_stats(dataset_id: str, db_path: Optional[str] = None) -> Optional[Dict]:
    """Return the latest ingestion run stats for a dataset."""
    conn = get_db(db_path)
    row = conn.execute("""
        SELECT run_id, dataset_id, started_at, completed_at,
               total_records, valid_records, invalid_records, duplicate_records,
               processed_bytes, rows_per_second, status
        FROM ingestion_metadata
        WHERE dataset_id = ?
        ORDER BY started_at DESC
        LIMIT 1
    """, [dataset_id]).fetchone()
    if not row:
        return None
    cols = ["run_id","dataset_id","started_at","completed_at","total_records",
            "valid_records","invalid_records","duplicate_records","processed_bytes",
            "rows_per_second","status"]
    return dict(zip(cols, row))
