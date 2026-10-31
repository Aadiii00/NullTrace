"""
Dataset validator — pre-flight checks before ingestion.

Validates:
- File exists and is readable
- File size > 0
- First non-empty character indicates expected format
- Sample of records parse as valid JSON objects
- Required fields present in samples
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REQUIRED_FIELDS = ["event", "host", "user", "@timestamp"]
REQUIRED_EVENT_FIELDS = ["id", "kind", "category", "action"]


def validate_file(file_path: str | Path, sample_size: int = 20) -> Dict:
    """
    Validate a JSON/JSONL file before ingestion.
    
    Returns a dict with:
      - valid: bool
      - format: 'jsonl' | 'json' | 'unknown'
      - file_size: int
      - errors: List[str]
      - warnings: List[str]
      - sample_valid: int
      - sample_invalid: int
      - missing_fields: Dict[str, int]
    """
    path = Path(file_path)
    result = {
        "valid": False,
        "format": "unknown",
        "file_size": 0,
        "errors": [],
        "warnings": [],
        "sample_valid": 0,
        "sample_invalid": 0,
        "missing_fields": {},
    }

    if not path.exists():
        result["errors"].append(f"File not found: {path}")
        return result

    if not path.is_file():
        result["errors"].append(f"Path is not a file: {path}")
        return result

    result["file_size"] = path.stat().st_size
    if result["file_size"] == 0:
        result["errors"].append("File is empty")
        return result

    # Detect format
    fmt, first_char_err = _detect_format(path)
    result["format"] = fmt
    if first_char_err:
        result["errors"].append(first_char_err)
        return result

    # Sample validation
    sample_errors = []
    missing: Dict[str, int] = {}

    lines_checked = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            # For JSON array format, just try to parse the whole first N chars
            if fmt == "json":
                if lines_checked == 0:
                    try:
                        # Validate it's parseable at all — we won't load all
                        partial = stripped[:2000]
                        if not partial.startswith("[") and not partial.startswith("{"):
                            sample_errors.append("File does not start with [ or {")
                    except Exception as e:
                        sample_errors.append(str(e))
                lines_checked += 1
                if lines_checked >= sample_size:
                    break
                continue

            # JSONL
            try:
                obj = json.loads(stripped)
                if not isinstance(obj, dict):
                    sample_errors.append(f"Line is not a JSON object")
                    result["sample_invalid"] += 1
                    continue

                # Check required top-level fields
                for field in REQUIRED_FIELDS:
                    if field not in obj:
                        missing[field] = missing.get(field, 0) + 1

                # Check event sub-fields
                event_obj = obj.get("event", {})
                if isinstance(event_obj, dict):
                    for field in REQUIRED_EVENT_FIELDS:
                        if field not in event_obj:
                            key = f"event.{field}"
                            missing[key] = missing.get(key, 0) + 1

                result["sample_valid"] += 1

            except json.JSONDecodeError as e:
                sample_errors.append(f"JSON parse error: {e}")
                result["sample_invalid"] += 1

            lines_checked += 1
            if lines_checked >= sample_size:
                break

    result["missing_fields"] = missing

    if sample_errors:
        result["warnings"].extend(sample_errors[:5])

    # Warnings for missing fields
    for field, count in missing.items():
        if count > sample_size * 0.5:
            result["errors"].append(f"Required field '{field}' missing in {count}/{lines_checked} sampled records")
        elif count > 0:
            result["warnings"].append(f"Field '{field}' missing in {count}/{lines_checked} sampled records")

    if result["errors"]:
        result["valid"] = False
    elif result["sample_valid"] == 0 and lines_checked > 0:
        result["errors"].append("No valid records found in sample")
        result["valid"] = False
    else:
        result["valid"] = True

    return result


def _detect_format(path: Path) -> Tuple[str, Optional[str]]:
    """Return (format, error_or_None)."""
    with open(path, "rb") as f:
        raw = b""
        for _ in range(4096):
            b = f.read(1)
            if not b:
                break
            ch = b.decode("utf-8", errors="ignore")
            if ch.strip():
                raw = b
                break

    if not raw:
        return "unknown", "File appears empty or contains only whitespace"

    first_ch = raw.decode("utf-8", errors="ignore").strip()
    if first_ch == "[":
        return "json", None
    if first_ch == "{":
        return "jsonl", None
    return "unknown", f"Unexpected first character '{first_ch}' — expected '{{' (JSONL) or '[' (JSON array)"
