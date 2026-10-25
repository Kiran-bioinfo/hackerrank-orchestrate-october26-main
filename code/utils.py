"""
utils.py — Shared helpers for the Ghost Data deletion-audit agent.

Modules:
  1. Data loaders  – safe CSV / evidence file readers
  2. Identity resolver – transitive alias expansion
  3. Evidence parsers  – SQL, JSON, log, text evidence readers
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import re
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATASET_DIR = Path(__file__).resolve().parent.parent / "dataset"

# Columns expected per CSV file (minimum required; extras are allowed)
_EXPECTED_COLUMNS: dict[str, list[str]] = {
    "deletion_requests.csv": [
        "case_id", "email", "requested_at", "reported_status",
        "reported_at", "audit_at", "request_text",
    ],
    "sample_deletion_requests.csv": [
        "case_id", "email", "requested_at", "reported_status",
        "reported_at", "audit_at", "request_text",
    ],
    "user_identities.csv": [
        "user_id", "name", "email", "phone", "email_hash", "updated_at",
    ],
    "user_audit_log.csv": [
        "audit_id", "user_id", "event_time", "field_name", "old_value", "new_value",
    ],
    "system_activity.csv": [
        "activity_id", "event_time", "event_type", "source_system",
        "target_system", "resource_id", "reported_result", "details",
    ],
    "deletion_rules.csv": [
        "rule_id", "data_category", "condition", "required_action",
    ],
    "evidence_files.csv": [
        "file_id", "file_path", "origin", "captured_at",
    ],
}


# ---------------------------------------------------------------------------
# 1. Data Loaders
# ---------------------------------------------------------------------------

def _load_csv(filename: str, *, dataset_dir: Path | None = None) -> pd.DataFrame:
    """Load a CSV from dataset_dir, validate columns, and return a DataFrame.

    Missing columns are added as empty strings so downstream code can rely
    on them existing without crashing.
    """
    base = dataset_dir or DATASET_DIR
    path = base / filename
    if not path.exists():
        logger.warning("CSV not found: %s – returning empty DataFrame", path)
        cols = _EXPECTED_COLUMNS.get(filename, [])
        return pd.DataFrame(columns=cols)

    try:
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
    except Exception as exc:
        logger.error("Failed to read %s: %s", path, exc)
        cols = _EXPECTED_COLUMNS.get(filename, [])
        return pd.DataFrame(columns=cols)

    # Ensure all expected columns exist
    for col in _EXPECTED_COLUMNS.get(filename, []):
        if col not in df.columns:
            logger.warning("Column '%s' missing from %s; filling with ''", col, filename)
            df[col] = ""

    return df


def load_deletion_requests(sample: bool = False, dataset_dir: Path | None = None) -> pd.DataFrame:
    """Return deletion_requests.csv (or sample_deletion_requests.csv)."""
    fname = "sample_deletion_requests.csv" if sample else "deletion_requests.csv"
    df = _load_csv(fname, dataset_dir=dataset_dir)
    df["audit_at_dt"] = pd.to_datetime(df["audit_at"], utc=True, errors="coerce")
    df["requested_at_dt"] = pd.to_datetime(df["requested_at"], utc=True, errors="coerce")
    return df


def load_user_identities(dataset_dir: Path | None = None) -> pd.DataFrame:
    """Return user_identities.csv with lowercased email/email_hash."""
    df = _load_csv("user_identities.csv", dataset_dir=dataset_dir)
    df["email_lower"] = df["email"].str.lower().str.strip()
    df["email_hash_lower"] = df["email_hash"].str.lower().str.strip()
    return df


def load_user_audit_log(dataset_dir: Path | None = None) -> pd.DataFrame:
    """Return user_audit_log.csv."""
    df = _load_csv("user_audit_log.csv", dataset_dir=dataset_dir)
    df["event_time_dt"] = pd.to_datetime(df["event_time"], utc=True, errors="coerce")
    return df


def load_system_activity(dataset_dir: Path | None = None) -> pd.DataFrame:
    """Return system_activity.csv."""
    df = _load_csv("system_activity.csv", dataset_dir=dataset_dir)
    df["event_time_dt"] = pd.to_datetime(df["event_time"], utc=True, errors="coerce")
    return df


def load_deletion_rules(dataset_dir: Path | None = None) -> pd.DataFrame:
    """Return deletion_rules.csv keyed by data_category for fast lookup."""
    return _load_csv("deletion_rules.csv", dataset_dir=dataset_dir)


def load_evidence_files(dataset_dir: Path | None = None) -> pd.DataFrame:
    """Return evidence_files.csv with captured_at parsed."""
    df = _load_csv("evidence_files.csv", dataset_dir=dataset_dir)
    df["captured_at_dt"] = pd.to_datetime(df["captured_at"], utc=True, errors="coerce")
    return df


# ---------------------------------------------------------------------------
# 2. Transitive Identity Resolver
# ---------------------------------------------------------------------------

def resolve_identities(
    user_id: str,
    identities_df: pd.DataFrame,
    audit_log_df: pd.DataFrame,
) -> dict[str, set[str]]:
    """Resolve all current and historical identifiers for *user_id*.

    Returns a dict:
        {
          "user_ids":     {user_id, ...},
          "emails":       {current_email, historical_emails, ...},  # lowercase
          "phones":       {current_phone, historical_phones, ...},
          "email_hashes": {current_hash, ...},                      # lowercase
        }

    Algorithm:
      1. Seed with current identity record (user_identities.csv).
      2. Walk user_audit_log.csv for the matched user_id collecting every
         old_value / new_value for email and phone fields.
      3. Transitively close: if an email appears in old_value of *any* row,
         pull that row's user_id into the set, then repeat from step 2 for
         newly discovered user_ids.  This handles alias chains.
    """
    aliases: dict[str, set[str]] = {
        "user_ids": set(),
        "emails": set(),
        "phones": set(),
        "email_hashes": set(),
    }

    # Helper: lower-strip a value safely
    def norm(v: Any) -> str:
        return str(v).lower().strip() if v and str(v).strip() else ""

    def add_identity_row(row: pd.Series) -> None:
        if row.get("user_id"):
            aliases["user_ids"].add(str(row["user_id"]).strip())
        if row.get("email"):
            aliases["emails"].add(norm(row["email"]))
        if row.get("phone"):
            aliases["phones"].add(str(row["phone"]).strip())
        if row.get("email_hash"):
            aliases["email_hashes"].add(norm(row["email_hash"]))
        if row.get("email_lower"):
            aliases["emails"].add(row["email_lower"])
        if row.get("email_hash_lower"):
            aliases["email_hashes"].add(row["email_hash_lower"])

    # Step 1 – seed from user_identities
    uid_rows = identities_df[identities_df["user_id"] == user_id]
    for _, row in uid_rows.iterrows():
        add_identity_row(row)

    # Also add the raw user_id itself even if not in snapshot
    aliases["user_ids"].add(user_id)

    # Step 2+3 – walk audit log transitively
    processed_uids: set[str] = set()
    queue: set[str] = set(aliases["user_ids"])

    max_iterations = 20  # guard against infinite loops in malformed data
    iteration = 0

    while queue and iteration < max_iterations:
        iteration += 1
        uid = queue.pop()
        if uid in processed_uids:
            continue
        processed_uids.add(uid)

        rows = audit_log_df[audit_log_df["user_id"] == uid]
        for _, row in rows.iterrows():
            field = str(row.get("field_name", "")).lower()
            old_val = str(row.get("old_value", "")).strip()
            new_val = str(row.get("new_value", "")).strip()

            if field == "email":
                if old_val:
                    aliases["emails"].add(old_val.lower())
                    # Hash old email too
                    aliases["email_hashes"].add(_sha256(old_val.lower()))
                if new_val:
                    aliases["emails"].add(new_val.lower())
                    aliases["email_hashes"].add(_sha256(new_val.lower()))
            elif field == "phone":
                if old_val:
                    aliases["phones"].add(old_val)
                if new_val:
                    aliases["phones"].add(new_val)

        # Cross-reference: find other user_ids that share any alias email
        for email in list(aliases["emails"]):
            cross_rows = identities_df[identities_df["email_lower"] == email]
            for _, cr in cross_rows.iterrows():
                uid2 = str(cr["user_id"]).strip()
                if uid2 not in processed_uids:
                    aliases["user_ids"].add(uid2)
                    add_identity_row(cr)
                    queue.add(uid2)

    # Remove empty strings
    for key in aliases:
        aliases[key] = {v for v in aliases[key] if v}

    return aliases


def sha256_email(email: str) -> str:
    """Return the SHA-256 hash of a lowercased email, matching the dataset format."""
    return _sha256(email.lower().strip())


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def find_user_by_email(
    email: str,
    identities_df: pd.DataFrame,
    audit_log_df: pd.DataFrame,
) -> tuple[str | None, dict[str, set[str]]]:
    """Given a case email, find the matching user_id and resolve all aliases.

    Returns (user_id, alias_dict) or (None, empty_alias_dict).
    """
    email_lower = email.lower().strip()
    email_hash = _sha256(email_lower)

    # 1. Match on current email (case-insensitive)
    match = identities_df[identities_df["email_lower"] == email_lower]
    if match.empty:
        # 2. Match on email_hash
        match = identities_df[identities_df["email_hash_lower"] == email_hash]

    if match.empty:
        # 3. Scan audit_log old_value/new_value for email
        old_match = audit_log_df["old_value"].str.lower().str.strip() == email_lower
        new_match = audit_log_df["new_value"].str.lower().str.strip() == email_lower
        email_audit = audit_log_df[
            (audit_log_df["field_name"] == "email") & (old_match | new_match)
        ]
        if not email_audit.empty:
            uid = email_audit.iloc[0]["user_id"]
            aliases = resolve_identities(uid, identities_df, audit_log_df)
            return uid, aliases

        logger.debug("No user found for email: %s", email)
        # Return minimal stub so pipeline can still run
        stub_aliases: dict[str, set[str]] = {
            "user_ids": set(),
            "emails": {email_lower},
            "phones": set(),
            "email_hashes": {email_hash},
        }
        return None, stub_aliases

    uid = match.iloc[0]["user_id"]
    aliases = resolve_identities(uid, identities_df, audit_log_df)
    return uid, aliases


# ---------------------------------------------------------------------------
# 3. Evidence Parsers
# ---------------------------------------------------------------------------

def parse_sql_evidence(file_path: Path) -> list[dict[str, Any]]:
    """Execute a SQLite-compatible .sql snapshot and return all rows as dicts.

    Each dict contains: resource_id, origin_system, collection_name,
    record_json (parsed to dict), updated_at, _table (source table name).
    """
    if not file_path.exists():
        logger.warning("SQL evidence not found: %s", file_path)
        return []

    sql_text = file_path.read_text(encoding="utf-8", errors="replace")

    records: list[dict[str, Any]] = []
    try:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name

        conn = sqlite3.connect(tmp_path)
        conn.row_factory = sqlite3.Row
        try:
            conn.executescript(sql_text)
            cursor = conn.cursor()

            # Discover all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [r[0] for r in cursor.fetchall()]

            for table in tables:
                try:
                    cursor.execute(f"SELECT * FROM [{table}]")
                    rows = cursor.fetchall()
                    for row in rows:
                        d = dict(row)
                        rec: dict[str, Any] = {
                            "resource_id": d.get("resource_id", ""),
                            "origin_system": d.get("origin_system", ""),
                            "collection_name": d.get("collection_name", ""),
                            "record_json": {},
                            "updated_at": d.get("updated_at", ""),
                            "_table": table,
                        }
                        # Copy all remaining columns from the SQL row into the
                        # record dict so flat-column schemas (e.g. user_id,
                        # email, phone, account_status) are visible to matching.
                        for k, v in d.items():
                            if k not in rec:
                                rec[k] = v
                        raw_json = d.get("record_json", "{}")
                        if isinstance(raw_json, str):
                            try:
                                rec["record_json"] = json.loads(raw_json)
                            except json.JSONDecodeError:
                                rec["record_json"] = {}
                        records.append(rec)
                except Exception as tbl_exc:
                    logger.debug("Table %s skipped: %s", table, tbl_exc)
        finally:
            conn.close()
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    except Exception as exc:
        logger.error("SQL parse error for %s: %s", file_path, exc)

    return records


def parse_json_evidence(file_path: Path) -> list[dict[str, Any]]:
    """Parse a JSON evidence file (snapshot bundle, connector config, etc.).

    Returns a flat list of record-like dicts, each with a best-effort
    resource_id, origin_system, collection_name, and raw_data payload.
    """
    if not file_path.exists():
        logger.warning("JSON evidence not found: %s", file_path)
        return []

    try:
        data = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        logger.error("JSON parse error for %s: %s", file_path, exc)
        return []

    records: list[dict[str, Any]] = []

    # Pattern: {"service_exports": {system: {subkey: [records]}}}
    if isinstance(data, dict) and "service_exports" in data:
        exports = data.get("service_exports") or {}
        if isinstance(exports, dict):
            for system, subsystems in exports.items():
                if not isinstance(subsystems, dict):
                    continue
                for subkey, recs in subsystems.items():
                    if not isinstance(recs, list):
                        continue
                    for record in recs:
                        if isinstance(record, dict):
                            records.append({
                                "resource_id": record.get("resource_id", ""),
                                "origin_system": str(system),
                                "collection_name": str(subkey),
                                "record_json": record,
                                "raw_data": record,
                            })
        return records

    # Pattern: {"snapshots": [...]} (customer_data_snapshot_bundle)
    if isinstance(data, dict) and "snapshots" in data:
        for snap in data.get("snapshots", []):
            data_store = snap.get("data_store", "")
            collection = snap.get("collection", "")
            captured_at = snap.get("captured_at", "")
            for rec in snap.get("records", []):
                records.append({
                    "resource_id": rec.get("resource_id", ""),
                    "origin_system": data_store,
                    "collection_name": collection,
                    "captured_at": captured_at,
                    "record_json": rec,
                    "raw_data": rec,
                })
        return records

    # Pattern: {"resources": [...]} (service_resource_export)
    if isinstance(data, dict) and "resources" in data:
        for item in data.get("resources", []):
            records.append({
                "resource_id": item.get("resource_id", ""),
                "origin_system": item.get("system", item.get("origin_system", "")),
                "collection_name": item.get("collection", item.get("collection_name", "")),
                "captured_at": data.get("exported_at", ""),
                "record_json": item,
                "raw_data": item,
            })
        return records

    # Pattern: {"connectors": [...]} (connector_configurations)
    if isinstance(data, dict) and "connectors" in data:
        for item in data.get("connectors", []):
            records.append({
                "resource_id": item.get("resource_id", item.get("connector_id", "")),
                "origin_system": "integration_service",
                "collection_name": "connector_configurations",
                "captured_at": data.get("exported_at", data.get("captured_at", "")),
                "record_json": item,
                "raw_data": item,
            })
        return records

    # Pattern: {"jobs": [...]} (export_jobs)
    if isinstance(data, dict) and "jobs" in data:
        for item in data.get("jobs", []):
            records.append({
                "resource_id": item.get("resource_id", item.get("job_id", "")),
                "origin_system": "export_service",
                "collection_name": "export_jobs",
                "captured_at": data.get("exported_at", data.get("captured_at", "")),
                "record_json": item,
                "raw_data": item,
            })
        return records

    # Pattern: {"records": [...]} (security_audit_ledger, generic)
    if isinstance(data, dict) and "records" in data:
        for item in data.get("records", []):
            records.append({
                "resource_id": item.get("resource_id", ""),
                "origin_system": item.get("system", data.get("source", "")),
                "collection_name": item.get("collection", ""),
                "captured_at": data.get("exported_at", data.get("captured_at", "")),
                "record_json": item,
                "raw_data": item,
            })
        return records

    # Pattern: top-level list
    if isinstance(data, list):
        for item in data:
            records.append({
                "resource_id": item.get("resource_id", "") if isinstance(item, dict) else "",
                "origin_system": item.get("system", "") if isinstance(item, dict) else "",
                "collection_name": "",
                "captured_at": "",
                "record_json": item if isinstance(item, dict) else {},
                "raw_data": item,
            })
        return records

    # Generic recursive fallback: walk any dict/list and collect dict items
    # that contain "resource_id", "user_id", or "email" keys.
    if not records:
        collected = _flatten_json_records(data)
        for item in collected:
            records.append({
                "resource_id": item.get("resource_id", ""),
                "origin_system": "",
                "collection_name": "",
                "record_json": item,
                "raw_data": item,
            })
        if records:
            return records

    # Fallback: wrap entire doc
    records.append({
        "resource_id": "",
        "origin_system": "",
        "collection_name": "",
        "captured_at": "",
        "record_json": data if isinstance(data, dict) else {},
        "raw_data": data,
    })
    return records




def _flatten_json_records(data: Any) -> list[dict[str, Any]]:
    """Recursively walk *data* and collect dict items carrying identifiers."""
    collected: list[dict[str, Any]] = []
    match_keys = set(_RECORD_MATCH_KEYS) | {"resource_id"}
    match_keys_lower = {str(k).lower() for k in match_keys}

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            if any(str(k).lower() in match_keys_lower for k in node.keys()) or "resource_id" in node:
                collected.append(node)
            for value in node.values():
                _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(data)
    return collected



def parse_log_evidence(file_path: Path) -> list[dict[str, Any]]:
    """Parse structured log files into a list of event dicts.

    Handles two formats:
      - Key=value log lines  (e.g. resource_lookup_trace)
      - Plain-text log lines (fall back to raw line storage)

    For readback traces with paired "started"/"completed" events for the
    same resource_id, the two events are merged so the resulting record
    carries both the lookup_key (email/user_id) and the result
    (rows/http_status).
    """
    if not file_path.exists():
        logger.warning("Log evidence not found: %s", file_path)
        return []

    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    raw_events: list[dict[str, Any]] = []

    # Regex for "key=value" or "key=\"value with spaces\"" tokens
    kv_pattern = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')

    for line in lines:
        line = line.strip()
        if not line:
            continue

        pairs = kv_pattern.findall(line)
        if pairs:
            event: dict[str, Any] = {}
            for key, val in pairs:
                val = val.strip('"')
                event[key] = val
            event["_raw_line"] = line
            if "resource_id" not in event:
                event["resource_id"] = ""
            raw_events.append(event)
        else:
            raw_events.append({"raw_line": line, "resource_id": "", "_raw_line": line})

    # Merge paired started/completed events by resource_id
    by_resource: dict[str, list[dict[str, Any]]] = {}
    for ev in raw_events:
        rid = ev.get("resource_id", "")
        if rid:
            by_resource.setdefault(rid, []).append(ev)
        else:
            by_resource.setdefault("__raw__", []).append(ev)

    events: list[dict[str, Any]] = []
    for rid, evs in by_resource.items():
        if rid == "__raw__":
            events.extend(evs)
            continue

        if len(evs) == 1:
            events.append(evs[0])
            continue

        # Merge: started event has lookup_key, completed event has rows/http_status
        merged: dict[str, Any] = {}
        for ev in evs:
            merged.update(ev)
        # Prefer completed-event fields for result info
        for ev in evs:
            if ev.get("event", "").endswith("_completed"):
                for k in ("rows", "http_status", "result"):
                    if k in ev:
                        merged[k] = ev[k]
                break
        events.append(merged)

    return events


def parse_text_evidence(file_path: Path) -> list[dict[str, Any]]:
    """Parse a plain-text or handover .txt evidence file.

    Handles two formats:
      - Handover logs with pipe-delimited lines (e.g. customer_account_handover)
      - Generic plain-text (single record with extracted identifiers)

    Returns a list of record dicts, one per parsed line/entry.
    """
    if not file_path.exists():
        logger.warning("Text evidence not found: %s", file_path)
        return []

    text = file_path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    # Detect pipe-delimited handover format:
    #   - timestamp | system | resource_id | category | status | email
    handover_pattern = re.compile(
        r'^\s*-\s*\S+\s*\|\s*([^|]+?)\s*\|\s*(\S+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*(.+?)\s*$'
    )

    records: list[dict[str, Any]] = []
    handover_count = 0

    for line in lines:
        line = line.strip()
        if not line:
            continue

        m = handover_pattern.match(line)
        if m:
            handover_count += 1
            system = m.group(1).strip()
            res_id = m.group(2).strip()
            category = m.group(3).strip()
            status = m.group(4).strip()
            email = m.group(5).strip()

            # Map category text to origin_system for _infer_category
            origin_map = {
                "USER_PROFILE": "account_service",
                "ANALYTICS_PROFILE": "analytics_platform",
                "SEARCH_INDEX_ENTRY": "search_service",
                "SUPPORT_MESSAGE": "support_platform",
                "SUPPORT_ATTACHMENT": "support_platform",
                "USER_EXPORT": "export_service",
                "BACKUP_ARCHIVE": "backup_service",
                "DATA_FLOW": "integration_service",
                "SECURITY_AUDIT_LOG": "security_service",
            }
            origin = origin_map.get(category, system)

            # Determine actual state from status text
            status_lower = status.lower()
            if status_lower in ("not_found", "deleted", "absent", "removed"):
                actual_state = "DELETED"
                exposed_pii = False
            elif status_lower in ("redacted", "blocked", "disabled", "anonymized"):
                actual_state = status_lower.upper()
                exposed_pii = False
            elif status_lower in ("found", "identifiable", "active"):
                actual_state = "ACTIVE"
                exposed_pii = True if status_lower in ("found", "identifiable") else False
            else:
                actual_state = "ACTIVE"
                exposed_pii = True

            records.append({
                "resource_id": res_id,
                "origin_system": origin,
                "collection_name": category,
                "record_json": {
                    "resource_id": res_id,
                    "email": email if email and email not in ("no direct identifier", "") else "",
                    "status": status,
                    "category": category,
                },
                "updated_at": "",
                "_table": "text_handover",
                "actual_state_override": actual_state,
                "exposed_pii_override": exposed_pii,
            })
        else:
            # Non-handover line: collect identifiers for a generic record
            pass

    if handover_count > 0:
        return records

    # Fallback: generic single-record parse (original behavior)
    resource_ids = re.findall(r'\b(account_\w+|analytics_\w+|search_\w+|support_\w+|'
                               r'audit_record_\w+|backup_\w+|data_flow_\w+|'
                               r'tombstone_\w+|export_\w+|marketing_\w+)\b', text)
    emails = re.findall(r'[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}', text)
    user_ids = re.findall(r'\buser_\d+\b', text)

    return [{
        "resource_id": resource_ids[0] if resource_ids else "",
        "origin_system": "document",
        "collection_name": "text_document",
        "record_json": {
            "raw_text": text,
            "extracted_resource_ids": resource_ids,
            "extracted_emails": emails,
            "extracted_user_ids": user_ids,
        },
        "raw_data": text,
    }]


def load_evidence_file(
    evidence_row: pd.Series,
    dataset_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Dispatch to the correct parser based on the evidence file extension.

    Args:
        evidence_row: A row from evidence_files.csv (must have 'file_path').
        dataset_dir:  Root of the dataset directory; defaults to DATASET_DIR.

    Returns:
        A list of parsed record dicts.
    """
    base = dataset_dir or DATASET_DIR
    rel_path = str(evidence_row.get("file_path", ""))
    full_path = base / rel_path
    ext = full_path.suffix.lower()

    if ext == ".sql":
        return parse_sql_evidence(full_path)
    elif ext == ".json":
        return parse_json_evidence(full_path)
    elif ext == ".log":
        return parse_log_evidence(full_path)
    elif ext in (".txt", ".md"):
        return parse_text_evidence(full_path)
    elif ext in (".png", ".jpg", ".jpeg", ".pdf"):
        # Binary files – return stub (content not machine-parseable without OCR/PDF libs)
        logger.debug("Skipping binary evidence file: %s", full_path)
        return [{
            "resource_id": "",
            "origin_system": evidence_row.get("origin", ""),
            "collection_name": "binary_document",
            "record_json": {"note": f"binary file – {ext}", "path": str(full_path)},
            "raw_data": None,
        }]
    else:
        logger.warning("Unknown evidence extension %s for %s", ext, full_path)
        return []


# Flat keys that may carry identifying values in a record dict. Matching is
# exact and normalized (lowercase + stripped) against the alias sets; no
# recursive substring scanning is performed.
_RECORD_MATCH_KEYS: tuple[str, ...] = (
    "user_id",
    "email",
    "email_hash",
    "phone",
    "customer_email",
    "customer_reference",
    "subject_reference",
    "subject_selector",
    "lookup_key",
    "owner_email",
    "query",
    "contact_email",
    "account_id",
    "target_user",
    "actor_email",
    "username",
    "userId",
    "customer_id",
    "subscriber_email",
    "affected_user",
    "recipient",
)


# ---------------------------------------------------------------------------
# 4. Identifier-matching helper
# ---------------------------------------------------------------------------

def record_matches_aliases(record: dict[str, Any], aliases: dict[str, set[str]]) -> bool:
    """Return True if any identifier in *record* matches the user's aliases."""
    if not record or not aliases:
        return False

    emails_l = {str(e).lower().strip() for e in (aliases.get("emails") or set()) if e}
    email_hashes_l = {str(e).lower().strip() for e in (aliases.get("email_hashes") or set()) if e}
    user_ids_s = {str(u).strip() for u in (aliases.get("user_ids") or set()) if u}
    phones_s = {str(p).strip() for p in (aliases.get("phones") or set()) if p}
    names = {str(n).lower().strip() for n in (aliases.get("names") or set()) if n}
    usernames = {str(u).lower().strip() for u in (aliases.get("usernames") or set()) if u}

    match_keys_lower = {str(x).lower() for x in _RECORD_MATCH_KEYS}

    def _norm(v: Any) -> str:
        if v is None:
            return ""
        return str(v).lower().strip()

    def _matches_key_value(key: str, val: Any) -> bool:
        # Value-based match: emails, SHA-256 hashes, user_ids and phone
        # numbers are distinctive strings, so ANY field carrying one of them
        # links the record to the subject, regardless of the field name
        # (e.g. correlation_key, matched_value, subject_key, ...).
        k = str(key).lower()
        if k in ("_raw_line", "raw_line", "_evidence_id", "_captured_at"):
            return False
        n = _norm(val)
        if not n or len(n) < 4:
            return False
        if n in emails_l or n in email_hashes_l:
            return True
        if n in user_ids_s:
            return True
        raw = str(val).strip() if val is not None else ""
        if raw and raw in phones_s:
            return True
        return False

    def _free_text_match(val: Any) -> bool:
        if not isinstance(val, str):
            return False
        s_text = val.lower()
        for name in names:
            if name and len(name) >= 2 and name in s_text:
                return True
        for uname in usernames:
            if uname and len(uname) >= 2 and uname in s_text:
                return True
        return False

    found = False

    def _check_flat(d: dict[str, Any]) -> None:
        nonlocal found
        if not isinstance(d, dict) or found:
            return
        for k, v in d.items():
            if found:
                break
            if _matches_key_value(k, v):
                found = True
                break
            kl = str(k).lower()
            if kl in ("name", "full_name", "display_name", "username", "user_name"):
                if isinstance(v, str) and _free_text_match(v):
                    found = True
                    break
            if isinstance(v, str) and kl in ("bio", "description"):
                if _free_text_match(v):
                    found = True
                    break

    _check_flat(record)
    if not found:
        rj = record.get("record_json", {}) if isinstance(record, dict) else {}
        if isinstance(rj, dict):
            _check_flat(rj)
    return found



def dedup_by_resource(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group *records* by ``resource_id`` and keep one representative per id.

    When several parsed records share the same ``resource_id`` (e.g. primary
    and replica copies captured at different times), the representative with
    the most non-empty fields is preferred; ties are broken by the latest
    ``captured_at`` / ``updated_at`` timestamp.  Records with an empty
    ``resource_id`` are always kept.

    Returns a list of deduplicated records in first-seen order.
    """
    if not records:
        return []

    groups: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for rec in records:
        rid = str(rec.get("resource_id", "") or "").strip()
        key = rid if rid else ""
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(rec)

    def _score(rec: dict[str, Any]) -> tuple[int, str]:
        # Count non-empty top-level fields (excluding internal metadata).
        skip = {"_table", "actual_state_override", "exposed_pii_override", "raw_data"}
        non_empty = 0
        for k, v in rec.items():
            if k in skip:
                continue
            if v is None:
                continue
            if isinstance(v, str):
                if v.strip():
                    non_empty += 1
            elif isinstance(v, (dict, list)):
                if v:
                    non_empty += 1
            else:
                non_empty += 1
        # Latest timestamp as secondary sort key (lexicographic works for ISO).
        ts = str(rec.get("captured_at") or rec.get("updated_at") or "")
        return (non_empty, ts)

    result: list[dict[str, Any]] = []
    for key in order:
        group = groups[key]
        if not key:
            # Empty resource_id: keep all (they are not duplicates of each other).
            result.extend(group)
            continue
        # Prefer highest score; stable sort keeps first-seen on exact ties.
        group_sorted = sorted(group, key=_score, reverse=True)
        result.append(group_sorted[0])
    return result


def filter_by_audit_time(records: list[dict[str, Any]], audit_at_dt: datetime | None) -> list[dict[str, Any]]:
    """Keep only records captured/updated at or before *audit_at_dt*.

    Each record may carry a ``captured_at`` or ``updated_at`` field.  Records
    whose timestamp parses to a datetime after *audit_at_dt* are dropped.
    If *audit_at_dt* is ``None`` or a timestamp is unparseable, the record is
    kept (conservative: do not discard evidence we cannot date).
    """
    if not records:
        return []
    if audit_at_dt is None:
        return list(records)

    kept: list[dict[str, Any]] = []
    for rec in records:
        ts = rec.get("captured_at") or rec.get("updated_at") or ""
        dt = parse_iso_dt(str(ts))
        if dt is None:
            kept.append(rec)
        elif dt <= audit_at_dt:
            kept.append(rec)
    return kept


def parse_iso_dt(ts: str) -> datetime | None:
    """Parse an ISO-8601 timestamp string to an aware datetime (UTC)."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return None


def is_before_audit(captured_at: str, audit_at_dt: datetime) -> bool:
    """Return True if captured_at is at or before audit_at_dt."""
    dt = parse_iso_dt(captured_at)
    if dt is None:
        return True  # If we can't parse, include by default (conservative)
    return dt <= audit_at_dt


# ---------------------------------------------------------------------------
# 5. State-Aware Evidence Helpers (NEW)
# ---------------------------------------------------------------------------

def extract_record_state(record: dict[str, Any]) -> dict[str, Any]:
    """Determine the actual compliance state of a matched evidence record.

    Inspects record_json fields to classify the record's current state:
      - account_status: ACTIVE / DELETED / CLOSED / REMOVED
      - enabled: true/false (data flows)
      - restore_allowed: true/false (backups)
      - message_text: "[REDACTED]" or plain text (support conversations)
      - subject_reference / customer_reference → user_id link

    Also honors override fields set by text-evidence parsers:
      - actual_state_override / exposed_pii_override

    Returns:
        {
          "actual_state": "ACTIVE|DELETED|REDACTED|ANONYMIZED|RETAINED|UNKNOWN",
          "exposed_pii": bool,
          "restore_allowed": bool,
          "flow_enabled": bool,
        }
    """
    # Honor parser-level overrides first
    if record.get("actual_state_override"):
        state = record["actual_state_override"]
        # Derive restore/flow flags from the overridden state: an ACTIVE
        # backup still allows restore, an ACTIVE data flow is still enabled.
        origin = str(record.get("origin_system", "")).lower()
        is_backup = "backup" in origin or record.get("collection_name") == "BACKUP_ARCHIVE"
        is_flow = "integration" in origin or record.get("collection_name") == "DATA_FLOW"
        return {
            "actual_state": state,
            "exposed_pii": record.get("exposed_pii_override", False),
            "restore_allowed": is_backup and state == "ACTIVE",
            "flow_enabled": is_flow and state == "ACTIVE",
        }

    # Merged field view: SQL/log parsers often place fields (restore_allowed,
    # customer_email, enabled, ...) at the top level while JSON parsers nest
    # them in record_json.  Merge both views (record_json wins on conflict)
    # so state extraction sees every field regardless of parser layout.
    rj: dict[str, Any] = {k: v for k, v in record.items() if not k.startswith("_")}
    rj.update(record.get("record_json", {}) or {})

    # Log events: readback trace results indicate presence/absence
    rows = rj.get("rows", record.get("rows", ""))
    http_status = str(rj.get("http_status", record.get("http_status", "")))
    event_type = str(rj.get("event", record.get("event", "")))
    if rows != "" or http_status != "":
        rows_str = str(rows)
        if rows_str == "0" or http_status == "404":
            # Lookup returned no rows → record is ABSENT/DELETED
            return {
                "actual_state": "DELETED",
                "exposed_pii": False,
                "restore_allowed": False,
                "flow_enabled": False,
            }
        if rows_str == "1" or http_status == "200":
            # Lookup found the record → ACTIVE/PRESENT
            return {
                "actual_state": "ACTIVE",
                "exposed_pii": True,
                "restore_allowed": False,
                "flow_enabled": False,
            }

    category = (record.get("category") or "").upper()
    origin = (record.get("origin_system") or "").lower()

    # Normalize booleans
    def _bool(v: Any) -> bool:
        if isinstance(v, bool):
            return v
        if v is None:
            return False
        return str(v).strip().lower() in ("true", "1", "yes", "enabled")

    exposed_pii = False
    restore_allowed = _bool(rj.get("restore_allowed"))
    flow_enabled = _bool(rj.get("enabled"))

    # Exposed PII: record still carries identifying fields with values.
    # For ACCOUNT_TOMBSTONE records, user_id / subject_reference /
    # customer_reference are stable internal references and are NOT considered
    # exposed PII.  Only direct identifiers count: email, phone, name,
    # email_hash, full_name, customer_email.
    is_tombstone = category == "ACCOUNT_TOMBSTONE" or "tombstone" in origin
    if is_tombstone:
        pii_fields = ("email", "phone", "name", "email_hash",
                      "full_name", "customer_email")
    else:
        pii_fields = ("email", "phone", "email_hash", "full_name",
                      "customer_email")
    for f in pii_fields:
        v = rj.get(f)
        if v and str(v).strip() not in ("", "null", "None", "N/A"):
            exposed_pii = True
            break

    # Also check nested document (search records)
    doc = rj.get("document")
    if isinstance(doc, dict):
        for f in ("email", "display_name", "customer_reference"):
            v = doc.get(f)
            if v and str(v).strip() not in ("", "null", "None", "N/A"):
                exposed_pii = True
                break

    # Determine actual_state
    account_status = str(rj.get("account_status", "")).strip().upper()

    if account_status in ("DELETED", "CLOSED", "REMOVED", "INACTIVE"):
        actual_state = "DELETED"
    elif category == "ACCOUNT_TOMBSTONE" or "tombstone" in origin:
        # Tombstone: redacted if PII fields are null/absent, active otherwise
        if exposed_pii:
            actual_state = "ACTIVE"
        else:
            actual_state = "REDACTED"
    elif category == "SUPPORT_MESSAGE" or "support" in origin:
        msg = str(rj.get("message_text", ""))
        if "[REDACTED]" in msg or msg.strip() == "":
            actual_state = "REDACTED"
        else:
            actual_state = "ACTIVE"
    elif category == "BACKUP_ARCHIVE" or "backup" in origin:
        if not restore_allowed:
            actual_state = "RETAINED"
        else:
            actual_state = "ACTIVE"
    elif category == "SECONDARY_IDENTIFIER" or "integration" in origin or "data_flow" in origin:
        if not flow_enabled:
            actual_state = "DISABLED"
        else:
            actual_state = "ACTIVE"
    elif category == "ANALYTICS_PROFILE" or "analytics" in origin:
        # Anonymized if no identifying fields remain
        if exposed_pii:
            actual_state = "ACTIVE"
        else:
            actual_state = "ANONYMIZED"
    elif category == "SECURITY_AUDIT_LOG" or "security" in origin or "audit" in origin:
        actual_state = "RETAINED"
    elif category == "LEGAL_HOLD_RECORD" or "legal" in origin:
        actual_state = "RETAINED"
    elif category == "USER_EXPORT" or "export" in origin:
        actual_state = "ACTIVE"
    elif exposed_pii:
        actual_state = "ACTIVE"
    else:
        actual_state = "UNKNOWN"

    return {
        "actual_state": actual_state,
        "exposed_pii": exposed_pii,
        "restore_allowed": restore_allowed,
        "flow_enabled": flow_enabled,
    }


def lookup_activity_events(
    resource_id: str,
    audit_at_dt: datetime,
    activity_df: "pd.DataFrame",
    aliases: dict[str, set[str]] | None = None,
) -> list[dict[str, Any]]:
    """Return system_activity.csv events for *resource_id* at or before *audit_at_dt*.

    Also matches events where details contains any alias email/user_id if
    aliases are provided. Each event dict: {activity_id, event_time, event_type,
    source_system, target_system, reported_result, details, resource_id}.
    """
    if activity_df is None or activity_df.empty:
        return []

    emails_l = set()
    user_ids_s = set()
    if aliases:
        emails_l = {str(e).lower() for e in (aliases.get("emails") or set()) if e}
        user_ids_s = {str(u).strip() for u in (aliases.get("user_ids") or set()) if u}

    mask = pd.Series([False] * len(activity_df), index=activity_df.index)
    if resource_id:
        mask = mask | (activity_df["resource_id"].astype(str) == str(resource_id))

    # Also match by aliases in details or resource_id
    if aliases:
        for idx, row in activity_df.iterrows():
            if mask.at[idx]:
                continue
            details = str(row.get("details", ""))
            rid = str(row.get("resource_id", ""))
            dl = details.lower()
            matched = False
            for em in emails_l:
                if em and em in dl:
                    matched = True
                    break
            if not matched:
                for uid in user_ids_s:
                    if uid and (uid in rid or uid.lower() in dl):
                        matched = True
                        break
            if matched:
                mask.at[idx] = True

    if not mask.any():
        return []

    subset = activity_df[mask].copy()
    # Filter to events at or before audit_at
    if "event_time_dt" in subset.columns and audit_at_dt is not None:
        subset = subset[subset["event_time_dt"] <= audit_at_dt]

    events: list[dict[str, Any]] = []
    for _, row in subset.iterrows():
        events.append({
            "activity_id": row.get("activity_id", ""),
            "event_time": row.get("event_time", ""),
            "event_type": row.get("event_type", ""),
            "source_system": row.get("source_system", ""),
            "target_system": row.get("target_system", ""),
            "reported_result": row.get("reported_result", ""),
            "details": row.get("details", ""),
            "resource_id": row.get("resource_id", ""),
        })
    return events


def detect_replica_drift(
    sql_records: list[dict[str, Any]],
) -> dict[str, bool]:
    """Detect replication drift between primary and replica tables.

    Groups records by resource_id and checks whether primary and replica
    copies disagree on identifying fields. Returns a map of resource_id ->
    drift_detected (bool).
    """
    by_resource: dict[str, list[dict[str, Any]]] = {}
    for rec in sql_records:
        rid = rec.get("resource_id", "")
        if rid:
            by_resource.setdefault(rid, []).append(rec)

    drift: dict[str, bool] = {}
    for rid, recs in by_resource.items():
        if len(recs) < 2:
            continue
        # Compare account_status / enabled / restore_allowed across copies
        statuses = {r.get("record_json", {}).get("account_status") for r in recs}
        enableds = {r.get("record_json", {}).get("enabled") for r in recs}
        restores = {r.get("record_json", {}).get("restore_allowed") for r in recs}
        if len(statuses) > 1 or len(enableds) > 1 or len(restores) > 1:
            drift[rid] = True
        else:
            drift[rid] = False
    return drift



# ---------------------------------------------------------------------------
# 6. Replication / Active Flow Scanning
# ---------------------------------------------------------------------------


def scan_activity_for_user_aliases(
    aliases: dict[str, set[str]],
    audit_at_dt: datetime,
    activity_df: "pd.DataFrame",
) -> list[dict[str, Any]]:
    """Find system_activity events (any event_type) whose details or resource_id
    contains any alias email/user_id/phone, at or before audit_at.
    """
    if activity_df is None or activity_df.empty or not aliases:
        return []

    emails = set(aliases.get("emails", set()) or set())
    user_ids = set(aliases.get("user_ids", set()) or set())
    phones = set(aliases.get("phones", set()) or set())

    emails_l = {str(e).lower() for e in emails if e}
    user_ids_s = {str(u).strip() for u in user_ids if u}
    phones_s = {str(p).strip() for p in phones if p}

    events: list[dict[str, Any]] = []
    for _, row in activity_df.iterrows():
        # Check time
        if "event_time_dt" in activity_df.columns and audit_at_dt is not None:
            et = row.get("event_time_dt")
            try:
                if pd.notna(et) and et > audit_at_dt:
                    continue
            except Exception:
                pass

        details = str(row.get("details", ""))
        rid = str(row.get("resource_id", ""))
        dl = details.lower()

        matched = False
        for em in emails_l:
            if em and em in dl:
                matched = True
                break
        if not matched:
            for uid in user_ids_s:
                if uid and (uid in rid or uid.lower() in dl):
                    matched = True
                    break
        if not matched:
            for ph in phones_s:
                if ph and ph in details:
                    matched = True
                    break

        if matched:
            events.append({
                "activity_id": row.get("activity_id", ""),
                "event_time": row.get("event_time", ""),
                "event_type": row.get("event_type", ""),
                "source_system": row.get("source_system", ""),
                "target_system": row.get("target_system", ""),
                "reported_result": row.get("reported_result", ""),
                "details": row.get("details", ""),
                "resource_id": row.get("resource_id", ""),
            })
    return events


def detect_active_replication_flows(
    resource_id: str,
    audit_at_dt: datetime,
    activity_df: "pd.DataFrame",
    aliases: dict[str, set[str]] | None = None,
) -> list[dict[str, Any]]:
    """Scan system_activity.csv for events where event_type contains "SYNC",
    "REPLICATE", "RESTORE", "AUTO_RESTORE", "IMPORT" and the details or
    resource_id match the user's aliases/resource, at or before audit_at.
    """
    if activity_df is None or activity_df.empty:
        return []

    keywords = ("sync", "replicate", "restore", "auto_restore", "import")

    # Get candidate events
    candidates = []
    if resource_id:
        candidates = lookup_activity_events(resource_id, audit_at_dt, activity_df, aliases)
    if not candidates and aliases:
        candidates = scan_activity_for_user_aliases(aliases, audit_at_dt, activity_df)

    results: list[dict[str, Any]] = []
    for ev in candidates:
        etype = str(ev.get("event_type", "")).lower()
        if any(k in etype for k in keywords):
            results.append(ev)
            continue
        # Also check details
        details = str(ev.get("details", "")).lower()
        if any(k in details for k in keywords):
            results.append(ev)
            continue
    return results



def discover_user_resources(aliases, activity_df, audit_at_dt):
    discovered = set()
    if activity_df is None:
        return discovered
    try:
        if getattr(activity_df, 'empty', False):
            return discovered
    except Exception:
        pass
    emails = set(); user_ids = set(); phones = set(); email_hashes = set()
    for e in (aliases.get('emails') or set()):
        if e:
            s = str(e).lower().strip()
            if s: emails.add(s)
    for u in (aliases.get('user_ids') or set()):
        if u:
            s = str(u).strip()
            if s: user_ids.add(s)
    for p in (aliases.get('phones') or set()):
        if p:
            s = str(p).strip()
            if s: phones.add(s)
    for h in (aliases.get('email_hashes') or set()):
        if h:
            s = str(h).lower().strip()
            if s: email_hashes.add(s)
    pd_mod = None
    try:
        import pandas as _pd
        pd_mod = _pd
    except Exception:
        pass
    for _, row in activity_df.iterrows():
        if audit_at_dt is not None and pd_mod is not None and 'event_time_dt' in getattr(activity_df, 'columns', []):
            et = row.get('event_time_dt')
            try:
                if pd_mod.notna(et):
                    try:
                        et_cmp = et.to_pydatetime() if hasattr(et, 'to_pydatetime') else et
                        ad_cmp = audit_at_dt.to_pydatetime() if hasattr(audit_at_dt, 'to_pydatetime') else audit_at_dt
                        if et_cmp > ad_cmp: continue
                    except Exception: pass
            except Exception: pass
        details = str(row.get('details', ''))
        details_l = details.lower()
        resource_id = str(row.get('resource_id', ''))
        source_system = str(row.get('source_system', ''))
        target_system = str(row.get('target_system', ''))
        reported_result = str(row.get('reported_result', ''))
        matched = False
        for uid in user_ids:
            if uid and uid in resource_id: matched = True; break
        if not matched:
            for em in emails:
                if em and (em == source_system.lower() or em == target_system.lower() or em == reported_result.lower() or em == resource_id.lower()): matched = True; break
        if not matched:
            for ph in phones:
                if ph and (ph == source_system or ph == target_system or ph == resource_id or ph == reported_result): matched = True; break
        if not matched:
            for eh in email_hashes:
                if eh and (eh == source_system.lower() or eh == target_system.lower() or eh == reported_result.lower() or eh == resource_id.lower()): matched = True; break
        if not matched:
            for em in emails:
                if em and em in details_l: matched = True; break
        if not matched:
            for uid in user_ids:
                if uid and uid.lower() in details_l: matched = True; break
        if not matched:
            for ph in phones:
                if ph and ph in details: matched = True; break
        if not matched:
            for eh in email_hashes:
                if eh and eh in details_l: matched = True; break
        if matched:
            if resource_id: discovered.add(resource_id)
            if target_system:
                if target_system.startswith(('account_', 'backup_', 'search_', 'analytics_', 'support_', 'tombstone_', 'export_', 'marketing_', 'data_flow_', 'cache_', 'audit_record_')):
                    discovered.add(target_system)
            rr = reported_result
            if rr:
                for pref in ('backup_', 'account_', 'search_', 'analytics_', 'support_', 'tombstone_', 'data_flow_', 'export_'):
                    if pref in rr:
                        for token in str(rr).replace(',', ' ').replace(';', ' ').split():
                            if token.startswith(pref):
                                discovered.add(token)
    return discovered
