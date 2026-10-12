"""Database access layer for ChronoTrace.
Provides SQLite initialization, transactional persistence, and querying.
Enforces the mandatory requirement: every normalized event must have a non-empty raw_ref.
"""

import sqlite3
import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "chronotrace.db")
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Returns a SQLite connection with Row factory enabled."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str = DB_PATH) -> None:
    """Initializes tables using schema.sql."""
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema_sql = f.read()
    with get_connection(db_path) as conn:
        conn.executescript(schema_sql)
        conn.commit()


# --- Investigation Management ---

def create_investigation(
    investigation_id: str,
    name: str,
    description: str = "",
    status: str = "Active",
    is_demo: bool = False,
    db_path: str = DB_PATH
) -> None:
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO investigations (id, name, description, created_at, status, is_demo)
            VALUES (?, ?, ?, datetime('now'), ?, ?)
            """,
            (investigation_id, name, description, status, 1 if is_demo else 0)
        )
        conn.commit()


def get_investigations(db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        rows = conn.execute("SELECT * FROM investigations ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def get_investigation(investigation_id: str, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
        return dict(row) if row else None


# --- Raw Evidence Storage ---

def insert_raw_events(raw_records: List[Dict[str, Any]], db_path: str = DB_PATH) -> int:
    """Inserts raw evidence records. Raises ValueError if raw_ref is missing."""
    inserted = 0
    with get_connection(db_path) as conn:
        for rec in raw_records:
            raw_ref = rec.get("raw_ref")
            if not raw_ref or not str(raw_ref).strip():
                raise ValueError(f"CRITICAL FORENSIC ERROR: raw_ref is mandatory and cannot be empty! Record: {rec}")

            conn.execute(
                """
                INSERT OR REPLACE INTO raw_events 
                (raw_ref, investigation_id, source_file, record_number, source, event_code, raw_json, ingested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
                """,
                (
                    raw_ref,
                    rec.get("investigation_id", "inv-default"),
                    rec.get("source_file", "unknown"),
                    int(rec.get("record_number", 0)),
                    rec.get("source", "Unknown"),
                    int(rec.get("event_code", 0)),
                    rec.get("raw_json") if isinstance(rec.get("raw_json"), str) else json.dumps(rec.get("raw_json", {}))
                )
            )
            inserted += 1
        conn.commit()
    return inserted


def get_raw_events(investigation_id: str, limit: int = 500, db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT * FROM raw_events 
            WHERE investigation_id = ? 
            ORDER BY record_number ASC 
            LIMIT ?
            """,
            (investigation_id, limit)
        ).fetchall()
        return [dict(r) for r in rows]


def get_raw_event_by_ref(raw_ref: str, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM raw_events WHERE raw_ref = ?", (raw_ref,)).fetchone()
        return dict(row) if row else None


# --- Normalized Events Storage ---

def insert_events(events: List[Dict[str, Any]], db_path: str = DB_PATH) -> int:
    """
    Inserts normalized events adhering to the Section 6 Schema.
    Strictly verifies that raw_ref is non-empty.
    """
    inserted = 0
    with get_connection(db_path) as conn:
        for ev in events:
            raw_ref = ev.get("raw_ref")
            if not raw_ref or not str(raw_ref).strip():
                raise ValueError(
                    f"CRITICAL FORENSIC ERROR: Event {ev.get('event_id')} has an empty raw_ref! "
                    "Rule 0 & 17 of ChronoTrace require every event to retain its original log record."
                )

            conn.execute(
                """
                INSERT OR REPLACE INTO events (
                    event_id, investigation_id, host, source, event_code,
                    ts_start_utc, ts_end_utc, process_guid, pid, ppid, parent_guid,
                    image, command_line, user, src_ip, dst_ip, dst_port,
                    raw_ref, mitre_technique
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ev.get("event_id"),
                    ev.get("investigation_id", "inv-default"),
                    ev.get("host"),
                    ev.get("source"),
                    ev.get("event_code"),
                    ev.get("ts_start_utc"),
                    ev.get("ts_end_utc"),
                    ev.get("process_guid"),
                    ev.get("pid"),
                    ev.get("ppid"),
                    ev.get("parent_guid"),
                    ev.get("image"),
                    ev.get("command_line"),
                    ev.get("user"),
                    ev.get("src_ip"),
                    ev.get("dst_ip"),
                    ev.get("dst_port"),
                    raw_ref,
                    ev.get("mitre_technique")
                )
            )
            inserted += 1
        conn.commit()
    return inserted


def get_events(
    investigation_id: str,
    host: Optional[str] = None,
    source: Optional[str] = None,
    min_confidence: Optional[float] = None,
    db_path: str = DB_PATH
) -> List[Dict[str, Any]]:
    query = """
        SELECT e.*, f.confidence, f.flags, f.stage, f.explanation,
               f.corroboration, f.source_reliability, f.time_certainty, f.link_strength
        FROM events e
        LEFT JOIN findings f ON e.event_id = f.event_id AND e.investigation_id = f.investigation_id
        WHERE e.investigation_id = ?
    """
    params: List[Any] = [investigation_id]

    if host and host != "All Hosts":
        query += " AND e.host = ?"
        params.append(host)

    if source and source != "All Sources":
        query += " AND e.source = ?"
        params.append(source)

    if min_confidence is not None:
        query += " AND (f.confidence IS NULL OR f.confidence >= ?)"
        params.append(min_confidence)

    query += " ORDER BY e.ts_start_utc ASC"

    with get_connection(db_path) as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get("flags") and isinstance(d["flags"], str):
                try:
                    d["flags_list"] = json.loads(d["flags"])
                except Exception:
                    d["flags_list"] = [d["flags"]]
            else:
                d["flags_list"] = []
            result.append(d)
        return result


def get_event_by_id(event_id: str, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        row = conn.execute(
            """
            SELECT e.*, f.confidence, f.flags, f.stage, f.explanation,
                   f.corroboration, f.source_reliability, f.time_certainty, f.link_strength
            FROM events e
            LEFT JOIN findings f ON e.event_id = f.event_id AND e.investigation_id = f.investigation_id
            WHERE e.event_id = ?
            """,
            (event_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        if d.get("flags") and isinstance(d["flags"], str):
            try:
                d["flags_list"] = json.loads(d["flags"])
            except Exception:
                d["flags_list"] = [d["flags"]]
        else:
            d["flags_list"] = []
        return d


# --- Provenance Graph Persistence ---

def insert_entities(entities: List[Dict[str, Any]], db_path: str = DB_PATH) -> None:
    with get_connection(db_path) as conn:
        for ent in entities:
            conn.execute(
                """
                INSERT OR REPLACE INTO entities 
                (entity_id, investigation_id, type, key, host, label, first_seen, last_seen, attributes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ent.get("entity_id"),
                    ent.get("investigation_id", "inv-default"),
                    ent.get("type"),
                    ent.get("key"),
                    ent.get("host"),
                    ent.get("label"),
                    ent.get("first_seen"),
                    ent.get("last_seen"),
                    json.dumps(ent.get("attributes", {})) if isinstance(ent.get("attributes"), dict) else ent.get("attributes")
                )
            )
        conn.commit()


def insert_edges(edges: List[Dict[str, Any]], db_path: str = DB_PATH) -> None:
    with get_connection(db_path) as conn:
        for ed in edges:
            conn.execute(
                """
                INSERT OR REPLACE INTO edges 
                (edge_id, investigation_id, src_entity, dst_entity, relation, link_strength, is_uncertain, evidence_event_ids)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ed.get("edge_id"),
                    ed.get("investigation_id", "inv-default"),
                    ed.get("src_entity"),
                    ed.get("dst_entity"),
                    ed.get("relation"),
                    float(ed.get("link_strength", 1.0)),
                    1 if ed.get("is_uncertain") else 0,
                    json.dumps(ed.get("evidence_event_ids", [])) if isinstance(ed.get("evidence_event_ids"), list) else ed.get("evidence_event_ids")
                )
            )
        conn.commit()


def get_graph_data(investigation_id: str, db_path: str = DB_PATH) -> Dict[str, Any]:
    with get_connection(db_path) as conn:
        entities = [dict(r) for r in conn.execute(
            "SELECT * FROM entities WHERE investigation_id = ?", (investigation_id,)
        ).fetchall()]
        edges = [dict(r) for r in conn.execute(
            "SELECT * FROM edges WHERE investigation_id = ?", (investigation_id,)
        ).fetchall()]
        
        # parse json fields
        for ent in entities:
            if ent.get("attributes"):
                try:
                    ent["attributes"] = json.loads(ent["attributes"])
                except Exception:
                    pass
        for ed in edges:
            if ed.get("evidence_event_ids"):
                try:
                    ed["evidence_event_ids"] = json.loads(ed["evidence_event_ids"])
                except Exception:
                    ed["evidence_event_ids"] = []
                    
        return {"entities": entities, "edges": edges}


# --- Findings & Reporting ---

def insert_findings(findings: List[Dict[str, Any]], db_path: str = DB_PATH) -> None:
    with get_connection(db_path) as conn:
        for f in findings:
            conn.execute(
                """
                INSERT OR REPLACE INTO findings 
                (finding_id, investigation_id, event_id, stage, confidence, flags, explanation,
                 corroboration, source_reliability, time_certainty, link_strength)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f.get("finding_id"),
                    f.get("investigation_id", "inv-default"),
                    f.get("event_id"),
                    f.get("stage"),
                    float(f.get("confidence", 0.0)),
                    json.dumps(f.get("flags", [])) if isinstance(f.get("flags"), list) else f.get("flags"),
                    f.get("explanation"),
                    float(f.get("corroboration", 0.0)),
                    float(f.get("source_reliability", 0.0)),
                    float(f.get("time_certainty", 0.0)),
                    float(f.get("link_strength", 0.0))
                )
            )
        conn.commit()


def get_findings(investigation_id: str, db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT f.*, e.host, e.source, e.event_code, e.image, e.command_line, 
                   e.user, e.raw_ref, e.ts_start_utc, e.ts_end_utc, e.mitre_technique
            FROM findings f
            JOIN events e ON f.event_id = e.event_id AND f.investigation_id = e.investigation_id
            WHERE f.investigation_id = ?
            ORDER BY e.ts_start_utc ASC
            """,
            (investigation_id,)
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get("flags"):
                try:
                    d["flags_list"] = json.loads(d["flags"])
                except Exception:
                    d["flags_list"] = [d["flags"]]
            else:
                d["flags_list"] = []
            result.append(d)
        return result


def record_ingestion_log(
    investigation_id: str,
    filename: str,
    file_size_bytes: int,
    total_records: int,
    normalized_records: int,
    unsupported_records: int,
    errors_count: int,
    status: str,
    details: str = "",
    db_path: str = DB_PATH
) -> None:
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO ingestion_logs 
            (investigation_id, filename, file_size_bytes, total_records, 
             normalized_records, unsupported_records, errors_count, status, ingested_at, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)
            """,
            (
                investigation_id, filename, file_size_bytes, total_records,
                normalized_records, unsupported_records, errors_count, status, details
            )
        )
        conn.commit()


def get_ingestion_logs(investigation_id: str, db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM ingestion_logs WHERE investigation_id = ? ORDER BY id DESC",
            (investigation_id,)
        ).fetchall()
        return [dict(r) for r in rows]
