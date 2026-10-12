"""Event Normalization Service for ChronoTrace.

Enforces Section 6 Event Schema:
- event_id
- host
- source
- event_code
- ts_start_utc (earliest possible time, UTC ISO format)
- ts_end_utc (latest possible time, UTC ISO format)
- process_guid
- pid
- ppid
- parent_guid
- image
- command_line
- user
- src_ip
- dst_ip
- dst_port
- raw_ref (MANDATORY - FAIL LOUDLY IF EMPTY)
- mitre_technique
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone
import dateutil.parser
from services.mitre_tagger import tag_mitre_technique


def parse_to_utc_iso(time_val: Any) -> str:
    """Parses date/time strings or timestamps and normalizes to UTC ISO 8601."""
    if not time_val:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(time_val, datetime):
        if time_val.tzinfo is None:
            time_val = time_val.replace(tzinfo=timezone.utc)
        return time_val.astimezone(timezone.utc).isoformat()
    try:
        dt = dateutil.parser.parse(str(time_val))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return str(time_val)


def normalize_record(raw_record: Dict[str, Any], event_index: int = 1) -> Dict[str, Any]:
    """
    Normalizes a single raw log dictionary into the strict ChronoTrace event schema.
    Raises ValueError if raw_ref is missing or empty.
    """
    raw_ref = raw_record.get("raw_ref")
    if not raw_ref or not str(raw_ref).strip():
        raise ValueError(
            f"CRITICAL FORENSIC VALIDATION FAILURE: raw_ref is required and cannot be empty! "
            f"Violated on record: {raw_record.get('record_number', event_index)}"
        )

    raw_json = raw_record.get("raw_json", {})
    if isinstance(raw_json, str):
        import json
        try:
            raw_json = json.loads(raw_json)
        except Exception:
            raw_json = {}

    # Extract event code and source
    event_code = raw_record.get("event_code") or raw_json.get("EventID") or raw_json.get("event_id") or 0
    try:
        event_code = int(event_code)
    except Exception:
        event_code = 0

    source = raw_record.get("source") or raw_json.get("Channel") or raw_json.get("Provider_Name") or "Unknown"

    # Hostname
    host = (
        raw_record.get("host") or 
        raw_json.get("Computer") or 
        raw_json.get("Host") or 
        raw_json.get("host") or 
        "VICTIM-PC01"
    )

    # Timestamps (ts_start_utc, ts_end_utc)
    ts_raw_start = (
        raw_record.get("ts_start_utc") or 
        raw_json.get("TimeCreated") or 
        raw_json.get("UtcTime") or 
        raw_json.get("timestamp")
    )
    ts_raw_end = (
        raw_record.get("ts_end_utc") or 
        raw_record.get("ts_start_utc") or 
        ts_raw_start
    )

    ts_start_utc = parse_to_utc_iso(ts_raw_start)
    ts_end_utc = parse_to_utc_iso(ts_raw_end)

    # Process and Entity Attributes
    process_guid = (
        raw_record.get("process_guid") or 
        raw_json.get("ProcessGuid") or 
        raw_json.get("process_guid")
    )
    parent_guid = (
        raw_record.get("parent_guid") or 
        raw_json.get("ParentProcessGuid") or 
        raw_json.get("parent_guid")
    )

    pid = raw_record.get("pid") or raw_json.get("ProcessId") or raw_json.get("NewProcessId") or raw_json.get("pid")
    try:
        pid = int(pid) if pid is not None else None
    except Exception:
        pid = None

    ppid = raw_record.get("ppid") or raw_json.get("ParentProcessId") or raw_json.get("ppid")
    try:
        ppid = int(ppid) if ppid is not None else None
    except Exception:
        ppid = None

    image = (
        raw_record.get("image") or 
        raw_json.get("Image") or 
        raw_json.get("NewProcessName") or 
        raw_json.get("TargetFilename") or 
        raw_json.get("image") or 
        ""
    )

    cmd_line = (
        raw_record.get("command_line") or 
        raw_json.get("CommandLine") or 
        raw_json.get("command_line") or 
        ""
    )

    user = (
        raw_record.get("user") or 
        raw_json.get("User") or 
        raw_json.get("TargetUserName") or 
        raw_json.get("user") or 
        ""
    )

    src_ip = raw_record.get("src_ip") or raw_json.get("SourceIp") or raw_json.get("IpAddress") or raw_json.get("src_ip")
    dst_ip = raw_record.get("dst_ip") or raw_json.get("DestinationIp") or raw_json.get("dst_ip")
    dst_port = raw_record.get("dst_port") or raw_json.get("DestinationPort") or raw_json.get("dst_port")
    try:
        dst_port = int(dst_port) if dst_port is not None else None
    except Exception:
        dst_port = None

    event_id = raw_record.get("event_id") or f"EVT-{event_index:04d}"

    normalized: Dict[str, Any] = {
        "event_id": event_id,
        "investigation_id": raw_record.get("investigation_id", "inv-default"),
        "host": host,
        "source": source,
        "event_code": event_code,
        "ts_start_utc": ts_start_utc,
        "ts_end_utc": ts_end_utc,
        "process_guid": str(process_guid) if process_guid else None,
        "pid": pid,
        "ppid": ppid,
        "parent_guid": str(parent_guid) if parent_guid else None,
        "image": image,
        "command_line": cmd_line,
        "user": user,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "raw_ref": raw_ref,
        "mitre_technique": raw_record.get("mitre_technique")
    }

    # Automatically apply rule-based MITRE tagger if not already explicitly tagged
    if not normalized.get("mitre_technique"):
        tech_id, _, _ = tag_mitre_technique(normalized)
        normalized["mitre_technique"] = tech_id

    return normalized
