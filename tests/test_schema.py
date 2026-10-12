"""Unit tests for ChronoTrace schema enforcement and Rule 0/17 compliance."""

import pytest
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from services.normalization import normalize_record
from database.db import insert_events, insert_raw_events


def test_raw_ref_mandatory_in_normalization():
    """Rule 0 & 17: raw_ref must never be empty. Fail loudly if empty."""
    invalid_record = {
        "event_id": "EVT-ERR",
        "host": "VICTIM-PC01",
        "source": "Sysmon",
        "event_code": 1,
        "raw_ref": "",  # Empty raw_ref!
        "raw_json": {}
    }
    with pytest.raises(ValueError, match="raw_ref is required and cannot be empty"):
        normalize_record(invalid_record)


def test_schema_field_presence():
    """Verify all Section 6 required fields exist in normalized output."""
    valid_record = {
        "raw_ref": "sysmon.evtx#42",
        "host": "DC-SRV01",
        "source": "Microsoft-Windows-Sysmon",
        "event_code": 1,
        "ts_start_utc": "2026-10-12T04:15:10Z",
        "ts_end_utc": "2026-10-12T04:15:10Z",
        "process_guid": "{F82A1B90-1111-5D3C-AA01-000000000100}",
        "pid": 4820,
        "ppid": 1052,
        "parent_guid": "{F82A1B90-0000-5D3C-AA00-000000000001}",
        "image": "C:\\Windows\\System32\\powershell.exe",
        "command_line": "powershell.exe -enc test",
        "user": "CORP\\admin",
        "src_ip": None,
        "dst_ip": None,
        "dst_port": None,
        "raw_json": {}
    }
    norm = normalize_record(valid_record)
    expected_fields = [
        "event_id", "host", "source", "event_code", "ts_start_utc", "ts_end_utc",
        "process_guid", "pid", "ppid", "parent_guid", "image", "command_line",
        "user", "src_ip", "dst_ip", "dst_port", "raw_ref", "mitre_technique"
    ]
    for field in expected_fields:
        assert field in norm, f"Missing required Section 6 field: {field}"
    assert norm["raw_ref"] == "sysmon.evtx#42"
