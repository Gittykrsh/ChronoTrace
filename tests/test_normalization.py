"""Unit tests for event normalization across Sysmon and Security logs."""

import pytest
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from services.normalization import normalize_record, parse_to_utc_iso


def test_utc_conversion():
    utc_str = parse_to_utc_iso("2026-10-12 04:15:10")
    assert "2026-10-12T04:15:10" in utc_str
    assert "+00:00" in utc_str or "Z" in utc_str


def test_sysmon_process_creation():
    raw = {
        "raw_ref": "sysmon.evtx#101",
        "source": "Microsoft-Windows-Sysmon",
        "event_code": 1,
        "host": "VICTIM-PC01",
        "ts_start_utc": "2026-10-12T04:15:10Z",
        "process_guid": "{GUID-123}",
        "pid": 5000,
        "parent_guid": "{GUID-001}",
        "image": "C:\\Windows\\System32\\powershell.exe",
        "command_line": "powershell.exe -enc aW1wb3J0"
    }
    norm = normalize_record(raw)
    assert norm["event_id"].startswith("EVT-")
    assert norm["process_guid"] == "{GUID-123}"
    assert norm["mitre_technique"] == "T1059.001"
    assert norm["raw_ref"] == "sysmon.evtx#101"
