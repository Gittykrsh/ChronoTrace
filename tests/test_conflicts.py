"""Unit tests for ChronoTrace Conflict and Missing-Evidence Engine."""

import pytest
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from services.conflict_detection import detect_conflicts


def test_missing_parent_detection():
    events = [
        {
            "event_id": "EVT-ORPHAN",
            "host": "VICTIM-PC01",
            "source": "Microsoft-Windows-Sysmon",
            "event_code": 1,
            "ts_start_utc": "2026-10-12T04:16:05.000Z",
            "ts_end_utc": "2026-10-12T04:16:05.100Z",
            "process_guid": "{CHILD-GUID-001}",
            "parent_guid": "{NON-EXISTENT-PARENT-GUID}",
            "raw_ref": "sysmon.evtx#10"
        }
    ]
    res = detect_conflicts(events)
    flags = res["EVT-ORPHAN"]["flags"]
    assert "MISSING_PARENT" in flags


def test_log_cleared_detection():
    events = [
        {
            "event_id": "EVT-CLEAR",
            "host": "VICTIM-PC01",
            "source": "Microsoft-Windows-Security-Auditing",
            "event_code": 1102,
            "ts_start_utc": "2026-10-12T04:17:11.000Z",
            "ts_end_utc": "2026-10-12T04:17:11.100Z",
            "raw_ref": "sec.evtx#99"
        }
    ]
    res = detect_conflicts(events)
    flags = res["EVT-CLEAR"]["flags"]
    assert "LOG_CLEARED" in flags


def test_order_conflict_detection():
    # Two adjacent events on same host with overlapping ranges
    events = [
        {
            "event_id": "EVT-A",
            "host": "VICTIM-PC01",
            "source": "Sysmon",
            "event_code": 1,
            "ts_start_utc": "2026-10-12T04:16:30.000Z",
            "ts_end_utc": "2026-10-12T04:16:45.000Z",
            "raw_ref": "ev1.evtx#1"
        },
        {
            "event_id": "EVT-B",
            "host": "VICTIM-PC01",
            "source": "Security",
            "event_code": 4688,
            "ts_start_utc": "2026-10-12T04:16:35.000Z",
            "ts_end_utc": "2026-10-12T04:16:50.000Z",
            "raw_ref": "ev2.evtx#2"
        }
    ]
    res = detect_conflicts(events)
    flags_a = res["EVT-A"]["flags"]
    assert "ORDER_CONFLICT" in flags_a
