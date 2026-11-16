"""Unit tests for Cryptographic Evidence Hash Chaining & Merkle Tree."""

import pytest
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from services.crypto_chain import (
    build_investigation_hash_chain,
    verify_investigation_hash_chain,
    compute_merkle_root
)


def test_empty_chain():
    res = build_investigation_hash_chain([], "inv-empty")
    assert res["total_blocks"] == 0
    assert res["status"] == "EMPTY_CHAIN"
    verify = verify_investigation_hash_chain([], "inv-empty")
    assert verify["is_valid"] is True


def test_hash_chain_creation_and_tamper_detection():
    events = [
        {
            "event_id": "EVT-0001",
            "raw_ref": "sysmon.evtx#1",
            "host": "HOST-01",
            "source": "Sysmon",
            "event_code": 1,
            "ts_start_utc": "2026-11-16T12:00:00Z",
            "ts_end_utc": "2026-11-16T12:00:01Z",
            "image": "C:\\Windows\\cmd.exe",
            "command_line": "cmd.exe"
        },
        {
            "event_id": "EVT-0002",
            "raw_ref": "sysmon.evtx#2",
            "host": "HOST-01",
            "source": "Sysmon",
            "event_code": 3,
            "ts_start_utc": "2026-11-16T12:01:00Z",
            "ts_end_utc": "2026-11-16T12:01:01Z",
            "dst_ip": "1.2.3.4"
        }
    ]

    res = build_investigation_hash_chain(events, "inv-test")
    assert res["total_blocks"] == 2
    root = res["merkle_root"]
    assert root is not None
    assert len(root) == 64  # SHA-256 length

    # Verification passes with original events
    v1 = verify_investigation_hash_chain(events, "inv-test", expected_root=root)
    assert v1["is_valid"] is True

    # Tampering test: modify command line in event 1
    tampered_events = [
        dict(events[0], command_line="malicious.exe --tampered"),
        events[1]
    ]
    v2 = verify_investigation_hash_chain(tampered_events, "inv-test", expected_root=root)
    assert v2["is_valid"] is False
    assert "mismatch" in v2["reason"].lower()
