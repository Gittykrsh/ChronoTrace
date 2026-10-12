"""Unit tests for ChronoTrace 4-factor confidence scoring formula."""

import pytest
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from services.confidence import evaluate_event_confidence, calculate_time_certainty


def test_confidence_equal_weights():
    """Formula: confidence = 0.25*corroboration + 0.25*source_reliability + 0.25*time_certainty + 0.25*link_strength"""
    event = {
        "event_id": "EVT-001",
        "source": "Microsoft-Windows-Sysmon",
        "event_code": 1,
        "ts_start_utc": "2026-10-12T04:15:10.000Z",
        "ts_end_utc": "2026-10-12T04:15:10.500Z",
        "process_guid": "{F82A1B90-1111-5D3C-AA01-000000000100}",
        "raw_ref": "sysmon.evtx#1"
    }

    # Highly corroborated, resolved parent, narrow time range
    score, factors, explanation = evaluate_event_confidence(
        event=event,
        sources_count=2,
        parent_resolved=True,
        is_uncertain_link=False
    )

    assert 0.0 <= score <= 1.0
    assert factors["corroboration"] == 0.85
    assert factors["source_reliability"] == 0.95
    assert factors["time_certainty"] == 1.0
    assert factors["link_strength"] == 0.95
    expected = 0.25 * 0.85 + 0.25 * 0.95 + 0.25 * 1.0 + 0.25 * 0.95
    assert pytest.approx(score, 0.01) == round(expected, 3)


def test_time_certainty_degrades_with_interval_width():
    # Narrow interval (<= 1s)
    tc_tight = calculate_time_certainty("2026-10-12T04:15:10Z", "2026-10-12T04:15:10.500Z")
    assert tc_tight == 1.0

    # Wide interval (5 minutes clock skew)
    tc_wide = calculate_time_certainty("2026-10-12T04:15:00Z", "2026-10-12T04:20:00Z")
    assert tc_wide <= 0.40
