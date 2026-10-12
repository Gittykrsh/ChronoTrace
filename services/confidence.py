"""Confidence Scoring Engine for ChronoTrace.

Implements the first-draft confidence formula from Section 9:
confidence = w1 * corroboration + w2 * source_reliability + w3 * time_certainty + w4 * link_strength

Each factor is normalized between 0.0 and 1.0.
Default equal weights: 0.25 each (configurable).

IMPORTANT FORENSIC PRINCIPLE:
Confidence scores are algorithmic corroboration heuristics, NOT mathematical probabilities of ground truth.
They measure evidence consistency and corroboration across independent logs.
"""

from typing import Dict, Any, Tuple
from datetime import datetime


DEFAULT_WEIGHTS = {
    "w_corroboration": 0.25,
    "w_source_reliability": 0.25,
    "w_time_certainty": 0.25,
    "w_link_strength": 0.25
}

# Source baseline reliability weights
SOURCE_RELIABILITY_MAP = {
    # Sysmon with detailed GUIDs and hashes
    "Microsoft-Windows-Sysmon": 0.95,
    "Sysmon": 0.95,
    # Windows Security Auditing (high trust for audit events, medium for reused PIDs)
    "Microsoft-Windows-Security-Auditing": 0.85,
    "Security": 0.85,
    # System log
    "System": 0.80,
    # Generic fallback
    "Unknown": 0.50
}


def calculate_time_certainty(ts_start_str: str, ts_end_str: str) -> float:
    """
    Evaluates certainty of timestamp range.
    Narrow range (<= 1s) = 1.0.
    Small uncertainty window (<= 10s) = 0.85.
    Moderate window (<= 60s) = 0.65.
    Wide window (> 60s, e.g. clock drift or delay) = 0.35.
    """
    try:
        t_start = datetime.fromisoformat(ts_start_str.replace("Z", "+00:00"))
        t_end = datetime.fromisoformat(ts_end_str.replace("Z", "+00:00"))
        delta_sec = abs((t_end - t_start).total_seconds())

        if delta_sec <= 1.0:
            return 1.0
        elif delta_sec <= 5.0:
            return 0.90
        elif delta_sec <= 15.0:
            return 0.75
        elif delta_sec <= 60.0:
            return 0.60
        else:
            return 0.35
    except Exception:
        return 0.50


def calculate_source_reliability(source_name: str, event_code: int) -> float:
    """Evaluates intrinsic forensic reliability of the logging provider."""
    # Audit log cleared event (1102) is authoritative
    if event_code == 1102:
        return 1.0
    for key, score in SOURCE_RELIABILITY_MAP.items():
        if key.lower() in source_name.lower():
            return score
    return 0.60


def evaluate_event_confidence(
    event: Dict[str, Any],
    sources_count: int = 1,
    parent_resolved: bool = True,
    is_uncertain_link: bool = False,
    weights: Dict[str, float] = None
) -> Tuple[float, Dict[str, float], str]:
    """
    Calculates overall event confidence score and factor breakdown.
    Returns:
        (total_confidence, factor_breakdown, explanation)
    """
    if weights is None:
        weights = DEFAULT_WEIGHTS

    # 1. Corroboration: How many independent sources saw this activity
    if sources_count >= 3:
        corroboration = 1.0
    elif sources_count == 2:
        corroboration = 0.85
    else:
        corroboration = 0.45  # single source

    # 2. Source reliability
    source_reliability = calculate_source_reliability(
        event.get("source", "Unknown"),
        event.get("event_code", 0)
    )

    # 3. Time certainty
    ts_start = event.get("ts_start_utc", "")
    ts_end = event.get("ts_end_utc", "")
    time_certainty = calculate_time_certainty(ts_start, ts_end)

    # 4. Link strength (entity resolution confidence)
    has_guid = bool(event.get("process_guid"))
    if has_guid and parent_resolved and not is_uncertain_link:
        link_strength = 0.95
    elif has_guid and not parent_resolved:
        link_strength = 0.40  # missing parent weakens provenance chain
    elif not has_guid and event.get("event_code") in (1, 4688):
        link_strength = 0.35  # PID reuse risk
    elif event.get("event_code") in (3, 11, 4624, 1102):
        link_strength = 0.85  # standard entity association
    else:
        link_strength = 0.50

    if is_uncertain_link:
        link_strength = min(link_strength, 0.30)

    # Weighted calculation
    score = (
        weights["w_corroboration"] * corroboration +
        weights["w_source_reliability"] * source_reliability +
        weights["w_time_certainty"] * time_certainty +
        weights["w_link_strength"] * link_strength
    )

    factors = {
        "corroboration": round(corroboration, 3),
        "source_reliability": round(source_reliability, 3),
        "time_certainty": round(time_certainty, 3),
        "link_strength": round(link_strength, 3)
    }

    score_rounded = round(min(max(score, 0.0), 1.0), 3)

    explanation = (
        f"Score {score_rounded:.2f} derived from corroboration ({corroboration:.2f}), "
        f"source reliability ({source_reliability:.2f}), timestamp precision ({time_certainty:.2f}), "
        f"and entity linkage strength ({link_strength:.2f})."
    )

    return score_rounded, factors, explanation
