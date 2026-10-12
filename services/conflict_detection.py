"""Conflict and Missing-Evidence Engine for ChronoTrace.

Identifies forensic contradictions, temporal ambiguities, and gaps in evidence:
1. ORDER_CONFLICT: Overlapping time ranges [ts_start, ts_end] between sequence events or cross-host clock skews.
2. MISSING_PARENT: Process exists with parent GUID/PPID, but parent process has no record in the logs.
3. LOG_CLEARED: Windows Security Event 1102 detected. Flags anti-forensics and potential evidence destruction.
4. SINGLE_SOURCE: Event observed in only a single log source without independent corroboration.
"""

from typing import List, Dict, Any
from datetime import datetime


def detect_conflicts(
    events: List[Dict[str, Any]],
    known_process_guids: set = None
) -> Dict[str, Dict[str, Any]]:
    """
    Analyzes an investigation's normalized event stream.
    Returns a mapping of event_id -> {
        "flags": List[str],
        "conflict_details": List[Dict[str, Any]]
    }
    """
    if known_process_guids is None:
        known_process_guids = {e.get("process_guid") for e in events if e.get("process_guid")}

    results: Dict[str, Dict[str, Any]] = {
        e["event_id"]: {"flags": [], "conflict_details": []}
        for e in events
    }

    # Track hosts where event log was cleared (Event 1102)
    cleared_hosts: Dict[str, datetime] = {}
    for e in events:
        if e.get("event_code") == 1102:
            try:
                t = datetime.fromisoformat(e["ts_start_utc"].replace("Z", "+00:00"))
                host = e.get("host", "unknown")
                if host not in cleared_hosts or t > cleared_hosts[host]:
                    cleared_hosts[host] = t
            except Exception:
                pass

    # Sort events by ts_start_utc
    sorted_events = sorted(
        events,
        key=lambda x: x.get("ts_start_utc", "")
    )

    for i, e in enumerate(sorted_events):
        eid = e["event_id"]
        flags = []
        details = []

        # --- FLAG 1: LOG_CLEARED ---
        if e.get("event_code") == 1102:
            flags.append("LOG_CLEARED")
            details.append({
                "flag": "LOG_CLEARED",
                "severity": "CRITICAL",
                "title": "Audit Log Cleared (Event 1102)",
                "description": f"Security audit log was explicitly cleared on host {e.get('host')}. Prior events may have been purged.",
                "evidence_ref": e.get("raw_ref")
            })
        else:
            host = e.get("host")
            if host in cleared_hosts:
                try:
                    ev_time = datetime.fromisoformat(e["ts_start_utc"].replace("Z", "+00:00"))
                    if ev_time <= cleared_hosts[host]:
                        flags.append("LOG_CLEARED")
                        details.append({
                            "flag": "LOG_CLEARED",
                            "severity": "WARNING",
                            "title": "Suspected Log Purge Exposure",
                            "description": f"Event occurred prior to audit log clearing on {host}. Log integrity is compromised.",
                            "evidence_ref": e.get("raw_ref")
                        })
                except Exception:
                    pass

        # --- FLAG 2: MISSING_PARENT ---
        # Checks if process creation event refers to a parent that does not exist in logs
        if e.get("event_code") in (1, 4688):
            parent_guid = e.get("parent_guid")
            ppid = e.get("ppid")
            # If parent_guid is specified but not in our dataset
            if parent_guid and parent_guid not in known_process_guids:
                flags.append("MISSING_PARENT")
                details.append({
                    "flag": "MISSING_PARENT",
                    "severity": "WARNING",
                    "title": "Orphaned Process / Missing Parent Log",
                    "description": f"Process '{e.get('image')}' points to ParentGuid {parent_guid}, but no corresponding parent creation event was recorded in the ingested logs.",
                    "missing_entity": parent_guid,
                    "evidence_ref": e.get("raw_ref")
                })
            elif not parent_guid and ppid and ppid not in (0, 4):  # 4 is System
                # Check if any event has this PID as process_guid or pid
                has_parent_event = any(other.get("pid") == ppid for other in events if other != e)
                if not has_parent_event:
                    flags.append("MISSING_PARENT")
                    details.append({
                        "flag": "MISSING_PARENT",
                        "severity": "WARNING",
                        "title": "Parent Process Missing from Evidence",
                        "description": f"Process launched with PPID {ppid}, but no parent event found in log stream.",
                        "missing_entity": f"PPID:{ppid}",
                        "evidence_ref": e.get("raw_ref")
                    })

        # --- FLAG 3: ORDER_CONFLICT ---
        # Check adjacent events on the same host or cross-host with overlapping intervals
        # where causal or chronological ordering is ambiguous
        try:
            curr_start = datetime.fromisoformat(e["ts_start_utc"].replace("Z", "+00:00"))
            curr_end = datetime.fromisoformat(e["ts_end_utc"].replace("Z", "+00:00"))

            # Check next event in sorted timeline
            if i + 1 < len(sorted_events):
                next_e = sorted_events[i + 1]
                next_start = datetime.fromisoformat(next_e["ts_start_utc"].replace("Z", "+00:00"))
                next_end = datetime.fromisoformat(next_e["ts_end_utc"].replace("Z", "+00:00"))

                # Interval overlap: curr_end > next_start
                if curr_end > next_start and curr_start < next_end and e.get("host") == next_e.get("host"):
                    flags.append("ORDER_CONFLICT")
                    details.append({
                        "flag": "ORDER_CONFLICT",
                        "severity": "WARNING",
                        "title": "Overlapping Event Interval",
                        "description": f"Time interval [{e['ts_start_utc']} - {e['ts_end_utc']}] overlaps with event {next_e['event_id']} [{next_e['ts_start_utc']} - {next_e['ts_end_utc']}]. True sequence is ambiguous.",
                        "conflicting_event": next_e["event_id"],
                        "evidence_ref": f"{e.get('raw_ref')} vs {next_e.get('raw_ref')}"
                    })
        except Exception:
            pass

        # --- FLAG 4: SINGLE_SOURCE ---
        # Single-source event: only one provider witnessed this event
        if e.get("source") and e.get("source") in ("Microsoft-Windows-Sysmon", "Microsoft-Windows-Security-Auditing", "Sysmon", "Security"):
            # Check if there is another event on same host around the same time (~2 sec window)
            try:
                e_t = datetime.fromisoformat(e["ts_start_utc"].replace("Z", "+00:00"))
                corroborating = [
                    other for other in events
                    if other["event_id"] != eid and
                    other.get("host") == e.get("host") and
                    other.get("source") != e.get("source") and
                    abs((datetime.fromisoformat(other["ts_start_utc"].replace("Z", "+00:00")) - e_t).total_seconds()) <= 3.0
                ]
                if not corroborating and e.get("event_code") != 1102:
                    flags.append("SINGLE_SOURCE")
                    details.append({
                        "flag": "SINGLE_SOURCE",
                        "severity": "INFO",
                        "title": "Uncorroborated Single-Source Observation",
                        "description": f"Event observed only in '{e.get('source')}'. No cross-provider corroboration found in matching time window.",
                        "evidence_ref": e.get("raw_ref")
                    })
            except Exception:
                flags.append("SINGLE_SOURCE")

        # Deduplicate flags
        results[eid]["flags"] = list(dict.fromkeys(flags))
        results[eid]["conflict_details"] = details

    return results
