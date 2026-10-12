"""Database seeder for ChronoTrace demonstration investigations.

Seeds synthetic forensic dataset with:
- Multi-stage attack chain (Logon -> PowerShell -> C2 -> Persistence -> Credential Dump -> Account Creation -> Log Clearing -> Lateral Movement)
- All 4 core conflict/uncertainty flags:
  1. ORDER_CONFLICT (overlapping intervals between net.exe and net1.exe)
  2. MISSING_PARENT (procdump.exe with unlogged parent GUID)
  3. LOG_CLEARED (wevtutil cl Security & Security Event 1102)
  4. SINGLE_SOURCE (uncorroborated network or file drop telemetry)
- Strict adherence to non-empty raw_ref requirement.
"""

import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import json
from database.db import (
    init_db,
    create_investigation,
    insert_raw_events,
    insert_events,
    insert_entities,
    insert_edges,
    insert_findings,
    record_ingestion_log
)
from services.normalization import normalize_record
from services.correlation import build_provenance_graph
from services.confidence import evaluate_event_confidence
from services.conflict_detection import detect_conflicts
from services.mitre_tagger import tag_mitre_technique

SAMPLE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_events.json")


def seed_demo_data(force: bool = False) -> str:
    init_db()
    inv_id = "inv-demo-01"
    inv_name = "Operation Chimera — Multi-Stage Intrusion & Anti-Forensics"
    inv_desc = "Synthetic demonstration dataset (DEMO DATA — NOT REAL FORENSIC EVIDENCE). Exhibits full ATT&CK kill-chain with four uncertainty flags."

    create_investigation(
        investigation_id=inv_id,
        name=inv_name,
        description=inv_desc,
        status="Active",
        is_demo=True
    )

    with open(SAMPLE_FILE, "r", encoding="utf-8") as f:
        records = json.load(f)

    # 1. Insert Raw Events
    raw_evidence = []
    for r in records:
        raw_evidence.append({
            "raw_ref": r["raw_ref"],
            "investigation_id": inv_id,
            "source_file": r["source_file"],
            "record_number": r["record_number"],
            "source": r["source"],
            "event_code": r["event_code"],
            "raw_json": r["raw_json"]
        })
    insert_raw_events(raw_evidence)

    # 2. Normalize and insert Events
    normalized_events = []
    for idx, r in enumerate(records, start=1):
        norm = normalize_record(r, event_index=idx)
        norm["investigation_id"] = inv_id
        normalized_events.append(norm)
    insert_events(normalized_events)

    # 3. Build Provenance Graph (NetworkX)
    G, entities, edges = build_provenance_graph(normalized_events, investigation_id=inv_id)
    insert_entities(entities)
    insert_edges(edges)

    # 4. Conflict Engine and Confidence Scoring
    conflicts_map = detect_conflicts(normalized_events)
    findings = []

    for ev in normalized_events:
        eid = ev["event_id"]
        c_info = conflicts_map.get(eid, {"flags": [], "conflict_details": []})
        flags = c_info["flags"]

        score, factors, expl = evaluate_event_confidence(
            event=ev,
            sources_count=1 if "SINGLE_SOURCE" in flags else 2,
            parent_resolved=("MISSING_PARENT" not in flags),
            is_uncertain_link=("ORDER_CONFLICT" in flags)
        )

        tech_id, tech_name, stage = tag_mitre_technique(ev)
        findings.append({
            "finding_id": f"FND-{eid}",
            "investigation_id": inv_id,
            "event_id": eid,
            "stage": stage,
            "confidence": score,
            "flags": flags,
            "explanation": f"{tech_name}: {expl}",
            "corroboration": factors["corroboration"],
            "source_reliability": factors["source_reliability"],
            "time_certainty": factors["time_certainty"],
            "link_strength": factors["link_strength"]
        })
    insert_findings(findings)

    # 5. Ingestion Log
    record_ingestion_log(
        investigation_id=inv_id,
        filename="sysmon_victim_pc01.evtx, security_victim_pc01.evtx, security_dc_srv01.evtx",
        file_size_bytes=1048576,
        total_records=len(records),
        normalized_records=len(normalized_events),
        unsupported_records=0,
        errors_count=0,
        status="Completed (Demo)",
        details=json.dumps({"demo": True, "kill_chain": "T1078 -> T1059.001 -> T1071.001 -> T1053.005 -> T1003.001 -> T1136.001 -> T1070.001"})
    )

    return inv_id


if __name__ == "__main__":
    inv = seed_demo_data()
    print(f"Successfully seeded demo investigation: {inv}")
