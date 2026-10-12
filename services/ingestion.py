"""Evidence Ingestion Service for ChronoTrace.

Handles:
- .evtx ingestion using python-evtx (falling back gracefully if non-evtx)
- Structured .json forensic log ingestion
- Normalization into strict schema
- Correlation, Graph Construction, Confidence calculation, Conflict detection, and Findings generation
"""

import os
import json
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Tuple
from database.db import (
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

SUPPORTED_EVENT_CODES = {1, 3, 11, 4624, 4688, 1102}


def parse_evtx_xml(xml_str: str) -> Dict[str, Any]:
    """Parses standard Windows Event XML into flat dictionary."""
    data = {}
    try:
        # Strip XML namespaces for simpler parsing
        xml_clean = xml_str
        if "xmlns=" in xml_clean:
            import re
            xml_clean = re.sub(r' xmlns="[^"]+"', '', xml_clean)
            xml_clean = re.sub(r' xmlns:[a-zA-Z0-9]+="[^"]+"', '', xml_clean)

        root = ET.fromstring(xml_clean)

        # System header
        sys_node = root.find("System")
        if sys_node is not None:
            for child in sys_node:
                tag = child.tag
                if tag == "EventID":
                    data["EventID"] = int(child.text) if child.text else 0
                elif tag == "TimeCreated":
                    data["TimeCreated"] = child.attrib.get("SystemTime", "")
                elif tag == "Provider":
                    data["Provider_Name"] = child.attrib.get("Name", "")
                elif tag == "Computer":
                    data["Computer"] = child.text or ""
                elif tag == "EventRecordID":
                    data["EventRecordID"] = int(child.text) if child.text else 0
                elif tag == "Channel":
                    data["Channel"] = child.text or ""

        # EventData payload
        evdata_node = root.find("EventData")
        if evdata_node is not None:
            for data_elem in evdata_node.findall("Data"):
                name = data_elem.attrib.get("Name")
                val = data_elem.text or ""
                if name:
                    data[name] = val

    except Exception:
        pass
    return data


def process_evtx_file(file_path: str, filename: str) -> List[Dict[str, Any]]:
    """Parses .evtx file using python-evtx library."""
    from Evtx.Evtx import Evtx
    raw_records = []
    with Evtx(file_path) as evtx:
        for idx, record in enumerate(evtx.records(), start=1):
            xml_content = record.xml()
            parsed = parse_evtx_xml(xml_content)
            rec_num = parsed.get("EventRecordID", idx)
            raw_ref = f"{filename}#{rec_num}"
            raw_records.append({
                "raw_ref": raw_ref,
                "source_file": filename,
                "record_number": rec_num,
                "source": parsed.get("Provider_Name") or parsed.get("Channel") or "Windows",
                "event_code": parsed.get("EventID", 0),
                "raw_json": parsed
            })
    return raw_records


def run_ingestion_pipeline(
    investigation_id: str,
    file_bytes_map: Dict[str, bytes]
) -> Dict[str, Any]:
    """
    Executes the full 8-stage ChronoTrace processing pipeline on uploaded evidence files.
    Returns summary statistics and processing status.
    """
    summary = {
        "files_processed": 0,
        "raw_records_parsed": 0,
        "supported_events_normalized": 0,
        "unsupported_records": 0,
        "parsing_errors": 0,
        "missing_required_fields": 0,
        "invalid_timestamps": 0,
        "stages_completed": [],
        "errors": []
    }

    raw_evidence_list: List[Dict[str, Any]] = []
    normalized_events: List[Dict[str, Any]] = []

    # Stage 1: File Validation & Parsing
    summary["stages_completed"].append("File validation")
    import tempfile

    for filename, content in file_bytes_map.items():
        summary["files_processed"] += 1
        is_evtx = filename.lower().endswith(".evtx")
        is_json = filename.lower().endswith(".json")

        if is_evtx:
            with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            try:
                records = process_evtx_file(tmp_path, filename)
                raw_evidence_list.extend(records)
                summary["raw_records_parsed"] += len(records)
            except Exception as e:
                summary["parsing_errors"] += 1
                summary["errors"].append(f"EVTX parse error in {filename}: {str(e)}")
            finally:
                if os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass
        elif is_json:
            try:
                json_data = json.loads(content.decode("utf-8", errors="ignore"))
                if isinstance(json_data, dict):
                    json_data = [json_data]
                for idx, item in enumerate(json_data, start=1):
                    rec_num = item.get("record_number", idx)
                    raw_ref = item.get("raw_ref") or f"{filename}#{rec_num}"
                    raw_evidence_list.append({
                        "raw_ref": raw_ref,
                        "source_file": filename,
                        "record_number": rec_num,
                        "source": item.get("source") or item.get("Provider_Name") or "Sysmon",
                        "event_code": int(item.get("event_code") or item.get("EventID") or 0),
                        "raw_json": item
                    })
                    summary["raw_records_parsed"] += 1
            except Exception as e:
                summary["parsing_errors"] += 1
                summary["errors"].append(f"JSON parse error in {filename}: {str(e)}")
        else:
            summary["parsing_errors"] += 1
            summary["errors"].append(f"Unsupported file format: {filename}")

    # Stage 2: Raw Event Storage
    summary["stages_completed"].append("Raw event storage")
    for r in raw_evidence_list:
        r["investigation_id"] = investigation_id

    try:
        insert_raw_events(raw_evidence_list)
    except Exception as e:
        summary["errors"].append(f"Database raw storage error: {str(e)}")

    # Stage 3: Event Normalization
    summary["stages_completed"].append("Event normalization")
    evt_counter = 1
    for raw in raw_evidence_list:
        code = raw.get("event_code")
        if code in SUPPORTED_EVENT_CODES:
            try:
                norm = normalize_record(raw, event_index=evt_counter)
                norm["investigation_id"] = investigation_id
                normalized_events.append(norm)
                summary["supported_events_normalized"] += 1
                evt_counter += 1
            except ValueError as ve:
                summary["missing_required_fields"] += 1
                summary["errors"].append(str(ve))
            except Exception as e:
                summary["errors"].append(f"Normalization error: {str(e)}")
        else:
            summary["unsupported_records"] += 1

    if normalized_events:
        insert_events(normalized_events)

    # Stage 4 & 5: Entity Resolution & Graph Construction
    summary["stages_completed"].append("Entity resolution & Graph construction")
    G, entities, edges = build_provenance_graph(normalized_events, investigation_id=investigation_id)
    insert_entities(entities)
    insert_edges(edges)

    # Stage 6: Confidence and Conflict Analysis
    summary["stages_completed"].append("Confidence & Conflict analysis")
    conflicts_map = detect_conflicts(normalized_events)

    findings: List[Dict[str, Any]] = []
    for ev in normalized_events:
        eid = ev["event_id"]
        conflict_info = conflicts_map.get(eid, {"flags": [], "conflict_details": []})
        flags = conflict_info["flags"]

        score, factors, expl = evaluate_event_confidence(
            event=ev,
            sources_count=1 if "SINGLE_SOURCE" in flags else 2,
            parent_resolved=("MISSING_PARENT" not in flags),
            is_uncertain_link=("ORDER_CONFLICT" in flags)
        )

        tech_id, tech_name, stage = tag_mitre_technique(ev)
        finding_id = f"FND-{eid}"

        findings.append({
            "finding_id": finding_id,
            "investigation_id": investigation_id,
            "event_id": eid,
            "stage": stage,
            "confidence": score,
            "flags": flags,
            "explanation": f"{tech_name or 'Reconstructed activity'}: {expl}",
            "corroboration": factors["corroboration"],
            "source_reliability": factors["source_reliability"],
            "time_certainty": factors["time_certainty"],
            "link_strength": factors["link_strength"]
        })

    insert_findings(findings)

    # Stage 7: Timeline generation
    summary["stages_completed"].append("Timeline & Findings generation")

    # Record log
    record_ingestion_log(
        investigation_id=investigation_id,
        filename=", ".join(file_bytes_map.keys()),
        file_size_bytes=sum(len(c) for c in file_bytes_map.values()),
        total_records=summary["raw_records_parsed"],
        normalized_records=summary["supported_events_normalized"],
        unsupported_records=summary["unsupported_records"],
        errors_count=summary["parsing_errors"] + summary["missing_required_fields"],
        status="Completed" if not summary["errors"] else "Completed with warnings",
        details=json.dumps(summary)
    )

    return summary
