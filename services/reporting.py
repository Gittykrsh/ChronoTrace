"""Forensic Reporting and Export Service for ChronoTrace.

Generates:
1. CSV Timeline export
2. JSON findings & reconstructed events
3. Comprehensive Markdown Digital Forensics Incident Report with strict evidence citations
"""

import csv
import io
import json
from typing import List, Dict, Any
from datetime import datetime, timezone


def generate_csv_timeline(events: List[Dict[str, Any]]) -> str:
    """Exports events into forensic CSV timeline format."""
    output = io.StringIO()
    fields = [
        "event_id", "ts_start_utc", "ts_end_utc", "host", "source", "event_code",
        "image", "command_line", "user", "src_ip", "dst_ip", "dst_port",
        "mitre_technique", "confidence", "flags", "raw_ref"
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for ev in events:
        row = dict(ev)
        if isinstance(row.get("flags"), list):
            row["flags"] = ";".join(row["flags"])
        writer.writerow(row)
    return output.getvalue()


def generate_json_findings(
    investigation: Dict[str, Any],
    events: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    graph_data: Dict[str, Any]
) -> str:
    """Exports structured JSON dataset with full evidence provenance and uncertainty."""
    payload = {
        "export_metadata": {
            "system": "ChronoTrace — Uncertainty-Aware Cyberattack Reconstruction System",
            "version": "1.0.0-prototype",
            "exported_at_utc": datetime.now(timezone.utc).isoformat(),
            "investigation": investigation
        },
        "findings": findings,
        "timeline_events": events,
        "provenance_graph": {
            "entities_count": len(graph_data.get("entities", [])),
            "edges_count": len(graph_data.get("edges", [])),
            "entities": graph_data.get("entities", []),
            "edges": graph_data.get("edges", [])
        }
    }
    return json.dumps(payload, indent=2)


def generate_markdown_report(
    investigation: Dict[str, Any],
    events: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    conflict_summary: Dict[str, int]
) -> str:
    """
    Generates a professional Digital Forensics Incident Investigation Report in Markdown.
    Every finding retains citation to its original raw_ref.
    Uncertainty, conflicting evidence, and limitations are made fully explicit.
    """
    inv_name = investigation.get("name", "Unnamed Investigation")
    inv_id = investigation.get("id", "N/A")
    is_demo = investigation.get("is_demo", 0)

    demo_warning = ""
    if is_demo:
        demo_warning = """
> [!WARNING]
> **DEMONSTRATION NOTICE — SYNTHETIC EVIDENCE DATA**
> This report was compiled from synthetic demo records. It is designed for forensic methodology validation and educational demonstration only.
"""

    # Group findings by attack stage
    stages_order = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Credential Access", "Defense Evasion", "Lateral Movement", "Command and Control", "Collection"]
    grouped_findings: Dict[str, List[Dict[str, Any]]] = {s: [] for s in stages_order}
    for f in findings:
        stg = f.get("stage", "Execution")
        if stg not in grouped_findings:
            grouped_findings[stg] = []
        grouped_findings[stg].append(f)

    # Compute confidence distributions
    high_conf = sum(1 for f in findings if f.get("confidence", 0) >= 0.80)
    mod_conf = sum(1 for f in findings if 0.50 <= f.get("confidence", 0) < 0.80)
    low_conf = sum(1 for f in findings if f.get("confidence", 0) < 0.50)

    # Markdown document assembly
    md = f"""# CHRONOTRACE FORENSIC INCIDENT REPORT
## Multi-Stage Attack Reconstruction & Uncertainty Analysis

**Case Identifier:** `{inv_id}`  
**Investigation Name:** {inv_name}  
**Report Generation (UTC):** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Classification:** Forensically Documented — Uncertainty-Aware Reconstruction  

{demo_warning}

---

## 1. EXECUTIVE SUMMARY

ChronoTrace reconstructed a multi-stage attack campaign by ingesting and correlating Windows Sysmon and Security event logs across impacted hosts.

### Investigation Metrics
| Metric | Value | Forensic Description |
| :--- | :--- | :--- |
| **Total Ingested Events** | `{len(events)}` | Parsed and normalized into Section 6 Schema |
| **Reconstructed Findings** | `{len(findings)}` | Verifiable forensic observations |
| **High Confidence Events (>=0.80)** | `{high_conf}` | Multi-source corroborated with definitive GUID linkage |
| **Moderate Confidence (0.50 - 0.79)** | `{mod_conf}` | Single source or narrow temporal uncertainty |
| **Low Confidence (<0.50)** | `{low_conf}` | Ambiguous parentage, PID heuristics, or clock skew |
| **Order Conflicts Identified** | `{conflict_summary.get('ORDER_CONFLICT', 0)}` | Overlapping event intervals or cross-host drift |
| **Missing Parent Process Flags** | `{conflict_summary.get('MISSING_PARENT', 0)}` | Orphaned processes lacking logged parent events |
| **Audit Log Cleared Alerts** | `{conflict_summary.get('LOG_CLEARED', 0)}` | Event 1102 anti-forensics activity detected |

---

## 2. RECONSTRUCTION METHODOLOGY & CONFIDENCE MODEL

Every reconstructed event in this report adheres to the **ChronoTrace Uncertainty-Aware Architecture**:
1. **Evidence Traceability (Rule 0):** Every finding is bound directly to an immutable log record reference (`raw_ref`).
2. **Interval Timestamps:** Clocks are treated as uncertainty intervals `[ts_start_utc, ts_end_utc]`.
3. **Four-Factor Confidence Metric:**
   $$\\text{{confidence}} = 0.25 \\times \\text{{corroboration}} + 0.25 \\times \\text{{source\\_reliability}} + 0.25 \\times \\text{{time\\_certainty}} + 0.25 \\times \\text{{link\\_strength}}$$
   *Confidence measures evidence consistency across independent observers—it is not an unverified mathematical claim of ground truth.*

---

## 3. RECONSTRUCTED ATTACK PHASES & FINDINGS
"""

    for stage, f_list in grouped_findings.items():
        if not f_list:
            continue
        md += f"\n### Stage: {stage}\n"
        md += "| Finding ID | Event ID | Host | MITRE Technique | Confidence | Flags | Evidence Citation (`raw_ref`) |\n"
        md += "| :--- | :--- | :--- | :--- | :---: | :--- | :--- |\n"
        for f in f_list:
            flags_str = ", ".join(f.get("flags_list", [])) if f.get("flags_list") else "—"
            conf_val = f.get("confidence", 0.0)
            tech = f.get("mitre_technique") or "General"
            raw_ref = f.get("raw_ref", "MISSING")
            md += f"| `{f['finding_id']}` | `{f['event_id']}` | `{f.get('host', 'N/A')}` | `{tech}` | **{conf_val:.2f}** | `{flags_str}` | [`{raw_ref}`](#evidence) |\n"

    md += """
---

## 4. FORENSIC CONFLICTS & MISSING EVIDENCE ANALYSIS

ChronoTrace distinguishes itself by surfacing gaps and contradictions rather than masking them:
"""

    if conflict_summary.get("ORDER_CONFLICT", 0) > 0:
        md += """
### 4.1 Chronological Order Conflicts (`ORDER_CONFLICT`)
Events with overlapping timestamps or cross-host clock skews where exact causal ordering cannot be definitively proven from evidence. Investigators must not assume strict sequential execution.
"""

    if conflict_summary.get("MISSING_PARENT", 0) > 0:
        md += """
### 4.2 Missing Parent Processes (`MISSING_PARENT`)
Processes executed whose parent process GUID or PPID does not exist in the ingested log stream. This typically indicates:
- Parent process exited before Sysmon initialization.
- Process injection or unmonitored parent launch.
- Selective deletion of event logs prior to evidence acquisition.
"""

    if conflict_summary.get("LOG_CLEARED", 0) > 0:
        md += """
### 4.3 Log Purge Indicators (`LOG_CLEARED`)
Security Event 1102 was recorded. The security event log was cleared by an adversary. Any reconstructed activity occurring prior to this timestamp must be scrutinized for potential gaps.
"""

    md += """
---

## 5. EVIDENCE REPOSITORY & PROVENANCE CITATIONS

The following raw evidence records directly substantiate this reconstruction:

| Event ID | Host | Source Provider | Code | Image / Command | Raw Evidence Citation (`raw_ref`) |
| :--- | :--- | :--- | :---: | :--- | :--- |
"""
    for ev in events:
        cmd = (ev.get("command_line") or ev.get("image") or "")[:45]
        if len(cmd) == 45:
            cmd += "..."
        md += f"| `{ev['event_id']}` | `{ev['host']}` | `{ev['source']}` | `{ev['event_code']}` | `{cmd}` | `{ev['raw_ref']}` |\n"

    md += """
---

## 6. LIMITATIONS AND UNRESOLVED QUESTIONS

1. **Reused Process IDs:** In the absence of Sysmon `ProcessGuid`, Windows Security 4688 records rely on ephemeral PIDs which may have been reused by the operating system kernel.
2. **Network Payload Blindness:** Sysmon Event ID 3 provides connection telemetry (source/destination IP and port) but does not record full packet captures or application payloads.
3. **Clock Skew:** Sub-second ordering between separate endpoints is subject to NTP clock drift.

*Report automatically generated by ChronoTrace Digital Forensics Platform.*
"""
    return md
