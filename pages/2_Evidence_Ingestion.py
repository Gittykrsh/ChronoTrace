"""Evidence Ingestion Page — ChronoTrace.

Handles importing Windows event logs (.evtx and .json) and preparing them for forensic reconstruction:
- File type validation & size checking
- Explanation of supported Sysmon & Security Event IDs
- Multi-stage pipeline execution with visual progress
- Ingestion summary statistics
- Raw and normalized evidence preview
"""

import streamlit as st
import os
import sys
import json

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from components.page_setup import setup_forensic_page
from components.sidebar import render_sidebar
from components.topbar import render_topbar
from database.db import get_investigation, get_ingestion_logs, get_raw_events, get_events
from services.ingestion import run_ingestion_pipeline

# 1. Page Configuration
inv_id = setup_forensic_page("Evidence Ingestion")
selected_inv_id = render_sidebar(current_page_id="ingestion")
inv = get_investigation(selected_inv_id) or {"id": selected_inv_id, "name": "Active Investigation", "is_demo": 1}

# 2. Render Topbar
render_topbar("Evidence Ingestion", inv)

st.markdown(
    """
    <div style="margin-top: -12px; margin-bottom: 20px;">
        <span style="font-size: 0.95rem; color: #94A7C2; font-style: italic;">
            "Import Windows event logs and prepare them for forensic reconstruction."
        </span>
    </div>
    """,
    unsafe_allow_html=True
)

# 3. Supported Event Telemetry Scope Card
with st.expander("ℹ️ Supported Forensic Event Telemetry Scope (Prototype v1.0)", expanded=False):
    col_sys, col_sec = st.columns(2)
    with col_sys:
        st.markdown(
            """
            **Microsoft-Windows-Sysmon:**
            - `Event ID 1`: **Process Creation** (ProcessGuid, Image, CommandLine, ParentProcessGuid, User)
            - `Event ID 3`: **Network Connection** (Source/Dest IP, Port, ProcessGuid)
            - `Event ID 11`: **File Creation / Drop** (TargetFilename, ProcessGuid, Timestamp)
            """
        )
    with col_sec:
        st.markdown(
            """
            **Windows Security Auditing:**
            - `Event ID 4624`: **Successful Logon** (TargetUserName, LogonType, IpAddress)
            - `Event ID 4688`: **Process Creation** (NewProcessId, ProcessId, CommandLine)
            - `Event ID 1102`: **Audit Log Cleared** (Anti-Forensics / Tampering Indicator)
            """
        )
    st.caption("*Other Windows event IDs are safely retained in raw evidence storage but excluded from graph entity correlation.*")

# 4. Upload Interface
st.markdown("#### 📥 Upload Forensic Evidence Files")

uploaded_files = st.file_uploader(
    "Select Windows .evtx or structured .json log files:",
    type=["evtx", "json"],
    accept_multiple_files=True,
    help="Upload original forensic .evtx dumps or exported event JSON files."
)

if uploaded_files:
    st.markdown("##### 📄 Selected Files for Ingestion:")
    file_info = []
    file_bytes_map = {}
    for f in uploaded_files:
        size_kb = len(f.getvalue()) / 1024
        file_info.append({
            "Filename": f.name,
            "Format": f.name.split(".")[-1].upper(),
            "Size (KB)": f"{size_kb:.2f} KB",
            "Status": "Ready for Processing"
        })
        file_bytes_map[f.name] = f.getvalue()

    st.dataframe(file_info, use_container_width=True, hide_index=True)

    c_btn, c_note = st.columns([3, 7])
    with c_btn:
        start_ingest = st.button("🚀 Start Forensic Ingestion", type="primary", use_container_width=True)
    with c_note:
        st.caption("Validation check: Enforces non-empty raw_ref and UTC normalization across all ingested records.")

    if start_ingest:
        with st.status("Executing 8-Stage ChronoTrace Forensic Pipeline...", expanded=True) as status:
            st.write("1️⃣ Validating binary file headers and schema constraints...")
            st.write("2️⃣ Extracting EVTX records / JSON structures...")
            st.write("3️⃣ Committing raw evidence with immutable raw_ref citations...")
            st.write("4️⃣ Normalizing timestamps to UTC intervals [ts_start, ts_end]...")
            st.write("5️⃣ Executing entity resolution and building NetworkX provenance graph...")
            st.write("6️⃣ Calculating 4-factor confidence metrics...")
            st.write("7️⃣ Evaluating conflict and missing-evidence rules...")
            st.write("8️⃣ Reconstructing attack timeline and findings...")

            # Run actual ingestion
            summary = run_ingestion_pipeline(selected_inv_id, file_bytes_map)
            status.update(label="Forensic Ingestion Pipeline Completed Successfully!", state="complete", expanded=False)

        st.success(f"Processing complete! {summary['supported_events_normalized']} events normalized into active case.")

        # Display Ingestion Summary Card
        st.markdown("#### 📊 Ingestion Summary")
        s1, s2, s3, s4 = st.columns(4)
        with s1:
            st.metric("Files Processed", summary["files_processed"])
            st.metric("Parsing Errors", summary["parsing_errors"])
        with s2:
            st.metric("Raw Records Parsed", summary["raw_records_parsed"])
            st.metric("Missing Fields", summary["missing_required_fields"])
        with s3:
            st.metric("Supported Normalized", summary["supported_events_normalized"])
            st.metric("Invalid Timestamps", summary["invalid_timestamps"])
        with s4:
            st.metric("Unsupported Records", summary["unsupported_records"])
            st.metric("Stages Completed", len(summary["stages_completed"]))

st.markdown("<hr style='margin: 24px 0; border-color: rgba(148,167,194,0.12);'/>", unsafe_allow_html=True)

# 5. Ingestion History & Evidence Record Preview
st.markdown("#### 📋 Ingested Evidence Audit Trail")
logs = get_ingestion_logs(selected_inv_id)

if logs:
    log_table = []
    for l in logs:
        log_table.append({
            "Log ID": l["id"],
            "Sources": l["filename"],
            "Total Records": l["total_records"],
            "Normalized Events": l["normalized_records"],
            "Errors": l["errors_count"],
            "Status": l["status"],
            "Ingestion Time (UTC)": l["ingested_at"]
        })
    st.dataframe(log_table, use_container_width=True, hide_index=True)
else:
    st.info("No external files ingested yet. The current case is populated with the synthetic demonstration dataset.")

# Evidence Preview Tabs
st.markdown("##### 👁️ Evidence Previews (Active Case)")
tab_raw, tab_norm = st.tabs(["Raw Evidence Sample", "Normalized Events Sample"])

with tab_raw:
    raw_samples = get_raw_events(selected_inv_id, limit=5)
    if raw_samples:
        for r in raw_samples:
            with st.expander(f"Raw Record: {r['raw_ref']} ({r['source']} Event {r['event_code']})"):
                st.code(r["raw_json"], language="json")
    else:
        st.caption("No raw records available.")

with tab_norm:
    norm_samples = get_events(selected_inv_id)[:5]
    if norm_samples:
        st.dataframe(norm_samples, use_container_width=True)
    else:
        st.caption("No normalized events available.")
