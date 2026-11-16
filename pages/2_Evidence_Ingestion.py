"""Evidence Ingestion Page — ChronoTrace.

Handles importing Windows event logs (.evtx and .json) and preparing them for forensic reconstruction:
- File type validation & size checking
- Supported Sysmon & Windows Security Event Scope Card
- Multi-stage pipeline execution with live status updates
- Ingestion summary statistics & audit trail
- Raw and normalized evidence preview tabs
"""

import streamlit as st
import os
import sys
import json
import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ui.theme import (
    inject_theme,
    calc_df_height,
    icon_svg,
    SUCCESS_GREEN,
    STATUS_EMERALD,
    WARNING_AMBER,
    STATUS_AMBER,
    CRITICAL_RED,
    STATUS_ROSE,
    ACCENT_CYAN,
    ACCENT_VIOLET,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    TEXT_MUTED
)
from ui.layout import render_sidebar, render_topbar
from database.db import (
    init_db,
    get_investigation,
    get_ingestion_logs,
    get_raw_events,
    get_events
)
from services.ingestion import run_ingestion_pipeline

# 1. Page Configuration & Theme
st.set_page_config(
    page_title="Evidence Ingestion — ChronoTrace",
    page_icon=":material/upload_file:",
    layout="wide",
    initial_sidebar_state="expanded"
)
inject_theme()
init_db()

# 2. Render Persistent 280px Sidebar
selected_inv_id = render_sidebar(current_page_id="ingestion")
inv = get_investigation(selected_inv_id) or {"id": selected_inv_id, "name": "Active Investigation", "is_demo": 1}

# 3. Render Topbar
render_topbar("Evidence Ingestion", inv)

st.markdown(
    """
    <div style="margin-top: -10px; margin-bottom: 14px;">
        <span style="font-size: 0.84rem; color: #94A3B8; font-style: italic;">
            "Import Windows event logs and prepare them for forensic reconstruction."
        </span>
    </div>
    """,
    unsafe_allow_html=True
)

# 4. Upload & Scope Row
col_upload, col_scope = st.columns([6, 4], gap="medium")

with col_upload:
    ico_up = icon_svg("upload", size=14, color=ACCENT_CYAN)
    st.markdown(
        f"""
        <div style="font-size: 0.84rem; font-weight: 600; color: #F1F5F9; margin-bottom: 6px; display: flex; align-items: center; gap: 7px;">
            {ico_up} Upload Evidence Log Files (.evtx / .json)
        </div>
        """,
        unsafe_allow_html=True
    )
    uploaded_files = st.file_uploader(
        "Select Windows .evtx or structured .json log files:",
        type=["evtx", "json"],
        accept_multiple_files=True,
        help="Upload authentic forensic .evtx dumps or exported event JSON files.",
        label_visibility="collapsed"
    )

with col_scope:
    ico_info = icon_svg("shield", size=14, color=ACCENT_VIOLET)
    st.markdown(
        f"""
        <div style="font-size: 0.84rem; font-weight: 600; color: #F1F5F9; margin-bottom: 6px; display: flex; align-items: center; gap: 7px;">
            {ico_info} Supported Event Telemetry Scope (v1.0)
        </div>
        <div class="soc-card" style="padding: 10px 14px;">
            <div style="font-size: 0.74rem; font-family: 'JetBrains Mono', monospace; line-height: 1.6;">
                <span style="color: #35D6E8; font-weight: 600;">Microsoft-Windows-Sysmon:</span><br>
                • Event ID 1: Process Creation (GUID, Parent, CLI)<br>
                • Event ID 3: Network Connection (IP, Port, GUID)<br>
                • Event ID 11: File Creation (Drop path, Target)<br>
                <span style="color: #8B7CFF; font-weight: 600; margin-top: 4px; display: inline-block;">Windows Security Auditing:</span><br>
                • Event ID 4624: Successful Logon (Type, IP)<br>
                • Event ID 4688: Process Creation (PID, PPID)<br>
                • Event ID 1102: Audit Log Cleared (Anti-Forensics)
            </div>
            <div style="margin-top: 6px; font-size: 0.68rem; color: #64748B;">
                *Other IDs are retained in raw evidence storage but excluded from graph entity correlation.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

if uploaded_files:
    st.markdown("<div style='font-size: 0.82rem; font-weight: 600; color: #F1F5F9; margin: 10px 0 6px 0;'>Selected Files for Ingestion:</div>", unsafe_allow_html=True)
    file_info = []
    file_bytes_map = {}
    for f in uploaded_files:
        size_kb = len(f.getvalue()) / 1024
        file_info.append({
            "Filename": f.name,
            "Format": f.name.split(".")[-1].upper(),
            "Size": f"{size_kb:.2f} KB",
            "Status": "Ready for Processing"
        })
        file_bytes_map[f.name] = f.getvalue()

    df_files = pd.DataFrame(file_info)
    st.dataframe(df_files, use_container_width=True, hide_index=True, height=calc_df_height(df_files, min_h=80, max_h=200))

    c_btn, c_note = st.columns([3, 7])
    with c_btn:
        start_ingest = st.button("Start Forensic Ingestion", type="primary", use_container_width=True)
    with c_note:
        st.caption("Verification: Enforces non-empty raw_ref and UTC normalization across all ingested records.")

    if start_ingest:
        with st.status("Executing ChronoTrace Forensic Processing Pipeline...", expanded=True) as status:
            st.write("[Stage 1/7] Validating binary headers and file schema constraints...")
            st.write("[Stage 2/7] Extracting EVTX records / JSON structures into raw storage...")
            st.write("[Stage 3/7] Committing raw evidence with immutable raw_ref citations...")
            st.write("[Stage 4/7] Normalizing timestamps to UTC intervals [ts_start, ts_end]...")
            st.write("[Stage 5/7] Executing entity resolution and building NetworkX provenance graph...")
            st.write("[Stage 6/7] Calculating 4-factor confidence metrics and evaluating conflict rules...")
            st.write("[Stage 7/7] Reconstructing attack timeline, MITRE ATT&CK stages, and findings...")

            summary = run_ingestion_pipeline(selected_inv_id, file_bytes_map)
            status.update(label="Forensic Ingestion Pipeline Completed Successfully", state="complete", expanded=False)

        st.success(f"Processing complete: {summary['supported_events_normalized']} events normalized into active case.")

        # Ingestion Summary Metrics Row
        st.markdown("<div style='font-size: 0.84rem; font-weight: 600; color: #F1F5F9; margin: 12px 0 6px 0;'>Ingestion Summary</div>", unsafe_allow_html=True)
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

st.markdown("<hr style='margin: 14px 0; border-color: rgba(255, 255, 255, 0.06);'/>", unsafe_allow_html=True)

# 5. Ingestion History Audit Trail
ico_trail = icon_svg("report", size=14, color=ACCENT_CYAN)
st.markdown(
    f"""
    <div style="font-size: 0.84rem; font-weight: 600; color: #F1F5F9; margin-bottom: 6px; display: flex; align-items: center; gap: 7px;">
        {ico_trail} Ingested Evidence Audit Trail
    </div>
    """,
    unsafe_allow_html=True
)
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
    df_logs = pd.DataFrame(log_table)
    st.dataframe(df_logs, use_container_width=True, hide_index=True, height=calc_df_height(df_logs, min_h=90, max_h=200))
else:
    st.info("No external files ingested yet. The current case is populated with the synthetic demonstration dataset.")

st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

# 6. Evidence Previews
ico_prev = icon_svg("search", size=14, color=ACCENT_VIOLET)
st.markdown(
    f"""
    <div style="font-size: 0.84rem; font-weight: 600; color: #F1F5F9; margin-bottom: 6px; display: flex; align-items: center; gap: 7px;">
        {ico_prev} Evidence Previews (Active Case)
    </div>
    """,
    unsafe_allow_html=True
)
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
        df_norm = pd.DataFrame(norm_samples)
        st.dataframe(df_norm, use_container_width=True, height=calc_df_height(df_norm, min_h=120, max_h=240))
    else:
        st.caption("No normalized events available.")
