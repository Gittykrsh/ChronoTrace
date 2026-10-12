"""ChronoTrace — Uncertainty-Aware Cyberattack Reconstruction System.

Main Application Entry Point.
A professional digital forensics platform for incident responders, threat hunters, and forensics engineers.
"""

import streamlit as st
import os
import sys

# Ensure root directory is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from components.page_setup import setup_forensic_page
from components.sidebar import render_sidebar
from components.topbar import render_topbar
from components.metric_cards import render_metric_cards
from components.charts import (
    render_attack_activity_chart,
    render_confidence_distribution_chart,
    render_pipeline_status
)
from database.db import (
    get_investigation,
    get_events,
    get_findings,
    get_raw_events,
    get_ingestion_logs
)

# 1. Initialize Page Configuration & Theme
inv_id = setup_forensic_page("Investigation Overview")

# 2. Render Sidebar with active page ID
selected_inv_id = render_sidebar(current_page_id="overview")
inv = get_investigation(selected_inv_id) or {"id": selected_inv_id, "name": "Active Investigation", "is_demo": 1}

# 3. Fetch Data
events = get_events(selected_inv_id)
findings = get_findings(selected_inv_id)
raw_events = get_raw_events(selected_inv_id)
logs = get_ingestion_logs(selected_inv_id)

hosts = list({e["host"] for e in events if e.get("host")})
sources = list({e["source"] for e in events if e.get("source")})

# 4. Render Topbar
filters = render_topbar("Investigation Overview", inv, hosts=hosts, sources=sources)

# Apply global filters
filtered_events = events
if filters["host"] != "All Hosts":
    filtered_events = [e for e in filtered_events if e.get("host") == filters["host"]]
if filters["source"] != "All Sources":
    filtered_events = [e for e in filtered_events if e.get("source") == filters["source"]]
if filters["min_confidence"] > 0.0:
    filtered_events = [e for e in filtered_events if e.get("confidence", 0) >= filters["min_confidence"]]
if filters["search_query"]:
    q = filters["search_query"]
    filtered_events = [
        e for e in filtered_events
        if q in (e.get("image") or "").lower()
        or q in (e.get("command_line") or "").lower()
        or q in (e.get("user") or "").lower()
        or q in (e.get("raw_ref") or "").lower()
        or q in str(e.get("pid", ""))
    ]

filtered_event_ids = {e["event_id"] for e in filtered_events}
filtered_findings = [f for f in findings if f["event_id"] in filtered_event_ids]

# Subtitle
st.markdown(
    """
    <div style="margin-top: -12px; margin-bottom: 20px;">
        <span style="font-size: 0.95rem; color: #94A7C2; font-style: italic;">
            "Reconstruct attack sequences. Trace every finding to evidence."
        </span>
    </div>
    """,
    unsafe_allow_html=True
)

# 5. Forensic KPI Metrics Row
render_metric_cards(filtered_events, filtered_findings, raw_events)

st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

# 6. Main Visualization Row (Attack Activity & Confidence Distribution)
c_left, c_right = st.columns([6, 4])
with c_left:
    render_attack_activity_chart(filtered_events)
with c_right:
    render_confidence_distribution_chart(filtered_findings)

st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

# 7. Investigation Workflow Pipeline Panel
st.markdown("##### ⚙️ ChronoTrace Forensic Processing Pipeline")
render_pipeline_status(is_demo=bool(inv.get("is_demo")))

st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

# 8. Actionable Findings & Ingested Evidence
col_fnd, col_ev = st.columns([6, 4])

with col_fnd:
    st.markdown("##### 🎯 Reconstructed Attack Findings")
    if not filtered_findings:
        st.info("No findings matching current filters.")
    else:
        display_data = []
        for f in filtered_findings[:8]:
            flags = f.get("flags_list", [])
            flags_str = ", ".join(flags) if flags else "—"
            display_data.append({
                "Finding ID": f["finding_id"],
                "Event ID": f["event_id"],
                "Host": f.get("host", "N/A"),
                "Attack Stage": f.get("stage", "Execution"),
                "Confidence": f"{f.get('confidence', 0):.2f}",
                "Flags": flags_str,
                "Raw Ref": f.get("raw_ref", "MISSING")
            })
        st.dataframe(display_data, use_container_width=True, hide_index=True)

        selected_fnd_id = st.selectbox(
            "Select finding to inspect details & evidence reference:",
            options=[f["finding_id"] for f in filtered_findings[:8]],
            key="home_fnd_selector"
        )
        selected_fnd = next((f for f in filtered_findings if f["finding_id"] == selected_fnd_id), None)
        if selected_fnd:
            st.markdown(
                f"""
                <div style="background: #121D30; border-left: 3px solid #35D6E8; padding: 10px 14px; border-radius: 4px; font-size: 0.85rem;">
                    <strong>Assessment:</strong> {selected_fnd.get('explanation')}<br>
                    <strong>Original Evidence Citation:</strong> <code>{selected_fnd.get('raw_ref')}</code>
                </div>
                """,
                unsafe_allow_html=True
            )

with col_ev:
    st.markdown("##### 📦 Ingested Evidence Sources")
    if logs:
        log_rows = []
        for l in logs:
            log_rows.append({
                "Evidence Files": l.get("filename", "")[:35],
                "Records": l.get("total_records", 0),
                "Normalized": l.get("normalized_records", 0),
                "Status": l.get("status", "Completed"),
                "Ingested At": l.get("ingested_at", "")[:19]
            })
        st.dataframe(log_rows, use_container_width=True, hide_index=True)
    else:
        st.markdown(
            f"""
            <div style="background: #121D30; border: 1px solid rgba(148,167,194,0.15); border-radius: 6px; padding: 14px;">
                <div style="font-size: 0.82rem; color: #EDF4FF; font-weight: 600;">Active Evidence Set:</div>
                <div style="font-size: 0.78rem; color: #94A7C2; margin-top: 4px;">
                    • <code>sysmon_victim_pc01.evtx</code> (Sysmon v13.0)<br>
                    • <code>security_victim_pc01.evtx</code> (Windows Security Auditing)<br>
                    • <code>security_dc_srv01.evtx</code> (Domain Controller Auditing)
                </div>
                <div style="margin-top: 10px;">
                    <span class="badge badge-demo">Synthetic Ground Truth Dataset</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
