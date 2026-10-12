"""Findings & Reports Page — ChronoTrace.

Synthesizes reconstructed attack stages, MITRE ATT&CK mapping, and exportable forensic documentation:
- Reconstructed Findings Table with confidence factors
- Rule-based MITRE ATT&CK Matrix view
- Dedicated Conflict and Missing-Evidence Inspector
- Working export controls for CSV, JSON, and Markdown incident reports
"""

import streamlit as st
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from components.page_setup import setup_forensic_page
from components.sidebar import render_sidebar
from components.topbar import render_topbar
from components.conflict_inspector import render_conflict_inspector
from database.db import get_investigation, get_events, get_findings, get_graph_data
from services.reporting import (
    generate_csv_timeline,
    generate_json_findings,
    generate_markdown_report
)
from services.mitre_tagger import MITRE_TECHNIQUE_METADATA

# 1. Page Configuration
inv_id = setup_forensic_page("Findings & Reports")
selected_inv_id = render_sidebar(current_page_id="reports")
inv = get_investigation(selected_inv_id) or {"id": selected_inv_id, "name": "Active Investigation", "is_demo": 1}

# 2. Fetch Data
events = get_events(selected_inv_id)
findings = get_findings(selected_inv_id)
graph_data = get_graph_data(selected_inv_id)

hosts = list({e["host"] for e in events if e.get("host")})
sources = list({e["source"] for e in events if e.get("source")})

# 3. Render Topbar
filters = render_topbar("Findings & Reports", inv, hosts=hosts, sources=sources)

st.markdown(
    """
    <div style="margin-top: -12px; margin-bottom: 20px;">
        <span style="font-size: 0.95rem; color: #94A7C2; font-style: italic;">
            "Review reconstructed attack stages and export evidence-linked results."
        </span>
    </div>
    """,
    unsafe_allow_html=True
)

# Conflict summary
conflict_summary = {
    "ORDER_CONFLICT": sum(1 for f in findings if "ORDER_CONFLICT" in f.get("flags_list", [])),
    "MISSING_PARENT": sum(1 for f in findings if "MISSING_PARENT" in f.get("flags_list", [])),
    "LOG_CLEARED": sum(1 for f in findings if "LOG_CLEARED" in f.get("flags_list", [])),
    "SINGLE_SOURCE": sum(1 for f in findings if "SINGLE_SOURCE" in f.get("flags_list", []))
}

# 4. Export Controls Panel (Prominent & Functional)
st.markdown("#### 📤 Export Forensic Artifacts")
exp_c1, exp_c2, exp_c3 = st.columns(3)

csv_data = generate_csv_timeline(events)
json_data = generate_json_findings(inv, events, findings, graph_data)
md_report = generate_markdown_report(inv, events, findings, conflict_summary)

with exp_c1:
    st.download_button(
        label="📥 Export CSV Timeline",
        data=csv_data,
        file_name=f"{selected_inv_id}_timeline.csv",
        mime="text/csv",
        use_container_width=True
    )
    st.caption("RFC 4180 CSV containing normalized events, interval timestamps, and raw_ref.")

with exp_c2:
    st.download_button(
        label="📥 Export JSON Findings & Graph",
        data=json_data,
        file_name=f"{selected_inv_id}_findings.json",
        mime="application/json",
        use_container_width=True
    )
    st.caption("Structured JSON with findings, confidence factors, entities, and edges.")

with exp_c3:
    st.download_button(
        label="📥 Export Markdown Incident Report",
        data=md_report,
        file_name=f"{selected_inv_id}_incident_report.md",
        mime="text/markdown",
        use_container_width=True
    )
    st.caption("Forensic Incident Report citing all raw_ref evidence and uncertainty flags.")

st.markdown("<hr style='margin: 20px 0; border-color: rgba(148,167,194,0.12);'/>", unsafe_allow_html=True)

# 5. Core Views Tabs
tab_fnd, tab_mitre, tab_conflicts, tab_report_preview = st.tabs([
    f"🎯 Reconstructed Findings ({len(findings)})",
    "🛡️ Rule-Based MITRE ATT&CK View",
    f"⚠️ Conflict Inspector ({sum(conflict_summary.values())} flags)",
    "📑 Report Preview"
])

with tab_fnd:
    st.markdown("##### Actionable Forensic Findings")
    
    # Filter findings
    stage_filter = st.selectbox(
        "Filter by Attack Stage:",
        ["All Stages"] + sorted(list({f.get("stage", "Execution") for f in findings})),
        key="fnd_stage_filter"
    )
    
    filtered_fnds = findings
    if stage_filter != "All Stages":
        filtered_fnds = [f for f in filtered_fnds if f.get("stage") == stage_filter]
    if filters["host"] != "All Hosts":
        filtered_fnds = [f for f in filtered_fnds if f.get("host") == filters["host"]]

    fnd_rows = []
    for f in filtered_fnds:
        flags_str = ", ".join(f.get("flags_list", [])) if f.get("flags_list") else "—"
        fnd_rows.append({
            "Finding ID": f["finding_id"],
            "Event ID": f["event_id"],
            "Stage": f.get("stage", "N/A"),
            "Host": f.get("host", "N/A"),
            "Confidence": f"{f.get('confidence', 0.0):.2f}",
            "Corroboration": f"{f.get('corroboration', 0.0):.2f}",
            "Time Precision": f"{f.get('time_certainty', 0.0):.2f}",
            "Link Strength": f"{f.get('link_strength', 0.0):.2f}",
            "Flags": flags_str,
            "Raw Evidence Reference": f.get("raw_ref", "MISSING")
        })
    # Interactive findings table selection
    fnd_tbl_state = st.session_state.get("fnd_dataframe_selection", {})
    sel_f_idx = 0
    if isinstance(fnd_tbl_state, dict):
        frows = fnd_tbl_state.get("selection", {}).get("rows", [])
        if frows and 0 <= frows[0] < len(filtered_fnds):
            sel_f_idx = frows[0]

    selected_f = filtered_fnds[sel_f_idx] if filtered_fnds else None

    st.caption("Click any finding row below to inspect its detailed assessment and evidence citation:")
    try:
        fnd_table_sel = st.dataframe(
            fnd_rows,
            use_container_width=True,
            hide_index=True,
            selection_mode="single-row",
            on_select="rerun",
            key="fnd_dataframe_selection"
        )
        if fnd_table_sel and hasattr(fnd_table_sel, "selection") and fnd_table_sel.selection.rows:
            clicked_f_idx = fnd_table_sel.selection.rows[0]
            if 0 <= clicked_f_idx < len(filtered_fnds):
                selected_f = filtered_fnds[clicked_f_idx]
    except Exception:
        st.dataframe(fnd_rows, use_container_width=True, hide_index=True)

    # Detailed inspection card
    if selected_f:
        st.markdown(
            f"""
            <div style="background: #17243A; border-left: 4px solid #35D6E8; border-radius: 6px; padding: 14px; margin-top: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <strong style="color: #35D6E8; font-size: 1.05rem;">Finding {selected_f['finding_id']}</strong> 
                        <span style="color: #94A7C2; margin-left: 8px;">({selected_f['stage']})</span>
                    </div>
                    <span class="raw-ref-pill">📄 {selected_f.get('raw_ref')}</span>
                </div>
                <p style="color: #EDF4FF; margin: 8px 0; font-size: 0.9rem;">{selected_f.get('explanation')}</p>
                <div style="font-size: 0.8rem; color: #94A7C2;">
                    Host: <strong style="color: #EDF4FF;">{selected_f.get('host')}</strong> | 
                    Event ID: <strong style="color: #35D6E8;">{selected_f.get('event_id')}</strong> | 
                    Confidence: <strong style="color: #37D99A;">{selected_f.get('confidence', 0):.2f}</strong>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

with tab_mitre:
    st.markdown("##### Rule-Based MITRE ATT&CK Techniques")
    st.caption("*Mapped strictly via rule-based heuristics on verified log fields (no unverified ML guessing).*")
    
    # Techniques in active case
    tech_counts = {}
    for ev in events:
        tech = ev.get("mitre_technique")
        if tech:
            tech_counts[tech] = tech_counts.get(tech, 0) + 1

    m_cols = st.columns(3)
    for idx, (t_id, meta) in enumerate(MITRE_TECHNIQUE_METADATA.items()):
        count = tech_counts.get(t_id, 0)
        col = m_cols[idx % 3]
        card_border = "#35D6E8" if count > 0 else "rgba(148,167,194,0.2)"
        with col:
            st.markdown(
                f"""
                <div style="background: #121D30; border: 1px solid {card_border}; border-radius: 8px; padding: 12px; margin-bottom: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-family: monospace; font-size: 0.85rem; color: #35D6E8; font-weight: 700;">{t_id}</span>
                        <span class="badge {'badge-high-conf' if count > 0 else 'badge-single-source'}">{count} Events</span>
                    </div>
                    <div style="font-size: 0.9rem; font-weight: 600; color: #EDF4FF; margin: 4px 0;">{meta['name']}</div>
                    <div style="font-size: 0.72rem; color: #8B7CFF; font-family: monospace;">Tactic: {meta['tactic']}</div>
                    <div style="font-size: 0.76rem; color: #94A7C2; margin-top: 6px;">{meta['description']}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

with tab_conflicts:
    render_conflict_inspector(findings, events)

with tab_report_preview:
    st.markdown("##### Forensic Incident Report Preview")
    st.markdown(md_report)
