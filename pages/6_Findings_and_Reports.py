"""Findings & Reports Page — ChronoTrace.

Synthesizes reconstructed attack stages, MITRE ATT&CK mapping, uncertainty conflict analysis, and exportable documentation:
- One-click export action toolbar (CSV Timeline, JSON Findings, Markdown Incident Report)
- Actionable Findings table with single-click selection and stacked forensic assessment card
- Responsive rule-based MITRE ATT&CK Matrix cards
- Dedicated Conflict and Missing-Evidence Inspector (all 4 flags)
- Cleanly styled Report Preview tab
"""

import streamlit as st
import os
import sys
import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ui.theme import (
    inject_theme,
    calc_df_height,
    render_raw_ref_pill,
    render_flag_badge,
    render_confidence_badge,
    icon_svg,
    ACCENT_BLUE,
    EYEBROW_BLUE,
    STATUS_SUCCESS_TEXT,
    STATUS_WARN_TEXT,
    STATUS_CRIT_TEXT,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    TEXT_MUTED
)
from ui.layout import render_sidebar, render_topbar
from ui.components import render_page_header, render_card_header, render_stacked_result_card
from database.db import (
    init_db,
    get_investigation,
    get_events,
    get_findings,
    get_graph_data
)
from services.reporting import (
    generate_csv_timeline,
    generate_json_findings,
    generate_markdown_report
)
from services.mitre_tagger import MITRE_TECHNIQUE_METADATA

# 1. Page Configuration & Theme
st.set_page_config(
    page_title="Findings & Reports — ChronoTrace",
    page_icon=":material/description:",
    layout="wide",
    initial_sidebar_state="expanded"
)
inject_theme()
init_db()

# 2. Render Persistent Flat Sidebar
selected_inv_id = render_sidebar(current_page_id="reports")
inv = get_investigation(selected_inv_id) or {"id": selected_inv_id, "name": "Active Investigation", "is_demo": 1}

# 3. Fetch Data
events = get_events(selected_inv_id)
findings = get_findings(selected_inv_id)
graph_data = get_graph_data(selected_inv_id)

hosts = sorted(list({e["host"] for e in events if e.get("host")}))
sources = sorted(list({e["source"] for e in events if e.get("source")}))

# 4. Render Topbar
filters = render_topbar("Reports", inv, hosts=hosts, sources=sources)

# 5. Standardized Page Header Block
render_page_header(
    eyebrow="FORENSIC WORKSPACE / REPORTS",
    title="Findings & Reports",
    subtitle="Review reconstructed attack stages, investigate conflicts, and export evidence-linked results."
)

conflict_summary = {
    "ORDER_CONFLICT": sum(1 for f in findings if "ORDER_CONFLICT" in f.get("flags_list", [])),
    "MISSING_PARENT": sum(1 for f in findings if "MISSING_PARENT" in f.get("flags_list", [])),
    "LOG_CLEARED": sum(1 for f in findings if "LOG_CLEARED" in f.get("flags_list", [])),
    "SINGLE_SOURCE": sum(1 for f in findings if "SINGLE_SOURCE" in f.get("flags_list", []))
}

# 6. Flush Export Toolbar
render_card_header("Export Forensic Artifacts", pill_text="RFC 4180 / JSON / MD", pill_class="pill-primary", icon_name="download")
exp_c1, exp_c2, exp_c3 = st.columns(3, gap="small")

csv_data = generate_csv_timeline(events)
json_data = generate_json_findings(inv, events, findings, graph_data)
md_report = generate_markdown_report(inv, events, findings, conflict_summary)

with exp_c1:
    st.download_button(
        label="Export CSV Timeline",
        data=csv_data,
        file_name=f"{selected_inv_id}_timeline.csv",
        mime="text/csv",
        use_container_width=True
    )
    st.caption("RFC 4180 CSV containing normalized events, intervals, and raw_ref.")

with exp_c2:
    st.download_button(
        label="Export JSON Findings & Graph",
        data=json_data,
        file_name=f"{selected_inv_id}_findings.json",
        mime="application/json",
        use_container_width=True
    )
    st.caption("Structured JSON with findings, confidence factors, entities, and edges.")

with exp_c3:
    st.download_button(
        label="Export Markdown Incident Report",
        data=md_report,
        file_name=f"{selected_inv_id}_incident_report.md",
        mime="text/markdown",
        use_container_width=True
    )
    st.caption("Publication-ready Incident Report citing raw_ref evidence and flags.")

st.markdown("<hr style='margin: 12px 0 16px 0; border-color: rgba(255, 255, 255, 0.06);'/>", unsafe_allow_html=True)

# 7. Four Clean Segmented Analysis Tabs
tab_fnd, tab_mitre, tab_conflicts, tab_preview = st.tabs([
    f"Actionable Findings ({len(findings)})",
    "MITRE ATT&CK Matrix",
    f"Conflict Inspector ({sum(conflict_summary.values())} flags)",
    "Report Preview"
])

with tab_fnd:
    # Filter findings
    stage_options = ["All Stages"] + sorted(list({f.get("stage", "Execution") for f in findings}))
    selected_stage = st.selectbox(
        "Filter by Attack Stage:",
        options=stage_options,
        key="fnd_stage_filter_in_tab"
    )

    filtered_fnds = findings
    if selected_stage != "All Stages":
        filtered_fnds = [f for f in filtered_fnds if f.get("stage") == selected_stage]
    if filters["host"] != "All Hosts":
        filtered_fnds = [f for f in filtered_fnds if f.get("host") == filters["host"]]
    if filters["min_confidence"] > 0.0:
        filtered_fnds = [f for f in filtered_fnds if (f.get("confidence") or 0.0) >= filters["min_confidence"]]

    if not filtered_fnds:
        st.info("No findings match current stage or host filter.")
    else:
        fnd_table_data = []
        for f in filtered_fnds:
            flags = f.get("flags_list", [])
            fnd_table_data.append({
                "Finding ID": f["finding_id"],
                "Event ID": f["event_id"],
                "Stage": f.get("stage", "N/A"),
                "Host": f.get("host", "N/A"),
                "Confidence": f"{f.get('confidence', 0.0):.2f}",
                "Corroboration": f"{f.get('corroboration', 0.0):.2f}",
                "Time Precision": f"{f.get('time_certainty', 0.0):.2f}",
                "Link Strength": f"{f.get('link_strength', 0.0):.2f}",
                "Flags": ", ".join(flags) if flags else "—",
                "Raw Evidence Reference": f.get("raw_ref", "MISSING")
            })

        df_fnds = pd.DataFrame(fnd_table_data)

        # Single-click selection sync
        fnd_sel_state = st.session_state.get("fnd_dataframe_selection", {})
        active_f_idx = 0
        if isinstance(fnd_sel_state, dict):
            s_rows = fnd_sel_state.get("selection", {}).get("rows", [])
            if s_rows and 0 <= s_rows[0] < len(filtered_fnds):
                active_f_idx = s_rows[0]

        st.caption("Click any finding below to inspect its detailed assessment and evidence citation:")
        try:
            fnd_out = st.dataframe(
                df_fnds,
                use_container_width=True,
                hide_index=True,
                selection_mode="single-row",
                on_select="rerun",
                key="fnd_dataframe_selection",
                height=calc_df_height(df_fnds, min_h=150, max_h=280)
            )
            if fnd_out and hasattr(fnd_out, "selection") and fnd_out.selection.rows:
                c_idx = fnd_out.selection.rows[0]
                if 0 <= c_idx < len(filtered_fnds):
                    active_f_idx = c_idx
        except Exception:
            st.dataframe(df_fnds, use_container_width=True, hide_index=True, height=calc_df_height(df_fnds, min_h=150, max_h=280))

        selected_f = filtered_fnds[active_f_idx] if filtered_fnds else None
        if selected_f:
            st.markdown(
                f"""
                <div class="console-elevated" style="padding: 12px 16px; margin-top: 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <div>
                            <strong style="color: #38BDF8; font-size: 14px;">Finding {selected_f['finding_id']}</strong>
                            <span style="color: #94A3B8; margin-left: 8px; font-weight: 600;">({selected_f.get('stage', 'Execution')})</span>
                        </div>
                        {render_raw_ref_pill(selected_f.get('raw_ref', 'N/A'))}
                    </div>
                    <p style="color: #F8FAFC; margin: 4px 0 6px 0; font-size: 13px;">{selected_f.get('explanation')}</p>
                    <div style="font-size: 11px; color: #64748B; font-family: 'Inter', sans-serif;">
                        Host: <strong style="color: #F8FAFC;">{selected_f.get('host')}</strong> •
                        Event ID: <span style="color: #38BDF8; font-family: 'JetBrains Mono', monospace;">{selected_f.get('event_id')}</span> •
                        Confidence Score: <strong style="color: #34D399;">{selected_f.get('confidence', 0):.2f}</strong>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

with tab_mitre:
    st.markdown("<div style='font-size: 13px; font-weight: 600; color: #F8FAFC; margin-bottom: 2px;'>Rule-Based MITRE ATT&CK Matrix Techniques</div>", unsafe_allow_html=True)
    st.caption("Mapped deterministically via rule-based heuristics on verified log fields (no unverified ML guessing).")

    tech_counts = {}
    for ev in events:
        tech = ev.get("mitre_technique")
        if tech:
            tech_counts[tech] = tech_counts.get(tech, 0) + 1

    m_cols = st.columns(3)
    for idx, (t_id, meta) in enumerate(MITRE_TECHNIQUE_METADATA.items()):
        count = tech_counts.get(t_id, 0)
        col = m_cols[idx % 3]
        card_border = "rgba(56, 189, 248, 0.35)" if count > 0 else "rgba(255, 255, 255, 0.07)"
        with col:
            st.markdown(
                f"""
                <div class="console-card" style="border-color: {card_border}; padding: 12px 14px; margin-bottom: 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #38BDF8; font-weight: 600;">{t_id}</span>
                        <span class="status-pill {'pill-success' if count > 0 else 'pill-info'}">{count} Events</span>
                    </div>
                    <div style="font-size: 13px; font-weight: 600; color: #F8FAFC; margin: 4px 0;">{meta['name']}</div>
                    <div style="font-size: 11px; color: #818CF8; font-family: 'Inter', sans-serif;">Tactic: {meta['tactic']}</div>
                    <div style="font-size: 12px; color: #94A3B8; margin-top: 5px; line-height: 1.4;">{meta['description']}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

with tab_conflicts:
    st.markdown("<div style='font-size: 13px; font-weight: 600; color: #F8FAFC; margin-bottom: 2px;'>Conflict & Uncertainty Inspector</div>", unsafe_allow_html=True)
    st.caption("Surfaces timestamp ambiguities, orphaned parent processes, audit clearing, and single-source witness events.")

    flag_filter = st.radio(
        "Filter by Uncertainty Category:",
        ["All Flags", "ORDER_CONFLICT", "MISSING_PARENT", "LOG_CLEARED", "SINGLE_SOURCE"],
        horizontal=True,
        key="findings_conflict_filter_radio"
    )

    conflict_findings = [f for f in findings if f.get("flags_list")]
    if flag_filter != "All Flags":
        conflict_findings = [f for f in conflict_findings if flag_filter in f.get("flags_list", [])]

    if not conflict_findings:
        st.success(f"No findings matching flag filter '{flag_filter}'.")
    else:
        st.markdown(f"**Identified {len(conflict_findings)} flagged findings:**")
        events_map = {e["event_id"]: e for e in events}

        for f in conflict_findings:
            eid = f.get("event_id")
            ev = events_map.get(eid, {})
            flags = f.get("flags_list", [])
            raw_ref = ev.get("raw_ref", "N/A")

            box_border = "#FB7185" if "LOG_CLEARED" in flags else (
                "#FBBF24" if "ORDER_CONFLICT" in flags else (
                    "#F59E0B" if "MISSING_PARENT" in flags else "#818CF8"
                )
            )

            st.markdown(
                f"""
                <div class="console-card" style="border-left: 3px solid {box_border}; padding: 12px 16px; margin-bottom: 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <strong style="color: #F8FAFC; font-size: 13px;">Finding {f['finding_id']}</strong>
                            <span style="color: #94A3B8; font-size: 11px; margin-left: 8px;">(Event: {eid})</span>
                        </div>
                        {render_raw_ref_pill(raw_ref)}
                    </div>
                    <div style="margin: 6px 0;">
                        {' '.join([render_flag_badge(fl) for fl in flags])}
                    </div>
                    <div style="font-size: 12px; color: #CBD5E1; margin-top: 4px;">
                        <strong>Forensic Explanation:</strong> {f.get('explanation')}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            with st.expander(f"Inspect Telemetry & Evidence Linkage for {eid}", expanded=False):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("**Evidence Attributes:**")
                    st.markdown(f"- **Host:** `{ev.get('host')}`")
                    st.markdown(f"- **Provider:** `{ev.get('source')}` (Event `{ev.get('event_code')}`)")
                    st.markdown(f"- **Interval Window:** `{ev.get('ts_start_utc')}` &rarr; `{ev.get('ts_end_utc')}`")
                    st.markdown(f"- **Image:** `{ev.get('image')}`")
                    st.markdown(f"- **CommandLine:** `{ev.get('command_line')}`")
                    st.markdown(f"- **ProcessGuid:** `{ev.get('process_guid') or 'None'}`")
                    st.markdown(f"- **ParentGuid:** `{ev.get('parent_guid') or 'None'}`")
                with c2:
                    st.markdown("**Uncertainty Impact on Confidence:**")
                    st.markdown(f"- **Overall Score:** `{f.get('confidence', 0):.2f}` / 1.00")
                    st.markdown(f"- **Corroboration Factor:** `{f.get('corroboration', 0):.2f}`")
                    st.markdown(f"- **Time Precision Factor:** `{f.get('time_certainty', 0):.2f}`")
                    st.markdown(f"- **Entity Link Strength:** `{f.get('link_strength', 0):.2f}`")

                    if "ORDER_CONFLICT" in flags:
                        st.warning("ORDER_CONFLICT: Overlapping intervals establish that relative ordering is ambiguous. ChronoTrace preserves uncertainty rather than forcing an artificial order.")
                    if "MISSING_PARENT" in flags:
                        st.warning("MISSING_PARENT: Child process points to an unlogged parent. Indicates potential anti-forensics or unmonitored execution.")
                    if "LOG_CLEARED" in flags:
                        st.error("LOG_CLEARED: Windows Security Event 1102 recorded. Log stream was cleared; earlier telemetry integrity is compromised.")
                    if "SINGLE_SOURCE" in flags:
                        st.info("SINGLE_SOURCE: Witnessed by a single telemetry channel without cross-validation.")

with tab_preview:
    st.markdown("<div style='font-size: 13px; font-weight: 600; color: #F8FAFC; margin-bottom: 6px;'>Forensic Incident Report Preview</div>", unsafe_allow_html=True)
    st.markdown(
        """
        <div class="console-card" style="padding: 16px 20px;">
        """,
        unsafe_allow_html=True
    )
    st.markdown(md_report)
    st.markdown("</div>", unsafe_allow_html=True)
