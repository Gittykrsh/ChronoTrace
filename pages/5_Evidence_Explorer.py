"""Evidence Explorer Page — ChronoTrace.

Evidence-first forensic workspace allowing investigators to inspect the original records behind every reconstructed event:
- Dual-pane layout (Left: Searchable raw records table; Right: Structured monospace inspector)
- Formatted raw JSON in recessed #070B14 terminal box, normalized schema key-value grid, and provenance linkage
- Deep-linking support from Attack Timeline with persistent tab switching
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
    render_raw_ref_pill,
    render_flag_badge,
    render_confidence_badge,
    icon_svg,
    ACCENT_BLUE,
    EYEBROW_BLUE,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    TEXT_MUTED
)
from ui.layout import render_sidebar, render_topbar
from ui.components import render_page_header, render_card_header, render_key_value_grid, render_recessed_terminal
from database.db import init_db, get_investigation, get_raw_events, get_events

# 1. Page Configuration & Theme
st.set_page_config(
    page_title="Evidence Explorer — ChronoTrace",
    page_icon=":material/manage_search:",
    layout="wide",
    initial_sidebar_state="expanded"
)
inject_theme()
init_db()

# 2. Render Persistent Flat Sidebar
selected_inv_id = render_sidebar(current_page_id="explorer")
inv = get_investigation(selected_inv_id) or {"id": selected_inv_id, "name": "Active Investigation", "is_demo": 1}

# 3. Fetch Raw and Normalized Telemetry
raw_records = get_raw_events(selected_inv_id, limit=500)
events = get_events(selected_inv_id)

hosts = sorted(list({e["host"] for e in events if e.get("host")}))
sources = sorted(list({r["source"] for r in raw_records if r.get("source")}))

# 4. Render Topbar
filters = render_topbar("Explorer", inv, hosts=hosts, sources=sources)

# 5. Standardized Page Header Block
render_page_header(
    eyebrow="FORENSIC WORKSPACE / EXPLORER",
    title="Evidence Explorer",
    subtitle="Inspect the immutable original records behind the reconstructed timeline."
)

if not raw_records:
    st.info("No raw evidence records found for this investigation case.")
    st.stop()

# Map normalized event by raw_ref for fast O(1) correlation
norm_by_ref = {ev.get("raw_ref"): ev for ev in events}

# 6. Dual-Pane Forensic Workspace
col_left, col_right = st.columns([1.05, 1.35], gap="medium")

# Left Pane: Records Table
with col_left:
    render_card_header("Raw Evidence Records", pill_text=f"{len(raw_records)} CAPTURED", pill_class="pill-info", icon_name="file")

    # Search filter
    search_term = st.text_input(
        "Search records",
        value=filters["search"] if filters["search"] else "",
        placeholder="Filter by raw_ref, file, provider, or code...",
        key="ev_records_search_input",
        label_visibility="collapsed"
    ).strip().lower()

    filtered_records = raw_records
    if search_term:
        filtered_records = [
            r for r in filtered_records
            if search_term in r.get("raw_ref", "").lower()
            or search_term in r.get("source_file", "").lower()
            or search_term in r.get("source", "").lower()
            or search_term in str(r.get("event_code", ""))
        ]

    if not filtered_records:
        st.warning("No records match the current filter criteria.")
        st.stop()

    raw_ref_options = [r["raw_ref"] for r in filtered_records]

    # Handle deep-link from Attack Timeline or state
    preselected = st.session_state.get("selected_raw_ref") or st.session_state.get("active_explorer_ref")
    if preselected and preselected in raw_ref_options:
        st.session_state["active_explorer_ref"] = preselected
        st.session_state.pop("selected_raw_ref", None)

    # Sync selection from table clicks
    tbl_state = st.session_state.get("evidence_table_selection", {})
    if isinstance(tbl_state, dict):
        srows = tbl_state.get("selection", {}).get("rows", [])
        if srows and 0 <= srows[0] < len(filtered_records):
            st.session_state["active_explorer_ref"] = filtered_records[srows[0]]["raw_ref"]

    if "active_explorer_ref" not in st.session_state or st.session_state["active_explorer_ref"] not in raw_ref_options:
        st.session_state["active_explorer_ref"] = raw_ref_options[0]

    selected_raw_ref = st.session_state["active_explorer_ref"]

    # Table rows
    table_rows = []
    for r in filtered_records:
        ref = r.get("raw_ref", "")
        norm_ev = norm_by_ref.get(ref)
        norm_id = norm_ev.get("event_id", "—") if norm_ev else "Raw Only"
        table_rows.append({
            "Raw Reference": ref,
            "File": r.get("source_file", ""),
            "Rec #": r.get("record_number", 0),
            "Provider": r.get("source", ""),
            "Code": r.get("event_code", 0),
            "Event ID": norm_id
        })

    df_records = pd.DataFrame(table_rows)

    st.caption("Click any record below to inspect original JSON and normalized schema:")
    try:
        table_out = st.dataframe(
            df_records,
            use_container_width=True,
            hide_index=True,
            selection_mode="single-row",
            on_select="rerun",
            key="evidence_table_selection",
            height=calc_df_height(df_records, min_h=180, max_h=440)
        )
        if table_out and hasattr(table_out, "selection") and table_out.selection.rows:
            c_idx = table_out.selection.rows[0]
            if 0 <= c_idx < len(filtered_records):
                selected_raw_ref = filtered_records[c_idx]["raw_ref"]
                st.session_state["active_explorer_ref"] = selected_raw_ref
    except Exception:
        st.dataframe(df_records, use_container_width=True, hide_index=True, height=calc_df_height(df_records, min_h=180, max_h=440))

# Right Pane: Structured Forensic Record Inspector
with col_right:
    render_card_header("Structured Forensic Record Inspector", pill_text="IMMUTABLE EVIDENCE", pill_class="pill-primary", icon_name="search")

    active_rec = next((r for r in raw_records if r["raw_ref"] == selected_raw_ref), None)
    if not active_rec:
        st.info("Select a record from the left panel to inspect.")
    else:
        norm_ev = norm_by_ref.get(selected_raw_ref)

        # Header card with active raw_ref citation pill
        st.markdown(
            f"""
            <div class="console-card" style="padding: 12px 16px; margin-bottom: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-family: 'JetBrains Mono', monospace; font-size: 13px; color: #38BDF8; font-weight: 600;">
                        {active_rec['raw_ref']}
                    </span>
                    <span class="status-pill pill-success">AUTHENTIC RECORD</span>
                </div>
                <div style="font-size: 11px; color: #94A3B8; margin-top: 4px; font-family: 'JetBrains Mono', monospace;">
                    File: <strong style="color: #F8FAFC;">{active_rec.get('source_file')}</strong> • Rec #{active_rec.get('record_number')} • Provider: {active_rec.get('source')} (Event {active_rec.get('event_code')})
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # 3 Clean Segmented Inspector Tabs
        tab_raw_json, tab_norm_schema, tab_linkage = st.tabs([
            "Raw JSON",
            "Normalized Schema",
            "Provenance Link"
        ])

        with tab_raw_json:
            raw_content = active_rec.get("raw_json", {})
            if isinstance(raw_content, str):
                try:
                    raw_content = json.loads(raw_content)
                except Exception:
                    pass
            formatted_json = json.dumps(raw_content, indent=2)
            render_recessed_terminal(
                formatted_json,
                header_label=f"RAW EVENT TELEMETRY ({active_rec['raw_ref']})",
                status_pill="VERIFIED RECORD"
            )

        with tab_norm_schema:
            if norm_ev:
                st.caption("Normalized Section 6 Schema attributes derived from this record:")
                attr_dict = {
                    k: str(v) if v is not None else "—"
                    for k, v in norm_ev.items()
                    if k not in ("investigation_id", "flags_list")
                }
                render_key_value_grid(attr_dict, columns=2)
            else:
                st.warning("This record was not normalized into an active attack event (unsupported event ID or baseline noise).")

        with tab_linkage:
            st.caption("Causality Chain Traceability:")
            st.markdown(
                f"""
                <div class="console-elevated" style="padding: 14px; font-size: 12px; line-height: 1.8;">
                    <strong>Evidence Reference:</strong> <code>{active_rec['raw_ref']}</code><br>
                    <strong>Source File:</strong> <code>{active_rec.get('source_file')}</code><br>
                    <strong>Provider Channel:</strong> <code>{active_rec.get('source')}</code><br>
                """,
                unsafe_allow_html=True
            )
            if norm_ev:
                flags = norm_ev.get("flags_list", [])
                st.markdown(
                    f"""
                    <strong>Normalized Event ID:</strong> <span style="color: #38BDF8; font-weight: 600;">{norm_ev.get('event_id')}</span><br>
                    <strong>Execution Window:</strong> <code>{norm_ev.get('ts_start_utc')} &rarr; {norm_ev.get('ts_end_utc')}</code><br>
                    <strong>Executable Image:</strong> <code>{norm_ev.get('image')}</code><br>
                    <strong>MITRE ATT&CK:</strong> <span style="color: #818CF8; font-weight: 600;">{norm_ev.get('mitre_technique') or 'None'}</span><br>
                    <strong>Confidence Assessment:</strong> {render_confidence_badge(norm_ev.get('confidence') or 0.0)}<br>
                    <strong>Uncertainty Flags:</strong> {' '.join([render_flag_badge(fl) for fl in flags]) if flags else 'None'}<br>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            else:
                st.markdown("<em>No normalized attack finding mapped to this raw log record.</em></div>", unsafe_allow_html=True)
