"""Attack Timeline Page — ChronoTrace.

Forensic chronological reconstruction:
- Horizontal interactive Plotly Gantt timeline showing uncertainty intervals [ts_start, ts_end]
- Visual markers for ORDER_CONFLICT, MISSING_PARENT, LOG_CLEARED, SINGLE_SOURCE
- Interactive Master Event Sequence Table with single-click row selection
- Comprehensive forensic details drawer with hairline-divided key-value grid and instant drill-down to Evidence Explorer
"""

import streamlit as st
import os
import sys
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ui.theme import (
    inject_theme,
    calc_df_height,
    get_plotly_layout,
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
from ui.components import render_page_header, render_card_header, render_key_value_grid, render_notice_banner
from database.db import init_db, get_investigation, get_events

# 1. Page Configuration & Theme
st.set_page_config(
    page_title="Attack Timeline — ChronoTrace",
    page_icon=":material/timeline:",
    layout="wide",
    initial_sidebar_state="expanded"
)
inject_theme()
init_db()

# 2. Render Persistent Flat Sidebar
selected_inv_id = render_sidebar(current_page_id="timeline")
inv = get_investigation(selected_inv_id) or {"id": selected_inv_id, "name": "Active Investigation", "is_demo": 1}

# 3. Fetch Data & Metadata
events = get_events(selected_inv_id)
hosts = sorted(list({e["host"] for e in events if e.get("host")}))
sources = sorted(list({e["source"] for e in events if e.get("source")}))

# 4. Render Topbar
filters = render_topbar("Timeline", inv, hosts=hosts, sources=sources)

# Operational Assurance Notice Banner (Matches Reference Desktop Console)
render_notice_banner(
    "Uncertainty interval reconstruction notice. Events with ambiguous ordering are rendered as duration windows [ts_start_utc, ts_end_utc] rather than forced linear points. Explicit markers identify ORDER_CONFLICT and LOG_CLEARED boundaries.",
    icon_name="timeline",
    highlight_prefix="Chronological Reconstruction Notice:"
)

# 5. Standardized Page Header Block
render_page_header(
    eyebrow="FORENSIC WORKSPACE / TIMELINE",
    title="Attack Timeline",
    subtitle="Examine event sequences, uncertain ordering, and the verified evidence behind every finding."
)

# Apply global filters
filtered_events = events
if filters["host"] != "All Hosts":
    filtered_events = [e for e in filtered_events if e.get("host") == filters["host"]]
if filters["source"] != "All Sources":
    filtered_events = [e for e in filtered_events if e.get("source") == filters["source"]]
if filters["min_confidence"] > 0.0:
    filtered_events = [e for e in filtered_events if (e.get("confidence") or 0.0) >= filters["min_confidence"]]
if filters["search"]:
    q = filters["search"]
    filtered_events = [
        e for e in filtered_events
        if q in (e.get("image") or "").lower()
        or q in (e.get("command_line") or "").lower()
        or q in (e.get("user") or "").lower()
        or q in (e.get("raw_ref") or "").lower()
        or q in str(e.get("pid", ""))
        or q in (e.get("event_id") or "").lower()
    ]

# 6. Interactive Plotly Gantt / Range Timeline
render_card_header("Reconstructed Sequence Timeline", pill_text="[TS_START, TS_END] RANGE", pill_class="pill-primary", icon_name="timeline")

if not filtered_events:
    st.info("No timeline events to display for current filter criteria.")
else:
    df = pd.DataFrame(filtered_events)
    df["start_dt"] = pd.to_datetime(df["ts_start_utc"], errors="coerce")
    df["end_dt"] = pd.to_datetime(df["ts_end_utc"], errors="coerce")

    # Ensure minimum visible interval for instantaneous point events
    df["display_end_dt"] = df.apply(
        lambda row: row["end_dt"] if (row["end_dt"] - row["start_dt"]).total_seconds() >= 2.0
        else row["start_dt"] + pd.Timedelta(seconds=2.0),
        axis=1
    )

    df["label"] = df.apply(
        lambda r: f"[{r['event_id']}] {(r['image'] or '').split(r'\\')[-1] or r['source']} ({r.get('mitre_technique') or 'Evt ' + str(r['event_code'])})",
        axis=1
    )

    code_colors = {
        1: "#38BDF8",
        3: "#818CF8",
        11: "#34D399",
        4624: "#60A5FA",
        4688: "#FBBF24",
        1102: "#FB7185"
    }

    fig = go.Figure()
    for idx, row in df.iterrows():
        c_code = row.get("event_code", 1)
        bar_color = code_colors.get(c_code, "#94A3B8")
        flags = row.get("flags_list", [])

        # Border styling for conflicts
        if "LOG_CLEARED" in flags:
            line_color = "#FB7185"
            line_width = 2
        elif "ORDER_CONFLICT" in flags:
            line_color = "#FBBF24"
            line_width = 2
        elif "MISSING_PARENT" in flags:
            line_color = "#F59E0B"
            line_width = 1.5
        else:
            line_color = bar_color
            line_width = 1

        hover_text = (
            f"<b>{row['event_id']}</b> ({row['source']} Evt {row['event_code']})<br>"
            f"Host: {row['host']} | User: {row.get('user', 'N/A')}<br>"
            f"Interval: {row['ts_start_utc']} &rarr; {row['ts_end_utc']}<br>"
            f"Process: {row.get('image', 'N/A')}<br>"
            f"MITRE: {row.get('mitre_technique') or 'None'}<br>"
            f"Confidence: {row.get('confidence', 'N/A')}<br>"
            f"Flags: {', '.join(flags) if flags else 'None'}<br>"
            f"<b>raw_ref: {row['raw_ref']}</b>"
        )

        duration_ms = max(2000.0, (row["display_end_dt"] - row["start_dt"]).total_seconds() * 1000)

        fig.add_trace(go.Bar(
            name=row["label"],
            y=[row["label"]],
            x=[duration_ms],
            base=[row["start_dt"]],
            orientation="h",
            marker=dict(
                color=bar_color,
                line=dict(color=line_color, width=line_width)
            ),
            hoverinfo="text",
            hovertext=hover_text,
            showlegend=False
        ))

    calc_height = max(260, min(520, len(df) * 30 + 50))
    layout_timeline = get_plotly_layout(height=calc_height)
    layout_timeline["margin"] = dict(l=260, r=25, t=15, b=35)
    layout_timeline["xaxis"] = dict(
        type="date",
        gridcolor="rgba(255, 255, 255, 0.05)",
        showgrid=True,
        title=dict(text="Time Window (UTC)", font=dict(size=10, color=TEXT_MUTED)),
        tickfont=dict(family="JetBrains Mono, monospace", size=10, color=TEXT_MUTED)
    )
    layout_timeline["yaxis"] = dict(
        autorange="reversed",
        gridcolor="rgba(255, 255, 255, 0.05)",
        tickfont=dict(family="Inter, sans-serif", size=10, color=TEXT_PRIMARY)
    )
    fig.update_layout(**layout_timeline)
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

# 7. Master Sequence Table with Single-Click Selection
render_card_header("Master Normalized Event Sequence Table", pill_text=f"{len(filtered_events)} RECORDS", pill_class="pill-info", icon_name="report")
st.caption("Click any event row below to inspect its execution telemetry, 4-factor confidence assessment, and evidence citation:")

if filtered_events:
    table_rows = []
    for e in filtered_events:
        flags = e.get("flags_list", [])
        table_rows.append({
            "Event ID": e["event_id"],
            "Start Time (UTC)": e["ts_start_utc"],
            "End Time (UTC)": e["ts_end_utc"],
            "Host": e["host"],
            "Source Provider": e["source"],
            "Code": e["event_code"],
            "Process / Target": (e.get("image") or "").split("\\")[-1] or "N/A",
            "User": e.get("user") or "N/A",
            "MITRE": e.get("mitre_technique") or "—",
            "Conf.": f"{e.get('confidence', 0.0):.2f}" if e.get("confidence") is not None else "N/A",
            "Uncertainty Flags": ", ".join(flags) if flags else "—",
            "Raw Reference": e.get("raw_ref", "")
        })

    df_table = pd.DataFrame(table_rows)

    # Master selection state sync
    event_ids = [e["event_id"] for e in filtered_events]
    tbl_state = st.session_state.get("timeline_dataframe_selection", {})
    active_eid = event_ids[0]

    if isinstance(tbl_state, dict):
        srows = tbl_state.get("selection", {}).get("rows", [])
        if srows and 0 <= srows[0] < len(filtered_events):
            active_eid = filtered_events[srows[0]]["event_id"]
            st.session_state["selected_timeline_eid"] = active_eid

    if "selected_timeline_eid" in st.session_state and st.session_state["selected_timeline_eid"] in event_ids:
        active_eid = st.session_state["selected_timeline_eid"]
    else:
        st.session_state["selected_timeline_eid"] = active_eid

    try:
        tbl_out = st.dataframe(
            df_table,
            use_container_width=True,
            hide_index=True,
            selection_mode="single-row",
            on_select="rerun",
            key="timeline_dataframe_selection",
            height=calc_df_height(df_table, min_h=140, max_h=260)
        )
        if tbl_out and hasattr(tbl_out, "selection") and tbl_out.selection.rows:
            sel_idx = tbl_out.selection.rows[0]
            if 0 <= sel_idx < len(filtered_events):
                active_eid = filtered_events[sel_idx]["event_id"]
                st.session_state["selected_timeline_eid"] = active_eid
    except Exception:
        st.dataframe(df_table, use_container_width=True, hide_index=True, height=calc_df_height(df_table, min_h=140, max_h=260))

    selected_event = next((e for e in filtered_events if e["event_id"] == active_eid), filtered_events[0])

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # 8. Forensic Details Drawer (Hairline-Divided Key-Value Inspector Grid)
    if selected_event:
        st.markdown(
            f"""
            <div class="console-card" style="padding: 12px 16px; margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-family: 'JetBrains Mono', monospace; font-size: 14px; color: #38BDF8; font-weight: 600;">
                            {selected_event['event_id']}
                        </span>
                        <span style="color: #F8FAFC; font-size: 13px; font-weight: 600;">
                            {(selected_event.get('image') or '').split(r'\\')[-1] or selected_event.get('source')}
                        </span>
                    </div>
                    {render_raw_ref_pill(selected_event.get('raw_ref', 'N/A'))}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        col_telemetry, col_confidence = st.columns([6, 4], gap="medium")

        with col_telemetry:
            render_card_header("Execution Telemetry", pill_text="NORMALIZED SCHEMA", pill_class="pill-info", icon_name="terminal")
            telemetry_grid = {
                "Host Endpoint": selected_event.get("host"),
                "Source Provider": f"{selected_event.get('source')} (Event {selected_event.get('event_code')})",
                "Start Window (ts_start_utc)": selected_event.get("ts_start_utc"),
                "End Window (ts_end_utc)": selected_event.get("ts_end_utc"),
                "Process GUID": selected_event.get("process_guid") or "None (PID Reused / Legacy)",
                "Process ID (PID)": selected_event.get("pid") or "N/A",
                "Parent Process ID (PPID)": selected_event.get("ppid") or "N/A",
                "Parent GUID": selected_event.get("parent_guid") or "None (Orphaned / Missing)",
                "User Account": selected_event.get("user") or "N/A",
                "Executable Path": selected_event.get("image") or "N/A",
                "MITRE Technique": selected_event.get("mitre_technique") or "N/A"
            }
            render_key_value_grid(telemetry_grid, columns=2)

            cmd = selected_event.get("command_line")
            if cmd:
                st.markdown("<div style='font-size: 11px; font-weight: 600; color: #64748B; text-transform: uppercase; margin-top: 8px;'>Command Line:</div>", unsafe_allow_html=True)
                st.code(cmd, language="powershell")

            if selected_event.get("dst_ip"):
                st.markdown(f"<div style='font-size: 12px; color: #94A3B8; margin-top: 4px;'>Network: <code>{selected_event.get('src_ip') or 'N/A'}</code> &rarr; <code>{selected_event.get('dst_ip')}:{selected_event.get('dst_port')}</code></div>", unsafe_allow_html=True)

        with col_confidence:
            render_card_header("Confidence & Conflict Assessment", pill_text="DETERMINISTIC", pill_class="pill-primary", icon_name="shield")
            conf_val = selected_event.get("confidence")
            if conf_val is not None:
                st.markdown(f"**Score:** `{float(conf_val):.2f}` / 1.00")
                st.progress(float(conf_val))

                st.markdown("<div style='font-size: 11px; font-weight: 600; color: #64748B; text-transform: uppercase; letter-spacing: 0.06em; margin-top: 10px;'>4-Factor Deterministic Breakdown:</div>", unsafe_allow_html=True)
                factors = {
                    "Corroboration": selected_event.get("corroboration", 0.5),
                    "Source Reliability": selected_event.get("source_reliability", 0.8),
                    "Time Precision": selected_event.get("time_certainty", 0.9),
                    "Link Strength": selected_event.get("link_strength", 0.8)
                }
                f_html = []
                for fname, fval in factors.items():
                    pct = int(float(fval) * 100)
                    f_html.append(f"""
                    <div style="background: #050811; border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 5px; padding: 6px 8px;">
                        <div style="display: flex; justify-content: space-between; font-size: 10.5px; color: #94A3B8; margin-bottom: 4px;">
                            <span>{fname}</span>
                            <strong style="color: #38BDF8; font-family: 'JetBrains Mono', monospace;">{float(fval):.2f}</strong>
                        </div>
                        <div style="background: rgba(255, 255, 255, 0.08); height: 4px; border-radius: 2px; overflow: hidden;">
                            <div style="background: linear-gradient(90deg, #1D6FE8, #38BDF8); width: {pct}%; height: 100%; border-radius: 2px;"></div>
                        </div>
                    </div>
                    """)
                st.markdown(f'<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-top: 5px;">{"".join(f_html)}</div>', unsafe_allow_html=True)
            else:
                st.info("Confidence score unavailable.")

            flags = selected_event.get("flags_list", [])
            if flags:
                st.markdown("<div style='font-size: 12px; font-weight: 600; color: #CBD5E1; margin-top: 8px;'>Active Flags:</div>", unsafe_allow_html=True)
                flag_badges = "".join([render_flag_badge(fl) + " " for fl in flags])
                st.markdown(flag_badges, unsafe_allow_html=True)

                expl = selected_event.get("explanation")
                if expl:
                    st.caption(f"**Assessment:** {expl}")

            st.markdown("<hr style='margin: 12px 0; border-color: rgba(255, 255, 255, 0.06);'/>", unsafe_allow_html=True)
            render_card_header("Original Evidence Citation", pill_text="RULE 0 ENFORCED", pill_class="pill-info", icon_name="file")
            st.caption("Every reconstructed event maps directly to authentic raw log records.")
            st.code(selected_event.get("raw_ref"), language="text")

            # Deep Link to Evidence Explorer
            if st.button("Inspect in Evidence Explorer →", key=f"btn_jump_explorer_{selected_event['event_id']}", use_container_width=True):
                st.session_state["active_explorer_ref"] = selected_event["raw_ref"]
                st.session_state["selected_raw_ref"] = selected_event["raw_ref"]
                st.switch_page("pages/5_Evidence_Explorer.py")
