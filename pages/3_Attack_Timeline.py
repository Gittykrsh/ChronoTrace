"""Attack Timeline Page — ChronoTrace.

Forensic chronological reconstruction:
- Horizontal interactive Plotly Gantt timeline showing uncertainty intervals [ts_start, ts_end]
- Visual markers for ORDER_CONFLICT, MISSING_PARENT, LOG_CLEARED, SINGLE_SOURCE
- Interactive Master Event Sequence Table with single-click row selection
- Comprehensive forensic details drawer with 4-factor confidence breakdown and instant drill-down to Evidence Explorer
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
    get_plotly_layout,
    render_raw_ref_pill,
    render_flag_badge,
    render_confidence_badge,
    ACCENT_CYAN,
    ACCENT_VIOLET,
    SUCCESS_GREEN,
    WARNING_AMBER,
    ORANGE_WARN,
    CRITICAL_RED,
    TEXT_PRIMARY,
    TEXT_MUTED
)
from ui.layout import render_sidebar, render_topbar
from database.db import init_db, get_investigation, get_events

# 1. Page Configuration & Theme
st.set_page_config(
    page_title="Attack Timeline — ChronoTrace",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)
inject_theme()
init_db()

# 2. Render Sidebar
selected_inv_id = render_sidebar(current_page_id="timeline")
inv = get_investigation(selected_inv_id) or {"id": selected_inv_id, "name": "Active Investigation", "is_demo": 1}

# 3. Fetch Data & Metadata
events = get_events(selected_inv_id)
hosts = sorted(list({e["host"] for e in events if e.get("host")}))
sources = sorted(list({e["source"] for e in events if e.get("source")}))

# 4. Render Topbar
filters = render_topbar("Attack Timeline", inv, hosts=hosts, sources=sources)

st.markdown(
    """
    <div style="margin-top: -10px; margin-bottom: 14px;">
        <span style="font-size: 0.88rem; color: #94A7C2; font-style: italic;">
            "Examine event sequences, uncertain ordering, and the verified evidence behind every finding."
        </span>
    </div>
    """,
    unsafe_allow_html=True
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

# 5. Interactive Plotly Gantt / Range Timeline
st.markdown(
    """
    <div style="font-size: 0.88rem; font-weight: 700; color: #EDF4FF; margin-bottom: 6px; display: flex; align-items: center; justify-content: space-between;">
        <div style="display: flex; align-items: center; gap: 6px;">
            <span>⏱️</span> Interactive Reconstructed Timeline (Uncertainty Intervals)
        </div>
        <span style="font-size: 0.70rem; color: #35D6E8; font-family: monospace;">Horizontal Bars = [ts_start, ts_end] Range</span>
    </div>
    """,
    unsafe_allow_html=True
)

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
        1: "#35D6E8",
        3: "#8B7CFF",
        11: "#37D99A",
        4624: "#4A90E2",
        4688: "#F5B942",
        1102: "#FF647C"
    }

    fig = go.Figure()
    for idx, row in df.iterrows():
        c_code = row.get("event_code", 1)
        bar_color = code_colors.get(c_code, "#94A7C2")
        flags = row.get("flags_list", [])

        # Border styling for conflicts
        if "LOG_CLEARED" in flags:
            line_color = CRITICAL_RED
            line_width = 2.5
        elif "ORDER_CONFLICT" in flags:
            line_color = WARNING_AMBER
            line_width = 2.5
        elif "MISSING_PARENT" in flags:
            line_color = ORANGE_WARN
            line_width = 2
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

    calc_height = max(280, min(650, len(df) * 32 + 50))
    layout_timeline = get_plotly_layout(height=calc_height)
    layout_timeline["margin"] = dict(l=260, r=25, t=15, b=35)
    layout_timeline["xaxis"] = dict(
        type="date",
        gridcolor="rgba(148, 167, 194, 0.12)",
        showgrid=True,
        title=dict(text="Time Window (UTC)", font=dict(size=10, color=TEXT_MUTED)),
        tickfont=dict(family="JetBrains Mono, monospace", size=10, color=TEXT_MUTED)
    )
    layout_timeline["yaxis"] = dict(
        autorange="reversed",
        gridcolor="rgba(148, 167, 194, 0.12)",
        tickfont=dict(family="JetBrains Mono, monospace", size=10, color=TEXT_PRIMARY)
    )
    fig.update_layout(**layout_timeline)
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

# 6. Master Sequence Table with Single-Click Selection
st.markdown(
    """
    <div style="font-size: 0.88rem; font-weight: 700; color: #EDF4FF; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
        <span>📋</span> Master Normalized Event Sequence Table
    </div>
    """,
    unsafe_allow_html=True
)
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
            height=260
        )
        if tbl_out and hasattr(tbl_out, "selection") and tbl_out.selection.rows:
            sel_idx = tbl_out.selection.rows[0]
            if 0 <= sel_idx < len(filtered_events):
                active_eid = filtered_events[sel_idx]["event_id"]
                st.session_state["selected_timeline_eid"] = active_eid
    except Exception:
        st.dataframe(df_table, use_container_width=True, hide_index=True, height=260)

    selected_event = next((e for e in filtered_events if e["event_id"] == active_eid), filtered_events[0])

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # 7. Forensic Details Drawer (Triggered by Row Selection)
    if selected_event:
        st.markdown(
            f"""
            <div class="soc-elevated" style="border-left: 4px solid #35D6E8; padding: 14px 18px;">
                <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(148,167,194,0.12); padding-bottom: 8px; margin-bottom: 12px;">
                    <div>
                        <span style="font-family: 'JetBrains Mono', monospace; font-size: 1.15rem; color: #35D6E8; font-weight: 800;">
                            {selected_event['event_id']}
                        </span>
                        <span style="color: #EDF4FF; font-size: 0.95rem; margin-left: 10px; font-weight: 600;">
                            {(selected_event.get('image') or '').split(r'\\')[-1] or selected_event.get('source')}
                        </span>
                    </div>
                    <div>
                        {render_raw_ref_pill(selected_event.get('raw_ref', 'N/A'))}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        col_telemetry, col_confidence = st.columns([6, 4], gap="medium")

        with col_telemetry:
            st.markdown("##### 🔍 Execution Telemetry")
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
            for k, v in telemetry_grid.items():
                st.markdown(f"**{k}:** `{v}`")

            cmd = selected_event.get("command_line")
            if cmd:
                st.markdown("**Command Line Execution:**")
                st.code(cmd, language="powershell")

            if selected_event.get("dst_ip"):
                st.markdown(f"**Network Endpoint:** `{selected_event.get('src_ip') or 'N/A'}` &rarr; `{selected_event.get('dst_ip')}:{selected_event.get('dst_port')}`")

        with col_confidence:
            st.markdown("##### ⚖️ Confidence & Conflict Assessment")
            conf_val = selected_event.get("confidence")
            if conf_val is not None:
                st.markdown(f"**Deterministic Score:** `{float(conf_val):.2f}` / 1.00")
                st.progress(float(conf_val))

                st.markdown("**Four-Factor Confidence Breakdown:**")
                factors = {
                    "Corroboration (Multi-Source Witness)": selected_event.get("corroboration", 0.5),
                    "Source Reliability (Channel Integrity)": selected_event.get("source_reliability", 0.8),
                    "Time Precision (Window Delta)": selected_event.get("time_certainty", 0.9),
                    "Entity Link Strength (GUID Resolution)": selected_event.get("link_strength", 0.8)
                }
                for fname, fval in factors.items():
                    st.caption(f"{fname}: **{fval:.2f}**")
                    st.progress(float(fval))
            else:
                st.info("Confidence score unavailable.")

            flags = selected_event.get("flags_list", [])
            if flags:
                st.markdown("**Active Forensic Flags:**")
                flag_badges = "".join([render_flag_badge(fl) + " " for fl in flags])
                st.markdown(flag_badges, unsafe_allow_html=True)

                expl = selected_event.get("explanation")
                if expl:
                    st.caption(f"**Assessment:** {expl}")

            st.markdown("<hr style='margin: 12px 0;'/>", unsafe_allow_html=True)
            st.markdown("##### 📑 Original Evidence Citation")
            st.markdown(f"Every reconstructed event maps directly to authentic raw log records.")
            st.code(selected_event.get("raw_ref"), language="text")

            # Deep Link to Evidence Explorer
            if st.button("Inspect in Evidence Explorer →", key=f"btn_jump_explorer_{selected_event['event_id']}", use_container_width=True):
                st.session_state["active_explorer_ref"] = selected_event["raw_ref"]
                st.session_state["selected_raw_ref"] = selected_event["raw_ref"]
                st.switch_page("pages/5_Evidence_Explorer.py")
