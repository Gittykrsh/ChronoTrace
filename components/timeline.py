"""Forensic Attack Timeline Component for ChronoTrace.

Renders:
1. Interactive time-interval visualization (Plotly Gantt/Range chart showing [ts_start, ts_end] uncertainty intervals)
2. Interactive forensic events table with search, sorting, and pagination
3. Comprehensive Event Detail Drawer with 4-factor confidence breakdown, conflict analysis, and clickable raw_ref
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone


def render_timeline_gantt(events: List[Dict[str, Any]]) -> None:
    """Renders visual interval timeline showing uncertainty windows and conflict flags."""
    if not events:
        st.info("No timeline events to display.")
        return

    df = pd.DataFrame(events)
    df["start_dt"] = pd.to_datetime(df["ts_start_utc"], errors="coerce")
    df["end_dt"] = pd.to_datetime(df["ts_end_utc"], errors="coerce")
    
    # Ensure minimum visible interval for point events
    df["display_end_dt"] = df.apply(
        lambda row: row["end_dt"] if (row["end_dt"] - row["start_dt"]).total_seconds() >= 2.0
        else row["start_dt"] + pd.Timedelta(seconds=2.0),
        axis=1
    )

    df["label"] = df.apply(
        lambda r: f"[{r['event_id']}] {r['image'].split(r'\\')[-1] or r['source']} ({r.get('mitre_technique') or 'Evt ' + str(r['event_code'])})",
        axis=1
    )

    code_colors = {
        1: "#35D6E8",   # Process Create
        3: "#8B7CFF",   # Network Conn
        11: "#37D99A",  # File Drop
        4624: "#4A90E2",# Logon
        4688: "#F5B942",# Sec Process Create
        1102: "#FF647C" # Audit Cleared
    }

    fig = go.Figure()

    for idx, row in df.iterrows():
        c_code = row.get("event_code", 1)
        bar_color = code_colors.get(c_code, "#94A7C2")
        flags = row.get("flags_list", [])

        # Border styling for conflicts
        line_color = "#FF647C" if "LOG_CLEARED" in flags else ("#F5B942" if "ORDER_CONFLICT" in flags else ("#FF9B42" if "MISSING_PARENT" in flags else bar_color))
        line_width = 2 if flags else 1

        hover_text = (
            f"<b>{row['event_id']}</b><br>"
            f"Host: {row['host']}<br>"
            f"Source: {row['source']} (Event {row['event_code']})<br>"
            f"Interval: {row['ts_start_utc']} &rarr; {row['ts_end_utc']}<br>"
            f"Image: {row['image']}<br>"
            f"MITRE: {row.get('mitre_technique') or 'None'}<br>"
            f"Confidence: {row.get('confidence', 'N/A')}<br>"
            f"Flags: {', '.join(flags) if flags else 'None'}<br>"
            f"<b>raw_ref: {row['raw_ref']}</b>"
        )

        fig.add_trace(go.Bar(
            name=row["label"],
            y=[row["label"]],
            x=[(row["display_end_dt"] - row["start_dt"]).total_seconds() * 1000],
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

    fig.update_layout(
        title="<b>Interactive Reconstructed Timeline (Uncertainty Intervals)</b>",
        template="plotly_dark",
        plot_bgcolor="#121D30",
        paper_bgcolor="#121D30",
        height=max(360, len(df) * 36),
        margin=dict(l=260, r=30, t=50, b=40),
        font=dict(family="JetBrains Mono, Inter, sans-serif", color="#EDF4FF", size=11),
        xaxis=dict(
            type="date",
            gridcolor="rgba(148, 167, 194, 0.12)",
            showgrid=True,
            title_text="Time Window (UTC)"
        ),
        yaxis=dict(
            autorange="reversed",
            gridcolor="rgba(148, 167, 194, 0.12)"
        )
    )

    st.plotly_chart(fig, use_container_width=True)


def render_event_details_drawer(selected_event: Dict[str, Any]) -> None:
    """Renders comprehensive forensic event details drawer."""
    if not selected_event:
        return

    st.markdown(
        f"""
        <div class="forensic-panel" style="border-left: 4px solid #35D6E8;">
            <div class="panel-header">
                <div>
                    <span style="font-size: 1.2rem; font-family: 'JetBrains Mono', monospace; color: #35D6E8; font-weight: 800;">
                        {selected_event['event_id']}
                    </span>
                    <span style="margin-left: 10px; color: #EDF4FF; font-size: 0.95rem;">
                        {selected_event.get('image', '').split(r'\\')[-1] or selected_event.get('source')}
                    </span>
                </div>
                <div>
                    <span class="raw-ref-pill">📄 {selected_event.get('raw_ref')}</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    col1, col2 = st.columns([6, 4])

    with col1:
        st.markdown("#### 🔍 Process & Execution Telemetry")
        meta_table = {
            "Host": selected_event.get("host"),
            "Source Provider": selected_event.get("source"),
            "Original Event Code": selected_event.get("event_code"),
            "Earliest Time (ts_start_utc)": selected_event.get("ts_start_utc"),
            "Latest Time (ts_end_utc)": selected_event.get("ts_end_utc"),
            "Process GUID": selected_event.get("process_guid") or "None (PID only / Reused)",
            "PID": selected_event.get("pid") or "N/A",
            "PPID": selected_event.get("ppid") or "N/A",
            "Parent GUID": selected_event.get("parent_guid") or "None",
            "User Account": selected_event.get("user") or "N/A",
            "Executable Image": selected_event.get("image") or "N/A",
            "MITRE Technique": selected_event.get("mitre_technique") or "N/A"
        }
        for k, v in meta_table.items():
            st.markdown(f"**{k}:** `{v}`")

        cmd = selected_event.get("command_line")
        if cmd:
            st.markdown("**Command Line:**")
            st.code(cmd, language="powershell")

        # Network endpoints if Sysmon 3
        if selected_event.get("event_code") == 3 or selected_event.get("dst_ip"):
            st.markdown("#### 🌐 Network Endpoints")
            st.markdown(f"**Source IP:** `{selected_event.get('src_ip') or 'N/A'}`")
            st.markdown(f"**Destination IP:** `{selected_event.get('dst_ip') or 'N/A'}`")
            st.markdown(f"**Destination Port:** `{selected_event.get('dst_port') or 'N/A'}`")

    with col2:
        st.markdown("#### ⚖️ Uncertainty & Confidence Assessment")
        conf_val = selected_event.get("confidence")
        if conf_val is not None:
            st.markdown(f"**Overall Score:** `{conf_val:.2f}` / 1.00")
            st.progress(float(conf_val))

            st.markdown("**Four-Factor Breakdown:**")
            factors = {
                "Corroboration (Independent Sources)": selected_event.get("corroboration", 0.5),
                "Source Reliability": selected_event.get("source_reliability", 0.8),
                "Time Certainty (Window Precision)": selected_event.get("time_certainty", 0.9),
                "Link Strength (Entity Provenance)": selected_event.get("link_strength", 0.8)
            }
            for fname, fval in factors.items():
                st.caption(f"{fname}: **{fval:.2f}**")
                st.progress(float(fval))
        else:
            st.info("Confidence score unavailable.")

        flags = selected_event.get("flags_list", [])
        if flags:
            st.markdown("#### ⚠️ Identified Forensic Flags")
            for fl in flags:
                badge_class = {
                    "ORDER_CONFLICT": "badge-order-conflict",
                    "MISSING_PARENT": "badge-missing-parent",
                    "LOG_CLEARED": "badge-log-cleared",
                    "SINGLE_SOURCE": "badge-single-source"
                }.get(fl, "badge-single-source")
                st.markdown(f"<span class='badge {badge_class}' style='font-size: 0.85rem;'>{fl}</span>", unsafe_allow_html=True)
                
            expl = selected_event.get("explanation")
            if expl:
                st.caption(f"**Assessment:** {expl}")

        st.markdown("---")
        st.markdown("#### 📑 Original Evidence Provenance")
        raw_ref = selected_event.get("raw_ref")
        st.markdown(f"Every finding maps to raw evidence. Citation:")
        st.code(raw_ref, language="text")
        if st.button("Inspect in Evidence Explorer", key=f"inspect_ev_btn_{selected_event['event_id']}", use_container_width=True):
            st.session_state["selected_raw_ref"] = raw_ref
            st.session_state["active_explorer_ref"] = raw_ref
            st.switch_page("pages/5_Evidence_Explorer.py")


def render_event_table(events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Renders interactive event table with selection and returns selected event."""
    if not events:
        st.info("No events match current filter criteria.")
        return None

    df_data = []
    for e in events:
        flags = e.get("flags_list", [])
        flags_str = ", ".join(flags) if flags else "—"
        df_data.append({
            "event_id": e["event_id"],
            "ts_start_utc": e["ts_start_utc"],
            "host": e["host"],
            "source": e["source"],
            "event_code": e["event_code"],
            "image": (e.get("image") or "").split("\\")[-1] or "N/A",
            "user": e.get("user") or "N/A",
            "mitre_technique": e.get("mitre_technique") or "—",
            "confidence": f"{e.get('confidence', 0.0):.2f}" if e.get("confidence") is not None else "N/A",
            "flags": flags_str,
            "raw_ref": e.get("raw_ref", "")
        })

    table_df = pd.DataFrame(df_data)

    event_ids = [e["event_id"] for e in events]

    # Check if a row was clicked in the dataframe
    tbl_state = st.session_state.get("timeline_dataframe_selection", {})
    if isinstance(tbl_state, dict):
        srows = tbl_state.get("selection", {}).get("rows", [])
        if srows and 0 <= srows[0] < len(events):
            st.session_state["selected_timeline_eid"] = events[srows[0]]["event_id"]

    if "selected_timeline_eid" not in st.session_state or st.session_state["selected_timeline_eid"] not in event_ids:
        st.session_state["selected_timeline_eid"] = event_ids[0]

    st.markdown("##### 📋 Normalized Event Sequence Table")
    st.caption("Click any event row below to inspect its execution telemetry, confidence score, and forensic provenance:")

    try:
        table_selection = st.dataframe(
            table_df,
            use_container_width=True,
            hide_index=True,
            selection_mode="single-row",
            on_select="rerun",
            key="timeline_dataframe_selection",
            column_config={
                "event_id": st.column_config.TextColumn("Event ID", width="small"),
                "ts_start_utc": st.column_config.TextColumn("Start Time (UTC)", width="medium"),
                "host": st.column_config.TextColumn("Host", width="small"),
                "source": st.column_config.TextColumn("Source Provider", width="medium"),
                "event_code": st.column_config.NumberColumn("Code", width="small"),
                "image": st.column_config.TextColumn("Process/Target", width="medium"),
                "user": st.column_config.TextColumn("User", width="small"),
                "mitre_technique": st.column_config.TextColumn("MITRE", width="small"),
                "confidence": st.column_config.TextColumn("Conf.", width="small"),
                "flags": st.column_config.TextColumn("Uncertainty Flags", width="medium"),
                "raw_ref": st.column_config.TextColumn("Raw Reference", width="medium")
            }
        )
        if table_selection and hasattr(table_selection, "selection") and table_selection.selection.rows:
            sel_idx = table_selection.selection.rows[0]
            if 0 <= sel_idx < len(events):
                st.session_state["selected_timeline_eid"] = events[sel_idx]["event_id"]
    except Exception:
        st.dataframe(table_df, use_container_width=True, hide_index=True)

    selected_event = next((e for e in events if e["event_id"] == st.session_state["selected_timeline_eid"]), None)
    return selected_event
