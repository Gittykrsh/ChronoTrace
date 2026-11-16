"""Investigation Overview Dashboard — ChronoTrace.

Primary operational dashboard for digital forensics investigators:
- 6 Uniform-height KPI metric cards with instant drill-down routing
- Interactive Plotly Attack Activity chart and Confidence Distribution histogram
- 8-Stage ChronoTrace Forensic Processing Pipeline Tracker
- Clickable Recent Findings table with single-row selection and forensic assessment drawer
- Ingested Evidence Sources audit trail
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
    render_confidence_badge,
    render_flag_badge,
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
from database.db import (
    init_db,
    get_investigation,
    get_investigations,
    get_events,
    get_findings,
    get_raw_events,
    get_ingestion_logs
)
from data.demo_seed import seed_demo_data

# 1. Page Configuration & Theme
st.set_page_config(
    page_title="Investigation Overview — ChronoTrace",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)
inject_theme()
init_db()

# Ensure demo case exists
invs = get_investigations()
if not invs:
    seed_demo_data()
    invs = get_investigations()

# 2. Render Sidebar
selected_inv_id = render_sidebar(current_page_id="overview")
inv = get_investigation(selected_inv_id) or {"id": selected_inv_id, "name": "Active Investigation", "is_demo": 1}

# 3. Fetch Investigation Data
events = get_events(selected_inv_id)
findings = get_findings(selected_inv_id)
raw_events = get_raw_events(selected_inv_id)
logs = get_ingestion_logs(selected_inv_id)

hosts = sorted(list({e["host"] for e in events if e.get("host")}))
sources = sorted(list({e["source"] for e in events if e.get("source")}))

# 4. Render Topbar with Synchronized Global Filters
filters = render_topbar("Investigation Overview", inv, hosts=hosts, sources=sources)

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

filtered_event_ids = {e["event_id"] for e in filtered_events}
filtered_findings = [f for f in findings if f["event_id"] in filtered_event_ids]

# Subtitle / Guiding Mission
st.markdown(
    """
    <div style="margin-top: -10px; margin-bottom: 14px;">
        <span style="font-size: 0.88rem; color: #94A7C2; font-style: italic;">
            "Reconstruct attack sequences. Trace every finding to verified evidence."
        </span>
    </div>
    """,
    unsafe_allow_html=True
)

# 5. 6 KPI Metric Cards (Uniform Height & Direct Routing)
total_events = len(filtered_events)
reconstructed_findings = len(filtered_findings)
high_conf_count = sum(1 for f in filtered_findings if (f.get("confidence") or 0.0) >= 0.80)
high_conf_pct = int((high_conf_count / reconstructed_findings * 100)) if reconstructed_findings > 0 else 0

order_conflicts = sum(1 for f in filtered_findings if "ORDER_CONFLICT" in f.get("flags_list", []))
log_cleared = sum(1 for f in filtered_findings if "LOG_CLEARED" in f.get("flags_list", []))
total_conflicts = order_conflicts + log_cleared

missing_parents = sum(1 for f in filtered_findings if "MISSING_PARENT" in f.get("flags_list", []))
unique_sources = len(set(e.get("source") for e in filtered_events if e.get("source")))

kpi1, kpi2, kpi3, kpi4, kpi5, kpi6 = st.columns(6)

with kpi1:
    st.markdown(
        f"""
        <div class="soc-kpi-card" title="Total normalized Windows event records matching filters.">
            <div class="soc-kpi-title">📊 Total Events</div>
            <div class="soc-kpi-value">{total_events}</div>
            <div class="soc-kpi-sub">Normalized records</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.page_link("pages/3_Attack_Timeline.py", label="Timeline →", use_container_width=True)

with kpi2:
    st.markdown(
        f"""
        <div class="soc-kpi-card" title="Actionable forensic findings mapped to MITRE ATT&CK steps.">
            <div class="soc-kpi-title">🎯 Findings</div>
            <div class="soc-kpi-value">{reconstructed_findings}</div>
            <div class="soc-kpi-sub">Mapped attack steps</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.page_link("pages/6_Findings_and_Reports.py", label="Findings →", use_container_width=True)

with kpi3:
    st.markdown(
        f"""
        <div class="soc-kpi-card" title="Events with confidence score >= 0.80 based on multi-source corroboration and exact ProcessGuid linkage.">
            <div class="soc-kpi-title">🛡️ High Conf.</div>
            <div class="soc-kpi-value" style="color: #37D99A;">{high_conf_count}</div>
            <div class="soc-kpi-sub">{high_conf_pct}% of findings</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.page_link("pages/3_Attack_Timeline.py", label="High Conf →", use_container_width=True)

with kpi4:
    color = WARNING_AMBER if total_conflicts > 0 else TEXT_PRIMARY
    st.markdown(
        f"""
        <div class="soc-kpi-card" title="Identified ORDER_CONFLICT (timestamp overlap) or LOG_CLEARED anti-forensic alerts.">
            <div class="soc-kpi-title">⚠️ Conflicts</div>
            <div class="soc-kpi-value" style="color: {color};">{total_conflicts}</div>
            <div class="soc-kpi-sub">{order_conflicts} order, {log_cleared} cleared</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.page_link("pages/6_Findings_and_Reports.py", label="Inspect →", use_container_width=True)

with kpi5:
    color = ORANGE_WARN if missing_parents > 0 else TEXT_PRIMARY
    st.markdown(
        f"""
        <div class="soc-kpi-card" title="Processes pointing to unmonitored or purged parent processes.">
            <div class="soc-kpi-title">🧩 Missing Parent</div>
            <div class="soc-kpi-value" style="color: {color};">{missing_parents}</div>
            <div class="soc-kpi-sub">Orphaned processes</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.page_link("pages/4_Provenance_Graph.py", label="Graph →", use_container_width=True)

with kpi6:
    st.markdown(
        f"""
        <div class="soc-kpi-card" title="Distinct logging providers contributing telemetry to this investigation.">
            <div class="soc-kpi-title">📡 Log Sources</div>
            <div class="soc-kpi-value">{unique_sources}</div>
            <div class="soc-kpi-sub">Independent providers</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.page_link("pages/5_Evidence_Explorer.py", label="Evidence →", use_container_width=True)

st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

# 6. Main Visualization Row (Equal Height 2-Column Grid)
col_chart_left, col_chart_right = st.columns([6, 4], gap="medium")

with col_chart_left:
    st.markdown(
        """
        <div style="font-size: 0.88rem; font-weight: 700; color: #EDF4FF; margin-bottom: 6px; display: flex; align-items: center; gap: 6px;">
            <span>📈</span> Reconstructed Attack Activity Timeline
        </div>
        """,
        unsafe_allow_html=True
    )
    if not filtered_events:
        st.info("No events match current filter criteria.")
    else:
        df_evt = pd.DataFrame(filtered_events)
        df_evt["time_dt"] = pd.to_datetime(df_evt["ts_start_utc"], errors="coerce")
        df_evt = df_evt.dropna(subset=["time_dt"])

        code_names = {
            1: "Sysmon 1 (Process Create)",
            3: "Sysmon 3 (Network Conn)",
            11: "Sysmon 11 (File Create)",
            4624: "Sec 4624 (Logon)",
            4688: "Sec 4688 (Process Create)",
            1102: "Sec 1102 (Log Cleared)"
        }
        code_colors = {
            1: "#35D6E8",
            3: "#8B7CFF",
            11: "#37D99A",
            4624: "#4A90E2",
            4688: "#F5B942",
            1102: "#FF647C"
        }

        fig_activity = go.Figure()
        for c_code, g in df_evt.groupby("event_code"):
            name = code_names.get(c_code, f"Event {c_code}")
            color = code_colors.get(c_code, "#94A7C2")
            fig_activity.add_trace(go.Histogram(
                x=g["time_dt"],
                name=name,
                marker_color=color,
                opacity=0.85
            ))

        layout_act = get_plotly_layout(height=280)
        layout_act["barmode"] = "stack"
        layout_act["xaxis"]["title"] = dict(text="Timestamp (UTC)", font=dict(size=10, color=TEXT_MUTED))
        layout_act["yaxis"]["title"] = dict(text="Event Frequency", font=dict(size=10, color=TEXT_MUTED))
        fig_activity.update_layout(**layout_act)
        st.plotly_chart(fig_activity, use_container_width=True, config={"displayModeBar": False})

with col_chart_right:
    st.markdown(
        """
        <div style="font-size: 0.88rem; font-weight: 700; color: #EDF4FF; margin-bottom: 6px; display: flex; align-items: center; justify-content: space-between;">
            <div style="display: flex; align-items: center; gap: 6px;">
                <span>⚖️</span> Event Confidence Distribution
            </div>
            <span style="font-size: 0.70rem; color: #94A7C2; font-family: monospace;" title="Corroboration metric, not a mathematical claim of ground truth.">ℹ️ 4-Factor Metric</span>
        </div>
        """,
        unsafe_allow_html=True
    )
    if not filtered_findings:
        st.info("No findings available to display.")
    else:
        high = sum(1 for f in filtered_findings if (f.get("confidence") or 0) >= 0.80)
        mod = sum(1 for f in filtered_findings if 0.50 <= (f.get("confidence") or 0) < 0.80)
        low = sum(1 for f in filtered_findings if (f.get("confidence") or 0) < 0.50)

        fig_conf = go.Figure(data=[
            go.Bar(
                x=["High (0.80–1.00)", "Mod (0.50–0.79)", "Low (0.00–0.49)"],
                y=[high, mod, low],
                marker_color=[SUCCESS_GREEN, WARNING_AMBER, CRITICAL_RED],
                text=[high, mod, low],
                textposition="auto",
                textfont=dict(color="#0B1020", family="JetBrains Mono", size=12)
            )
        ])
        layout_conf = get_plotly_layout(height=280)
        layout_conf["xaxis"]["title"] = dict(text="Confidence Band", font=dict(size=10, color=TEXT_MUTED))
        layout_conf["yaxis"]["title"] = dict(text="Findings Count", font=dict(size=10, color=TEXT_MUTED))
        fig_conf.update_layout(**layout_conf)
        st.plotly_chart(fig_conf, use_container_width=True, config={"displayModeBar": False})

st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

# 7. 8-Stage Pipeline Tracker
st.markdown(
    """
    <div style="font-size: 0.88rem; font-weight: 700; color: #EDF4FF; margin-bottom: 8px; display: flex; align-items: center; gap: 6px;">
        <span>⚙️</span> ChronoTrace Forensic Processing Pipeline
    </div>
    """,
    unsafe_allow_html=True
)

stages = [
    ("1. Ingestion", "COMPLETED"),
    ("2. Normalization", "COMPLETED"),
    ("3. Entity Resolution", "COMPLETED"),
    ("4. Graph Builder", "COMPLETED"),
    ("5. MITRE Tagger", "COMPLETED"),
    ("6. Confidence/Conflict", "COMPLETED"),
    ("7. Timeline & Report", "COMPLETED"),
    ("8. Investigation UI", "ACTIVE")
]

p_cols = st.columns(8)
for idx, (sname, sstate) in enumerate(stages):
    with p_cols[idx]:
        is_active = (sstate == "ACTIVE")
        badge_color = ACCENT_CYAN if is_active else SUCCESS_GREEN
        st.markdown(
            f"""
            <div style="background: #121D30; border: 1px solid {'#35D6E8' if is_active else 'rgba(53,214,232,0.18)'}; border-radius: 6px; padding: 8px 10px; text-align: center;">
                <div style="font-size: 0.68rem; font-weight: 700; color: #EDF4FF; margin-bottom: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{sname}</div>
                <span class="soc-badge" style="background: rgba(53,214,232,0.12); color: {badge_color}; font-size: 0.62rem;">{sstate}</span>
            </div>
            """,
            unsafe_allow_html=True
        )

st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

# 8. Bottom Row: Clickable Recent Findings & Ingested Evidence Sources
col_fnd, col_ev = st.columns([6, 4], gap="medium")

with col_fnd:
    st.markdown(
        """
        <div style="font-size: 0.88rem; font-weight: 700; color: #EDF4FF; margin-bottom: 6px; display: flex; align-items: center; gap: 6px;">
            <span>🎯</span> Actionable Reconstructed Findings
        </div>
        """,
        unsafe_allow_html=True
    )
    if not filtered_findings:
        st.info("No findings matching current filters.")
    else:
        table_findings = []
        for f in filtered_findings[:10]:
            flags = f.get("flags_list", [])
            table_findings.append({
                "Finding ID": f["finding_id"],
                "Event ID": f["event_id"],
                "Host": f.get("host", "N/A"),
                "Stage": f.get("stage", "Execution"),
                "Confidence": f"{f.get('confidence', 0.0):.2f}",
                "Flags": ", ".join(flags) if flags else "—",
                "Raw Ref": f.get("raw_ref", "MISSING")
            })

        df_fnd = pd.DataFrame(table_findings)

        # Single-click selection state synchronization
        sel_state = st.session_state.get("ov_fnd_dataframe_selection", {})
        active_idx = 0
        if isinstance(sel_state, dict):
            rows = sel_state.get("selection", {}).get("rows", [])
            if rows and 0 <= rows[0] < len(df_fnd):
                active_idx = rows[0]

        st.caption("Click any row to inspect its substantiating evidence and forensic assessment:")
        try:
            tbl_event = st.dataframe(
                df_fnd,
                use_container_width=True,
                hide_index=True,
                selection_mode="single-row",
                on_select="rerun",
                key="ov_fnd_dataframe_selection",
                height=220
            )
            if tbl_event and hasattr(tbl_event, "selection") and tbl_event.selection.rows:
                c_idx = tbl_event.selection.rows[0]
                if 0 <= c_idx < len(filtered_findings[:10]):
                    active_idx = c_idx
        except Exception:
            st.dataframe(df_fnd, use_container_width=True, hide_index=True, height=220)

        selected_finding = filtered_findings[:10][active_idx] if filtered_findings else None
        if selected_finding:
            st.markdown(
                f"""
                <div style="background: #17243A; border-left: 3px solid #35D6E8; padding: 10px 14px; border-radius: 4px; font-size: 0.82rem; margin-top: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                        <strong style="color: #35D6E8;">Finding {selected_finding['finding_id']} ({selected_finding.get('stage', 'Execution')})</strong>
                        {render_raw_ref_pill(selected_finding.get('raw_ref', 'N/A'))}
                    </div>
                    <div style="color: #EDF4FF; margin: 4px 0;">{selected_finding.get('explanation')}</div>
                    <div style="font-size: 0.74rem; color: #94A7C2; font-family: monospace;">
                        Event: <strong style="color: #35D6E8;">{selected_finding.get('event_id')}</strong> | Host: <strong>{selected_finding.get('host')}</strong> | Confidence: <strong>{selected_finding.get('confidence', 0):.2f}</strong>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

with col_ev:
    st.markdown(
        """
        <div style="font-size: 0.88rem; font-weight: 700; color: #EDF4FF; margin-bottom: 6px; display: flex; align-items: center; gap: 6px;">
            <span>📦</span> Ingested Evidence Sources
        </div>
        """,
        unsafe_allow_html=True
    )
    if logs:
        log_rows = []
        for l in logs[:10]:
            log_rows.append({
                "Evidence Files": l.get("filename", "")[:32],
                "Records": l.get("total_records", 0),
                "Normalized": l.get("normalized_records", 0),
                "Status": l.get("status", "Completed"),
                "Ingested At": l.get("ingested_at", "")[:19]
            })
        st.dataframe(pd.DataFrame(log_rows), use_container_width=True, hide_index=True, height=280)
    else:
        st.markdown(
            f"""
            <div style="background: #121D30; border: 1px solid rgba(53,214,232,0.18); border-radius: 6px; padding: 14px;">
                <div style="font-size: 0.82rem; color: #EDF4FF; font-weight: 700;">Active Ground-Truth Telemetry:</div>
                <div style="font-size: 0.78rem; color: #94A7C2; margin-top: 6px; line-height: 1.6; font-family: 'JetBrains Mono', monospace;">
                    • sysmon_victim_pc01.evtx (Sysmon v13.0)<br>
                    • security_victim_pc01.evtx (Windows Security)<br>
                    • security_dc_srv01.evtx (DC Security Auditing)
                </div>
                <div style="margin-top: 10px;">
                    <span class="soc-badge badge-demo">Synthetic Demo Dataset Seeded</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
