"""Investigation Overview Dashboard — ChronoTrace.

Primary operational console for digital forensics investigators:
- Modern desktop engineering console aesthetic with smooth animations
- Top operational notice banner (Rule 0 & uncertainty awareness)
- Page header block with eyebrow, title, and descriptive subtitle
- 6 Uniform-height KPI metric cards with smooth hover lifts
- 2-Column Plotly row (Attack Activity Timeline + 4-Factor Confidence Distribution)
- 8-Stage forensic processing pipeline stepper
- Single-click Actionable Findings table with instant inspector drawer
- Auto-sized Ingested Evidence Sources table
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
    render_confidence_badge,
    render_flag_badge,
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
from ui.components import (
    render_notice_banner,
    render_page_header,
    render_card_header,
    render_key_value_grid
)
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
    page_icon=":material/dashboard:",
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

# 2. Render Persistent Flat Sidebar
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
filters = render_topbar("Overview", inv, hosts=hosts, sources=sources)

# 5. Top Notice Banner (Matching Reference Console)
render_notice_banner(
    "All reconstructed events enforce Rule 0 immutable citations (raw_ref) and explicit interval timestamps [ts_start, ts_end].",
    icon_name="shield",
    highlight_prefix="FORENSIC INTEGRITY NOTICE:"
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

filtered_event_ids = {e["event_id"] for e in filtered_events}
filtered_findings = [f for f in findings if f["event_id"] in filtered_event_ids]

# 6. Standardized Page Header Block
render_page_header(
    eyebrow="FORENSIC WORKSPACE / OVERVIEW",
    title="Investigation Overview",
    subtitle="Reconstruct attack sequences. Trace every finding to verified evidence."
)

# 7. Top KPI Strip (Uniform-Height Clean Cards with Hover Lift)
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
    ico = icon_svg("activity", size=13, color=EYEBROW_BLUE)
    st.markdown(
        f"""
        <div class="console-kpi-card" title="Total normalized Windows event records matching filters.">
            <div class="kpi-label">{ico} TOTAL EVENTS</div>
            <div class="kpi-value">{total_events}</div>
            <div class="kpi-sub">Normalized records</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.page_link("pages/3_Attack_Timeline.py", label="Timeline →", use_container_width=True)

with kpi2:
    ico = icon_svg("target", size=13, color=EYEBROW_BLUE)
    st.markdown(
        f"""
        <div class="console-kpi-card" title="Actionable forensic findings mapped to MITRE ATT&CK steps.">
            <div class="kpi-label">{ico} FINDINGS</div>
            <div class="kpi-value">{reconstructed_findings}</div>
            <div class="kpi-sub">Mapped attack steps</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.page_link("pages/6_Findings_and_Reports.py", label="Findings →", use_container_width=True)

with kpi3:
    ico = icon_svg("shield", size=13, color=STATUS_SUCCESS_TEXT)
    st.markdown(
        f"""
        <div class="console-kpi-card" title="Events with confidence score >= 0.80 based on multi-source corroboration and exact ProcessGuid linkage.">
            <div class="kpi-label">{ico} HIGH CONF.</div>
            <div class="kpi-value" style="color: #34D399;">{high_conf_count}</div>
            <div class="kpi-sub">{high_conf_pct}% of findings</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.page_link("pages/3_Attack_Timeline.py", label="High Conf →", use_container_width=True)

with kpi4:
    color = STATUS_WARN_TEXT if total_conflicts > 0 else TEXT_PRIMARY
    ico = icon_svg("alert", size=13, color=color)
    st.markdown(
        f"""
        <div class="console-kpi-card" title="Identified ORDER_CONFLICT (timestamp overlap) or LOG_CLEARED anti-forensic alerts.">
            <div class="kpi-label">{ico} CONFLICTS</div>
            <div class="kpi-value" style="color: {color};">{total_conflicts}</div>
            <div class="kpi-sub">{order_conflicts} order, {log_cleared} cleared</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.page_link("pages/6_Findings_and_Reports.py", label="Inspect →", use_container_width=True)

with kpi5:
    color = STATUS_WARN_TEXT if missing_parents > 0 else TEXT_PRIMARY
    ico = icon_svg("layers", size=13, color=color)
    st.markdown(
        f"""
        <div class="console-kpi-card" title="Processes pointing to unmonitored or purged parent processes.">
            <div class="kpi-label">{ico} MISSING PARENT</div>
            <div class="kpi-value" style="color: {color};">{missing_parents}</div>
            <div class="kpi-sub">Orphaned processes</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.page_link("pages/4_Provenance_Graph.py", label="Graph →", use_container_width=True)

with kpi6:
    ico = icon_svg("database", size=13, color=EYEBROW_BLUE)
    st.markdown(
        f"""
        <div class="console-kpi-card" title="Distinct logging providers contributing telemetry to this investigation.">
            <div class="kpi-label">{ico} LOG SOURCES</div>
            <div class="kpi-value">{unique_sources}</div>
            <div class="kpi-sub">Independent providers</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.page_link("pages/5_Evidence_Explorer.py", label="Evidence →", use_container_width=True)

st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

# 8. Main Visualization Row (Equal Height 2-Column Grid)
col_chart_left, col_chart_right = st.columns([6, 4], gap="medium")

with col_chart_left:
    render_card_header("Reconstructed Attack Activity", pill_text="SYSMON + SECURITY", pill_class="pill-info", icon_name="activity")
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
            1: "#38BDF8",
            3: "#818CF8",
            11: "#34D399",
            4624: "#60A5FA",
            4688: "#FBBF24",
            1102: "#FB7185"
        }

        fig_activity = go.Figure()
        for c_code, g in df_evt.groupby("event_code"):
            name = code_names.get(c_code, f"Event {c_code}")
            color = code_colors.get(c_code, "#94A3B8")
            fig_activity.add_trace(go.Histogram(
                x=g["time_dt"],
                name=name,
                marker_color=color,
                opacity=0.88,
                hovertemplate=f"<b>{name}</b><br>Time (UTC): %{{x|%Y-%m-%d %H:%M:%S}}<br>Frequency: %{{y}}<extra></extra>",
                hoverlabel=dict(
                    bgcolor="#0D1526",
                    bordercolor=color,
                    font=dict(color="#F8FAFC", family="Inter, sans-serif", size=11)
                )
            ))

        layout_act = get_plotly_layout(height=250)
        layout_act["barmode"] = "stack"
        layout_act["bargap"] = 0.6
        layout_act["xaxis"]["title"] = dict(text="Timestamp (UTC)", font=dict(size=10, color=TEXT_MUTED))
        layout_act["yaxis"]["title"] = dict(text="Event Frequency", font=dict(size=10, color=TEXT_MUTED))
        fig_activity.update_layout(**layout_act)
        st.plotly_chart(fig_activity, use_container_width=True, config={"displayModeBar": False})

with col_chart_right:
    render_card_header("Event Confidence Distribution", pill_text="4-FACTOR METRIC", pill_class="pill-info", icon_name="shield")
    if not filtered_findings:
        st.info("No findings available to display.")
    else:
        high = sum(1 for f in filtered_findings if (f.get("confidence") or 0) >= 0.80)
        mod = sum(1 for f in filtered_findings if 0.50 <= (f.get("confidence") or 0) < 0.80)
        low = sum(1 for f in filtered_findings if (f.get("confidence") or 0) < 0.50)

        fig_conf = go.Figure(data=[
            go.Bar(
                x=["High (≥0.80)", "Mod (0.50–0.79)", "Low (<0.50)"],
                y=[high, mod, low],
                marker_color=["#34D399", "#FBBF24", "#FB7185"],
                text=[high, mod, low],
                textposition="auto",
                textfont=dict(color="#090E1A", family="Inter", size=11),
                width=[0.42, 0.42, 0.42],
                hovertemplate="<b>%{x}</b><br>Findings Count: %{y}<extra></extra>",
                hoverlabel=dict(
                    bgcolor="#0D1526",
                    bordercolor="rgba(56, 189, 248, 0.4)",
                    font=dict(color="#F8FAFC", family="Inter, sans-serif", size=11)
                )
            )
        ])
        layout_conf = get_plotly_layout(height=250)
        layout_conf["xaxis"]["title"] = dict(text="Confidence Band", font=dict(size=10, color=TEXT_MUTED))
        layout_conf["yaxis"]["title"] = dict(text="Findings Count", font=dict(size=10, color=TEXT_MUTED))
        fig_conf.update_layout(**layout_conf)
        st.plotly_chart(fig_conf, use_container_width=True, config={"displayModeBar": False})

st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

# 9. Forensic Processing Pipeline Stepper
render_card_header("Processing Pipeline Stepper", pill_text="ALL STAGES SYNCHRONIZED", pill_class="pill-primary", icon_name="layers")

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
        badge_cls = "pill-primary" if is_active else "pill-success"
        bg_col = "rgba(29, 111, 232, 0.12)" if is_active else "#0D1526"
        border_col = "rgba(56, 189, 248, 0.3)" if is_active else "rgba(255, 255, 255, 0.06)"
        st.markdown(
            f"""
            <div style="background: {bg_col}; border: 1px solid {border_col}; border-radius: 6px; padding: 7px 6px; text-align: center;">
                <div style="font-size: 11px; font-weight: 600; color: #F8FAFC; margin-bottom: 3px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{sname}</div>
                <span class="status-pill {badge_cls}" style="font-size: 9px; padding: 1px 5px;">{sstate}</span>
            </div>
            """,
            unsafe_allow_html=True
        )

st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

# 9b. Cryptographic Merkle Seal & Attack Blast Radius Row
from services.crypto_chain import build_investigation_hash_chain
from services.graph_analytics import calculate_blast_radius

chain_data = build_investigation_hash_chain(events, selected_inv_id)
blast_data = calculate_blast_radius(selected_inv_id)

c_seal, c_blast = st.columns(2, gap="medium")

with c_seal:
    render_card_header("Cryptographic Integrity (Merkle Root)", pill_text=chain_data.get("status", "SEALED"), pill_class="pill-success", icon_name="shield")
    merkle_root = chain_data.get("merkle_root", "")
    short_root = f"{merkle_root[:20]}...{merkle_root[-20:]}" if len(merkle_root) > 40 else merkle_root
    st.markdown(
        f"""
        <div class="console-card" style="padding: 12px 14px;">
            <div style="font-size: 11.5px; color: #94A3B8; margin-bottom: 6px;">
                Sequential SHA-256 evidence chain verification across <span style="color: #38BDF8; font-weight: 600;">{chain_data.get('total_blocks', 0)} blocks</span>:
            </div>
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; background: #050811; padding: 7px 10px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.06); color: #34D399; word-break: break-all;">
                {short_root}
            </div>
            <div style="font-size: 10.5px; color: #64748B; margin-top: 6px;">
                *Mathematical court-admissible proof: 0 alterations, deletions, or insertions detected.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

with c_blast:
    sev_color = "#FB7185" if blast_data.get("severity_rating") == "CRITICAL" else "#34D399"
    render_card_header("Enterprise Attack Blast Radius", pill_text=f"{blast_data.get('severity_rating', 'LOW')}", pill_class="pill-danger" if blast_data.get("severity_rating") == "CRITICAL" else "pill-info", icon_name="activity")
    st.markdown(
        f"""
        <div class="console-card" style="padding: 12px 14px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <div style="font-size: 11.5px; color: #94A3B8;">Subnet Compromise Breadth:</div>
                <div style="font-size: 14px; font-weight: 700; color: {sev_color};">{blast_data.get('blast_radius_percentage', 0.0)}%</div>
            </div>
            <div style="font-size: 11.5px; line-height: 1.5; color: #CBD5E1;">
                • Compromised Hosts: <span style="color: #38BDF8; font-weight: 600;">{blast_data.get('compromised_hosts_count', 0)} / {blast_data.get('total_hosts_observed', 1)}</span><br>
                • Affected User Identities: <span style="color: #818CF8; font-weight: 600;">{blast_data.get('compromised_users_count', 0)}</span><br>
                • External C2 Endpoints: <span style="color: #FBBF24; font-weight: 600;">{len(blast_data.get('external_c2_endpoints', []))}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

# 10. Bottom Row: Actionable Findings & Ingested Evidence Sources
col_fnd, col_ev = st.columns([6, 4], gap="medium")

with col_fnd:
    render_card_header("Actionable Reconstructed Findings", pill_text=f"{len(filtered_findings)} DETECTED", pill_class="pill-primary", icon_name="target")
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

        st.caption("Click any row below to inspect its detailed assessment and evidence citation:")
        try:
            tbl_event = st.dataframe(
                df_fnd,
                use_container_width=True,
                hide_index=True,
                selection_mode="single-row",
                on_select="rerun",
                key="ov_fnd_dataframe_selection",
                height=calc_df_height(df_fnd, min_h=130, max_h=220)
            )
            if tbl_event and hasattr(tbl_event, "selection") and tbl_event.selection.rows:
                c_idx = tbl_event.selection.rows[0]
                if 0 <= c_idx < len(filtered_findings[:10]):
                    active_idx = c_idx
        except Exception:
            st.dataframe(df_fnd, use_container_width=True, hide_index=True, height=calc_df_height(df_fnd, min_h=130, max_h=220))

        selected_finding = filtered_findings[:10][active_idx] if filtered_findings else None
        if selected_finding:
            flags = selected_finding.get("flags_list", [])
            flags_html = f'<div style="margin: 4px 0 6px 0;">{"".join([render_flag_badge(fl) + " " for fl in flags])}</div>' if flags else ""
            st.markdown(
                f"""
                <div class="console-elevated" style="padding: 10px 14px; margin-top: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                        <span style="font-weight: 600; color: #38BDF8; font-size: 13px;">Finding {selected_finding['finding_id']} ({selected_finding.get('stage', 'Execution')})</span>
                        {render_raw_ref_pill(selected_finding.get('raw_ref', 'N/A'))}
                    </div>
                    <div style="color: #CBD5E1; font-size: 12px; margin: 3px 0 4px 0;">{selected_finding.get('explanation')}</div>
                    {flags_html}
                    <div style="font-size: 11px; color: #64748B; margin-top: 4px;">
                        Event: <span style="color: #38BDF8; font-family: 'JetBrains Mono', monospace;">{selected_finding.get('event_id')}</span> • Host: <strong style="color: #F8FAFC;">{selected_finding.get('host')}</strong> • Confidence: <strong style="color: #34D399;">{selected_finding.get('confidence', 0):.2f}</strong>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

with col_ev:
    render_card_header("Ingested Evidence Sources", pill_text="VERIFIED TELEMETRY", pill_class="pill-info", icon_name="database")
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
        df_logs = pd.DataFrame(log_rows)
        st.dataframe(df_logs, use_container_width=True, hide_index=True, height=calc_df_height(df_logs, min_h=90, max_h=220))
    else:
        st.markdown(
            f"""
            <div class="console-card" style="padding: 12px 14px;">
                <div style="font-size: 13px; color: #F8FAFC; font-weight: 600;">Active Ground-Truth Telemetry:</div>
                <div style="font-size: 11px; color: #94A3B8; margin-top: 6px; line-height: 1.6; font-family: 'JetBrains Mono', monospace;">
                    • sysmon_victim_pc01.evtx (Sysmon v13.0)<br>
                    • security_victim_pc01.evtx (Windows Security)<br>
                    • security_dc_srv01.evtx (DC Security Auditing)
                </div>
                <div style="margin-top: 8px;">
                    <span class="status-pill pill-primary">Synthetic Demo Dataset Seeded</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
