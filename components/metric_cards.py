"""Forensic KPI Metrics Component for ChronoTrace.

Renders the 6 core metrics from Section 5:
1. Total Events
2. Reconstructed Findings
3. High-Confidence Events
4. Evidence Conflicts
5. Missing-Evidence Flags
6. Evidence Sources
With interactive drill-down buttons to jump directly to filtered views.
"""

import streamlit as st
from typing import List, Dict, Any


def render_metric_cards(
    events: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    raw_events: List[Dict[str, Any]]
) -> None:
    """Renders 6 interactive forensic KPI cards with explicit tooltips and drill-downs."""
    total_events = len(events)
    reconstructed_findings = len(findings)

    high_conf_count = sum(1 for f in findings if f.get("confidence", 0) >= 0.80)
    high_conf_pct = int((high_conf_count / reconstructed_findings * 100)) if reconstructed_findings > 0 else 0

    # Evidence Conflicts (ORDER_CONFLICT + LOG_CLEARED)
    order_conflicts = sum(1 for f in findings if "ORDER_CONFLICT" in f.get("flags_list", []))
    log_cleared = sum(1 for f in findings if "LOG_CLEARED" in f.get("flags_list", []))
    total_conflicts = order_conflicts + log_cleared

    # Missing Evidence Flags (MISSING_PARENT)
    missing_parent_flags = sum(1 for f in findings if "MISSING_PARENT" in f.get("flags_list", []))

    # Evidence Sources count
    unique_sources = len(set(e.get("source") for e in events if e.get("source")))

    c1, c2, c3, c4, c5, c6 = st.columns(6)

    with c1:
        st.markdown(
            f"""
            <div class="metric-card" title="Total normalized Windows event records ingested and validated in the active case.">
                <div class="metric-title">📊 Total Events</div>
                <div class="metric-value">{total_events}</div>
                <div class="metric-sub">Normalized records</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.page_link("pages/3_Attack_Timeline.py", label="Timeline →", use_container_width=True)

    with c2:
        st.markdown(
            f"""
            <div class="metric-card" title="Actionable forensic findings reconstructed and linked to verifiable log evidence.">
                <div class="metric-title">🎯 Findings</div>
                <div class="metric-value">{reconstructed_findings}</div>
                <div class="metric-sub">Mapped ATT&CK steps</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.page_link("pages/6_Findings_and_Reports.py", label="Findings →", use_container_width=True)

    with c3:
        st.markdown(
            f"""
            <div class="metric-card" title="Events with confidence score >= 0.80 based on multi-source corroboration and exact ProcessGuid linkage.">
                <div class="metric-title">🛡️ High Conf.</div>
                <div class="metric-value" style="color: #37D99A;">{high_conf_count}</div>
                <div class="metric-sub">{high_conf_pct}% of findings</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.page_link("pages/3_Attack_Timeline.py", label="High Conf →", use_container_width=True)

    with c4:
        color = "#F5B942" if total_conflicts > 0 else "#EDF4FF"
        st.markdown(
            f"""
            <div class="metric-card" title="Identified ORDER_CONFLICT (timestamp overlap/clock skew) or LOG_CLEARED anti-forensic alerts.">
                <div class="metric-title">⚠️ Conflicts</div>
                <div class="metric-value" style="color: {color};">{total_conflicts}</div>
                <div class="metric-sub">{order_conflicts} order, {log_cleared} cleared</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.page_link("pages/6_Findings_and_Reports.py", label="Inspect →", use_container_width=True)

    with c5:
        color = "#FF9B42" if missing_parent_flags > 0 else "#EDF4FF"
        st.markdown(
            f"""
            <div class="metric-card" title="Identified MISSING_PARENT events where child process points to an unlogged or purged parent process.">
                <div class="metric-title">🧩 Missing Parent</div>
                <div class="metric-value" style="color: {color};">{missing_parent_flags}</div>
                <div class="metric-sub">Orphaned processes</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.page_link("pages/4_Provenance_Graph.py", label="Graph →", use_container_width=True)

    with c6:
        st.markdown(
            f"""
            <div class="metric-card" title="Distinct logging providers contributing telemetry to this investigation (e.g. Sysmon, Security Auditing).">
                <div class="metric-title">📡 Log Sources</div>
                <div class="metric-value">{unique_sources}</div>
                <div class="metric-sub">Independent providers</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.page_link("pages/5_Evidence_Explorer.py", label="Evidence →", use_container_width=True)
