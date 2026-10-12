"""Top Navigation Bar Component for ChronoTrace.

Provides:
- Synchronized global filters (host, source, confidence, search) across all workspaces
- Case status & UTC time indicator
- Evidence traceability banner
"""

import streamlit as st
from datetime import datetime, timezone
from typing import Dict, Any, List


def render_topbar(
    page_title: str,
    investigation: Dict[str, Any],
    hosts: List[str] = None,
    sources: List[str] = None
) -> Dict[str, Any]:
    """Renders top bar and returns synchronized global filters."""
    if hosts is None:
        hosts = []
    if sources is None:
        sources = []

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    is_demo = bool(investigation.get("is_demo", 0))

    # Initialize shared filter state in session_state if not already present
    if "shared_host" not in st.session_state:
        st.session_state["shared_host"] = "All Hosts"
    if "shared_source" not in st.session_state:
        st.session_state["shared_source"] = "All Sources"
    if "shared_search" not in st.session_state:
        st.session_state["shared_search"] = ""
    if "shared_min_conf" not in st.session_state:
        st.session_state["shared_min_conf"] = 0.0

    # Demo Banner if synthetic case
    if is_demo:
        st.markdown(
            """
            <div style="background: rgba(53, 214, 232, 0.08); border-left: 4px solid #35D6E8; padding: 6px 14px; margin-bottom: 12px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 0.78rem; color: #35D6E8; font-family: 'JetBrains Mono', monospace; font-weight: 700;">
                    ⚠️ DEMO MODE ACTIVE — SYNTHETIC EVIDENCE DATASET (NOT REAL FORENSIC EVIDENCE)
                </span>
                <span style="font-size: 0.72rem; color: #94A7C2;">Strict provenance & uncertainty rules enabled</span>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Topbar header container
    col1, col2 = st.columns([6, 4])
    with col1:
        st.markdown(
            f"""
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 2px;">
                <svg viewBox="0 0 56 56" width="16" height="16" style="filter: drop-shadow(0 0 6px rgba(53, 214, 232, 0.7)); display: inline-block; vertical-align: middle;">
                    <path d="M 28 3 L 51 12 L 51 34 C 51 47 28 54 28 54 C 28 54 5 47 5 34 L 5 12 Z" fill="#121D30" stroke="#35D6E8" stroke-width="3.2"/>
                    <circle cx="28" cy="27" r="12" fill="none" stroke="#35D6E8" stroke-width="2" stroke-dasharray="16 12"/>
                    <circle cx="28" cy="27" r="3" fill="#35D6E8"/>
                </svg>
                <span style="font-size: 0.78rem; color: #94A7C2; font-family: monospace;">CHRONOTRACE &rsaquo;</span>
                <span style="font-size: 0.78rem; color: #35D6E8; font-weight: 700; font-family: monospace;">{page_title.upper()}</span>
                <span class="badge {'badge-demo' if is_demo else 'badge-high-conf'}">
                    {'DEMO CASE' if is_demo else 'ACTIVE CASE'}
                </span>
            </div>
            <h2 style="margin: 0; font-size: 1.55rem; color: #EDF4FF; font-weight: 800;">{page_title}</h2>
            """,
            unsafe_allow_html=True
        )

    with col2:
        st.markdown(
            f"""
            <div style="text-align: right; margin-top: 2px;">
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; color: #35D6E8; font-weight: 700;">
                    🕒 {now_utc}
                </div>
                <div style="font-size: 0.74rem; color: #94A7C2; margin-top: 2px;">
                    Case: <strong style="color: #EDF4FF;">{investigation.get('name', 'N/A')[:35]}</strong>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Synchronized Global Filter Bar
    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
    fcol1, fcol2, fcol3, fcol4 = st.columns([4, 3, 3, 2])

    with fcol1:
        search_query = st.text_input(
            "Search Telemetry",
            value=st.session_state["shared_search"],
            placeholder="Search image, PID, IP, command, raw_ref...",
            key="input_shared_search",
            label_visibility="collapsed"
        )
        st.session_state["shared_search"] = search_query

    with fcol2:
        host_options = ["All Hosts"] + [h for h in hosts if h]
        curr_host_idx = 0
        if st.session_state["shared_host"] in host_options:
            curr_host_idx = host_options.index(st.session_state["shared_host"])
        selected_host = st.selectbox(
            "Filter Host",
            options=host_options,
            index=curr_host_idx,
            key="input_shared_host",
            label_visibility="collapsed"
        )
        st.session_state["shared_host"] = selected_host

    with fcol3:
        source_options = ["All Sources"] + [s for s in sources if s]
        curr_src_idx = 0
        if st.session_state["shared_source"] in source_options:
            curr_src_idx = source_options.index(st.session_state["shared_source"])
        selected_source = st.selectbox(
            "Filter Source",
            options=source_options,
            index=curr_src_idx,
            key="input_shared_source",
            label_visibility="collapsed"
        )
        st.session_state["shared_source"] = selected_source

    with fcol4:
        conf_options = [0.0, 0.5, 0.8]
        curr_conf_idx = 0
        if st.session_state["shared_min_conf"] in conf_options:
            curr_conf_idx = conf_options.index(st.session_state["shared_min_conf"])
        min_conf = st.selectbox(
            "Min Confidence",
            options=conf_options,
            index=curr_conf_idx,
            format_func=lambda x: f"Conf. ≥ {int(x*100)}%" if x > 0 else "All Conf.",
            key="input_shared_min_conf",
            label_visibility="collapsed"
        )
        st.session_state["shared_min_conf"] = min_conf

    st.markdown("<hr style='margin: 12px 0 18px 0; border-color: rgba(148,167,194,0.12);'/>", unsafe_allow_html=True)

    return {
        "search_query": search_query.strip().lower(),
        "host": selected_host,
        "source": selected_source,
        "min_confidence": min_conf
    }
