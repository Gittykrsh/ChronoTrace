"""Shared UI Layout Module for ChronoTrace.

Provides:
- Persistent sidebar with brandmark, page navigation, active case selector, case creation dialog, and system health status.
- Synchronized top navigation bar with breadcrumb, live UTC clock, and global filter controls (search, host, source, min_confidence).
"""

import streamlit as st
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from database.db import get_investigations, create_investigation
from data.demo_seed import seed_demo_data

NAV_ITEMS = [
    {"label": "Overview", "icon": "📊", "file": "pages/1_Investigation_Overview.py", "id": "overview"},
    {"label": "Evidence Ingestion", "icon": "📥", "file": "pages/2_Evidence_Ingestion.py", "id": "ingestion"},
    {"label": "Attack Timeline", "icon": "⏱️", "file": "pages/3_Attack_Timeline.py", "id": "timeline"},
    {"label": "Provenance Graph", "icon": "🕸️", "file": "pages/4_Provenance_Graph.py", "id": "graph"},
    {"label": "Evidence Explorer", "icon": "🔬", "file": "pages/5_Evidence_Explorer.py", "id": "explorer"},
    {"label": "Findings & Reports", "icon": "📑", "file": "pages/6_Findings_and_Reports.py", "id": "reports"}
]


if hasattr(st, "dialog"):
    @st.dialog("Create Forensic Investigation Case")
    def _create_case_dialog() -> None:
        invs = get_investigations()
        new_id = st.text_input("Investigation Case ID", value=f"inv-case-{len(invs)+1:02d}")
        new_name = st.text_input("Case Title", placeholder="e.g. Incident Alpha 2026")
        new_desc = st.text_area("Scope / Forensic Notes", placeholder="Victim host, suspected attack vectors...")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Initialize Case", type="primary", use_container_width=True):
                if new_name.strip():
                    create_investigation(new_id.strip(), new_name.strip(), new_desc.strip(), status="Active", is_demo=False)
                    st.session_state["active_investigation_id"] = new_id.strip()
                    st.session_state["sb_inv_selector"] = new_id.strip()
                    st.success(f"Case '{new_name}' initialized.")
                    st.rerun()
                else:
                    st.warning("Please provide a case title.")
        with c2:
            if st.button("Cancel", use_container_width=True):
                st.rerun()
else:
    def _create_case_dialog() -> None:
        pass


def render_sidebar(current_page_id: str = "overview") -> str:
    """Renders persistent sidebar and returns the active investigation_id."""
    with st.sidebar:
        # 1. High-Definition Vector Brandmark & Typography (Fitted Header)
        st.markdown(
            """
            <div style="display: flex; align-items: center; gap: 11px; padding: 4px 2px 14px 2px; border-bottom: 1px solid rgba(53, 214, 232, 0.18); margin-bottom: 10px; width: 100%;">
                <div style="flex-shrink: 0; width: 42px; height: 42px; display: flex; align-items: center; justify-content: center;">
                    <svg viewBox="0 0 56 56" width="42" height="42" style="filter: drop-shadow(0 0 10px rgba(53, 214, 232, 0.65)); display: block;">
                        <defs>
                            <linearGradient id="sbShield" x1="0%" y1="0%" x2="100%" y2="100%">
                                <stop offset="0%" stop-color="#35D6E8"/>
                                <stop offset="50%" stop-color="#8B7CFF"/>
                                <stop offset="100%" stop-color="#121D30"/>
                            </linearGradient>
                            <filter id="sbGlow">
                                <feGaussianBlur stdDeviation="2" result="b"/>
                                <feComposite in="SourceGraphic" in2="b" operator="over"/>
                            </filter>
                        </defs>
                        <!-- Cyber Shield Frame -->
                        <path d="M 28 3 L 51 12 L 51 34 C 51 47 28 54 28 54 C 28 54 5 47 5 34 L 5 12 Z" 
                              fill="#121D30" stroke="url(#sbShield)" stroke-width="2.6" stroke-linejoin="round"/>
                        <!-- Clock Radar -->
                        <circle cx="28" cy="27" r="14" fill="#0E1628" stroke="#1E2F4D" stroke-width="1.2"/>
                        <circle cx="28" cy="27" r="14" fill="none" stroke="#35D6E8" stroke-width="1.8" stroke-dasharray="24 16" stroke-linecap="round"/>
                        <!-- Graph Links -->
                        <line x1="20" y1="21" x2="36" y2="23" stroke="#8B7CFF" stroke-width="1.6"/>
                        <line x1="36" y1="23" x2="27" y2="35" stroke="#35D6E8" stroke-width="1.8"/>
                        <!-- Radar Hands -->
                        <line x1="28" y1="27" x2="28" y2="18" stroke="#35D6E8" stroke-width="2.2" stroke-linecap="round"/>
                        <line x1="28" y1="27" x2="34" y2="27" stroke="#37D99A" stroke-width="2" stroke-linecap="round"/>
                        <!-- Glowing Pivots -->
                        <circle cx="28" cy="27" r="2.5" fill="#FFFFFF"/>
                        <circle cx="20" cy="21" r="3" fill="#8B7CFF" filter="url(#sbGlow)"/>
                        <circle cx="36" cy="23" r="3.2" fill="#35D6E8" filter="url(#sbGlow)"/>
                        <circle cx="27" cy="35" r="2.8" fill="#37D99A" filter="url(#sbGlow)"/>
                    </svg>
                </div>
                <div style="display: flex; flex-direction: column; justify-content: center; min-width: 0; flex: 1;">
                    <div style="font-family: 'Inter', -apple-system, sans-serif; font-size: 1.28rem; font-weight: 900; letter-spacing: 0.05em; line-height: 1.15; color: #FFFFFF; white-space: nowrap;">
                        CHRONO<span style="color: #35D6E8; text-shadow: 0 0 12px rgba(53, 214, 232, 0.75);">TRACE</span>
                    </div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.60rem; font-weight: 800; color: #35D6E8; letter-spacing: 0.14em; margin-top: 2px; text-transform: uppercase; white-space: nowrap;">
                        FORENSIC RECONSTRUCTION
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # 2. Navigation Header
        st.markdown(
            "<div style='margin-top: 10px; margin-bottom: 6px; font-size: 0.68rem; font-weight: 800; color: #94A7C2; letter-spacing: 0.1em; text-transform: uppercase;'>Forensic Workspaces</div>",
            unsafe_allow_html=True
        )

        for item in NAV_ITEMS:
            st.page_link(
                item["file"],
                label=item["label"],
                icon=item["icon"],
                use_container_width=True
            )

        st.markdown("<hr style='margin: 14px 0; border-color: rgba(148,167,194,0.12);'/>", unsafe_allow_html=True)

        # 3. Active Investigation Selector
        invs = get_investigations()
        if not invs:
            seed_demo_data()
            invs = get_investigations()

        inv_options = {inv["id"]: f"{'🧪 ' if inv.get('is_demo') else '📁 '} {inv['name']}" for inv in invs}

        if "active_investigation_id" not in st.session_state or st.session_state["active_investigation_id"] not in inv_options:
            st.session_state["active_investigation_id"] = list(inv_options.keys())[0]

        selected_id = st.selectbox(
            "ACTIVE INVESTIGATION",
            options=list(inv_options.keys()),
            format_func=lambda x: inv_options[x],
            index=list(inv_options.keys()).index(st.session_state["active_investigation_id"]),
            key="sb_inv_selector",
            label_visibility="visible"
        )
        st.session_state["active_investigation_id"] = selected_id

        # Quick Case Creation Button / Modal
        col_new, col_rst = st.columns(2)
        with col_new:
            if hasattr(st, "dialog"):
                if st.button("➕ New Case", key="sb_btn_new_case", use_container_width=True):
                    _create_case_dialog()
            else:
                with st.expander("➕ New Case"):
                    new_id = st.text_input("Case ID", value=f"inv-case-{len(invs)+1:02d}")
                    new_name = st.text_input("Title")
                    if st.button("Save"):
                        create_investigation(new_id, new_name, "", "Active", False)
                        st.session_state["active_investigation_id"] = new_id
                        st.rerun()

        with col_rst:
            if st.button("🔄 Reset Demo", key="sb_btn_reset_demo", help="Resets synthetic demonstration evidence", use_container_width=True):
                seed_demo_data(force=True)
                st.session_state["active_investigation_id"] = "inv-demo-01"
                st.session_state["sb_inv_selector"] = "inv-demo-01"
                for stale_key in [
                    "selected_timeline_eid", "active_explorer_ref", "selected_raw_ref",
                    "timeline_dataframe_selection", "evidence_table_selection",
                    "ov_fnd_dataframe_selection", "fnd_dataframe_selection"
                ]:
                    st.session_state.pop(stale_key, None)
                st.success("Demo dataset reset.")
                st.rerun()

        # 4. Scope Badge
        current_inv = next((i for i in invs if i["id"] == selected_id), None)
        if current_inv:
            is_demo = bool(current_inv.get("is_demo"))
            st.markdown(
                f"""
                <div style="background: #121D30; border: 1px solid rgba(53,214,232,0.2); border-radius: 6px; padding: 10px; margin: 12px 0;">
                    <div style="font-size: 0.65rem; color: #94A7C2; text-transform: uppercase; font-family: monospace;">Case Scope</div>
                    <div style="font-size: 0.82rem; font-weight: 700; color: #EDF4FF; margin: 2px 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                        {current_inv['name']}
                    </div>
                    <span class="soc-badge {'badge-demo' if is_demo else 'badge-high-conf'}">
                        {'DEMO CASE — SYNTHETIC' if is_demo else 'LIVE INVESTIGATION'}
                    </span>
                </div>
                """,
                unsafe_allow_html=True
            )

        # 5. Global Health Status Footer
        st.markdown(
            """
            <div style="padding-top: 4px;">
                <div class="status-pill"><span class="status-dot dot-green"></span> <span>SQLite: WAL Mode</span></div>
                <div class="status-pill"><span class="status-dot dot-cyan"></span> <span>Engine: Deterministic (No ML)</span></div>
                <div class="status-pill"><span class="status-dot dot-violet"></span> <span>Rule 0: Enforced (raw_ref)</span></div>
                <div style="margin-top: 8px; font-size: 0.68rem; color: #5B6B82; font-family: 'JetBrains Mono', monospace;">
                    ChronoTrace v1.0.0-prototype
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        return selected_id


def render_topbar(
    breadcrumb_label: str,
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
    if "global_host" not in st.session_state:
        st.session_state["global_host"] = "All Hosts"
    if "global_source" not in st.session_state:
        st.session_state["global_source"] = "All Sources"
    if "global_search" not in st.session_state:
        st.session_state["global_search"] = ""
    if "global_min_confidence" not in st.session_state:
        st.session_state["global_min_confidence"] = 0.0

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
                <span style="font-size: 0.76rem; color: #94A7C2; font-family: 'JetBrains Mono', monospace;">CHRONOTRACE &rsaquo;</span>
                <span style="font-size: 0.76rem; color: #35D6E8; font-weight: 700; font-family: 'JetBrains Mono', monospace;">{breadcrumb_label.upper()}</span>
                <span class="soc-badge {'badge-demo' if is_demo else 'badge-high-conf'}">
                    {'DEMO CASE' if is_demo else 'ACTIVE CASE'}
                </span>
            </div>
            <h2 style="margin: 0; font-size: 1.45rem; color: #EDF4FF; font-weight: 800; letter-spacing: -0.02em;">{breadcrumb_label}</h2>
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
                    Case: <strong style="color: #EDF4FF;">{investigation.get('name', 'N/A')[:32]}</strong>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Synchronized Global Filter Bar
    st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)
    fcol1, fcol2, fcol3, fcol4 = st.columns([4, 2.6, 2.6, 2.8])

    with fcol1:
        search_query = st.text_input(
            "Global Search",
            value=st.session_state["global_search"],
            placeholder="Search image, PID, IP, command, raw_ref...",
            key="input_global_search",
            label_visibility="collapsed"
        )
        st.session_state["global_search"] = search_query

    with fcol2:
        host_options = ["All Hosts"] + sorted([h for h in hosts if h])
        curr_host_idx = 0
        if st.session_state["global_host"] in host_options:
            curr_host_idx = host_options.index(st.session_state["global_host"])
        selected_host = st.selectbox(
            "Filter Host",
            options=host_options,
            index=curr_host_idx,
            key="input_global_host",
            label_visibility="collapsed"
        )
        st.session_state["global_host"] = selected_host

    with fcol3:
        source_options = ["All Sources"] + sorted([s for s in sources if s])
        curr_src_idx = 0
        if st.session_state["global_source"] in source_options:
            curr_src_idx = source_options.index(st.session_state["global_source"])
        selected_source = st.selectbox(
            "Filter Source",
            options=source_options,
            index=curr_src_idx,
            key="input_global_source",
            label_visibility="collapsed"
        )
        st.session_state["global_source"] = selected_source

    with fcol4:
        min_conf = st.slider(
            "Min Confidence",
            min_value=0.0,
            max_value=1.0,
            value=float(st.session_state["global_min_confidence"]),
            step=0.05,
            format="Conf ≥ %.2f",
            key="input_global_min_confidence",
            label_visibility="collapsed"
        )
        st.session_state["global_min_confidence"] = min_conf

    st.markdown("<hr style='margin: 8px 0 14px 0; border-color: rgba(148,167,194,0.12);'/>", unsafe_allow_html=True)

    return {
        "search": search_query.strip().lower(),
        "host": selected_host,
        "source": selected_source,
        "min_confidence": min_conf
    }
