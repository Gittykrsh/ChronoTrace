"""Shared UI Layout Module for ChronoTrace — Flagship SOC Operations Platform.

Provides:
- Persistent 280px sidebar with high-definition vector brandmark, native material icon navigation,
  case management dialog modal, reset demo dataset trigger, and live system health pills.
- Synchronized top command bar with breadcrumbs, live UTC chronometer, and global filter controls.
"""

import streamlit as st
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from database.db import get_investigations, create_investigation
from data.demo_seed import seed_demo_data
from ui.theme import icon_svg, ACCENT_CYAN, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED

NAV_ITEMS = [
    {"label": "Investigation Overview", "icon": ":material/dashboard:", "file": "pages/1_Investigation_Overview.py", "id": "overview"},
    {"label": "Evidence Ingestion", "icon": ":material/upload_file:", "file": "pages/2_Evidence_Ingestion.py", "id": "ingestion"},
    {"label": "Attack Timeline", "icon": ":material/timeline:", "file": "pages/3_Attack_Timeline.py", "id": "timeline"},
    {"label": "Provenance Graph", "icon": ":material/hub:", "file": "pages/4_Provenance_Graph.py", "id": "graph"},
    {"label": "Evidence Explorer", "icon": ":material/manage_search:", "file": "pages/5_Evidence_Explorer.py", "id": "explorer"},
    {"label": "Findings & Reports", "icon": ":material/description:", "file": "pages/6_Findings_and_Reports.py", "id": "reports"}
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
    """Renders persistent 280px sidebar and returns the active investigation_id."""
    with st.sidebar:
        # 1. Vector Brandmark Header (Optimized 36px insignia, zero text clipping)
        st.markdown(
            """
            <div style="display: flex; align-items: center; gap: 10px; padding: 2px 2px 12px 2px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); margin-bottom: 10px; width: 100%;">
                <div style="flex-shrink: 0; width: 38px; height: 38px; display: flex; align-items: center; justify-content: center;">
                    <svg viewBox="0 0 56 56" width="38" height="38" style="filter: drop-shadow(0 0 8px rgba(53, 214, 232, 0.5)); display: block;">
                        <defs>
                            <linearGradient id="sbShield" x1="0%" y1="0%" x2="100%" y2="100%">
                                <stop offset="0%" stop-color="#35D6E8"/>
                                <stop offset="60%" stop-color="#8B7CFF"/>
                                <stop offset="100%" stop-color="#111827"/>
                            </linearGradient>
                        </defs>
                        <!-- Cyber Shield Frame -->
                        <path d="M 28 4 L 49 12 L 49 32 C 49 44 28 51 28 51 C 28 51 7 44 7 32 L 7 12 Z" 
                              fill="#111827" stroke="url(#sbShield)" stroke-width="2.6" stroke-linejoin="round"/>
                        <!-- Clock Radar -->
                        <circle cx="28" cy="26" r="12" fill="#0D1321" stroke="rgba(255, 255, 255, 0.12)" stroke-width="1.2"/>
                        <circle cx="28" cy="26" r="12" fill="none" stroke="#35D6E8" stroke-width="1.6" stroke-dasharray="20 14" stroke-linecap="round"/>
                        <!-- Graph Links -->
                        <line x1="21" y1="21" x2="35" y2="23" stroke="#8B7CFF" stroke-width="1.6"/>
                        <line x1="35" y1="23" x2="27" y2="33" stroke="#35D6E8" stroke-width="1.6"/>
                        <!-- Radar Hands -->
                        <line x1="28" y1="26" x2="28" y2="18" stroke="#35D6E8" stroke-width="2" stroke-linecap="round"/>
                        <line x1="28" y1="26" x2="33" y2="26" stroke="#10B981" stroke-width="1.8" stroke-linecap="round"/>
                        <!-- Glowing Pivots -->
                        <circle cx="28" cy="26" r="2.2" fill="#FFFFFF"/>
                        <circle cx="21" cy="21" r="2.5" fill="#8B7CFF"/>
                        <circle cx="35" cy="23" r="2.7" fill="#35D6E8"/>
                        <circle cx="27" cy="33" r="2.5" fill="#10B981"/>
                    </svg>
                </div>
                <div style="display: flex; flex-direction: column; justify-content: center; min-width: 0; flex: 1; overflow: hidden;">
                    <div style="font-family: 'Inter', -apple-system, sans-serif; font-size: 1.12rem; font-weight: 800; letter-spacing: 0.04em; line-height: 1.1; color: #F1F5F9; white-space: nowrap;">
                        CHRONO<span style="color: #35D6E8;">TRACE</span>
                    </div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.58rem; font-weight: 700; color: #35D6E8; letter-spacing: 0.12em; margin-top: 2px; text-transform: uppercase; white-space: nowrap;">
                        FORENSIC RECONSTRUCTION
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # 2. Forensic Workspaces Section Header
        st.markdown(
            "<div style='margin-top: 6px; margin-bottom: 5px; font-size: 0.65rem; font-weight: 700; color: #64748B; letter-spacing: 0.08em; text-transform: uppercase;'>Workspaces</div>",
            unsafe_allow_html=True
        )

        for item in NAV_ITEMS:
            st.page_link(
                item["file"],
                label=item["label"],
                icon=item["icon"],
                use_container_width=True
            )

        st.markdown("<hr style='margin: 12px 0; border-color: rgba(255, 255, 255, 0.06);'/>", unsafe_allow_html=True)

        # 3. Active Investigation Case Management
        invs = get_investigations()
        if not invs:
            seed_demo_data()
            invs = get_investigations()

        inv_options = {inv["id"]: f"{'[DEMO] ' if inv.get('is_demo') else '[LIVE] '}{inv['name']}" for inv in invs}

        if "active_investigation_id" not in st.session_state or st.session_state["active_investigation_id"] not in inv_options:
            st.session_state["active_investigation_id"] = list(inv_options.keys())[0]

        st.markdown(
            "<div style='margin-bottom: 4px; font-size: 0.65rem; font-weight: 700; color: #64748B; letter-spacing: 0.08em; text-transform: uppercase;'>Active Case</div>",
            unsafe_allow_html=True
        )

        selected_id = st.selectbox(
            "Active Investigation",
            options=list(inv_options.keys()),
            format_func=lambda x: inv_options[x],
            index=list(inv_options.keys()).index(st.session_state["active_investigation_id"]),
            key="sb_inv_selector",
            label_visibility="collapsed"
        )
        st.session_state["active_investigation_id"] = selected_id

        # Quick Case Creation Button & Reset Demo (Adequate space, zero vertical letter wrapping)
        col_new, col_rst = st.columns([1, 1], gap="small")
        with col_new:
            if hasattr(st, "dialog"):
                if st.button("+ New Case", key="sb_btn_new_case", use_container_width=True, help="Create a new forensic case"):
                    _create_case_dialog()
            else:
                with st.expander("+ New Case"):
                    new_id = st.text_input("Case ID", value=f"inv-case-{len(invs)+1:02d}")
                    new_name = st.text_input("Title")
                    if st.button("Save"):
                        create_investigation(new_id, new_name, "", "Active", False)
                        st.session_state["active_investigation_id"] = new_id
                        st.rerun()

        with col_rst:
            if st.button("↺ Reset Demo", key="sb_btn_reset_demo", help="Resets synthetic demonstration evidence", use_container_width=True):
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

        # 4. Scope Status Card
        current_inv = next((i for i in invs if i["id"] == selected_id), None)
        if current_inv:
            is_demo = bool(current_inv.get("is_demo"))
            badge_cls = "badge-demo" if is_demo else "badge-high-conf"
            scope_label = "DEMO CASE (SYNTHETIC)" if is_demo else "LIVE INVESTIGATION"
            st.markdown(
                f"""
                <div style="background: #111827; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 6px; padding: 10px 12px; margin: 10px 0;">
                    <div style="font-size: 0.62rem; color: #64748B; text-transform: uppercase; font-family: 'JetBrains Mono', monospace; font-weight: 600;">Case Scope</div>
                    <div style="font-size: 0.80rem; font-weight: 600; color: #F1F5F9; margin: 2px 0 6px 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                        {current_inv['name']}
                    </div>
                    <span class="soc-badge {badge_cls}">
                        {scope_label}
                    </span>
                </div>
                """,
                unsafe_allow_html=True
            )

        # 5. Global Health Status Footer
        st.markdown(
            """
            <div style="padding-top: 6px; border-top: 1px solid rgba(255, 255, 255, 0.06);">
                <div class="status-pill"><span class="status-dot dot-green"></span> <span>SQLite: WAL Mode</span></div>
                <div class="status-pill"><span class="status-dot dot-cyan"></span> <span>Engine: Deterministic</span></div>
                <div class="status-pill"><span class="status-dot dot-violet"></span> <span>Rule 0: Enforced (raw_ref)</span></div>
                <div style="margin-top: 6px; font-size: 0.65rem; color: #64748B; font-family: 'JetBrains Mono', monospace;">
                    ChronoTrace v1.0.0-soc
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
    """Renders top command bar and returns synchronized global filters."""
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
        shield_micro = icon_svg("shield", size=14, color=ACCENT_CYAN)
        st.markdown(
            f"""
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 2px;">
                <span style="display: inline-flex; align-items: center;">{shield_micro}</span>
                <span style="font-size: 0.74rem; color: #64748B; font-family: 'JetBrains Mono', monospace;">ChronoTrace /</span>
                <span style="font-size: 0.74rem; color: #35D6E8; font-weight: 700; font-family: 'JetBrains Mono', monospace;">{breadcrumb_label}</span>
                <span class="soc-badge {'badge-demo' if is_demo else 'badge-high-conf'}">
                    {'DEMO CASE' if is_demo else 'LIVE CASE'}
                </span>
            </div>
            <h2 style="margin: 0; font-size: 1.45rem; color: #F1F5F9; font-weight: 700; letter-spacing: -0.02em;">{breadcrumb_label}</h2>
            """,
            unsafe_allow_html=True
        )

    with col2:
        clock_micro = icon_svg("clock", size=13, color=ACCENT_CYAN)
        st.markdown(
            f"""
            <div style="text-align: right; margin-top: 2px;">
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.80rem; color: #35D6E8; font-weight: 600; display: inline-flex; align-items: center; gap: 5px;">
                    {clock_micro} {now_utc}
                </div>
                <div style="font-size: 0.74rem; color: #94A3B8; margin-top: 2px;">
                    Case: <strong style="color: #F1F5F9;">{investigation.get('name', 'N/A')[:32]}</strong>
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

    st.markdown("<hr style='margin: 8px 0 14px 0; border-color: rgba(255, 255, 255, 0.06);'/>", unsafe_allow_html=True)

    return {
        "search": search_query.strip().lower(),
        "host": selected_host,
        "source": selected_source,
        "min_confidence": min_conf
    }
