"""Shared UI Layout Module for ChronoTrace — Modern Desktop Styling.

Directly matches the visual structure and layout of the desktop console reference:
- Flat borderless 255px sidebar with brand badge, workspace navigation, case engine controls,
  and bottom 'CONNECTED TELEMETRY' status card with animated pulsing status dot.
- Fixed 48px top command bar with live UTC chronometer, case badges, and synchronized filters.
"""

import streamlit as st
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from database.db import get_investigations, create_investigation
from data.demo_seed import seed_demo_data
from ui.theme import icon_svg, ACCENT_BLUE, EYEBROW_BLUE, TEXT_PRIMARY, TEXT_MUTED

NAV_ITEMS = [
    {"label": "Investigation Overview", "icon": ":material/dashboard:", "file": "pages/1_Investigation_Overview.py", "id": "overview", "match": "overview"},
    {"label": "Evidence Ingestion", "icon": ":material/upload_file:", "file": "pages/2_Evidence_Ingestion.py", "id": "ingestion", "match": "ingestion"},
    {"label": "Attack Timeline", "icon": ":material/timeline:", "file": "pages/3_Attack_Timeline.py", "id": "timeline", "match": "timeline"},
    {"label": "Provenance Graph", "icon": ":material/hub:", "file": "pages/4_Provenance_Graph.py", "id": "graph", "match": "graph"},
    {"label": "Evidence Explorer", "icon": ":material/manage_search:", "file": "pages/5_Evidence_Explorer.py", "id": "explorer", "match": "explorer"},
    {"label": "Findings & Reports", "icon": ":material/description:", "file": "pages/6_Findings_and_Reports.py", "id": "reports", "match": "reports"}
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
    """Renders flat borderless 268px desktop console sidebar (fixed non-scrolling dock)."""
    with st.sidebar:
        # 1. Top Brand Lockup (Shifted to absolute top flush with window and topbar)
        st.markdown(
            """
            <div style="display: flex; align-items: center; gap: 9px; padding: 2px 4px 8px 2px; border-bottom: 1px solid rgba(255, 255, 255, 0.06); margin-bottom: 8px; width: 100%;">
                <div style="width: 30px; height: 30px; border-radius: 6px; background: linear-gradient(135deg, #1D6FE8 0%, #0F172A 100%); border: 1px solid rgba(56, 189, 248, 0.35); display: flex; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 2px 8px rgba(29, 111, 232, 0.3);">
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#F8FAFC" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                </div>
                <div style="display: flex; flex-direction: column; justify-content: center; min-width: 0; flex: 1; overflow: hidden;">
                    <div style="font-family: 'Inter', sans-serif; font-size: 14px; font-weight: 700; color: #F8FAFC; letter-spacing: -0.01em; line-height: 1.1; white-space: nowrap;">
                        Chrono<span style="color: #38BDF8;">Trace</span>
                    </div>
                    <div style="font-family: 'Inter', sans-serif; font-size: 9.5px; font-weight: 600; color: #64748B; letter-spacing: 0.08em; margin-top: 1px; text-transform: uppercase; white-space: nowrap;">
                        DFIR CONSOLE v1.0.0
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # 2. Workspace Navigation Section with High-Contrast Active Indicator
        st.markdown(
            "<div style='margin-bottom: 2px; font-size: 9.5px; font-weight: 600; color: #64748B; letter-spacing: 0.08em; text-transform: uppercase;'>Workspace</div>",
            unsafe_allow_html=True
        )

        active_item = next((item for item in NAV_ITEMS if item["id"] == current_page_id), NAV_ITEMS[0])
        active_match = active_item.get("match", "overview")

        # Inject high-visibility active workspace style targeting this specific page
        st.markdown(
            f"""
            <style>
            section[data-testid="stSidebar"] div.stPageLink a[href*="{active_match}" i] {{
                background: #1D6FE8 !important;
                background-color: #1D6FE8 !important;
                border: 1px solid #38BDF8 !important;
                border-left: 3px solid #38BDF8 !important;
                color: #FFFFFF !important;
                font-weight: 600 !important;
                box-shadow: 0 2px 12px rgba(29, 111, 232, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.2) !important;
                transform: none !important;
            }}
            section[data-testid="stSidebar"] div.stPageLink a[href*="{active_match}" i] p {{
                color: #FFFFFF !important;
                font-weight: 600 !important;
            }}
            section[data-testid="stSidebar"] div.stPageLink a[href*="{active_match}" i] span,
            section[data-testid="stSidebar"] div.stPageLink a[href*="{active_match}" i] [data-testid="stIconMaterial"] {{
                color: #FFFFFF !important;
                font-weight: 600 !important;
                fill: #FFFFFF !important;
            }}
            section[data-testid="stSidebar"] div.stPageLink a[href*="{active_match}" i]:hover {{
                background: #2563EB !important;
                background-color: #2563EB !important;
                border-color: #60A5FA !important;
                border-left-color: #38BDF8 !important;
                color: #FFFFFF !important;
                transform: none !important;
                box-shadow: 0 4px 14px rgba(29, 111, 232, 0.65) !important;
            }}
            </style>
            """,
            unsafe_allow_html=True
        )

        for item in NAV_ITEMS:
            st.page_link(
                item["file"],
                label=item["label"],
                icon=item["icon"],
                use_container_width=True
            )

        st.markdown("<hr style='margin: 8px 0; border-color: rgba(255, 255, 255, 0.06);'/>", unsafe_allow_html=True)

        # 3. Case & Engine Management Section
        st.markdown(
            "<div style='margin-bottom: 2px; font-size: 9.5px; font-weight: 600; color: #64748B; letter-spacing: 0.08em; text-transform: uppercase;'>Case & Engine</div>",
            unsafe_allow_html=True
        )

        invs = get_investigations()
        if not invs:
            seed_demo_data()
            invs = get_investigations()

        inv_options = {inv["id"]: f"{'[DEMO] ' if inv.get('is_demo') else '[LIVE] '}{inv['name']}" for inv in invs}

        if "active_investigation_id" not in st.session_state or st.session_state["active_investigation_id"] not in inv_options:
            st.session_state["active_investigation_id"] = list(inv_options.keys())[0]

        selected_id = st.selectbox(
            "Select Case",
            options=list(inv_options.keys()),
            format_func=lambda x: inv_options[x],
            index=list(inv_options.keys()).index(st.session_state["active_investigation_id"]),
            key="sb_inv_selector",
            label_visibility="collapsed"
        )
        st.session_state["active_investigation_id"] = selected_id

        # Clean single-line action buttons with prioritized ratio so Reset Demo never clips
        col_new, col_rst = st.columns([0.82, 1.18], gap="small")
        with col_new:
            if hasattr(st, "dialog"):
                if st.button("+ New Case", key="sb_btn_new_case", use_container_width=True):
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
            if st.button("↺ Reset Demo", key="sb_btn_reset_demo", use_container_width=True):
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

        # 4. Connected Telemetry Status Card (Matching 'CONNECTED DEVICE' from screenshots)
        current_inv = next((i for i in invs if i["id"] == selected_id), None)
        inv_name = current_inv["name"] if current_inv else "Active Case"
        is_demo = bool(current_inv.get("is_demo")) if current_inv else False

        st.markdown(
            f"""
            <div style="background: #0D1526; border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 6px; padding: 8px 10px; margin-top: 8px;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 2px;">
                    <span style="font-size: 9.5px; font-weight: 600; color: #64748B; text-transform: uppercase; letter-spacing: 0.06em;">CONNECTED TELEMETRY</span>
                    <span style="display: inline-flex; align-items: center; gap: 4px; font-size: 9.5px; color: #34D399; font-weight: 600;">
                        <span class="pulsing-dot" style="background: #34D399;"></span>
                        {'DEMO' if is_demo else 'LIVE'}
                    </span>
                </div>
                <div style="font-size: 11.5px; font-weight: 600; color: #F8FAFC; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                    {inv_name}
                </div>
                <div style="font-size: 10px; color: #64748B; margin-top: 2px; font-family: 'JetBrains Mono', monospace;">
                    Sysmon • WinSec • Rule 0
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # 5. Authenticated Analyst Profile Dock & Sign Out
        user_prof = st.session_state.get("user_profile")
        if not user_prof:
            user_prof = {
                "name": "Forensic Investigator",
                "email": "analyst@chronotrace.soc",
                "provider": "google",
                "clearance_level": "L3 Lead Specialist"
            }
        is_google = user_prof.get("provider") == "google"
        prov_badge = f'<span class="status-pill pill-primary" style="font-size: 8.5px; padding: 1px 4px;">{icon_svg("google", size=9)} GOOGLE</span>' if is_google else '<span class="status-pill pill-info" style="font-size: 8.5px; padding: 1px 4px;">SECURE SOC</span>'

        st.markdown(
            f"""
            <div style="background: #090E1A; border: 1px solid rgba(255, 255, 255, 0.07); border-radius: 6px; padding: 7px 10px; margin-top: 7px;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 2px;">
                    <span style="font-size: 9px; font-weight: 600; color: #64748B; text-transform: uppercase; letter-spacing: 0.06em;">INVESTIGATOR</span>
                    {prov_badge}
                </div>
                <div style="font-size: 11px; font-weight: 600; color: #F8FAFC; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                    {user_prof.get('name', 'Forensic Investigator')}
                </div>
                <div style="font-size: 9px; color: #64748B; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: 'JetBrains Mono', monospace;">
                    {user_prof.get('email', 'analyst@chronotrace.soc')}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        if st.button("⎋ Sign Out", key="sb_btn_signout", use_container_width=True):
            st.session_state["authenticated"] = False
            st.session_state.pop("user_profile", None)
            try:
                st.switch_page("app.py")
            except Exception:
                st.rerun()

        return selected_id


def render_topbar(
    breadcrumb_label: str,
    investigation: Dict[str, Any],
    hosts: List[str] = None,
    sources: List[str] = None
) -> Dict[str, Any]:
    """Renders 48px fixed top command bar and returns synchronized global filters."""
    if hosts is None:
        hosts = []
    if sources is None:
        sources = []

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    is_demo = bool(investigation.get("is_demo", 0))

    if "global_host" not in st.session_state:
        st.session_state["global_host"] = "All Hosts"
    if "global_source" not in st.session_state:
        st.session_state["global_source"] = "All Sources"
    if "global_search" not in st.session_state:
        st.session_state["global_search"] = ""
    if "global_min_confidence" not in st.session_state:
        st.session_state["global_min_confidence"] = 0.0

    # 48px Top Command Bar with Smooth Layout
    st.markdown(
        f"""
        <div style="background: #0D1526; border-bottom: 1px solid rgba(255, 255, 255, 0.06); margin: -0.9rem -2rem 14px -2rem; padding: 8px 2rem; display: flex; align-items: center; justify-content: space-between; height: 48px;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 13px; font-weight: 600; color: #F8FAFC;">ChronoTrace</span>
                <span class="status-pill pill-success" style="font-size: 10px; padding: 1px 6px;">v1.0.0</span>
                <span style="color: #64748B; font-size: 12px;">/</span>
                <span style="font-size: 12px; color: #94A3B8; font-weight: 500;">{breadcrumb_label}</span>
            </div>
            <div style="display: flex; align-items: center; gap: 8px;">
                <span class="status-pill {'pill-primary' if is_demo else 'pill-success'}">
                    {'DEMO CASE' if is_demo else 'LIVE CASE'}
                </span>
                <span class="status-pill pill-info" style="font-family: 'JetBrains Mono', monospace; font-size: 11px;">
                    {now_utc}
                </span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Compact Global Filter Bar
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

    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

    return {
        "search": search_query.strip().lower(),
        "host": selected_host,
        "source": selected_source,
        "min_confidence": min_conf
    }
