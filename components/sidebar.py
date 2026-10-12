"""Global Sidebar Component for ChronoTrace.

Renders:
- Crisp, high-definition SVG insignia & brandmark
- Glitch-free native st.page_link navigation with custom cyber styling
- Active investigation selector (Demo vs Real)
- Quick case creation modal
- System health & DB connection status
"""

import streamlit as st
import os
import base64
from database.db import get_investigations, create_investigation
from data.demo_seed import seed_demo_data

LOGO_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets", "logo.svg")

NAV_ITEMS = [
    {"label": "Overview", "icon": "📊", "file": "pages/1_Investigation_Overview.py", "id": "overview"},
    {"label": "Evidence Ingestion", "icon": "📥", "file": "pages/2_Evidence_Ingestion.py", "id": "ingestion"},
    {"label": "Attack Timeline", "icon": "⏱️", "file": "pages/3_Attack_Timeline.py", "id": "timeline"},
    {"label": "Provenance Graph", "icon": "🕸️", "file": "pages/4_Provenance_Graph.py", "id": "graph"},
    {"label": "Evidence Explorer", "icon": "🔬", "file": "pages/5_Evidence_Explorer.py", "id": "explorer"},
    {"label": "Findings & Reports", "icon": "📑", "file": "pages/6_Findings_and_Reports.py", "id": "reports"}
]


def render_sidebar(current_page_id: str = "overview") -> str:
    """Renders persistent sidebar and returns active investigation_id."""
    with st.sidebar:
        # 1. High-Definition Vector Brandmark & Typography (Fitted Header)
        st.markdown(
            """
            <div style="display: flex; align-items: center; gap: 11px; padding: 4px 2px 14px 2px; border-bottom: 1px solid rgba(53, 214, 232, 0.18); margin-bottom: 12px; width: 100%;">
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
                    <div style="font-family: 'Inter', -apple-system, sans-serif; font-size: 1.32rem; font-weight: 900; letter-spacing: 0.05em; line-height: 1.15; color: #FFFFFF; white-space: nowrap;">
                        CHRONO<span style="color: #35D6E8; text-shadow: 0 0 12px rgba(53, 214, 232, 0.75);">TRACE</span>
                    </div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.62rem; font-weight: 800; color: #35D6E8; letter-spacing: 0.14em; margin-top: 3px; text-transform: uppercase; white-space: nowrap;">
                        FORENSIC RECONSTRUCTION
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # 2. Glitch-Free Native Page Navigation Links
        st.markdown(
            "<div style='margin-top: 14px; margin-bottom: 8px; font-size: 0.68rem; font-weight: 800; color: #94A7C2; letter-spacing: 0.1em; text-transform: uppercase;'>Forensic Workspaces</div>", 
            unsafe_allow_html=True
        )

        for item in NAV_ITEMS:
            st.page_link(
                item["file"],
                label=item["label"],
                icon=item["icon"],
                use_container_width=True
            )

        st.markdown("<hr style='margin: 16px 0; border-color: rgba(148,167,194,0.12);'/>", unsafe_allow_html=True)

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
            key="sb_inv_selector"
        )
        st.session_state["active_investigation_id"] = selected_id

        # Quick New Investigation Dialog
        with st.expander("➕ New Investigation", expanded=False):
            new_id = st.text_input("Case ID", value=f"inv-case-{len(invs)+1:02d}", key="new_inv_id_in")
            new_name = st.text_input("Case Name", placeholder="e.g. Incident Alpha 2026", key="new_inv_name_in")
            new_desc = st.text_area("Scope / Notes", placeholder="Victim host and evidence details...", key="new_inv_desc_in")
            if st.button("Create Case", key="create_new_case_btn", use_container_width=True):
                if new_name.strip():
                    create_investigation(new_id.strip(), new_name.strip(), new_desc.strip(), status="Active", is_demo=False)
                    st.session_state["active_investigation_id"] = new_id.strip()
                    st.session_state["sb_inv_selector"] = new_id.strip()
                    st.success(f"Case '{new_name}' initialized.")
                    st.rerun()
                else:
                    st.warning("Please specify an investigation name.")

        # Reload Demo Case Button
        if st.button("🔄 Reset Demo Case", key="reload_demo_btn", help="Re-seeds the synthetic demonstration case", use_container_width=True):
            seed_demo_data(force=True)
            st.session_state["active_investigation_id"] = "inv-demo-01"
            st.session_state["sb_inv_selector"] = "inv-demo-01"
            st.session_state.pop("selected_timeline_eid", None)
            st.session_state.pop("active_explorer_ref", None)
            st.session_state.pop("selected_raw_ref", None)
            st.session_state.pop("timeline_dataframe_selection", None)
            st.session_state.pop("evidence_table_selection", None)
            st.success("Synthetic demo investigation reset!")
            st.rerun()

        # 4. Scope Badge
        current_inv = next((i for i in invs if i["id"] == selected_id), None)
        if current_inv:
            is_demo = bool(current_inv.get("is_demo"))
            st.markdown(
                f"""
                <div style="background: #121D30; border: 1px solid rgba(53,214,232,0.22); border-radius: 6px; padding: 10px; margin: 12px 0;">
                    <div style="font-size: 0.68rem; color: #94A7C2; text-transform: uppercase; font-family: monospace;">Case Scope</div>
                    <div style="font-size: 0.8rem; font-weight: 700; color: #EDF4FF; margin: 2px 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                        {current_inv['name']}
                    </div>
                    <span class="badge {'badge-demo' if is_demo else 'badge-high-conf'}" style="font-size: 0.68rem;">
                        {'DEMO MODE — SYNTHETIC' if is_demo else 'LIVE INVESTIGATION'}
                    </span>
                </div>
                """,
                unsafe_allow_html=True
            )

        # 5. Global Status Footer
        st.markdown(
            """
            <div style="padding-top: 4px;">
                <div class="status-pill"><span class="status-dot dot-green"></span> <span>SQLite: Connected (WAL)</span></div>
                <div class="status-pill"><span class="status-dot dot-cyan"></span> <span>Engine: EVTX + JSON</span></div>
                <div class="status-pill"><span class="status-dot dot-amber"></span> <span>Model: Rule-Based (No ML)</span></div>
                <div style="margin-top: 8px; font-size: 0.68rem; color: #5B6B82; font-family: monospace;">
                    ChronoTrace v1.0.0-prototype
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        return selected_id
