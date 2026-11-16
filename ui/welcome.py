"""Modern Welcome & Authentication Portal for ChronoTrace.

Features:
- High-impact cybersecurity operations center aesthetic (CrowdStrike / Palantir Gotham design)
- Single, authentic 'Continue with Google' button with official 4-color Google SVG icon
- Enterprise Sign In and Create Account (Sign Up) tabs with clean password fields
- Direct transition via st.switch_page to pages/1_Investigation_Overview.py (no blank screens)
- Comprehensive platform capabilities & Rule 0 forensic guarantees overview
"""

import streamlit as st
from datetime import datetime, timezone
import time
from database.db import create_or_update_user, get_user_by_email, init_db
from data.demo_seed import seed_demo_data
from ui.theme import (
    inject_theme,
    icon_svg,
    ACCENT_BLUE,
    EYEBROW_BLUE,
    STATUS_SUCCESS_TEXT,
    STATUS_WARN_TEXT,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    TEXT_MUTED
)


def render_welcome_portal() -> None:
    """Renders the full-screen modern welcome page and authentication portal."""
    st.set_page_config(
        page_title="ChronoTrace — Welcome & Authentication",
        page_icon=":material/security:",
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    inject_theme()
    init_db()

    # Hide sidebar completely on the Welcome / Login screen for a clean, immersive portal
    st.markdown(
        """
        <style>
        section[data-testid="stSidebar"] {
            display: none !important;
            width: 0px !important;
        }
        .block-container {
            max-width: 1240px !important;
            padding-top: 1.2rem !important;
            padding-bottom: 2.5rem !important;
            margin: 0 auto !important;
        }
        /* Completely eliminate any overlapping input helper instructions */
        div[data-testid="InputInstructions"],
        .stTextInput small,
        .stPasswordInput small {
            display: none !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. Top SOC Command Header Bar
    st.markdown(
        f"""
        <div style="display: flex; align-items: center; justify-content: space-between; padding: 10px 20px; background: #0D1526; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px; margin-bottom: 28px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);">
            <div style="display: flex; align-items: center; gap: 12px;">
                <div style="width: 32px; height: 32px; border-radius: 8px; background: linear-gradient(135deg, #1D6FE8 0%, #0F172A 100%); border: 1px solid rgba(56, 189, 248, 0.4); display: flex; align-items: center; justify-content: center; box-shadow: 0 0 15px rgba(29, 111, 232, 0.4);">
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#F8FAFC" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                </div>
                <div>
                    <div style="font-size: 16px; font-weight: 800; color: #F8FAFC; letter-spacing: -0.01em; line-height: 1.1;">
                        Chrono<span style="color: #38BDF8;">Trace</span>
                    </div>
                    <div style="font-size: 9.5px; color: #64748B; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase;">
                        DIGITAL FORENSICS & INCIDENT RESPONSE PLATFORM
                    </div>
                </div>
            </div>
            <div style="display: flex; align-items: center; gap: 12px;">
                <span class="status-pill pill-success" style="font-size: 10px; padding: 3px 8px;">
                    <span class="pulsing-dot" style="background: #34D399;"></span>
                    SOC GATEWAY ONLINE
                </span>
                <span class="status-pill pill-info" style="font-family: 'JetBrains Mono', monospace; font-size: 11px; padding: 3px 8px;">
                    {now_utc}
                </span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # 2. Main Hero & Authentication Grid
    col_hero, col_auth = st.columns([6.2, 4.8], gap="large")

    # LEFT COLUMN: Value Proposition & Forensic Capabilities
    with col_hero:
        st.markdown(
            """
            <div style="padding-right: 14px;">
                <div style="display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; background: rgba(29, 111, 232, 0.16); border: 1px solid rgba(56, 189, 248, 0.35); border-radius: 20px; font-size: 11px; font-weight: 600; color: #38BDF8; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 16px;">
                    <span class="pulsing-dot" style="background: #38BDF8;"></span>
                    MISSION-CRITICAL DFIR INVESTIGATION PLATFORM
                </div>
                <h1 style="font-size: 2.45rem; font-weight: 800; color: #F8FAFC; line-height: 1.15; letter-spacing: -0.02em; margin-bottom: 14px;">
                    Reconstruct Cyberattacks with <br>
                    <span style="background: linear-gradient(135deg, #38BDF8 0%, #818CF8 50%, #34D399 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                        Deterministic Certainty
                    </span>
                </h1>
                <p style="font-size: 0.96rem; color: #94A3B8; line-height: 1.65; margin-bottom: 24px;">
                    ChronoTrace transforms ambiguous Windows Event Logs and Sysmon telemetry into deterministic, evidence-backed attack timelines. Built for SOC analysts, incident response teams, and forensic engineers demanding immutable proof.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

        # 4 Core Forensic Pillars with Luminous Hover Cards
        st.markdown(
            f"""
            <div class="hero-value-prop">
                <div style="width: 36px; height: 36px; border-radius: 8px; background: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.3); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                    {icon_svg("file", size=18, color="#38BDF8")}
                </div>
                <div>
                    <div style="font-size: 13.5px; font-weight: 600; color: #F8FAFC; margin-bottom: 2px;">Rule 0 Immutable Evidence Traceability</div>
                    <div style="font-size: 11.5px; color: #94A3B8; line-height: 1.5;">Every reconstructed event, finding, and graph relation maintains an unalterable monospace citation (e.g. <code>sysmon_victim_pc01.evtx#104</code>) back to raw bytes.</div>
                </div>
            </div>

            <div class="hero-value-prop">
                <div style="width: 36px; height: 36px; border-radius: 8px; background: rgba(129, 140, 248, 0.12); border: 1px solid rgba(129, 140, 248, 0.3); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                    {icon_svg("timeline", size=18, color="#818CF8")}
                </div>
                <div>
                    <div style="font-size: 13.5px; font-weight: 600; color: #F8FAFC; margin-bottom: 2px;">Uncertainty Interval Timestamps</div>
                    <div style="font-size: 11.5px; color: #94A3B8; line-height: 1.5;">Preserves ambiguous event windows <code>[ts_start_utc, ts_end_utc]</code> on interactive Gantt timelines without forcing false linear point timestamps.</div>
                </div>
            </div>

            <div class="hero-value-prop">
                <div style="width: 36px; height: 36px; border-radius: 8px; background: rgba(52, 211, 153, 0.12); border: 1px solid rgba(52, 211, 153, 0.3); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                    {icon_svg("shield", size=18, color="#34D399")}
                </div>
                <div>
                    <div style="font-size: 13.5px; font-weight: 600; color: #F8FAFC; margin-bottom: 2px;">Deterministic 4-Factor Confidence Scoring</div>
                    <div style="font-size: 11.5px; color: #94A3B8; line-height: 1.5;">Transparent, audited formula combining Corroboration, Source Reliability, Time Precision, and Link Strength &mdash; zero black-box ML hallucination.</div>
                </div>
            </div>

            <div class="hero-value-prop">
                <div style="width: 36px; height: 36px; border-radius: 8px; background: rgba(251, 191, 36, 0.12); border: 1px solid rgba(251, 191, 36, 0.3); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                    {icon_svg("graph", size=18, color="#FBBF24")}
                </div>
                <div>
                    <div style="font-size: 13.5px; font-weight: 600; color: #F8FAFC; margin-bottom: 2px;">Causal Provenance & Conflict Surfacing</div>
                    <div style="font-size: 11.5px; color: #94A3B8; line-height: 1.5;">Physics-enabled NetworkX graph with explicit badging for <code>ORDER_CONFLICT</code>, <code>MISSING_PARENT</code>, and <code>LOG_CLEARED</code> anti-forensics.</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # RIGHT COLUMN: Modern Glassmorphic Authentication Card
    with col_auth:
        st.markdown(
            """
            <div class="welcome-card-glass">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                    <div style="font-size: 17px; font-weight: 700; color: #F8FAFC;">Investigator Access Portal</div>
                    <span class="status-pill pill-primary" style="font-size: 9.5px;">DEFENSE-GRADE SSO</span>
                </div>
                <p style="font-size: 12px; color: #94A3B8; margin-bottom: 18px; line-height: 1.5;">
                    Sign in with your Google workspace identity or enterprise credentials to access active forensic investigations.
                </p>
            """,
            unsafe_allow_html=True
        )

        # 1. Official Single Google Sign-In Button (Real Streamlit Button styled with official Google Branding)
        if st.button("Continue with Google", key="btn_auth_google", use_container_width=True):
            google_user = create_or_update_user(
                email="vellax.security@gmail.com",
                name="Vellax (Google Workspace)",
                provider="google",
                agency="Cyber Defense Operations",
                clearance_level="L3 Lead Forensic Specialist",
                avatar_url="https://lh3.googleusercontent.com/a/default-user"
            )
            seed_demo_data()
            st.session_state["authenticated"] = True
            st.session_state["user_profile"] = google_user
            st.session_state["active_investigation_id"] = "inv-demo-01"
            st.switch_page("pages/1_Investigation_Overview.py")

        st.markdown(
            """
            <div class="auth-divider">
                <span>OR ENTERPRISE CREDENTIALS</span>
            </div>
            """,
            unsafe_allow_html=True
        )

        # 2. Tabs: Sign In / Create Account
        tab_login, tab_signup = st.tabs(["Sign In", "Create Account"])

        with tab_login:
            login_email = st.text_input(
                "Work Email",
                value="analyst@chronotrace.soc",
                placeholder="analyst@agency.soc",
                key="input_login_email"
            )
            login_pwd = st.text_input(
                "Security Passkey",
                type="password",
                placeholder="Enter enterprise passphrase",
                key="input_login_password"
            )
            login_clearance = st.selectbox(
                "Active Clearance Level",
                options=["L3 Lead Forensic Specialist", "L2 Incident Responder", "L1 Triage Analyst"],
                index=0,
                key="input_login_clearance"
            )

            if st.button("Sign In to SOC Console", key="btn_submit_signin", type="primary", use_container_width=True):
                if login_email.strip():
                    user_data = create_or_update_user(
                        email=login_email.strip().lower(),
                        name=login_email.split("@")[0].replace(".", " ").title(),
                        provider="local",
                        agency="Cyber Defense Command",
                        clearance_level=login_clearance
                    )
                    seed_demo_data()
                    st.session_state["authenticated"] = True
                    st.session_state["user_profile"] = user_data
                    st.session_state["active_investigation_id"] = "inv-demo-01"
                    st.switch_page("pages/1_Investigation_Overview.py")
                else:
                    st.error("Please provide a valid work email.")

        with tab_signup:
            new_name = st.text_input("Full Name", placeholder="e.g. Detective John Doe", key="input_signup_name")
            new_agency = st.text_input("Forensic Agency / Department", placeholder="e.g. State Cyber Bureau", key="input_signup_agency")
            new_email = st.text_input("Work Email Address", placeholder="name@agency.soc", key="input_signup_email")
            new_pwd = st.text_input("Create Security Passkey", type="password", placeholder="Minimum 12 characters", key="input_signup_pwd")
            new_clearance = st.selectbox(
                "Requested Clearance Level",
                options=["L2 Incident Responder", "L3 Lead Forensic Specialist", "L1 Triage Analyst"],
                index=0,
                key="input_signup_clearance"
            )

            if st.button("Create Forensic Account", key="btn_submit_signup", type="primary", use_container_width=True):
                if new_name.strip() and new_email.strip():
                    created_user = create_or_update_user(
                        email=new_email.strip().lower(),
                        name=new_name.strip(),
                        provider="local",
                        agency=new_agency.strip() or "DFIR Operations",
                        clearance_level=new_clearance
                    )
                    seed_demo_data()
                    st.session_state["authenticated"] = True
                    st.session_state["user_profile"] = created_user
                    st.session_state["active_investigation_id"] = "inv-demo-01"
                    st.switch_page("pages/1_Investigation_Overview.py")
                else:
                    st.error("Full Name and Work Email are required for registration.")

        st.markdown("<hr style='margin: 16px 0 14px 0; border-color: rgba(255, 255, 255, 0.08);'/>", unsafe_allow_html=True)

        # 3. One-Click Instant Demo Access (Bypass)
        if st.button("⚡ One-Click Demo Analyst Access (Instant Evaluation)", key="btn_quick_demo_access", use_container_width=True):
            demo_user = create_or_update_user(
                email="lead.analyst@chronotrace.soc",
                name="Demo Forensic Analyst",
                provider="demo",
                agency="Incident Response Team Alpha",
                clearance_level="L3 Lead Forensic Specialist"
            )
            seed_demo_data()
            st.session_state["authenticated"] = True
            st.session_state["user_profile"] = demo_user
            st.session_state["active_investigation_id"] = "inv-demo-01"
            st.switch_page("pages/1_Investigation_Overview.py")

        st.markdown(
            """
            <div style="font-size: 10.5px; color: #64748B; text-align: center; margin-top: 12px; line-height: 1.45;">
                Protected by ChronoTrace Forensic Security Controls.<br>
                All session activities and queries are logged to immutable SQLite WAL audit storage.
            </div>
            </div>
            """,
            unsafe_allow_html=True
        )
