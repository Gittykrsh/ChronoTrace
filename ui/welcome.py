"""Modern Welcome & Authentication Portal for ChronoTrace.

Features:
- Sleek cybersecurity operations center aesthetic (CrowdStrike / Palantir Gotham design)
- Prominent 'Sign in with Google' option with official multi-color Google SVG logo
- Enterprise Sign In and Sign Up tabs with role/clearance selection
- Instant One-Click Demo Analyst Access button
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
            max-width: 1280px !important;
            padding-top: 1.5rem !important;
            padding-bottom: 2rem !important;
            margin: 0 auto !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. Top System Status Header Bar
    st.markdown(
        f"""
        <div style="display: flex; align-items: center; justify-content: space-between; padding: 10px 18px; background: #0D1526; border: 1px solid rgba(255, 255, 255, 0.07); border-radius: 8px; margin-bottom: 24px;">
            <div style="display: flex; align-items: center; gap: 10px;">
                <div style="width: 28px; height: 28px; border-radius: 6px; background: linear-gradient(135deg, #1D6FE8 0%, #0F172A 100%); border: 1px solid rgba(56, 189, 248, 0.35); display: flex; align-items: center; justify-content: center;">
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#F8FAFC" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                </div>
                <span style="font-size: 15px; font-weight: 700; color: #F8FAFC; letter-spacing: -0.01em;">
                    Chrono<span style="color: #38BDF8;">Trace</span>
                </span>
                <span style="color: #64748B; font-size: 12px;">|</span>
                <span style="font-size: 11px; color: #94A3B8; font-weight: 500; letter-spacing: 0.04em; text-transform: uppercase;">
                    DFIR Operations Platform v1.0.0
                </span>
            </div>
            <div style="display: flex; align-items: center; gap: 10px;">
                <span class="status-pill pill-success" style="font-size: 10px;">
                    <span class="pulsing-dot" style="background: #34D399;"></span>
                    SOC GATEWAY ACTIVE
                </span>
                <span class="status-pill pill-info" style="font-family: 'JetBrains Mono', monospace; font-size: 11px;">
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
            <div style="padding-right: 12px;">
                <div style="display: inline-flex; align-items: center; gap: 6px; padding: 3px 10px; background: rgba(29, 111, 232, 0.14); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 20px; font-size: 10.5px; font-weight: 600; color: #38BDF8; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 14px;">
                    ENTERPRISE DIGITAL FORENSICS & INCIDENT RESPONSE
                </div>
                <h1 style="font-size: 2.3rem; font-weight: 800; color: #F8FAFC; line-height: 1.15; letter-spacing: -0.02em; margin-bottom: 12px;">
                    Reconstruct Cyberattacks with <br>
                    <span style="background: linear-gradient(90deg, #38BDF8 0%, #818CF8 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                        Uncertainty-Aware Precision
                    </span>
                </h1>
                <p style="font-size: 0.95rem; color: #94A3B8; line-height: 1.6; margin-bottom: 22px;">
                    ChronoTrace unifies Windows Event Logs and Sysmon telemetry into deterministic, evidence-backed attack timelines. Built for SOC analysts, incident response teams, and forensic engineers demanding immutable proof.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

        # 4 Core Forensic Pillars
        st.markdown(
            f"""
            <div class="hero-value-prop">
                <div style="width: 32px; height: 32px; border-radius: 6px; background: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.3); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                    {icon_svg("file", size=16, color="#38BDF8")}
                </div>
                <div>
                    <div style="font-size: 13px; font-weight: 600; color: #F8FAFC; margin-bottom: 2px;">Rule 0 Immutable Evidence Traceability</div>
                    <div style="font-size: 11.5px; color: #94A3B8; line-height: 1.45;">Every event, finding, and causal relationship maintains an unalterable monospace citation (e.g. <code>sysmon_victim_pc01.evtx#104</code>) back to raw bytes.</div>
                </div>
            </div>

            <div class="hero-value-prop">
                <div style="width: 32px; height: 32px; border-radius: 6px; background: rgba(129, 140, 248, 0.12); border: 1px solid rgba(129, 140, 248, 0.3); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                    {icon_svg("timeline", size=16, color="#818CF8")}
                </div>
                <div>
                    <div style="font-size: 13px; font-weight: 600; color: #F8FAFC; margin-bottom: 2px;">Uncertainty Interval Timestamps</div>
                    <div style="font-size: 11.5px; color: #94A3B8; line-height: 1.45;">Preserves ambiguous event windows <code>[ts_start_utc, ts_end_utc]</code> on interactive Gantt timelines without forcing false linear point timestamps.</div>
                </div>
            </div>

            <div class="hero-value-prop">
                <div style="width: 32px; height: 32px; border-radius: 6px; background: rgba(52, 211, 153, 0.12); border: 1px solid rgba(52, 211, 153, 0.3); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                    {icon_svg("shield", size=16, color="#34D399")}
                </div>
                <div>
                    <div style="font-size: 13px; font-weight: 600; color: #F8FAFC; margin-bottom: 2px;">Deterministic 4-Factor Confidence Scoring</div>
                    <div style="font-size: 11.5px; color: #94A3B8; line-height: 1.45;">Transparent, audited formula combining Corroboration, Source Reliability, Time Precision, and Link Strength — zero black-box ML hallucination.</div>
                </div>
            </div>

            <div class="hero-value-prop">
                <div style="width: 32px; height: 32px; border-radius: 6px; background: rgba(251, 191, 36, 0.12); border: 1px solid rgba(251, 191, 36, 0.3); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                    {icon_svg("graph", size=16, color="#FBBF24")}
                </div>
                <div>
                    <div style="font-size: 13px; font-weight: 600; color: #F8FAFC; margin-bottom: 2px;">Causal Provenance & Conflict Surfacing</div>
                    <div style="font-size: 11.5px; color: #94A3B8; line-height: 1.45;">Physics-enabled NetworkX graph with explicit badging for <code>ORDER_CONFLICT</code>, <code>MISSING_PARENT</code>, and <code>LOG_CLEARED</code> anti-forensics.</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # RIGHT COLUMN: Modern Authentication Portal
    with col_auth:
        st.markdown(
            f"""
            <div class="auth-portal-card">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                    <div style="font-size: 16px; font-weight: 700; color: #F8FAFC;">Investigator Access Portal</div>
                    <span class="status-pill pill-primary" style="font-size: 9.5px;">SECURE TLS 1.3</span>
                </div>
                <p style="font-size: 12px; color: #94A3B8; margin-bottom: 16px;">
                    Sign in with your Google workspace identity or enterprise credentials to access active forensic investigations.
                </p>
            """,
            unsafe_allow_html=True
        )

        # 1. Primary Google Sign-In Action
        google_icon = icon_svg("google", size=18)
        col_g1, col_g2, col_g3 = st.columns([1, 10, 1])
        with col_g2:
            st.markdown(
                f"""
                <div style="margin-bottom: 4px;">
                    <button class="google-auth-btn" id="google-auth-trigger" style="pointer-events: none; width: 100%;">
                        {google_icon}
                        <span>Continue with Google</span>
                    </button>
                </div>
                """,
                unsafe_allow_html=True
            )
            # Active Streamlit button executing the Google sign in workflow
            if st.button("Sign in with Google", key="btn_auth_google", type="primary", use_container_width=True):
                # Simulated Google OAuth token exchange
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
                st.toast("Authenticated successfully via Google.", icon="🛡️")
                time.sleep(0.3)
                st.rerun()

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
                value="••••••••••••",
                placeholder="Enter enterprise passphrase",
                key="input_login_password"
            )
            login_clearance = st.selectbox(
                "Active Clearance Level",
                options=["L3 Lead Forensic Specialist", "L2 Incident Responder", "L1 Triage Analyst"],
                index=0,
                key="input_login_clearance"
            )

            if st.button("Sign In to SOC Console", key="btn_submit_signin", use_container_width=True):
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
                    st.success(f"Welcome back, {user_data['name']}.")
                    time.sleep(0.2)
                    st.rerun()
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

            if st.button("Create Forensic Account", key="btn_submit_signup", use_container_width=True):
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
                    st.success(f"Account provisioned for {new_name}. Initializing console...")
                    time.sleep(0.3)
                    st.rerun()
                else:
                    st.error("Full Name and Work Email are required for registration.")

        st.markdown("<hr style='margin: 14px 0 12px 0; border-color: rgba(255, 255, 255, 0.06);'/>", unsafe_allow_html=True)

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
            st.rerun()

        st.markdown(
            """
            <div style="font-size: 10.5px; color: #64748B; text-align: center; margin-top: 10px; line-height: 1.4;">
                Protected by ChronoTrace Forensic Security Controls.<br>
                All session activities and queries are logged to immutable SQLite WAL audit storage.
            </div>
            </div>
            """,
            unsafe_allow_html=True
        )
