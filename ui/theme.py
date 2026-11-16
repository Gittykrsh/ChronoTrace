"""ChronoTrace UI Theme & Design System.

Enforces:
- Dark-first cybersecurity operations aesthetic (#0B1020, #0E1628, #121D30, #17243A)
- Primary cyan (#35D6E8), violet (#8B7CFF), green (#37D99A), amber (#F5B942), red (#FF647C)
- Typography: Inter for UI/Body, JetBrains Mono for monospace forensic telemetry
- Custom CSS injection, layout resets, and Plotly dark theme templates
"""

import streamlit as st
import plotly.graph_objects as go
from typing import Dict, Any, Optional

# Color Tokens
APP_BG = "#0B1020"
SIDEBAR_BG = "#0E1628"
CARD_BG = "#121D30"
ELEVATED_BG = "#17243A"
ACCENT_CYAN = "#35D6E8"
ACCENT_VIOLET = "#8B7CFF"
SUCCESS_GREEN = "#37D99A"
WARNING_AMBER = "#F5B942"
ORANGE_WARN = "#FF9B42"
CRITICAL_RED = "#FF647C"
TEXT_PRIMARY = "#EDF4FF"
TEXT_MUTED = "#94A7C2"
BORDER_SUBTLE = "rgba(53, 214, 232, 0.18)"
BORDER_GLOW = "rgba(53, 214, 232, 0.45)"

THEME_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700;800&display=swap');

/* Global Font & Reset */
html, body, [class*="css"], [class*="st-"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    color: #EDF4FF !important;
    -webkit-font-smoothing: antialiased;
}

/* Monospace elements */
code, pre, .mono-text, .raw-ref-pill {
    font-family: 'JetBrains Mono', 'Consolas', monospace !important;
}

/* Hide Streamlit Header Clutter while keeping Sidebar Controls Accessible */
header[data-testid="stHeader"] {
    background: transparent !important;
    height: 2.2rem !important;
    z-index: 99 !important;
}
header[data-testid="stHeader"] .stDeployButton,
header[data-testid="stHeader"] button[title="View app in Streamlit Community Cloud"],
#MainMenu, footer {
    display: none !important;
}

/* Hide Default Sidebar Auto-Navigation (using our persistent custom forensic navigation) */
[data-testid="stSidebarNav"] {
    display: none !important;
}

/* Main Container: Tight, flush layout without wasted top space */
.stApp {
    background-color: #0B1020 !important;
    background-image: 
        radial-gradient(circle at 8% 8%, rgba(53, 214, 232, 0.04) 0%, transparent 40%),
        radial-gradient(circle at 92% 92%, rgba(139, 124, 255, 0.04) 0%, transparent 40%) !important;
}

.block-container {
    padding-top: 0.75rem !important;
    padding-bottom: 1.25rem !important;
    padding-left: 1.5rem !important;
    padding-right: 1.5rem !important;
    max-width: 100% !important;
}

/* Custom Sleek Scrollbars */
::-webkit-scrollbar {
    width: 6px;
    height: 6px;
}
::-webkit-scrollbar-track {
    background: #0E1628;
}
::-webkit-scrollbar-thumb {
    background: #1E2F4D;
    border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover {
    background: #35D6E8;
}

/* Sidebar Custom Styling */
section[data-testid="stSidebar"] {
    background-color: #0E1628 !important;
    border-right: 1px solid rgba(53, 214, 232, 0.14) !important;
}

section[data-testid="stSidebar"] div[data-testid="stSidebarUserContent"] {
    padding-top: 0.75rem !important;
    padding-left: 1rem !important;
    padding-right: 1rem !important;
    padding-bottom: 1.25rem !important;
}

section[data-testid="stSidebar"] hr {
    border-color: rgba(148, 167, 194, 0.12) !important;
    margin: 12px 0 !important;
}

/* Native st.page_link Navigation Item Styling */
div.stPageLink a {
    background: rgba(18, 29, 48, 0.75) !important;
    border: 1px solid rgba(53, 214, 232, 0.14) !important;
    border-radius: 6px !important;
    padding: 8px 12px !important;
    color: #94A7C2 !important;
    font-weight: 600 !important;
    font-size: 0.84rem !important;
    display: flex !important;
    align-items: center !important;
    gap: 8px !important;
    text-decoration: none !important;
    transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important;
    margin-bottom: 4px !important;
}

div.stPageLink a:hover {
    background: rgba(53, 214, 232, 0.12) !important;
    border-color: #35D6E8 !important;
    color: #EDF4FF !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 0 12px rgba(53, 214, 232, 0.22) !important;
}

div.stPageLink a[aria-current="page"] {
    background: linear-gradient(90deg, rgba(53, 214, 232, 0.22) 0%, rgba(139, 124, 255, 0.16) 100%) !important;
    border: 1px solid #35D6E8 !important;
    color: #35D6E8 !important;
    font-weight: 700 !important;
    box-shadow: 0 0 14px rgba(53, 214, 232, 0.28) !important;
}

div.stPageLink a span {
    color: inherit !important;
}

/* Metric KPI Cards (Uniform Height, Hover Glow) */
.soc-card {
    background: #121D30;
    border: 1px solid rgba(53, 214, 232, 0.18);
    border-radius: 6px;
    padding: 14px 16px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35);
    transition: transform 0.2s cubic-bezier(0.4, 0, 0.2, 1), border-color 0.2s ease, box-shadow 0.2s ease;
    margin-bottom: 8px;
}

.soc-card:hover {
    transform: translateY(-1px);
    border-color: #35D6E8;
    box-shadow: 0 4px 18px rgba(53, 214, 232, 0.18);
}

.soc-kpi-card {
    background: #121D30;
    border: 1px solid rgba(53, 214, 232, 0.18);
    border-radius: 6px;
    padding: 12px 14px;
    min-height: 110px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35);
    transition: transform 0.2s cubic-bezier(0.4, 0, 0.2, 1), border-color 0.2s ease, box-shadow 0.2s ease;
    margin-bottom: 6px;
}

.soc-kpi-card:hover {
    transform: translateY(-1px);
    border-color: #35D6E8;
    box-shadow: 0 4px 18px rgba(53, 214, 232, 0.2);
}

.soc-kpi-title {
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #94A7C2;
    display: flex;
    align-items: center;
    gap: 6px;
}

.soc-kpi-value {
    font-size: 1.8rem;
    font-weight: 900;
    color: #EDF4FF;
    font-family: 'JetBrains Mono', monospace;
    line-height: 1.1;
    margin: 4px 0 2px 0;
}

.soc-kpi-sub {
    font-size: 0.72rem;
    color: #35D6E8;
    font-family: 'JetBrains Mono', monospace;
}

/* Elevated Panel */
.soc-elevated {
    background-color: #17243A;
    border: 1px solid rgba(53, 214, 232, 0.2);
    border-radius: 6px;
    padding: 16px;
    margin-bottom: 12px;
    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.35);
}

/* Raw Reference Citation Pill */
.raw-ref-pill {
    background: #0E1628;
    color: #35D6E8;
    border: 1px solid rgba(53, 214, 232, 0.45);
    padding: 3px 8px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.74rem;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    gap: 4px;
}

/* Forensic Badges */
.soc-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    font-family: 'JetBrains Mono', monospace;
    text-transform: uppercase;
}

.badge-order-conflict {
    background: rgba(245, 185, 66, 0.14);
    color: #F5B942;
    border: 1px solid rgba(245, 185, 66, 0.5);
}

.badge-missing-parent {
    background: rgba(255, 155, 66, 0.14);
    color: #FF9B42;
    border: 1px solid rgba(255, 155, 66, 0.5);
}

.badge-log-cleared {
    background: rgba(255, 100, 124, 0.16);
    color: #FF647C;
    border: 1px solid rgba(255, 100, 124, 0.55);
}

.badge-single-source {
    background: rgba(139, 124, 255, 0.14);
    color: #8B7CFF;
    border: 1px solid rgba(139, 124, 255, 0.45);
}

.badge-demo {
    background: rgba(53, 214, 232, 0.12);
    color: #35D6E8;
    border: 1px solid rgba(53, 214, 232, 0.45);
}

.badge-high-conf {
    background: rgba(55, 217, 154, 0.14);
    color: #37D99A;
    border: 1px solid rgba(55, 217, 154, 0.45);
}

.badge-mod-conf {
    background: rgba(245, 185, 66, 0.14);
    color: #F5B942;
    border: 1px solid rgba(245, 185, 66, 0.45);
}

.badge-low-conf {
    background: rgba(255, 100, 124, 0.14);
    color: #FF647C;
    border: 1px solid rgba(255, 100, 124, 0.45);
}

/* System Health Status Dots */
.status-pill {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.72rem;
    color: #94A7C2;
    padding: 3px 0;
    font-family: 'JetBrains Mono', monospace;
}

.status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    display: inline-block;
}
.dot-green { background-color: #37D99A; box-shadow: 0 0 6px #37D99A; }
.dot-amber { background-color: #F5B942; box-shadow: 0 0 6px #F5B942; }
.dot-cyan  { background-color: #35D6E8; box-shadow: 0 0 6px #35D6E8; }
.dot-violet { background-color: #8B7CFF; box-shadow: 0 0 6px #8B7CFF; }

/* Interactive Buttons & Download Triggers */
.stButton>button, .stDownloadButton>button {
    background-color: #17243A !important;
    color: #EDF4FF !important;
    border: 1px solid rgba(53, 214, 232, 0.3) !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    font-size: 0.82rem !important;
    transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important;
}

.stButton>button:hover, .stDownloadButton>button:hover {
    background-color: #35D6E8 !important;
    color: #0B1020 !important;
    border-color: #35D6E8 !important;
    box-shadow: 0 0 14px rgba(53, 214, 232, 0.4) !important;
    transform: translateY(-1px) !important;
}

.stButton>button:active, .stDownloadButton>button:active {
    transform: translateY(1px) !important;
}

/* Tabs: Tight dark tabs */
.stTabs [data-baseweb="tab-list"] {
    background-color: #0E1628 !important;
    border-radius: 6px !important;
    padding: 3px !important;
    gap: 4px !important;
    border: 1px solid rgba(53, 214, 232, 0.14) !important;
}

.stTabs [data-baseweb="tab"] {
    color: #94A7C2 !important;
    border-radius: 5px !important;
    padding: 6px 14px !important;
    font-size: 0.82rem !important;
    font-weight: 600 !important;
    transition: all 0.2s ease !important;
    white-space: nowrap !important;
}

.stTabs [aria-selected="true"] {
    background-color: #17243A !important;
    color: #35D6E8 !important;
    border-bottom: 2px solid #35D6E8 !important;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.35) !important;
}

/* Form Inputs, Selectboxes & Text Areas */
div[data-baseweb="select"] > div,
div[data-baseweb="input"] > div,
div[data-baseweb="textarea"] > div {
    background-color: #0E1628 !important;
    border: 1px solid rgba(53, 214, 232, 0.22) !important;
    color: #EDF4FF !important;
    border-radius: 6px !important;
}

div[data-baseweb="select"] > div:hover,
div[data-baseweb="input"] > div:hover {
    border-color: #35D6E8 !important;
}

/* Dataframe Container Styling: Clean border, zero outer overflow */
div[data-testid="stDataFrame"] {
    border: 1px solid rgba(53, 214, 232, 0.2) !important;
    border-radius: 6px !important;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25) !important;
}

/* Expanders */
.stExpander, details[data-testid="stExpander"] {
    background-color: #121D30 !important;
    border: 1px solid rgba(53, 214, 232, 0.16) !important;
    border-radius: 6px !important;
}

details[data-testid="stExpander"]:hover {
    border-color: rgba(53, 214, 232, 0.35) !important;
}

details[data-testid="stExpander"] summary {
    color: #EDF4FF !important;
    font-weight: 600 !important;
}

details[data-testid="stExpander"] summary:hover {
    color: #35D6E8 !important;
}

/* Monospace Code & JSON blocks */
.stCodeBlock, pre, code {
    background-color: #090D1A !important;
    color: #35D6E8 !important;
    border: 1px solid rgba(53, 214, 232, 0.18) !important;
    border-radius: 6px !important;
}
</style>
"""


def inject_theme() -> None:
    """Injects high-density SOC dark theme CSS into the active Streamlit app."""
    st.markdown(THEME_CSS, unsafe_allow_html=True)


def get_plotly_layout(title: str = "", height: int = 340, **kwargs) -> Dict[str, Any]:
    """Returns standardized Plotly dark layout template adhering to SOC aesthetic."""
    layout = dict(
        title=dict(
            text=f"<b>{title}</b>" if title else "",
            font=dict(family="Inter, sans-serif", size=13, color=TEXT_PRIMARY)
        ),
        template="plotly_dark",
        plot_bgcolor="#0E1628",
        paper_bgcolor="#121D30",
        height=height,
        margin=dict(l=45, r=20, t=40 if title else 20, b=35),
        font=dict(family="Inter, -apple-system, sans-serif", color=TEXT_PRIMARY, size=11),
        xaxis=dict(
            gridcolor="rgba(148, 167, 194, 0.12)",
            zerolinecolor="rgba(148, 167, 194, 0.2)",
            tickfont=dict(family="JetBrains Mono, monospace", size=10, color=TEXT_MUTED)
        ),
        yaxis=dict(
            gridcolor="rgba(148, 167, 194, 0.12)",
            zerolinecolor="rgba(148, 167, 194, 0.2)",
            tickfont=dict(family="JetBrains Mono, monospace", size=10, color=TEXT_MUTED)
        ),
        legend=dict(
            bgcolor="rgba(14, 22, 40, 0.8)",
            bordercolor="rgba(53, 214, 232, 0.2)",
            borderwidth=1,
            font=dict(size=10)
        )
    )
    layout.update(kwargs)
    return layout


def render_raw_ref_pill(raw_ref: str) -> str:
    """Returns HTML for an immutable raw reference badge."""
    return f'<span class="raw-ref-pill">📄 {raw_ref}</span>'


def render_flag_badge(flag: str) -> str:
    """Returns HTML badge for an uncertainty conflict flag."""
    badge_map = {
        "ORDER_CONFLICT": "badge-order-conflict",
        "MISSING_PARENT": "badge-missing-parent",
        "LOG_CLEARED": "badge-log-cleared",
        "SINGLE_SOURCE": "badge-single-source"
    }
    css_class = badge_map.get(flag, "badge-single-source")
    return f'<span class="soc-badge {css_class}">{flag}</span>'


def render_confidence_badge(score: float) -> str:
    """Returns HTML badge for confidence score."""
    if score >= 0.80:
        return f'<span class="soc-badge badge-high-conf">CONF {score:.2f} (HIGH)</span>'
    elif score >= 0.50:
        return f'<span class="soc-badge badge-mod-conf">CONF {score:.2f} (MODERATE)</span>'
    else:
        return f'<span class="soc-badge badge-low-conf">CONF {score:.2f} (LOW)</span>'
