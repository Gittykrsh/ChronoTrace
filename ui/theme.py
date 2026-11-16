"""ChronoTrace UI Theme & Design System — Enterprise SOC Operations Aesthetic.

Inspired by CrowdStrike Falcon, Wiz, SentinelOne Singularity, and Datadog Cloud SIEM.
Enforces:
- Dark-first layered surfaces (#090D16 canvas, #0D1321 sidebar, #111827 cards, #161F33 elevated drawers)
- Hairline borders (rgba(255, 255, 255, 0.08)), cyan accents (#35D6E8), violet accents (#8B7CFF)
- Semantic indicators: Emerald (#10B981), Amber (#F59E0B), Rose (#F43F5E)
- Typography: Inter for UI/Headings, JetBrains Mono for forensic telemetry & timestamps
- Non-leaking font selectors strictly preserving Streamlit's Material Symbols icon font
- Custom ultra-thin dark scrollbars & dynamic table height sizing
"""

import streamlit as st
import plotly.graph_objects as go
from typing import Dict, Any, Optional

# Color Tokens
APP_BG = "#090D16"
SIDEBAR_BG = "#0D1321"
CARD_BG = "#111827"
ELEVATED_BG = "#161F33"

ACCENT_CYAN = "#35D6E8"
ACCENT_VIOLET = "#8B7CFF"

STATUS_EMERALD = "#10B981"
SUCCESS_GREEN = "#10B981"
STATUS_AMBER = "#F59E0B"
WARNING_AMBER = "#F59E0B"
ORANGE_WARN = "#F97316"
STATUS_ROSE = "#F43F5E"
CRITICAL_RED = "#F43F5E"

TEXT_PRIMARY = "#F1F5F9"
TEXT_SECONDARY = "#94A3B8"
TEXT_MUTED = "#64748B"

BORDER_HAIRLINE = "rgba(255, 255, 255, 0.08)"
BORDER_GLOW = "rgba(53, 214, 232, 0.35)"

# Crisp Lucide-style inline SVG icon library (16px default, stroke-width 1.75)
SVG_ICONS = {
    "shield": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    "activity": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
    "timeline": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
    "graph": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>',
    "search": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
    "file": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
    "report": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg>',
    "alert": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    "check": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
    "upload": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>',
    "download": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
    "database": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
    "target": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
    "layers": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>',
    "refresh": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>',
    "plus": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>',
    "clock": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
    "filter": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>',
    "chevron_right": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>',
    "terminal": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>'
}


def icon_svg(name: str, size: int = 16, color: str = "currentColor") -> str:
    """Returns an inline SVG icon string."""
    template = SVG_ICONS.get(name, SVG_ICONS["shield"])
    return template.format(s=size, c=color)


THEME_CSS = """
<style>
/* 1. Typography Import */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

/* 2. Semantic Text Font Application (Strictly preserving Streamlit icon fonts) */
html, body, [data-testid="stAppViewContainer"], [data-testid="stSidebarContent"],
h1, h2, h3, h4, h5, h6, p, label, input, textarea {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: #F1F5F9;
    -webkit-font-smoothing: antialiased;
}

/* Explicitly preserve and force Streamlit Material Symbols Icon Font */
[class*="material-symbols"],
[data-testid="stIconMaterial"],
.material-symbols-rounded,
.material-symbols-outlined,
[data-testid="stSidebarCollapseButton"] span,
[data-testid="stSidebarCollapseButton"] button span,
span[data-testid="stIconMaterial"],
header span,
button[data-testid="stBaseButton-header"] span {
    font-family: "Material Symbols Rounded", "Material Symbols Outlined", sans-serif !important;
    font-weight: normal !important;
    font-style: normal !important;
    letter-spacing: normal !important;
    text-transform: none !important;
    display: inline-block !important;
    white-space: nowrap !important;
    word-wrap: normal !important;
    direction: ltr !important;
    -webkit-font-feature-settings: 'liga';
    -webkit-font-smoothing: antialiased;
}

/* Monospace Forensics & Telemetry */
code, pre, .mono-text, .raw-ref-pill, [data-testid="stCodeBlock"] code {
    font-family: 'JetBrains Mono', 'Consolas', monospace !important;
}

/* 3. Streamlit Header Clutter Cleanup (keep sidebar collapse functional) */
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

/* Hide Default Streamlit Sidebar Auto-Navigation (we use synchronized SOC navigation) */
[data-testid="stSidebarNav"] {
    display: none !important;
}

/* 4. Canvas & Layout Resets: Flush, edge-to-edge SOC layout */
.stApp {
    background-color: #090D16 !important;
    background-image: 
        radial-gradient(circle at 10% 10%, rgba(53, 214, 232, 0.03) 0%, transparent 45%),
        radial-gradient(circle at 90% 90%, rgba(139, 124, 255, 0.03) 0%, transparent 45%) !important;
}

.block-container {
    padding-top: 0.75rem !important;
    padding-bottom: 1.5rem !important;
    padding-left: 1.5rem !important;
    padding-right: 1.5rem !important;
    max-width: 100% !important;
}

/* 5. Custom Ultra-Thin Dark Scrollbars */
::-webkit-scrollbar {
    width: 5px;
    height: 5px;
}
::-webkit-scrollbar-track {
    background: transparent;
}
::-webkit-scrollbar-thumb {
    background: rgba(148, 163, 184, 0.25);
    border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover {
    background: rgba(53, 214, 232, 0.45);
}

/* 6. Clean Fixed Sidebar (Width 280px to eliminate clipped titles & buttons) */
section[data-testid="stSidebar"] {
    min-width: 280px !important;
    max-width: 280px !important;
    width: 280px !important;
    background-color: #0D1321 !important;
    border-right: 1px solid rgba(255, 255, 255, 0.06) !important;
}
section[data-testid="stSidebar"] > div {
    width: 280px !important;
}
[data-testid="stSidebarContent"] {
    width: 280px !important;
    padding-top: 0.6rem !important;
    padding-left: 0.85rem !important;
    padding-right: 0.85rem !important;
    padding-bottom: 1.25rem !important;
}

/* Sidebar action buttons */
section[data-testid="stSidebar"] .stButton > button {
    white-space: nowrap !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    padding: 6px 10px !important;
    font-size: 0.76rem !important;
    font-weight: 600 !important;
    min-height: 32px !important;
}

/* 7. Native st.page_link Navigation Item Styling */
div.stPageLink a {
    background: rgba(17, 24, 39, 0.5) !important;
    border: 1px solid rgba(255, 255, 255, 0.06) !important;
    border-radius: 6px !important;
    padding: 7px 12px !important;
    color: #94A3B8 !important;
    font-weight: 500 !important;
    font-size: 0.82rem !important;
    display: flex !important;
    align-items: center !important;
    gap: 10px !important;
    text-decoration: none !important;
    transition: all 0.15s ease-in-out !important;
    margin-bottom: 3px !important;
    white-space: nowrap !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
}

div.stPageLink a:hover {
    background: rgba(53, 214, 232, 0.08) !important;
    border-color: rgba(53, 214, 232, 0.4) !important;
    color: #F1F5F9 !important;
    transform: translateX(2px) !important;
}

div.stPageLink a[aria-current="page"] {
    background: rgba(53, 214, 232, 0.12) !important;
    border: 1px solid rgba(53, 214, 232, 0.5) !important;
    border-left: 3px solid #35D6E8 !important;
    color: #35D6E8 !important;
    font-weight: 600 !important;
}

div.stPageLink a span {
    color: inherit !important;
}

/* 8. Layered Surfaces & KPI Metric Cards */
.soc-card {
    background: #111827;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 8px;
    padding: 14px 16px;
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.35);
    transition: all 0.2s ease-in-out;
}
.soc-card:hover {
    border-color: rgba(53, 214, 232, 0.3);
    box-shadow: 0 4px 18px rgba(0, 0, 0, 0.45);
}

.soc-kpi-card {
    background: #111827;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 8px;
    padding: 12px 14px;
    min-height: 104px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    transition: all 0.2s ease-in-out;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}
.soc-kpi-card:hover {
    border-color: rgba(53, 214, 232, 0.35);
    box-shadow: 0 4px 16px rgba(53, 214, 232, 0.12);
    transform: translateY(-1px);
}

.soc-kpi-title {
    font-size: 0.70rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #64748B;
    display: flex;
    align-items: center;
    gap: 6px;
}

.soc-kpi-value {
    font-size: 1.75rem;
    font-weight: 700;
    color: #F1F5F9;
    font-family: 'JetBrains Mono', monospace;
    font-variant-numeric: tabular-nums;
    line-height: 1.1;
    margin: 4px 0 2px 0;
}

.soc-kpi-sub {
    font-size: 0.70rem;
    color: #94A3B8;
    font-family: 'JetBrains Mono', monospace;
}

/* Elevated Drawer / Inspector */
.soc-elevated {
    background-color: #161F33;
    border: 1px solid rgba(53, 214, 232, 0.22);
    border-radius: 8px;
    padding: 16px;
    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.4);
}

/* 9. Provenance & Micro-Badges */
.raw-ref-pill {
    background: rgba(13, 19, 33, 0.85);
    color: #35D6E8;
    border: 1px solid rgba(53, 214, 232, 0.3);
    padding: 3px 8px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.74rem;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 6px;
}

.soc-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    font-family: 'JetBrains Mono', monospace;
    text-transform: uppercase;
}

.badge-order-conflict {
    background: rgba(245, 158, 11, 0.12);
    color: #F59E0B;
    border: 1px solid rgba(245, 158, 11, 0.4);
}

.badge-missing-parent {
    background: rgba(249, 115, 22, 0.12);
    color: #F97316;
    border: 1px solid rgba(249, 115, 22, 0.4);
}

.badge-log-cleared {
    background: rgba(244, 63, 94, 0.14);
    color: #F43F5E;
    border: 1px solid rgba(244, 63, 94, 0.45);
}

.badge-single-source {
    background: rgba(139, 124, 255, 0.12);
    color: #8B7CFF;
    border: 1px solid rgba(139, 124, 255, 0.35);
}

.badge-demo {
    background: rgba(53, 214, 232, 0.1);
    color: #35D6E8;
    border: 1px solid rgba(53, 214, 232, 0.35);
}

.badge-high-conf {
    background: rgba(16, 185, 129, 0.12);
    color: #10B981;
    border: 1px solid rgba(16, 185, 129, 0.35);
}

.badge-mod-conf {
    background: rgba(245, 158, 11, 0.12);
    color: #F59E0B;
    border: 1px solid rgba(245, 158, 11, 0.35);
}

.badge-low-conf {
    background: rgba(244, 63, 94, 0.12);
    color: #F43F5E;
    border: 1px solid rgba(244, 63, 94, 0.35);
}

/* Status Indicators */
.status-pill {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.72rem;
    color: #94A3B8;
    padding: 3px 0;
    font-family: 'JetBrains Mono', monospace;
}

.status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    display: inline-block;
    flex-shrink: 0;
}
.dot-green  { background-color: #10B981; box-shadow: 0 0 5px #10B981; }
.dot-amber  { background-color: #F59E0B; box-shadow: 0 0 5px #F59E0B; }
.dot-cyan   { background-color: #35D6E8; box-shadow: 0 0 5px #35D6E8; }
.dot-violet { background-color: #8B7CFF; box-shadow: 0 0 5px #8B7CFF; }
.dot-rose   { background-color: #F43F5E; box-shadow: 0 0 5px #F43F5E; }

/* 10. Interactive Buttons */
.stButton > button, .stDownloadButton > button {
    background-color: #161F33 !important;
    color: #F1F5F9 !important;
    border: 1px solid rgba(255, 255, 255, 0.12) !important;
    border-radius: 6px !important;
    font-weight: 500 !important;
    font-size: 0.82rem !important;
    transition: all 0.15s ease-in-out !important;
    white-space: nowrap !important;
}

.stButton > button:hover, .stDownloadButton > button:hover {
    background-color: #1F2D4A !important;
    border-color: #35D6E8 !important;
    color: #35D6E8 !important;
    box-shadow: 0 0 10px rgba(53, 214, 232, 0.25) !important;
}

.stButton > button[kind="primary"] {
    background-color: #35D6E8 !important;
    color: #090D16 !important;
    font-weight: 600 !important;
    border: 1px solid #35D6E8 !important;
}

.stButton > button[kind="primary"]:hover {
    background-color: #55E0EF !important;
    box-shadow: 0 0 14px rgba(53, 214, 232, 0.5) !important;
}

/* 11. Tabs */
.stTabs [data-baseweb="tab-list"] {
    background-color: #0D1321 !important;
    border-radius: 6px !important;
    padding: 3px !important;
    gap: 4px !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
}

.stTabs [data-baseweb="tab"] {
    color: #94A3B8 !important;
    border-radius: 5px !important;
    padding: 6px 14px !important;
    font-size: 0.82rem !important;
    font-weight: 500 !important;
    transition: all 0.15s ease !important;
    white-space: nowrap !important;
}

.stTabs [aria-selected="true"] {
    background-color: #161F33 !important;
    color: #35D6E8 !important;
    border-bottom: 2px solid #35D6E8 !important;
    font-weight: 600 !important;
}

/* 12. Inputs, Selectboxes, Sliders */
div[data-baseweb="select"] > div,
div[data-baseweb="input"] > div,
div[data-baseweb="textarea"] > div {
    background-color: #0D1321 !important;
    border: 1px solid rgba(255, 255, 255, 0.12) !important;
    color: #F1F5F9 !important;
    border-radius: 6px !important;
}

div[data-baseweb="select"] > div:hover,
div[data-baseweb="input"] > div:hover {
    border-color: #35D6E8 !important;
}

/* 13. Dataframe Container Styling */
div[data-testid="stDataFrame"] {
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 6px !important;
    background: #111827 !important;
}

/* Expanders */
details[data-testid="stExpander"] {
    background-color: #111827 !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 6px !important;
}
details[data-testid="stExpander"]:hover {
    border-color: rgba(53, 214, 232, 0.3) !important;
}
details[data-testid="stExpander"] summary {
    color: #F1F5F9 !important;
    font-weight: 500 !important;
}
</style>
"""


def inject_theme() -> None:
    """Injects high-density SOC dark theme CSS into the active Streamlit app."""
    st.markdown(THEME_CSS, unsafe_allow_html=True)


def calc_df_height(df, min_h: int = 110, max_h: int = 420, row_h: int = 38, header_h: int = 42) -> int:
    """Dynamically calculates explicit dataframe height to eliminate empty ghost rows."""
    if df is None:
        return min_h
    row_count = len(df) if hasattr(df, "__len__") else 0
    if row_count == 0:
        return min_h
    computed = row_count * row_h + header_h
    return min(max_h, max(min_h, computed))


def get_plotly_layout(title: str = "", height: int = 280, **kwargs) -> Dict[str, Any]:
    """Returns standardized Plotly dark layout template for SOC aesthetic."""
    layout = dict(
        title=dict(
            text=f"<b>{title}</b>" if title else "",
            font=dict(family="Inter, sans-serif", size=12, color=TEXT_PRIMARY)
        ),
        template="plotly_dark",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        height=height,
        margin=dict(l=45, r=20, t=35 if title else 15, b=35),
        font=dict(family="Inter, -apple-system, sans-serif", color=TEXT_SECONDARY, size=11),
        xaxis=dict(
            showgrid=False,
            zerolinecolor="rgba(255, 255, 255, 0.08)",
            tickfont=dict(family="JetBrains Mono, monospace", size=10, color=TEXT_MUTED)
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor="rgba(255, 255, 255, 0.05)",
            zerolinecolor="rgba(255, 255, 255, 0.08)",
            tickfont=dict(family="JetBrains Mono, monospace", size=10, color=TEXT_MUTED)
        ),
        legend=dict(
            bgcolor="rgba(17, 24, 39, 0.8)",
            bordercolor="rgba(255, 255, 255, 0.08)",
            borderwidth=1,
            font=dict(size=10, color=TEXT_SECONDARY),
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        )
    )
    layout.update(kwargs)
    return layout


def render_raw_ref_pill(raw_ref: str) -> str:
    """Returns HTML for an immutable raw reference badge citing source record."""
    file_icon = icon_svg("file", size=12, color=ACCENT_CYAN)
    return f'<span class="raw-ref-pill">{file_icon} {raw_ref}</span>'


def render_flag_badge(flag: str) -> str:
    """Returns HTML badge for an uncertainty conflict flag."""
    badge_map = {
        "ORDER_CONFLICT": ("badge-order-conflict", STATUS_AMBER, "alert"),
        "MISSING_PARENT": ("badge-missing-parent", ORANGE_WARN, "alert"),
        "LOG_CLEARED": ("badge-log-cleared", STATUS_ROSE, "alert"),
        "SINGLE_SOURCE": ("badge-single-source", ACCENT_VIOLET, "info")
    }
    css_class, color, icon_name = badge_map.get(flag, ("badge-single-source", ACCENT_VIOLET, "info"))
    micro_icon = icon_svg(icon_name, size=11, color=color)
    return f'<span class="soc-badge {css_class}">{micro_icon} {flag}</span>'


def render_confidence_badge(score: float) -> str:
    """Returns HTML badge for confidence score."""
    if score >= 0.80:
        dot = f'<span class="status-dot dot-green"></span>'
        return f'<span class="soc-badge badge-high-conf">{dot} CONF {score:.2f} HIGH</span>'
    elif score >= 0.50:
        dot = f'<span class="status-dot dot-amber"></span>'
        return f'<span class="soc-badge badge-mod-conf">{dot} CONF {score:.2f} MOD</span>'
    else:
        dot = f'<span class="status-dot dot-rose"></span>'
        return f'<span class="soc-badge badge-low-conf">{dot} CONF {score:.2f} LOW</span>'
