"""ChronoTrace UI Theme & Design System — Matte Obsidian & Cobalt Engineering Console.

Clean, modern dark-mode desktop engineering console aesthetic:
- Matte obsidian canvas (#0B111E), sidebar (#090E1A), topbar (#0D1526)
- Flat hairline-bordered cards (#0F172A, 1px solid rgba(255,255,255,0.07), 8px radius)
- Elevated sub-panels (#131D31) and recessed terminal/log boxes (#070B14)
- Cobalt blue interactive accent (#1D6FE8, hover #2563EB)
- Eyebrow / highlight blue (#38BDF8) used sparingly for micro-labels
- Semantic status pills: Emerald (#34D399), Amber (#FBBF24), Rose (#FB7185), Slate (#94A3B8)
- Inter for UI typography, JetBrains Mono strictly for forensic telemetry & timestamps
- Flat borderless sidebar navigation, hidden header anchors, custom 5px scrollbars
"""

import streamlit as st
import plotly.graph_objects as go
from typing import Dict, Any, Optional

# Color Tokens
CANVAS_BG = "#0B111E"
SIDEBAR_BG = "#090E1A"
TOPBAR_BG = "#0D1526"
CARD_BG = "#0F172A"
ELEVATED_BG = "#131D31"
TERMINAL_BG = "#070B14"

ACCENT_BLUE = "#1D6FE8"
ACCENT_HOVER = "#2563EB"
EYEBROW_BLUE = "#38BDF8"

STATUS_SUCCESS_TEXT = "#34D399"
STATUS_SUCCESS_BG = "rgba(16, 185, 129, 0.14)"
STATUS_SUCCESS_BORDER = "rgba(16, 185, 129, 0.25)"

STATUS_WARN_TEXT = "#FBBF24"
STATUS_WARN_BG = "rgba(245, 158, 11, 0.14)"
STATUS_WARN_BORDER = "rgba(245, 158, 11, 0.25)"

STATUS_CRIT_TEXT = "#FB7185"
STATUS_CRIT_BG = "rgba(244, 63, 94, 0.14)"
STATUS_CRIT_BORDER = "rgba(244, 63, 94, 0.25)"

STATUS_INFO_TEXT = "#94A3B8"
STATUS_INFO_BG = "rgba(148, 163, 184, 0.10)"
STATUS_INFO_BORDER = "rgba(255, 255, 255, 0.08)"

TEXT_PRIMARY = "#F8FAFC"
TEXT_SECONDARY = "#CBD5E1"
TEXT_MUTED = "#64748B"
TEXT_CAPTION = "#94A3B8"

BORDER_HAIRLINE = "rgba(255, 255, 255, 0.07)"
BORDER_DIVIDER = "rgba(255, 255, 255, 0.05)"

# Lucide-style 15px inline SVGs (stroke-width 1.75, crisp engineering console aesthetic)
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
    "terminal": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>',
    "copy": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
    "arrow_right": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>'
}


def icon_svg(name: str, size: int = 15, color: str = "currentColor") -> str:
    """Returns an inline SVG icon string."""
    template = SVG_ICONS.get(name, SVG_ICONS["shield"])
    return template.format(s=size, c=color)


THEME_CSS = """
<style>
/* 1. Typography Import: Inter & JetBrains Mono */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* 2. Semantic Text Font Application (Strictly preserving Streamlit icon fonts) */
html, body, [data-testid="stAppViewContainer"], [data-testid="stSidebarContent"],
h1, h2, h3, h4, h5, h6, p, label, input, textarea {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    color: #F8FAFC;
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

/* Forensic Monospace: Exclusively for raw refs, code, hashes, and terminal logs */
code, pre, .mono-text, .raw-ref-pill, [data-testid="stCodeBlock"] code, .terminal-text {
    font-family: 'JetBrains Mono', 'Consolas', monospace !important;
}

/* Hide Streamlit Header Anchor Links and Clutter */
[data-testid="stHeaderActionElements"],
a.anchor-link,
header[data-testid="stHeader"] .stDeployButton,
header[data-testid="stHeader"] button[title="View app in Streamlit Community Cloud"],
#MainMenu, footer {
    display: none !important;
}

header[data-testid="stHeader"] {
    background: transparent !important;
    height: 2.2rem !important;
    z-index: 99 !important;
}

[data-testid="stSidebarNav"] {
    display: none !important;
}

/* 3. Main Container Spacing & Layout */
.stApp {
    background-color: #0B111E !important;
}

.block-container {
    padding-top: 1.0rem !important;
    padding-bottom: 2rem !important;
    padding-left: 2rem !important;
    padding-right: 2rem !important;
    max-width: 100% !important;
}

/* 4. Custom Sleek 5px Scrollbars */
::-webkit-scrollbar {
    width: 5px;
    height: 5px;
}
::-webkit-scrollbar-track {
    background: transparent;
}
::-webkit-scrollbar-thumb {
    background: rgba(148, 163, 184, 0.2);
    border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover {
    background: rgba(56, 189, 248, 0.4);
}

/* 5. Flat Borderless Sidebar (Width 255px) */
section[data-testid="stSidebar"] {
    min-width: 255px !important;
    max-width: 255px !important;
    width: 255px !important;
    background-color: #090E1A !important;
    border-right: 1px solid rgba(255, 255, 255, 0.06) !important;
}
section[data-testid="stSidebar"] > div {
    width: 255px !important;
}
[data-testid="stSidebarContent"] {
    width: 255px !important;
    padding-top: 0.6rem !important;
    padding-left: 0.8rem !important;
    padding-right: 0.8rem !important;
    padding-bottom: 1.25rem !important;
}

/* Flat Navigation Links: Inactive has NO background box and NO border */
div.stPageLink a {
    background: transparent !important;
    border: 1px solid transparent !important;
    border-radius: 6px !important;
    padding: 7px 10px !important;
    color: #94A3B8 !important;
    font-weight: 500 !important;
    font-size: 0.82rem !important;
    display: flex !important;
    align-items: center !important;
    gap: 9px !important;
    text-decoration: none !important;
    transition: all 0.12s ease-in-out !important;
    margin-bottom: 2px !important;
    white-space: nowrap !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
}

div.stPageLink a:hover {
    background: rgba(255, 255, 255, 0.04) !important;
    color: #F8FAFC !important;
}

/* Active navigation link: subtle cobalt blue pill with crisp cyan highlight */
div.stPageLink a[aria-current="page"] {
    background: rgba(29, 111, 232, 0.16) !important;
    border: 1px solid rgba(56, 189, 248, 0.28) !important;
    color: #F8FAFC !important;
    font-weight: 600 !important;
}

div.stPageLink a span {
    color: inherit !important;
}

/* Sidebar Action Buttons */
section[data-testid="stSidebar"] .stButton > button {
    white-space: nowrap !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    padding: 6px 10px !important;
    font-size: 0.76rem !important;
    font-weight: 500 !important;
    height: 34px !important;
    min-height: 34px !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    background: #131D31 !important;
    color: #F8FAFC !important;
    border-radius: 6px !important;
}
section[data-testid="stSidebar"] .stButton > button:hover {
    background: #1A2640 !important;
    border-color: rgba(255, 255, 255, 0.15) !important;
}

/* 6. Card & Panel Surface (#0F172A with hairline border) */
.console-card {
    background: #0F172A;
    border: 1px solid rgba(255, 255, 255, 0.07);
    border-radius: 8px;
    padding: 14px 16px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.25);
    transition: border-color 0.15s ease-in-out;
}
.console-card:hover {
    border-color: rgba(255, 255, 255, 0.12);
}

/* KPI Card Pattern */
.console-kpi-card {
    background: #0F172A;
    border: 1px solid rgba(255, 255, 255, 0.07);
    border-radius: 8px;
    padding: 12px 14px;
    min-height: 100px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    transition: all 0.15s ease-in-out;
}
.console-kpi-card:hover {
    border-color: rgba(56, 189, 248, 0.25);
}

.kpi-label {
    font-size: 0.68rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #64748B;
    display: flex;
    align-items: center;
    gap: 6px;
}

.kpi-value {
    font-size: 1.45rem;
    font-weight: 700;
    color: #F8FAFC;
    font-family: 'Inter', sans-serif;
    line-height: 1.15;
    margin: 3px 0 1px 0;
}

.kpi-sub {
    font-size: 0.68rem;
    color: #94A3B8;
}

/* Inner Sub-Card / Elevated Panel */
.console-elevated {
    background-color: #131D31;
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 6px;
    padding: 14px 16px;
}

/* Recessed Terminal Box */
.console-terminal {
    background-color: #070B14;
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 6px;
    padding: 12px 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: #CBD5E1;
    line-height: 1.6;
}

/* 7. Status Pills & Badges */
.status-pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.03em;
    font-family: 'Inter', sans-serif;
    text-transform: uppercase;
    white-space: nowrap;
}

.pill-success {
    background: rgba(16, 185, 129, 0.14);
    color: #34D399;
    border: 1px solid rgba(16, 185, 129, 0.25);
}

.pill-warning {
    background: rgba(245, 158, 11, 0.14);
    color: #FBBF24;
    border: 1px solid rgba(245, 158, 11, 0.25);
}

.pill-critical {
    background: rgba(244, 63, 94, 0.14);
    color: #FB7185;
    border: 1px solid rgba(244, 63, 94, 0.25);
}

.pill-info {
    background: rgba(148, 163, 184, 0.10);
    color: #94A3B8;
    border: 1px solid rgba(255, 255, 255, 0.08);
}

.pill-primary {
    background: rgba(29, 111, 232, 0.16);
    color: #38BDF8;
    border: 1px solid rgba(56, 189, 248, 0.28);
}

/* Raw Reference Citation Pill (Monospace) */
.raw-ref-pill {
    background: #070B14;
    color: #38BDF8;
    border: 1px solid rgba(56, 189, 248, 0.25);
    padding: 2px 7px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.72rem;
    font-weight: 500;
    display: inline-flex;
    align-items: center;
    gap: 5px;
}

/* 8. Interactive Buttons */
.stButton > button, .stDownloadButton > button {
    background-color: #131D31 !important;
    color: #F8FAFC !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 6px !important;
    font-weight: 500 !important;
    font-size: 0.82rem !important;
    transition: all 0.12s ease-in-out !important;
    white-space: nowrap !important;
}

.stButton > button:hover, .stDownloadButton > button:hover {
    background-color: #1A2640 !important;
    border-color: rgba(255, 255, 255, 0.16) !important;
    color: #F8FAFC !important;
}

.stButton > button[kind="primary"] {
    background-color: #1D6FE8 !important;
    color: #FFFFFF !important;
    font-weight: 600 !important;
    border: 1px solid #1D6FE8 !important;
}

.stButton > button[kind="primary"]:hover {
    background-color: #2563EB !important;
    border-color: #2563EB !important;
}

/* 9. Segmented Tabs Styling */
.stTabs [data-baseweb="tab-list"] {
    background-color: #090E1A !important;
    border-radius: 6px !important;
    padding: 2px !important;
    gap: 3px !important;
    border: 1px solid rgba(255, 255, 255, 0.06) !important;
}

.stTabs [data-baseweb="tab"] {
    color: #94A3B8 !important;
    border-radius: 5px !important;
    padding: 5px 12px !important;
    font-size: 0.80rem !important;
    font-weight: 500 !important;
    transition: all 0.12s ease !important;
    white-space: nowrap !important;
}

.stTabs [aria-selected="true"] {
    background-color: #131D31 !important;
    color: #F8FAFC !important;
    border-bottom: 2px solid #1D6FE8 !important;
    font-weight: 600 !important;
}

/* 10. Form Inputs & Selectboxes */
div[data-baseweb="select"] > div,
div[data-baseweb="input"] > div,
div[data-baseweb="textarea"] > div {
    background-color: #090E1A !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    color: #F8FAFC !important;
    border-radius: 6px !important;
}

div[data-baseweb="select"] > div:hover,
div[data-baseweb="input"] > div:hover {
    border-color: rgba(56, 189, 248, 0.4) !important;
}

/* 11. Dataframe Containers */
div[data-testid="stDataFrame"] {
    border: 1px solid rgba(255, 255, 255, 0.06) !important;
    border-radius: 6px !important;
    background: #0F172A !important;
}

/* Expanders */
details[data-testid="stExpander"] {
    background-color: #0F172A !important;
    border: 1px solid rgba(255, 255, 255, 0.06) !important;
    border-radius: 6px !important;
}
details[data-testid="stExpander"]:hover {
    border-color: rgba(255, 255, 255, 0.12) !important;
}
details[data-testid="stExpander"] summary {
    color: #F8FAFC !important;
    font-weight: 500 !important;
}
</style>
"""


def inject_theme() -> None:
    """Injects matte obsidian & cobalt console theme CSS into the active app."""
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


def get_plotly_layout(title: str = "", height: int = 260, **kwargs) -> Dict[str, Any]:
    """Returns standardized Plotly dark layout template for modern engineering console."""
    layout = dict(
        title=dict(
            text=f"<b>{title}</b>" if title else "",
            font=dict(family="Inter, sans-serif", size=12, color=TEXT_PRIMARY)
        ),
        template="plotly_dark",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        height=height,
        margin=dict(l=45, r=20, t=30 if title else 12, b=32),
        font=dict(family="Inter, -apple-system, sans-serif", color=TEXT_CAPTION, size=11),
        bargap=0.6,
        xaxis=dict(
            showgrid=False,
            zerolinecolor="rgba(255, 255, 255, 0.05)",
            tickfont=dict(family="Inter, sans-serif", size=10, color=TEXT_MUTED)
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor="rgba(255, 255, 255, 0.05)",
            zerolinecolor="rgba(255, 255, 255, 0.05)",
            tickfont=dict(family="Inter, sans-serif", size=10, color=TEXT_MUTED)
        ),
        legend=dict(
            bgcolor="rgba(15, 23, 42, 0.8)",
            bordercolor="rgba(255, 255, 255, 0.06)",
            borderwidth=1,
            font=dict(size=10, color=TEXT_CAPTION),
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
    file_icon = icon_svg("file", size=11, color=EYEBROW_BLUE)
    return f'<span class="raw-ref-pill">{file_icon} {raw_ref}</span>'


def render_flag_badge(flag: str) -> str:
    """Returns HTML badge for an uncertainty conflict flag."""
    badge_map = {
        "ORDER_CONFLICT": ("pill-warning", STATUS_WARN_TEXT, "alert"),
        "MISSING_PARENT": ("pill-warning", STATUS_WARN_TEXT, "alert"),
        "LOG_CLEARED": ("pill-critical", STATUS_CRIT_TEXT, "alert"),
        "SINGLE_SOURCE": ("pill-info", STATUS_INFO_TEXT, "activity")
    }
    css_class, color, icon_name = badge_map.get(flag, ("pill-info", STATUS_INFO_TEXT, "activity"))
    micro_icon = icon_svg(icon_name, size=11, color=color)
    return f'<span class="status-pill {css_class}">{micro_icon} {flag}</span>'


def render_confidence_badge(score: float) -> str:
    """Returns HTML badge for confidence score."""
    if score >= 0.80:
        return f'<span class="status-pill pill-success">CONF {score:.2f} HIGH</span>'
    elif score >= 0.50:
        return f'<span class="status-pill pill-warning">CONF {score:.2f} MOD</span>'
    else:
        return f'<span class="status-pill pill-critical">CONF {score:.2f} LOW</span>'
