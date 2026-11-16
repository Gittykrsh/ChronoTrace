"""ChronoTrace UI Theme & Design System — Matte Obsidian Desktop Console.

Inspired by modern high-performance desktop engineering consoles:
- Matte obsidian canvas (#090E1A), sidebar (#070B14), cards (#0D1526 / #0F1A2E)
- Hairline borders (rgba(255, 255, 255, 0.07)), cobalt blue primary actions (#1D6FE8, hover #2563EB)
- Micro-eyebrow & highlight cyan (#38BDF8), semantic status pills (Emerald, Amber, Rose, Slate)
- Smooth CSS animations (fade-in, hover-lift, pulse-dot, transition-all) across cards, inputs, dropdowns, and tabs
- Inter for UI typography, JetBrains Mono strictly for forensic telemetry & timestamps
- Custom 5px scrollbars, hidden header anchors, and dark Plotly templates
"""

import streamlit as st
import plotly.graph_objects as go
from typing import Dict, Any, Optional

# Color Tokens
CANVAS_BG = "#090E1A"
SIDEBAR_BG = "#070B14"
TOPBAR_BG = "#0D1526"
CARD_BG = "#0F1A2E"
CARD_SURFACE = "#0D1526"
ELEVATED_BG = "#131D31"
TERMINAL_BG = "#050811"

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

# Lucide-style 15px inline SVGs
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
    "info": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
    "bell": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>',
    "google": '<svg viewBox="0 0 24 24" width="{s}" height="{s}"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/></svg>',
    "user": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
    "logout": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',
    "lock": '<svg viewBox="0 0 24 24" width="{s}" height="{s}" fill="none" stroke="{c}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>'
}


def icon_svg(name: str, size: int = 15, color: str = "currentColor") -> str:
    """Returns an inline SVG icon string."""
    template = SVG_ICONS.get(name, SVG_ICONS["shield"])
    return template.format(s=size, c=color)


THEME_CSS = """
<style>
/* 1. Google Fonts Import: Inter & JetBrains Mono */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* 2. Keyframe Animations for Smooth Desktop Console Feel */
@keyframes consoleFadeIn {
    from {
        opacity: 0;
        transform: translateY(6px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@keyframes pulseGlow {
    0%, 100% {
        opacity: 1;
        transform: scale(1);
    }
    50% {
        opacity: 0.45;
        transform: scale(0.88);
    }
}

/* 3. Global Semantic Typography (Safely isolating Streamlit icon fonts) */
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
[data-testid="collapsedControl"],
[data-testid="stSidebarCollapseButton"],
#MainMenu, footer {
    display: none !important;
}

header[data-testid="stHeader"] {
    background: transparent !important;
    height: 0px !important;
    min-height: 0px !important;
    z-index: 1 !important;
    pointer-events: none !important;
}

[data-testid="stSidebarNav"] {
    display: none !important;
}

/* 4. Canvas & Smooth Layout Entry */
.stApp {
    background-color: #090E1A !important;
}

.block-container {
    padding-top: 0.9rem !important;
    padding-bottom: 2rem !important;
    padding-left: 2rem !important;
    padding-right: 2rem !important;
    max-width: 100% !important;
    animation: consoleFadeIn 0.28s cubic-bezier(0.16, 1, 0.3, 1) !important;
}

/* 5. Custom Sleek 5px Scrollbars */
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
    transition: background 0.2s ease;
}
::-webkit-scrollbar-thumb:hover {
    background: rgba(56, 189, 248, 0.45);
}

/* 6. Desktop Console Sidebar (Width 268px, Plain Fixed Dock without Arrow Controls) */
[data-testid="stSidebarCollapseButton"],
[data-testid="collapsedControl"],
button[data-testid="stSidebarCollapseButton"] {
    display: none !important;
    visibility: hidden !important;
    pointer-events: none !important;
    width: 0 !important;
    height: 0 !important;
}

div[data-testid="stSidebarHeader"] {
    height: 0px !important;
    min-height: 0px !important;
    padding: 0px !important;
    margin: 0px !important;
    overflow: hidden !important;
}

section[data-testid="stSidebar"] {
    min-width: 268px !important;
    max-width: 268px !important;
    width: 268px !important;
    background-color: #070B14 !important;
    border-right: 1px solid rgba(255, 255, 255, 0.06) !important;
}

section[data-testid="stSidebar"] > div {
    width: 268px !important;
}

[data-testid="stSidebarContent"] {
    width: 268px !important;
    padding-top: 0.5rem !important;
    padding-left: 0.75rem !important;
    padding-right: 0.75rem !important;
    padding-bottom: 1.25rem !important;
}

/* Hide scrollbar on sidebar */
section[data-testid="stSidebar"] ::-webkit-scrollbar,
[data-testid="stSidebarContent"]::-webkit-scrollbar {
    display: none !important;
    width: 0px !important;
    height: 0px !important;
}

/* Compact spacing for sidebar elements to fit effortlessly in viewport */
[data-testid="stSidebarContent"] .stElementContainer {
    margin-bottom: 3px !important;
}

/* Flat Navigation Links: Inactive has transparent background and smooth transitions */
section[data-testid="stSidebar"] div.stPageLink a {
    background: transparent !important;
    border: 1px solid transparent !important;
    border-radius: 6px !important;
    padding: 6px 10px !important;
    color: #94A3B8 !important;
    font-weight: 500 !important;
    font-size: 0.82rem !important;
    display: flex !important;
    align-items: center !important;
    gap: 9px !important;
    text-decoration: none !important;
    transition: all 0.18s cubic-bezier(0.16, 1, 0.3, 1) !important;
    margin-bottom: 2px !important;
    white-space: nowrap !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    cursor: pointer !important;
}

section[data-testid="stSidebar"] div.stPageLink a p {
    color: #94A3B8 !important;
    font-size: 0.82rem !important;
    font-weight: 500 !important;
    margin: 0 !important;
    transition: color 0.18s ease !important;
}

section[data-testid="stSidebar"] div.stPageLink a span,
section[data-testid="stSidebar"] div.stPageLink a [data-testid="stIconMaterial"] {
    color: #64748B !important;
    font-size: 1.05rem !important;
    transition: color 0.18s ease, transform 0.18s ease !important;
}

/* UNMISTAKABLE SIDEBAR HOVER STATE: High-visibility electric blue pill + cyan border + slide */
section[data-testid="stSidebar"] div.stPageLink a:hover {
    background: rgba(29, 111, 232, 0.18) !important;
    background-color: rgba(29, 111, 232, 0.18) !important;
    border: 1px solid rgba(56, 189, 248, 0.45) !important;
    color: #FFFFFF !important;
    transform: translateX(4px) !important;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.35), inset 0 0 10px rgba(56, 189, 248, 0.12) !important;
}

section[data-testid="stSidebar"] div.stPageLink a:hover p {
    color: #FFFFFF !important;
    font-weight: 600 !important;
}

section[data-testid="stSidebar"] div.stPageLink a:hover span,
section[data-testid="stSidebar"] div.stPageLink a:hover [data-testid="stIconMaterial"] {
    color: #38BDF8 !important;
    transform: scale(1.08) !important;
}

/* Instant click feedback */
section[data-testid="stSidebar"] div.stPageLink a:active {
    background: #1D6FE8 !important;
    border-color: #38BDF8 !important;
    color: #FFFFFF !important;
    transform: scale(0.98) !important;
}

/* Fallback Active State: Solid Cobalt Blue Pill with Glow & Crisp White Text */
section[data-testid="stSidebar"] div.stPageLink a[aria-current="page"] {
    background: #1D6FE8 !important;
    background-color: #1D6FE8 !important;
    border: 1px solid #38BDF8 !important;
    color: #FFFFFF !important;
    font-weight: 600 !important;
    box-shadow: 0 2px 12px rgba(29, 111, 232, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.2) !important;
    transform: none !important;
}

section[data-testid="stSidebar"] div.stPageLink a[aria-current="page"] p,
section[data-testid="stSidebar"] div.stPageLink a[aria-current="page"] span,
section[data-testid="stSidebar"] div.stPageLink a[aria-current="page"] [data-testid="stIconMaterial"] {
    color: #FFFFFF !important;
    font-weight: 600 !important;
    fill: #FFFFFF !important;
}

section[data-testid="stSidebar"] div.stPageLink a[aria-current="page"]:hover {
    background: #2563EB !important;
    background-color: #2563EB !important;
    border-color: #60A5FA !important;
    color: #FFFFFF !important;
    transform: none !important;
    box-shadow: 0 4px 14px rgba(29, 111, 232, 0.65) !important;
}

/* Sidebar Action Buttons: Crisp sizing, no text clipping, perfectly balanced */
section[data-testid="stSidebar"] .stButton > button {
    white-space: nowrap !important;
    overflow: visible !important;
    text-overflow: clip !important;
    padding: 4px 6px !important;
    font-size: 0.74rem !important;
    font-weight: 500 !important;
    height: 32px !important;
    min-height: 32px !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    background: #0D1526 !important;
    color: #F8FAFC !important;
    border-radius: 6px !important;
    transition: all 0.18s cubic-bezier(0.4, 0, 0.2, 1) !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
}
section[data-testid="stSidebar"] .stButton > button:hover {
    background: #131D31 !important;
    border-color: rgba(56, 189, 248, 0.35) !important;
    color: #38BDF8 !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 3px 10px rgba(0, 0, 0, 0.3) !important;
}

/* 7. Card & Panel Surface (#0D1526 with Hairline Border) */
.console-card {
    background: #0D1526;
    border: 1px solid rgba(255, 255, 255, 0.07);
    border-radius: 8px;
    padding: 14px 16px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.25);
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
}
.console-card:hover {
    border-color: rgba(255, 255, 255, 0.14);
    transform: translateY(-1px);
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.35);
}

/* KPI Card Pattern */
.console-kpi-card {
    background: #0D1526;
    border: 1px solid rgba(255, 255, 255, 0.07);
    border-radius: 8px;
    padding: 12px 14px;
    min-height: 98px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
}
.console-kpi-card:hover {
    border-color: rgba(56, 189, 248, 0.35);
    transform: translateY(-2px);
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
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

/* Elevated Sub-Panel */
.console-elevated {
    background-color: #111A2E;
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 6px;
    padding: 14px 16px;
    transition: border-color 0.18s ease;
}

/* Recessed Terminal Box */
.console-terminal {
    background-color: #050811;
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 6px;
    padding: 12px 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: #CBD5E1;
    line-height: 1.6;
}

/* 8. Notice Banner (Matching Screenshots) */
.console-notice-banner {
    background: rgba(13, 21, 38, 0.85);
    border: 1px solid rgba(56, 189, 248, 0.2);
    border-radius: 6px;
    padding: 8px 14px;
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 12px;
    color: #CBD5E1;
    margin-bottom: 12px;
    animation: consoleFadeIn 0.3s ease;
}

/* 9. Status Pills & Badges */
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
    transition: all 0.15s ease;
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
    background: #050811;
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
    transition: all 0.15s ease;
}
.raw-ref-pill:hover {
    border-color: #38BDF8;
    background: rgba(56, 189, 248, 0.08);
}

/* Pulsing Status Dot */
.pulsing-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    display: inline-block;
    animation: pulseGlow 2s infinite ease-in-out;
}

/* 10. Interactive Buttons with Smooth Hover & Active Effects */
.stButton > button, .stDownloadButton > button {
    background-color: #111A2E !important;
    color: #F8FAFC !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 6px !important;
    font-weight: 500 !important;
    font-size: 0.82rem !important;
    transition: all 0.18s cubic-bezier(0.4, 0, 0.2, 1) !important;
    white-space: nowrap !important;
}

.stButton > button:hover, .stDownloadButton > button:hover {
    background-color: #18243E !important;
    border-color: rgba(56, 189, 248, 0.35) !important;
    color: #F8FAFC !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3) !important;
}

.stButton > button:active, .stDownloadButton > button:active {
    transform: translateY(1px) !important;
}

.stButton > button[kind="primary"] {
    background-color: #1D6FE8 !important;
    color: #FFFFFF !important;
    font-weight: 600 !important;
    border: 1px solid #1D6FE8 !important;
    box-shadow: 0 2px 8px rgba(29, 111, 232, 0.3) !important;
}

.stButton > button[kind="primary"]:hover {
    background-color: #2563EB !important;
    border-color: #2563EB !important;
    box-shadow: 0 4px 14px rgba(29, 111, 232, 0.5) !important;
    transform: translateY(-1px) !important;
}

/* 11. Segmented Tabs with Smooth Indicator */
.stTabs [data-baseweb="tab-list"] {
    background-color: #070B14 !important;
    border-radius: 6px !important;
    padding: 3px !important;
    gap: 3px !important;
    border: 1px solid rgba(255, 255, 255, 0.06) !important;
}

.stTabs [data-baseweb="tab"] {
    color: #94A3B8 !important;
    border-radius: 5px !important;
    padding: 6px 14px !important;
    font-size: 0.80rem !important;
    font-weight: 500 !important;
    transition: all 0.18s cubic-bezier(0.4, 0, 0.2, 1) !important;
    white-space: nowrap !important;
}

.stTabs [data-baseweb="tab"]:hover {
    color: #F8FAFC !important;
    background: rgba(255, 255, 255, 0.04) !important;
}

.stTabs [aria-selected="true"] {
    background-color: #111A2E !important;
    color: #F8FAFC !important;
    border-bottom: 2px solid #1D6FE8 !important;
    font-weight: 600 !important;
}

/* 12. Inputs, Selectboxes, Dropdowns with Smooth Focus & Popover Animation */
div[data-baseweb="select"] > div,
div[data-baseweb="input"] > div,
div[data-baseweb="textarea"] > div {
    background-color: #070B14 !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    color: #F8FAFC !important;
    border-radius: 6px !important;
    transition: all 0.22s cubic-bezier(0.16, 1, 0.3, 1) !important;
}

div[data-baseweb="select"] > div:hover,
div[data-baseweb="input"] > div:hover {
    border-color: rgba(56, 189, 248, 0.45) !important;
    background-color: #090E1C !important;
}

div[data-baseweb="select"] > div:focus-within,
div[data-baseweb="input"] > div:focus-within {
    border-color: #1D6FE8 !important;
    box-shadow: 0 0 0 2px rgba(29, 111, 232, 0.25), 0 2px 8px rgba(0, 0, 0, 0.4) !important;
    background-color: #090E1C !important;
}

div[data-baseweb="select"] svg {
    color: #94A3B8 !important;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
}
div[data-baseweb="select"]:hover svg {
    color: #38BDF8 !important;
    transform: translateY(1px) !important;
}

/* Dropdown popover container with smooth slide-down animation */
div[data-baseweb="popover"] {
    border-radius: 6px !important;
    overflow: hidden !important;
    box-shadow: 0 10px 30px -5px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(255, 255, 255, 0.1) !important;
    animation: consoleDropdownSlide 0.18s cubic-bezier(0.16, 1, 0.3, 1) !important;
}

@keyframes consoleDropdownSlide {
    from {
        opacity: 0;
        transform: translateY(-4px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

ul[data-baseweb="menu"] {
    background-color: #0D1526 !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 6px !important;
    padding: 4px !important;
}

li[data-baseweb="menu-item"] {
    color: #CBD5E1 !important;
    font-size: 0.82rem !important;
    border-radius: 4px !important;
    padding: 6px 10px !important;
    transition: all 0.14s cubic-bezier(0.16, 1, 0.3, 1) !important;
}

li[data-baseweb="menu-item"]:hover {
    background-color: #131D31 !important;
    color: #38BDF8 !important;
    transform: translateX(2px) !important;
}

/* 13. Dataframe Containers */
div[data-testid="stDataFrame"] {
    border: 1px solid rgba(255, 255, 255, 0.06) !important;
    border-radius: 6px !important;
    background: #0D1526 !important;
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
}
div[data-testid="stDataFrame"]:hover {
    border-color: rgba(255, 255, 255, 0.14) !important;
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.25) !important;
}

/* 14. Expanders with Smooth Transitions */
details[data-testid="stExpander"] {
    background-color: #0D1526 !important;
    border: 1px solid rgba(255, 255, 255, 0.06) !important;
    border-radius: 6px !important;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
}
details[data-testid="stExpander"]:hover {
    border-color: rgba(56, 189, 248, 0.3) !important;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2) !important;
}
details[data-testid="stExpander"] summary {
    color: #F8FAFC !important;
    font-weight: 500 !important;
    transition: color 0.15s ease !important;
}
details[data-testid="stExpander"] summary:hover {
    color: #38BDF8 !important;
}

/* 15. Progress Bars with Smooth Cyan-to-Blue Gradient */
div[data-testid="stProgress"] > div > div > div > div {
    background: linear-gradient(90deg, #1D6FE8 0%, #38BDF8 100%) !important;
    border-radius: 4px !important;
    transition: width 0.4s cubic-bezier(0.16, 1, 0.3, 1) !important;
}
div[data-testid="stProgress"] > div > div > div {
    background-color: #050811 !important;
    border-radius: 4px !important;
    border: 1px solid rgba(255, 255, 255, 0.04) !important;
}

/* 16. Code Blocks (Recessed Terminal Styling) */
div[data-testid="stCodeBlock"] {
    border-radius: 6px !important;
    border: 1px solid rgba(255, 255, 255, 0.07) !important;
    background: #050811 !important;
}

/* 17. Alerts (Notice Card Style) */
div[data-testid="stAlert"] {
    background-color: #0D1526 !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 6px !important;
    color: #CBD5E1 !important;
    animation: consoleFadeIn 0.22s ease !important;
}

/* 18. Radio Button Group (Pill Buttons) */
div[data-testid="stRadio"] > div[role="radiogroup"] {
    gap: 8px !important;
}
div[data-testid="stRadio"] label {
    background: #0D1526 !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 6px !important;
    padding: 4px 10px !important;
    cursor: pointer !important;
    transition: all 0.16s cubic-bezier(0.16, 1, 0.3, 1) !important;
}
div[data-testid="stRadio"] label:hover {
    border-color: rgba(56, 189, 248, 0.4) !important;
    color: #38BDF8 !important;
    transform: translateY(-1px) !important;
}

/* 19. Metric Cards (st.metric) */
div[data-testid="stMetric"] {
    background-color: #0D1526 !important;
    border: 1px solid rgba(255, 255, 255, 0.07) !important;
    border-radius: 6px !important;
    padding: 10px 14px !important;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.25) !important;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
}
div[data-testid="stMetric"]:hover {
    border-color: rgba(56, 189, 248, 0.3) !important;
    transform: translateY(-1px) !important;
}
div[data-testid="stMetric"] label {
    font-size: 10.5px !important;
    font-weight: 600 !important;
    color: #64748B !important;
    text-transform: uppercase !important;
    letter-spacing: 0.06em !important;
}
div[data-testid="stMetric"] [data-testid="stMetricValue"] {
    font-size: 1.45rem !important;
    font-weight: 700 !important;
    color: #F8FAFC !important;
    font-family: 'Inter', sans-serif !important;
}

/* 20. File Uploader Dropzone (st.file_uploader) */
div[data-testid="stFileUploader"] {
    background-color: #070B14 !important;
    border: 1px dashed rgba(56, 189, 248, 0.35) !important;
    border-radius: 8px !important;
    padding: 16px 20px !important;
    transition: all 0.2s ease !important;
}
div[data-testid="stFileUploader"]:hover {
    border-color: #38BDF8 !important;
    background-color: #090E1C !important;
    box-shadow: 0 0 14px rgba(56, 189, 248, 0.12) !important;
}
div[data-testid="stFileUploaderDropzone"] {
    background: transparent !important;
    border: none !important;
}
div[data-testid="stFileUploader"] section {
    background: transparent !important;
}
div[data-testid="stFileUploader"] button {
    background-color: #111A2E !important;
    border: 1px solid rgba(56, 189, 248, 0.3) !important;
    color: #38BDF8 !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    font-size: 0.8rem !important;
    transition: all 0.18s ease !important;
}
div[data-testid="stFileUploader"] button:hover {
    background-color: #18243E !important;
    border-color: #38BDF8 !important;
    color: #F8FAFC !important;
    transform: translateY(-1px) !important;
}

/* 21. Status Pipeline Widget (st.status) */
div[data-testid="stStatusWidget"],
div[data-testid="stStatusWidget"] > details {
    background-color: #0D1526 !important;
    border: 1px solid rgba(56, 189, 248, 0.25) !important;
    border-radius: 6px !important;
    padding: 10px 14px !important;
}

/* 22. Slider Control (st.slider) */
div[data-testid="stSlider"] [data-baseweb="slider"] {
    margin-top: 4px !important;
}
div[data-testid="stSlider"] div[role="slider"] {
    background-color: #1D6FE8 !important;
    border: 2px solid #38BDF8 !important;
    box-shadow: 0 0 8px rgba(56, 189, 248, 0.5) !important;
    width: 14px !important;
    height: 14px !important;
}
div[data-testid="stSlider"] div[role="slider"]:focus {
    box-shadow: 0 0 0 4px rgba(29, 111, 232, 0.35) !important;
}

/* 23. Main Content Action Links (KPI Card Footers) */
.block-container div.stPageLink a {
    background: rgba(29, 111, 232, 0.10) !important;
    border: 1px solid rgba(56, 189, 248, 0.20) !important;
    border-radius: 5px !important;
    padding: 4px 8px !important;
    color: #38BDF8 !important;
    font-size: 0.74rem !important;
    font-weight: 600 !important;
    justify-content: center !important;
    text-align: center !important;
    margin-top: 4px !important;
    transition: all 0.18s ease !important;
}
.block-container div.stPageLink a:hover {
    background: rgba(29, 111, 232, 0.22) !important;
    border-color: #38BDF8 !important;
    color: #F8FAFC !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3) !important;
}

/* 24. Tight Flush Element Spacing across Workspaces */
.block-container .stElementContainer {
    margin-bottom: 0.55rem !important;
}

/* Hide ugly overlapping Streamlit input instructions (e.g. "Press Enter to apply") */
div[data-testid="InputInstructions"],
.stTextInput small,
.stPasswordInput small,
[data-testid="stTextInputRootElement"] small {
    display: none !important;
}

/* 25. Modern Welcome & Authentication Portal Styling */
.welcome-ambient-glow {
    position: absolute;
    top: 0;
    left: 50%;
    transform: translateX(-50%);
    width: 800px;
    height: 400px;
    background: radial-gradient(circle, rgba(29, 111, 232, 0.22) 0%, rgba(139, 92, 246, 0.12) 40%, transparent 70%);
    filter: blur(80px);
    pointer-events: none;
    z-index: 0;
}

.welcome-portal-wrap {
    position: relative;
    z-index: 1;
}

.welcome-card-glass {
    background: rgba(13, 21, 38, 0.88) !important;
    backdrop-filter: blur(20px) !important;
    border: 1px solid rgba(56, 189, 248, 0.22) !important;
    border-radius: 12px !important;
    padding: 28px !important;
    box-shadow: 0 20px 50px rgba(0, 0, 0, 0.65), 0 0 25px rgba(29, 111, 232, 0.14) !important;
    transition: all 0.25s ease !important;
}
.welcome-card-glass:hover {
    border-color: rgba(56, 189, 248, 0.4) !important;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.75), 0 0 35px rgba(29, 111, 232, 0.22) !important;
}

/* Official Google Sign-In Button Styling (Single Real Clickable Button) */
div.st-key-btn_auth_google button,
div[data-testid="stButton"]:has(button[key*="btn_auth_google"]) button {
    background-color: #FFFFFF !important;
    background: #FFFFFF !important;
    color: #1F2937 !important;
    font-family: 'Inter', -apple-system, sans-serif !important;
    font-weight: 600 !important;
    font-size: 0.92rem !important;
    border: 1px solid #E5E7EB !important;
    border-radius: 8px !important;
    height: 46px !important;
    min-height: 46px !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    gap: 12px !important;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3), 0 0 1px rgba(255, 255, 255, 0.5) !important;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
    cursor: pointer !important;
}
div.st-key-btn_auth_google button:hover,
div[data-testid="stButton"]:has(button[key*="btn_auth_google"]) button:hover {
    background-color: #F8FAFC !important;
    background: #F8FAFC !important;
    border-color: #4285F4 !important;
    color: #111827 !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 6px 20px rgba(66, 133, 244, 0.4) !important;
}
div.st-key-btn_auth_google button:active,
div[data-testid="stButton"]:has(button[key*="btn_auth_google"]) button:active {
    transform: scale(0.99) !important;
    background-color: #E2E8F0 !important;
}
div.st-key-btn_auth_google button::before,
div[data-testid="stButton"]:has(button[key*="btn_auth_google"]) button::before {
    content: '' !important;
    display: inline-block !important;
    width: 20px !important;
    height: 20px !important;
    flex-shrink: 0 !important;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%234285F4' d='M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z'/%3E%3Cpath fill='%2334A853' d='M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z'/%3E%3Cpath fill='%23FBBC05' d='M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z'/%3E%3Cpath fill='%23EA4335' d='M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z'/%3E%3C/svg%3E") !important;
    background-size: contain !important;
    background-repeat: no-repeat !important;
    background-position: center !important;
}

.auth-divider {
    display: flex;
    align-items: center;
    text-align: center;
    margin: 18px 0 14px 0;
    color: #64748B;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
}
.auth-divider::before, .auth-divider::after {
    content: '';
    flex: 1;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}
.auth-divider::before {
    margin-right: 12px;
}
.auth-divider::after {
    margin-left: 12px;
}

.hero-value-prop {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    padding: 14px 16px;
    background: #0D1526;
    border: 1px solid rgba(255, 255, 255, 0.07);
    border-radius: 8px;
    margin-bottom: 10px;
    transition: all 0.22s cubic-bezier(0.16, 1, 0.3, 1);
}
.hero-value-prop:hover {
    border-color: rgba(56, 189, 248, 0.35);
    transform: translateX(4px);
    background: #111A2E;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
}
</style>
"""


def inject_theme() -> None:
    """Injects desktop engineering console theme CSS with smooth animations."""
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


def get_plotly_layout(title: str = "", height: int = 250, **kwargs) -> Dict[str, Any]:
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
            bgcolor="rgba(13, 21, 38, 0.8)",
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
