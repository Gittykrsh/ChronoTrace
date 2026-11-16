"""Reusable Console Component Helpers for ChronoTrace — Modern Desktop Styling.

Directly matches the visual structure of the desktop operations console reference:
- Notice announcement banner (top safety/traceability alert)
- Page header block (eyebrow, title, subtitle)
- Card header with right-aligned micro pills
- Key-value inspector grid with hairline dividers (matching Connected Device telemetry)
- Stacked horizontal result cards with badges
- Recessed terminal / live output log boxes with copy & status indicators
"""

import streamlit as st
from typing import Dict, Any, List, Optional
from ui.theme import (
    icon_svg,
    render_raw_ref_pill,
    render_flag_badge,
    render_confidence_badge,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    TEXT_MUTED,
    TEXT_CAPTION,
    EYEBROW_BLUE,
    ACCENT_BLUE
)


def render_notice_banner(message: str, icon_name: str = "shield", highlight_prefix: str = "") -> None:
    """Renders a sleek top operational notice banner matching the desktop console reference."""
    ico = icon_svg(icon_name, size=13, color=EYEBROW_BLUE)
    prefix_html = f"<strong style='color: #F8FAFC; margin-right: 4px;'>{highlight_prefix}</strong>" if highlight_prefix else ""
    st.markdown(
        f"""
        <div class="console-notice-banner">
            <span style="display: inline-flex; align-items: center; flex-shrink: 0;">{ico}</span>
            <span>{prefix_html}{message}</span>
        </div>
        """,
        unsafe_allow_html=True
    )


def render_page_header(eyebrow: str, title: str, subtitle: str) -> None:
    """Renders standardized console page header block with eyebrow, title, and descriptive subtitle."""
    st.markdown(
        f"""
        <div style="margin-top: -4px; margin-bottom: 14px;">
            <div style="font-size: 11px; font-weight: 600; color: #38BDF8; letter-spacing: 0.08em; text-transform: uppercase; font-family: 'Inter', sans-serif; margin-bottom: 2px;">
                {eyebrow}
            </div>
            <div style="font-size: 20px; font-weight: 700; color: #F8FAFC; letter-spacing: -0.02em; font-family: 'Inter', sans-serif; line-height: 1.2;">
                {title}
            </div>
            <div style="font-size: 12.5px; color: #94A3B8; margin-top: 3px; font-family: 'Inter', sans-serif;">
                {subtitle}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def render_card_header(title: str, pill_text: str = "", pill_class: str = "pill-info", icon_name: str = "") -> None:
    """Renders card header with title on left and micro-pill on right."""
    ico_html = f"{icon_svg(icon_name, size=13, color=EYEBROW_BLUE)} " if icon_name else ""
    pill_html = f'<span class="status-pill {pill_class}">{pill_text}</span>' if pill_text else ""
    st.markdown(
        f"""
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
            <div style="font-size: 13.5px; font-weight: 600; color: #F8FAFC; display: flex; align-items: center; gap: 6px;">
                {ico_html}<span>{title}</span>
            </div>
            {pill_html}
        </div>
        """,
        unsafe_allow_html=True
    )


def render_key_value_grid(items: Dict[str, Any], columns: int = 2) -> None:
    """Renders a hairline-divided key-value inspector grid (matching Connected Device telemetry in screenshots)."""
    grid_items = list(items.items())
    rows_html = []
    
    for i in range(0, len(grid_items), columns):
        row_slice = grid_items[i:i + columns]
        cols_html = []
        for k, v in row_slice:
            val_str = str(v) if v is not None and str(v).strip() != "" else "—"
            is_mono = any(term in k.lower() for term in ["guid", "pid", "ref", "ip", "hash", "time", "utc", "path", "command", "serial", "build"])
            font_cls = "font-family: 'JetBrains Mono', monospace; font-size: 11.5px;" if is_mono else "font-family: 'Inter', sans-serif; font-size: 12.5px;"
            cols_html.append(
                f"""
                <div style="flex: 1; min-width: 0; padding: 5px 8px;">
                    <div style="font-size: 10.5px; font-weight: 600; color: #64748B; text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 2px;">
                        {k}
                    </div>
                    <div style="{font_cls} color: #F8FAFC; font-weight: 500; word-break: break-all; overflow-wrap: anywhere;">
                        {val_str}
                    </div>
                </div>
                """
            )
        rows_html.append(
            f"""
            <div style="display: flex; gap: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); padding-bottom: 5px; margin-bottom: 5px;">
                {''.join(cols_html)}
            </div>
            """
        )

    st.markdown(
        f"""
        <div class="console-elevated" style="padding: 10px 14px; margin-top: 6px;">
            {''.join(rows_html)}
        </div>
        """,
        unsafe_allow_html=True
    )


def render_stacked_result_card(
    title: str,
    stage: str,
    explanation: str,
    raw_ref: str,
    meta_line: str,
    flags: List[str] = None
) -> None:
    """Renders a stacked horizontal result card for findings or events (matching Image 5)."""
    if flags is None:
        flags = []
    flags_html = " ".join([render_flag_badge(fl) for fl in flags])
    raw_ref_html = render_raw_ref_pill(raw_ref) if raw_ref else ""

    st.markdown(
        f"""
        <div class="console-card" style="padding: 12px 16px; margin-bottom: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="font-weight: 600; font-size: 13.5px; color: #F8FAFC;">{title}</span>
                    <span class="status-pill pill-primary">{stage}</span>
                    {flags_html}
                </div>
                {raw_ref_html}
            </div>
            <div style="font-size: 12.5px; color: #CBD5E1; margin: 4px 0 6px 0; line-height: 1.45;">
                {explanation}
            </div>
            <div style="font-size: 11px; color: #64748B; font-family: 'Inter', sans-serif;">
                {meta_line}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def render_recessed_terminal(content: str, header_label: str = "LIVE OUTPUT", status_pill: str = "IDLE") -> None:
    """Renders a recessed terminal / log box with monospace text (matching Images 3, 4, 6, 7)."""
    st.markdown(
        f"""
        <div class="console-terminal" style="margin-top: 6px;">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255, 255, 255, 0.06); padding-bottom: 6px; margin-bottom: 8px;">
                <span style="color: #64748B; font-size: 11px; font-weight: 600; letter-spacing: 0.06em;">{header_label}</span>
                <span class="status-pill pill-info" style="font-size: 10px;">{status_pill}</span>
            </div>
            <div style="white-space: pre-wrap; word-break: break-all; max-height: 240px; overflow-y: auto;">
{content}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
