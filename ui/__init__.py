"""ChronoTrace UI Package."""

from .theme import (
    inject_theme,
    get_plotly_layout,
    render_raw_ref_pill,
    render_flag_badge,
    render_confidence_badge,
    APP_BG,
    SIDEBAR_BG,
    CARD_BG,
    ELEVATED_BG,
    ACCENT_CYAN,
    ACCENT_VIOLET,
    SUCCESS_GREEN,
    WARNING_AMBER,
    ORANGE_WARN,
    CRITICAL_RED,
    TEXT_PRIMARY,
    TEXT_MUTED
)
from .layout import (
    render_sidebar,
    render_topbar,
    NAV_ITEMS
)

__all__ = [
    "inject_theme",
    "get_plotly_layout",
    "render_raw_ref_pill",
    "render_flag_badge",
    "render_confidence_badge",
    "render_sidebar",
    "render_topbar",
    "NAV_ITEMS",
    "APP_BG",
    "SIDEBAR_BG",
    "CARD_BG",
    "ELEVATED_BG",
    "ACCENT_CYAN",
    "ACCENT_VIOLET",
    "SUCCESS_GREEN",
    "WARNING_AMBER",
    "ORANGE_WARN",
    "CRITICAL_RED",
    "TEXT_PRIMARY",
    "TEXT_MUTED"
]
