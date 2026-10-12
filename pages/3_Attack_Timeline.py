"""Attack Timeline Page — ChronoTrace.

Forensic chronological reconstruction:
- Horizontal interactive Plotly timeline showing uncertainty intervals [ts_start, ts_end]
- Visual markers for ORDER_CONFLICT, MISSING_PARENT, LOG_CLEARED, SINGLE_SOURCE
- Interactive event sequence table adhering to Section 6 schema
- Comprehensive event details drawer with 4-factor confidence breakdown and clickable raw_ref
"""

import streamlit as st
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from components.page_setup import setup_forensic_page
from components.sidebar import render_sidebar
from components.topbar import render_topbar
from components.timeline import (
    render_timeline_gantt,
    render_event_table,
    render_event_details_drawer
)
from database.db import get_investigation, get_events

# 1. Page Configuration
inv_id = setup_forensic_page("Attack Timeline")
selected_inv_id = render_sidebar(current_page_id="timeline")
inv = get_investigation(selected_inv_id) or {"id": selected_inv_id, "name": "Active Investigation", "is_demo": 1}

# 2. Fetch Data
events = get_events(selected_inv_id)
hosts = list({e["host"] for e in events if e.get("host")})
sources = list({e["source"] for e in events if e.get("source")})

# 3. Render Topbar
filters = render_topbar("Attack Timeline", inv, hosts=hosts, sources=sources)

st.markdown(
    """
    <div style="margin-top: -12px; margin-bottom: 20px;">
        <span style="font-size: 0.95rem; color: #94A7C2; font-style: italic;">
            "Examine event sequences, uncertain ordering, and the evidence behind every finding."
        </span>
    </div>
    """,
    unsafe_allow_html=True
)

# Apply filters
filtered_events = events
if filters["host"] != "All Hosts":
    filtered_events = [e for e in filtered_events if e.get("host") == filters["host"]]
if filters["source"] != "All Sources":
    filtered_events = [e for e in filtered_events if e.get("source") == filters["source"]]
if filters["min_confidence"] > 0.0:
    filtered_events = [e for e in filtered_events if e.get("confidence", 0) >= filters["min_confidence"]]
if filters["search_query"]:
    q = filters["search_query"]
    filtered_events = [
        e for e in filtered_events
        if q in (e.get("image") or "").lower()
        or q in (e.get("command_line") or "").lower()
        or q in (e.get("user") or "").lower()
        or q in (e.get("raw_ref") or "").lower()
        or q in str(e.get("pid", ""))
        or q in (e.get("event_id") or "").lower()
    ]

# 4. Interactive Timeline Interval Visualization
render_timeline_gantt(filtered_events)

st.markdown("<hr style='margin: 20px 0; border-color: rgba(148,167,194,0.12);'/>", unsafe_allow_html=True)

# 5. Interactive Event Table
selected_event = render_event_table(filtered_events)

st.markdown("<hr style='margin: 20px 0; border-color: rgba(148,167,194,0.12);'/>", unsafe_allow_html=True)

# 6. Selected Event Forensic Details Drawer
if selected_event:
    render_event_details_drawer(selected_event)
else:
    st.info("Select an event from the table above to open its comprehensive forensic drawer.")
