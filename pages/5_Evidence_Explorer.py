"""Evidence Explorer Page — ChronoTrace.

Evidence-first workspace allowing investigators to inspect the original records behind every reconstructed event:
- Dual-panel interface (Left: Filterable raw records; Right: Structured monospace inspector)
- Expandable raw JSON, key-value breakdown, and copy citations
- Explicit distinction between authentic source logs and inferred relationships
- Cross-linkage to normalized events and findings
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
from components.evidence_panel import render_evidence_explorer
from database.db import get_investigation, get_raw_events, get_events

# 1. Page Configuration
inv_id = setup_forensic_page("Evidence Explorer")
selected_inv_id = render_sidebar(current_page_id="explorer")
inv = get_investigation(selected_inv_id) or {"id": selected_inv_id, "name": "Active Investigation", "is_demo": 1}

# 2. Fetch Evidence Records
raw_records = get_raw_events(selected_inv_id, limit=500)
events = get_events(selected_inv_id)

hosts = list({e["host"] for e in events if e.get("host")})
sources = list({r["source"] for r in raw_records if r.get("source")})

# 3. Render Topbar
filters = render_topbar("Evidence Explorer", inv, hosts=hosts, sources=sources)

st.markdown(
    """
    <div style="margin-top: -12px; margin-bottom: 20px;">
        <span style="font-size: 0.95rem; color: #94A7C2; font-style: italic;">
            "Inspect the immutable original records behind the reconstructed timeline."
        </span>
    </div>
    """,
    unsafe_allow_html=True
)

# Check for preselected raw_ref passed from Timeline or Overview
preselected_ref = st.session_state.get("selected_raw_ref")

# 4. Render Dual-Pane Evidence Explorer
render_evidence_explorer(
    raw_records=raw_records,
    normalized_events=events,
    preselected_raw_ref=preselected_ref
)
