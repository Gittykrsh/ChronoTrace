"""Provenance Graph Page — ChronoTrace.

Visualizes causal relationships between processes, users, hosts, files, and network endpoints:
- NetworkX directed graph model
- PyVis physics-enabled interactive canvas with node drag, zoom, and pan
- Distinct shapes and color codes per entity type
- Clear visual conventions for uncertain relationships (dashed lines, low link strength)
- Node/Edge inspector and neighborhood explorer
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
from components.graph_view import render_provenance_graph, render_graph_legend
from database.db import get_investigation, get_graph_data

# 1. Page Configuration
inv_id = setup_forensic_page("Provenance Graph")
selected_inv_id = render_sidebar(current_page_id="graph")
inv = get_investigation(selected_inv_id) or {"id": selected_inv_id, "name": "Active Investigation", "is_demo": 1}

# 2. Fetch Graph Data
graph_data = get_graph_data(selected_inv_id)
entities = graph_data.get("entities", [])
edges = graph_data.get("edges", [])

hosts = list({e["host"] for e in entities if e.get("host")})

# 3. Render Topbar
filters = render_topbar("Provenance Graph", inv, hosts=hosts)

st.markdown(
    """
    <div style="margin-top: -12px; margin-bottom: 20px;">
        <span style="font-size: 0.95rem; color: #94A7C2; font-style: italic;">
            "Follow relationships between processes, users, hosts, files, and network endpoints."
        </span>
    </div>
    """,
    unsafe_allow_html=True
)

# 4. Graph Control Toolbar
col_type, col_search = st.columns([4, 6])
with col_type:
    type_options = ["All Types", "Process", "User", "Host", "IP", "File"]
    selected_type = st.selectbox("Entity Type Filter:", options=type_options, key="graph_type_select")

with col_search:
    entity_search = st.text_input(
        "Search Entity Name / Image / Key / GUID:",
        placeholder="e.g. powershell, 4820, jdoe, 185.220.101.5...",
        key="graph_entity_search"
    ).strip().lower()

# 5. Interactive Graph Canvas
render_provenance_graph(
    entities=entities,
    edges=edges,
    filter_type=selected_type if selected_type != "All Types" else None,
    filter_host=filters["host"] if filters["host"] != "All Hosts" else None,
    search_query=entity_search or filters["search_query"]
)

# 6. Graph Legend & Conventions
render_graph_legend()

st.markdown("<hr style='margin: 20px 0; border-color: rgba(148,167,194,0.12);'/>", unsafe_allow_html=True)

# 7. Entity & Relationship Inspector (Tabular Breakdown)
st.markdown("#### 🔍 Graph Entity & Edge Inspector")
tab_ent, tab_edg = st.tabs([f"Entities ({len(entities)})", f"Edges ({len(edges)})"])

with tab_ent:
    ent_rows = []
    for ent in entities:
        ent_rows.append({
            "Entity ID": ent["entity_id"],
            "Type": ent["type"].upper(),
            "Label": ent["label"],
            "Key / Identity": ent["key"],
            "Host": ent.get("host", "N/A"),
            "First Seen": ent.get("first_seen", "")[:19],
            "Last Seen": ent.get("last_seen", "")[:19]
        })
    st.dataframe(ent_rows, use_container_width=True, hide_index=True)

with tab_edg:
    edg_rows = []
    for ed in edges:
        is_unc = bool(ed.get("is_uncertain"))
        ev_ids = ed.get("evidence_event_ids", [])
        ev_str = ", ".join(ev_ids) if isinstance(ev_ids, list) else str(ev_ids)
        edg_rows.append({
            "Edge ID": ed["edge_id"],
            "Source Entity": ed["src_entity"],
            "Relation": ed["relation"],
            "Destination Entity": ed["dst_entity"],
            "Link Strength": f"{float(ed.get('link_strength', 1.0)):.2f}",
            "Uncertain?": "⚠️ UNCERTAIN (Heuristic)" if is_unc else "✓ High Confidence",
            "Supporting Events": ev_str
        })
    st.dataframe(edg_rows, use_container_width=True, hide_index=True)
