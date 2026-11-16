"""Provenance Graph Page — ChronoTrace.

Visualizes causal relationships between processes, users, hosts, files, and network endpoints:
- NetworkX directed graph model
- PyVis physics-enabled interactive canvas with node drag, zoom, and pan
- Distinct shapes and colors per entity type
- Visual conventions for uncertain relationships (dashed amber lines, low link strength)
- Compact toolbar with search, filters, inline legend, and entity/edge inspectors
"""

import streamlit as st
import streamlit.components.v1 as components
import os
import sys
import json
import tempfile
import networkx as nx
import pandas as pd
import plotly.graph_objects as go

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ui.theme import (
    inject_theme,
    calc_df_height,
    get_plotly_layout,
    render_raw_ref_pill,
    icon_svg,
    ACCENT_BLUE,
    EYEBROW_BLUE,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    TEXT_MUTED
)
from ui.layout import render_sidebar, render_topbar
from ui.components import render_page_header, render_card_header, render_notice_banner
from database.db import init_db, get_investigation, get_graph_data

# 1. Page Configuration & Theme
st.set_page_config(
    page_title="Provenance Graph — ChronoTrace",
    page_icon=":material/hub:",
    layout="wide",
    initial_sidebar_state="expanded"
)
inject_theme()
init_db()

# 2. Render Persistent Flat Sidebar
selected_inv_id = render_sidebar(current_page_id="graph")
inv = get_investigation(selected_inv_id) or {"id": selected_inv_id, "name": "Active Investigation", "is_demo": 1}

# 3. Fetch Graph Data
graph_data = get_graph_data(selected_inv_id)
entities = graph_data.get("entities", [])
edges = graph_data.get("edges", [])

hosts = sorted(list({e["host"] for e in entities if e.get("host")}))

# 4. Render Topbar
filters = render_topbar("Graph", inv, hosts=hosts)

# Operational Assurance Notice Banner (Matches Reference Desktop Console)
render_notice_banner(
    "Causal graph provenance notice. Interactive physics graph maps process lifecycles, user sessions, network sockets, and file mutations via NetworkX. Amber dashed edges indicate heuristic or uncertain linkages.",
    icon_name="graph",
    highlight_prefix="Causal Provenance Notice:"
)

# 5. Standardized Page Header Block
render_page_header(
    eyebrow="FORENSIC WORKSPACE / GRAPH",
    title="Provenance Graph",
    subtitle="Follow causal relationships between processes, users, hosts, files, and network endpoints."
)

# 6. Graph Control Toolbar & Inline Legend
t_col1, t_col2, t_col3 = st.columns([3, 4, 5], gap="small")

with t_col1:
    type_options = ["All Types", "Process", "User", "Host", "IP", "File"]
    selected_type = st.selectbox(
        "Entity Type Filter:",
        options=type_options,
        key="graph_type_select",
        label_visibility="collapsed"
    )

with t_col2:
    entity_search = st.text_input(
        "Search Entity",
        placeholder="Filter entity by name, GUID, PID, user, IP...",
        key="graph_entity_search",
        label_visibility="collapsed"
    ).strip().lower()

with t_col3:
    # Inline Compact Visual Legend (Clean dots, no emojis)
    st.markdown(
        """
        <div style="display: flex; align-items: center; justify-content: flex-end; gap: 12px; height: 38px; font-size: 11px; font-family: 'Inter', sans-serif;">
            <div style="display: flex; align-items: center; gap: 4px;"><span style="width: 8px; height: 8px; background: #38BDF8; border-radius: 2px;"></span> <span style="color: #94A3B8;">Process</span></div>
            <div style="display: flex; align-items: center; gap: 4px;"><span style="width: 8px; height: 8px; background: #818CF8; border-radius: 50%;"></span> <span style="color: #94A3B8;">User</span></div>
            <div style="display: flex; align-items: center; gap: 4px;"><span style="width: 8px; height: 8px; background: #60A5FA; border-radius: 2px;"></span> <span style="color: #94A3B8;">Host</span></div>
            <div style="display: flex; align-items: center; gap: 4px;"><span style="width: 8px; height: 8px; background: #34D399; border-radius: 50%;"></span> <span style="color: #94A3B8;">IP</span></div>
            <div style="display: flex; align-items: center; gap: 4px;"><span style="width: 8px; height: 8px; background: #FBBF24; border-radius: 2px;"></span> <span style="color: #94A3B8;">File</span></div>
            <div style="display: flex; align-items: center; gap: 4px;"><span style="width: 14px; border-top: 2px dashed #FBBF24;"></span> <span style="color: #94A3B8;">Uncertain</span></div>
        </div>
        """,
        unsafe_allow_html=True
    )

# 7. Filter Graph Entities & Edges
filtered_entities = entities
if selected_type != "All Types":
    filtered_entities = [e for e in filtered_entities if e.get("type", "").lower() == selected_type.lower()]
if filters["host"] != "All Hosts":
    filtered_entities = [e for e in filtered_entities if e.get("host") == filters["host"]]
if entity_search:
    filtered_entities = [
        e for e in filtered_entities
        if entity_search in e.get("label", "").lower()
        or entity_search in e.get("key", "").lower()
        or entity_search in str(e.get("attributes", "")).lower()
    ]

visible_ent_ids = {e["entity_id"] for e in filtered_entities}
filtered_edges = [
    ed for ed in edges
    if ed.get("src_entity") in visible_ent_ids and ed.get("dst_entity") in visible_ent_ids
]

NODE_COLOR_MAP = {
    "process": "#38BDF8",
    "user": "#818CF8",
    "host": "#60A5FA",
    "ip": "#34D399",
    "file": "#FBBF24"
}

NODE_SHAPE_MAP = {
    "process": "box",
    "user": "diamond",
    "host": "hexagon",
    "ip": "triangle",
    "file": "square"
}

# 8. Render Graph Canvas
if not filtered_entities:
    st.info("No entities match current graph filters.")
else:
    try:
        from pyvis.network import Network
        net = Network(height="500px", width="100%", bgcolor="#090E1A", font_color="#F8FAFC", directed=True)
        net.barnes_hut(gravity=-2500, central_gravity=0.30, spring_length=110, spring_strength=0.06, damping=0.92)

        for ent in filtered_entities:
            etype = ent.get("type", "process").lower()
            color = NODE_COLOR_MAP.get(etype, "#38BDF8")
            shape = NODE_SHAPE_MAP.get(etype, "dot")
            label = ent.get("label", ent.get("key", "N/A"))

            attrs = ent.get("attributes", {})
            title_lines = [
                f"Type: {etype.upper()}",
                f"Host: {ent.get('host', 'N/A')}",
                f"Identity: {ent.get('key')}"
            ]
            if isinstance(attrs, dict):
                for k, v in attrs.items():
                    if v and k not in ("hostname",):
                        title_lines.append(f"{k}: {str(v)[:65]}")
            tooltip = "\n".join(title_lines)

            net.add_node(
                ent["entity_id"],
                label=label,
                title=tooltip,
                color=color,
                shape=shape,
                size=20 if etype == "process" else 16,
                font={"size": 11, "face": "JetBrains Mono, monospace", "color": "#F8FAFC"}
            )

        for ed in filtered_edges:
            is_uncertain = bool(ed.get("is_uncertain", 0))
            link_strength = float(ed.get("link_strength", 1.0))
            relation = ed.get("relation", "connected")
            ev_ids = ed.get("evidence_event_ids", [])
            ev_str = ", ".join(ev_ids) if isinstance(ev_ids, list) else str(ev_ids)

            edge_title = f"Relation: {relation}\nLink Strength: {link_strength:.2f}\nUncertainty: {'YES (Heuristic)' if is_uncertain else 'NO (Deterministic)'}\nSupporting Events: {ev_str}"
            edge_color = "#FBBF24" if is_uncertain else "#38BDF8"

            net.add_edge(
                ed["src_entity"],
                ed["dst_entity"],
                title=edge_title,
                label=relation if not is_uncertain else f"{relation} (?)",
                color={"color": edge_color, "opacity": 0.45 if is_uncertain else 0.85},
                dashes=is_uncertain,
                width=1.5 if is_uncertain else 2.2
            )

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as tmp:
            tmp_path = tmp.name
            net.save_graph(tmp_path)

        with open(tmp_path, "r", encoding="utf-8") as f:
            html_code = f.read()

        try:
            os.unlink(tmp_path)
        except Exception:
            pass

        components.html(html_code, height=510, scrolling=False)

    except Exception as e:
        st.warning(f"Interactive PyVis fallback: {str(e)}")
        G = nx.DiGraph()
        for ent in filtered_entities:
            G.add_node(ent["entity_id"], **ent)
        for ed in filtered_edges:
            G.add_edge(ed["src_entity"], ed["dst_entity"], **ed)

        pos = nx.spring_layout(G, seed=42)
        edge_x, edge_y = [], []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=1.5, color="rgba(56, 189, 248, 0.4)"), mode="lines", hoverinfo="none")
        node_x = [pos[n][0] for n in G.nodes()]
        node_y = [pos[n][1] for n in G.nodes()]
        node_text = [f"[{G.nodes[n].get('type')}] {G.nodes[n].get('label')}" for n in G.nodes()]
        node_colors = [NODE_COLOR_MAP.get(G.nodes[n].get("type"), "#38BDF8") for n in G.nodes()]

        node_trace = go.Scatter(
            x=node_x, y=node_y, mode="markers+text",
            text=[G.nodes[n].get("label", "") for n in G.nodes()],
            textposition="top center",
            marker=dict(size=16, color=node_colors, line=dict(width=1, color="#F8FAFC")),
            hovertext=node_text, hoverinfo="text"
        )
        fig_fallback = go.Figure(data=[edge_trace, node_trace])
        layout_fb = get_plotly_layout(height=500)
        layout_fb["xaxis"] = dict(showgrid=False, zeroline=False, showticklabels=False)
        layout_fb["yaxis"] = dict(showgrid=False, zeroline=False, showticklabels=False)
        fig_fallback.update_layout(**layout_fb)
        st.plotly_chart(fig_fallback, use_container_width=True)

st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

# 9. Entity & Edge Inspectors (Tabular Breakdown)
render_card_header("Graph Entity & Edge Inspector", pill_text="CAUSAL TOPOLOGY", pill_class="pill-info", icon_name="search")
tab_ent, tab_edg = st.tabs([f"Entities ({len(filtered_entities)})", f"Edges ({len(filtered_edges)})"])

with tab_ent:
    ent_rows = []
    for ent in filtered_entities:
        ent_rows.append({
            "Entity ID": ent["entity_id"],
            "Type": ent["type"].upper(),
            "Label": ent["label"],
            "Identity / Key": ent["key"],
            "Host": ent.get("host", "N/A"),
            "First Seen (UTC)": ent.get("first_seen", "")[:19],
            "Last Seen (UTC)": ent.get("last_seen", "")[:19]
        })
    df_ent = pd.DataFrame(ent_rows)
    st.dataframe(df_ent, use_container_width=True, hide_index=True, height=calc_df_height(df_ent, min_h=120, max_h=240))

with tab_edg:
    edg_rows = []
    for ed in filtered_edges:
        is_unc = bool(ed.get("is_uncertain"))
        ev_ids = ed.get("evidence_event_ids", [])
        ev_str = ", ".join(ev_ids) if isinstance(ev_ids, list) else str(ev_ids)
        edg_rows.append({
            "Edge ID": ed["edge_id"],
            "Source Entity": ed["src_entity"],
            "Relation": ed["relation"],
            "Destination Entity": ed["dst_entity"],
            "Strength": f"{float(ed.get('link_strength', 1.0)):.2f}",
            "Uncertainty Status": "UNCERTAIN (Heuristic)" if is_unc else "High Confidence",
            "Supporting Evidence Events": ev_str
        })
    df_edg = pd.DataFrame(edg_rows)
    st.dataframe(df_edg, use_container_width=True, hide_index=True, height=calc_df_height(df_edg, min_h=120, max_h=240))
