"""Interactive Provenance Graph Component for ChronoTrace.

Uses NetworkX and PyVis (with Plotly fallback) to visualize causal relationships:
- Entities: Process, User, Host, IP, File
- Edges: spawned, logged-in, connected-to, created-file
- Visual treatment for uncertain relationships (dashed, reduced opacity, low link strength)
- Node/Edge inspector and neighborhood explorer
"""

import streamlit as st
import streamlit.components.v1 as components
import networkx as nx
import json
import tempfile
import os
from typing import List, Dict, Any, Optional

NODE_COLOR_MAP = {
    "process": "#35D6E8",
    "user": "#8B7CFF",
    "host": "#4A90E2",
    "ip": "#37D99A",
    "file": "#F5B942"
}

NODE_SHAPE_MAP = {
    "process": "box",
    "user": "diamond",
    "host": "hexagon",
    "ip": "triangle",
    "file": "square"
}


def render_provenance_graph(
    entities: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    filter_type: Optional[str] = None,
    filter_host: Optional[str] = None,
    search_query: str = ""
) -> None:
    """Renders interactive PyVis HTML physics graph with dark SOC theme."""
    if not entities:
        st.info("No entities available in active case for graph reconstruction.")
        return

    # Filter entities
    filtered_entities = entities
    if filter_type and filter_type != "All Types":
        filtered_entities = [e for e in filtered_entities if e.get("type", "").lower() == filter_type.lower()]
    if filter_host and filter_host != "All Hosts":
        filtered_entities = [e for e in filtered_entities if e.get("host") == filter_host]
    if search_query:
        filtered_entities = [
            e for e in filtered_entities 
            if search_query in e.get("label", "").lower() or search_query in e.get("key", "").lower()
        ]

    visible_ent_ids = {e["entity_id"] for e in filtered_entities}
    filtered_edges = [
        ed for ed in edges
        if ed.get("src_entity") in visible_ent_ids and ed.get("dst_entity") in visible_ent_ids
    ]

    try:
        from pyvis.network import Network
        net = Network(height="580px", width="100%", bgcolor="#121D30", font_color="#EDF4FF", directed=True)
        net.barnes_hut(gravity=-3000, central_gravity=0.3, spring_length=120, spring_strength=0.05, damping=0.95)

        for ent in filtered_entities:
            etype = ent.get("type", "process")
            color = NODE_COLOR_MAP.get(etype, "#35D6E8")
            shape = NODE_SHAPE_MAP.get(etype, "dot")
            label = ent.get("label", ent.get("key", "N/A"))
            
            # Formulate rich tooltip
            attrs = ent.get("attributes", {})
            title_lines = [
                f"Type: {etype.upper()}",
                f"Host: {ent.get('host', 'N/A')}",
                f"Key: {ent.get('key')}"
            ]
            if isinstance(attrs, dict):
                for k, v in attrs.items():
                    if v and k not in ("hostname",):
                        title_lines.append(f"{k}: {str(v)[:70]}")
            tooltip = "\n".join(title_lines)

            net.add_node(
                ent["entity_id"],
                label=label,
                title=tooltip,
                color=color,
                shape=shape,
                size=22 if etype == "process" else 18,
                font={"size": 12, "face": "JetBrains Mono, sans-serif"}
            )

        for ed in filtered_edges:
            is_uncertain = bool(ed.get("is_uncertain", 0))
            link_strength = float(ed.get("link_strength", 1.0))
            relation = ed.get("relation", "connected")
            ev_ids = ed.get("evidence_event_ids", [])
            ev_str = ", ".join(ev_ids) if isinstance(ev_ids, list) else str(ev_ids)

            edge_title = f"Relation: {relation}\nLink Strength: {link_strength:.2f}\nUncertain: {is_uncertain}\nSupporting Evidence Events: {ev_str}"

            edge_color = "#F5B942" if is_uncertain else "#35D6E8"
            
            net.add_edge(
                ed["src_entity"],
                ed["dst_entity"],
                title=edge_title,
                label=relation if not is_uncertain else f"{relation} (?)",
                color={"color": edge_color, "opacity": 0.45 if is_uncertain else 0.85},
                dashes=is_uncertain,
                width=1.5 if is_uncertain else 2.5
            )

        # Generate HTML file
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as tmp:
            tmp_path = tmp.name
            net.save_graph(tmp_path)

        with open(tmp_path, "r", encoding="utf-8") as f:
            html_code = f.read()

        try:
            os.unlink(tmp_path)
        except Exception:
            pass

        # Render interactive component
        components.html(html_code, height=600, scrolling=False)

    except Exception as e:
        st.warning(f"PyVis rendering fallback: {str(e)}")
        # Plotly fallback
        _render_plotly_graph_fallback(filtered_entities, filtered_edges)


def _render_plotly_graph_fallback(entities: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> None:
    """Plotly 2D Network fallback if PyVis is unavailable."""
    import plotly.graph_objects as go
    G = nx.DiGraph()
    for ent in entities:
        G.add_node(ent["entity_id"], **ent)
    for ed in edges:
        G.add_edge(ed["src_entity"], ed["dst_entity"], **ed)

    pos = nx.spring_layout(G, seed=42)

    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1.5, color="rgba(53, 214, 232, 0.4)"),
        hoverinfo="none",
        mode="lines"
    )

    node_x, node_y, node_color, node_text = [], [], [], []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        ndata = G.nodes[node]
        node_color.append(NODE_COLOR_MAP.get(ndata.get("type"), "#35D6E8"))
        node_text.append(f"[{ndata.get('type')}] {ndata.get('label')}")

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        text=[G.nodes[n].get("label", "") for n in G.nodes()],
        textposition="top center",
        marker=dict(size=18, color=node_color, line=dict(width=1, color="#EDF4FF")),
        hoverinfo="text",
        hovertext=node_text
    )

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(
        title="Provenance Graph (Plotly Fallback)",
        template="plotly_dark",
        plot_bgcolor="#121D30",
        paper_bgcolor="#121D30",
        showlegend=False,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
    )
    st.plotly_chart(fig, use_container_width=True)


def render_graph_legend() -> None:
    """Renders visual graph legend showing entity colors and edge certainty conventions."""
    st.markdown(
        """
        <div style="background: #17243A; border: 1px solid rgba(148,167,194,0.15); border-radius: 8px; padding: 14px; margin-top: 14px;">
            <div style="font-size: 0.82rem; font-weight: 700; color: #EDF4FF; margin-bottom: 8px; text-transform: uppercase;">
                PROVENANCE GRAPH CONVENTIONS & ENTITY LEGEND
            </div>
            <div style="display: flex; flex-wrap: wrap; gap: 16px; font-size: 0.78rem;">
                <div style="display: flex; align-items: center; gap: 6px;">
                    <span style="width: 12px; height: 12px; background: #35D6E8; border-radius: 2px;"></span>
                    <span><strong>Process:</strong> Sysmon / Security process execution</span>
                </div>
                <div style="display: flex; align-items: center; gap: 6px;">
                    <span style="width: 12px; height: 12px; background: #8B7CFF; transform: rotate(45deg);"></span>
                    <span><strong>User:</strong> Interactive or system account</span>
                </div>
                <div style="display: flex; align-items: center; gap: 6px;">
                    <span style="width: 12px; height: 12px; background: #4A90E2; border-radius: 50%;"></span>
                    <span><strong>Host:</strong> Endpoint machine / DC</span>
                </div>
                <div style="display: flex; align-items: center; gap: 6px;">
                    <span style="width: 12px; height: 12px; background: #37D99A;"></span>
                    <span><strong>IP Address:</strong> Network connection endpoint</span>
                </div>
                <div style="display: flex; align-items: center; gap: 6px;">
                    <span style="width: 12px; height: 12px; background: #F5B942; border-radius: 2px;"></span>
                    <span><strong>File:</strong> Created or modified payload</span>
                </div>
                <div style="display: flex; align-items: center; gap: 6px;">
                    <span style="width: 24px; border-top: 2px dashed #F5B942;"></span>
                    <span><strong>Dashed Edge:</strong> Uncertain link / PID heuristic</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
