"""Attack Pathfinding & Blast Radius Graph Analytics Engine for ChronoTrace.

Uses NetworkX algorithms to evaluate:
1. Blast Radius: Percentage and breadth of enterprise perimeter compromised.
2. Kill-Chain Paths: Directed causal flow from initial entry to high-impact actions.
3. High-Value Asset (HVA) Exposure: Identifies compromise of Domain Controllers, SYSTEM accounts, and credentials.
"""

from typing import Dict, Any, List, Optional
import networkx as nx
from database.db import get_entities, get_edges, get_events, get_findings


def build_networkx_graph_from_db(investigation_id: str) -> nx.DiGraph:
    """Builds a NetworkX DiGraph directly from stored database entities and edges."""
    G = nx.DiGraph()
    entities = get_entities(investigation_id)
    edges = get_edges(investigation_id)

    for ent in entities:
        G.add_node(ent["entity_id"], **ent)

    for ed in edges:
        src = ed["src_entity"]
        dst = ed["dst_entity"]
        if G.has_node(src) and G.has_node(dst):
            G.add_edge(src, dst, **ed)

    return G


def calculate_blast_radius(investigation_id: str) -> Dict[str, Any]:
    """
    Computes mathematical blast radius across hosts, users, IPs, and processes.
    """
    entities = get_entities(investigation_id)
    events = get_events(investigation_id)
    findings = get_findings(investigation_id)

    all_hosts = set()
    compromised_hosts = set()
    all_users = set()
    compromised_users = set()
    external_c2_ips = set()
    dropped_files = set()
    compromised_processes = set()

    for ent in entities:
        etype = ent.get("type")
        key = ent.get("key")
        host = ent.get("host")

        if host:
            all_hosts.add(host)

        if etype == "host":
            all_hosts.add(key)
        elif etype == "user":
            all_users.add(key)
        elif etype == "ip":
            external_c2_ips.add(key)
        elif etype == "file":
            dropped_files.add(key)
        elif etype == "process":
            compromised_processes.add(key)

    # Correlate with findings to determine verified compromise
    for f in findings:
        eid = f.get("event_id")
        stage = f.get("stage", "")
        # Match finding to event
        matching_event = next((e for e in events if e.get("event_id") == eid), None)
        if matching_event:
            h = matching_event.get("host")
            u = matching_event.get("user")
            if h:
                compromised_hosts.add(h)
            if u and u not in ("-", "ANONYMOUS LOGON"):
                compromised_users.add(u)

    total_hosts_count = max(len(all_hosts), 1)
    comp_hosts_count = len(compromised_hosts)
    blast_percentage = round((comp_hosts_count / total_hosts_count) * 100.0, 1)

    # Check for High-Value Targets (HVT)
    hvt_indicators = []
    for u in compromised_users:
        u_lower = u.lower()
        if "admin" in u_lower or "system" in u_lower or "root" in u_lower:
            hvt_indicators.append(f"Privileged Identity Compromised: {u}")

    for f in findings:
        if f.get("stage") == "Credential Access":
            hvt_indicators.append("Credential Store / LSASS Targeted")
        elif f.get("stage") == "Defense Evasion":
            hvt_indicators.append("Anti-Forensics / Audit Logs Purged")

    return {
        "investigation_id": investigation_id,
        "blast_radius_percentage": blast_percentage,
        "compromised_hosts_count": comp_hosts_count,
        "total_hosts_observed": total_hosts_count,
        "compromised_hosts": sorted(list(compromised_hosts)),
        "compromised_users_count": len(compromised_users),
        "compromised_users": sorted(list(compromised_users)),
        "external_c2_endpoints": sorted(list(external_c2_ips)),
        "dropped_files_count": len(dropped_files),
        "total_graph_nodes": len(entities),
        "high_value_target_exposures": list(set(hvt_indicators)),
        "severity_rating": "CRITICAL" if blast_percentage >= 50 or hvt_indicators else ("HIGH" if comp_hosts_count > 0 else "LOW")
    }


def compute_killchain_paths(investigation_id: str) -> List[Dict[str, Any]]:
    """
    Finds causal execution paths from root entry nodes to terminal malicious activities.
    """
    G = build_networkx_graph_from_db(investigation_id)
    if len(G) == 0:
        return []

    # Find root nodes (in-degree == 0)
    root_nodes = [n for n, d in G.in_degree() if d == 0]
    # Find terminal leaf nodes (out-degree == 0)
    leaf_nodes = [n for n, d in G.out_degree() if d == 0 and n not in root_nodes]

    paths_summary = []
    visited_pairs = set()

    for root in root_nodes[:5]:  # Limit search breadth
        for leaf in leaf_nodes[:5]:
            pair_key = (root, leaf)
            if pair_key in visited_pairs:
                continue
            visited_pairs.add(pair_key)

            if nx.has_path(G, root, leaf):
                try:
                    shortest = nx.shortest_path(G, source=root, target=leaf)
                    if len(shortest) >= 2:
                        path_steps = []
                        for node_id in shortest:
                            nd = G.nodes[node_id]
                            path_steps.append({
                                "entity_id": node_id,
                                "type": nd.get("type", "unknown"),
                                "label": nd.get("label", node_id),
                                "host": nd.get("host", "")
                            })
                        paths_summary.append({
                            "path_length": len(shortest),
                            "entry_entity": G.nodes[root].get("label", root),
                            "terminal_entity": G.nodes[leaf].get("label", leaf),
                            "steps": path_steps
                        })
                except Exception:
                    pass

    return paths_summary
