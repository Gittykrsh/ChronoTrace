"""Entity Resolution and Provenance Graph Builder for ChronoTrace.

Uses NetworkX to construct the forensic provenance graph:
- Entities: Process, User, Host, IP, File
- Edges: spawned, logged-in, connected-to, created-file
- Preserves evidence links: each edge points back to the supporting event_id(s)
- Uncertainty-aware: low link strength for PID-only or heuristically matched links without ProcessGuid
"""

import networkx as nx
from typing import List, Dict, Any, Tuple
import hashlib


def build_provenance_graph(
    events: List[Dict[str, Any]],
    investigation_id: str = "inv-default"
) -> Tuple[nx.DiGraph, List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Constructs a NetworkX directed provenance graph from normalized events.
    Returns:
        (G, entities_list, edges_list)
    """
    G = nx.DiGraph()
    entities: Dict[str, Dict[str, Any]] = {}
    edges: Dict[str, Dict[str, Any]] = {}

    def get_entity_id(ent_type: str, key: str, host: str = "") -> str:
        clean_key = f"{ent_type}:{host}:{key}".strip().lower()
        return f"{ent_type}_{hashlib.md5(clean_key.encode()).hexdigest()[:10]}"

    # Process cache to resolve parent-child
    guid_to_entity: Dict[str, str] = {}
    pid_host_to_entity: Dict[Tuple[int, str], str] = {}

    for ev in events:
        eid = ev["event_id"]
        host = ev.get("host", "UNKNOWN-HOST")
        user = ev.get("user")
        code = ev.get("event_code")
        ts_start = ev.get("ts_start_utc", "")
        ts_end = ev.get("ts_end_utc", "")
        raw_ref = ev.get("raw_ref", "")

        # 1. Host Entity
        host_ent_id = get_entity_id("host", host)
        if host_ent_id not in entities:
            entities[host_ent_id] = {
                "entity_id": host_ent_id,
                "investigation_id": investigation_id,
                "type": "host",
                "key": host,
                "host": host,
                "label": f"Host: {host}",
                "first_seen": ts_start,
                "last_seen": ts_end,
                "attributes": {"hostname": host}
            }

        # 2. User Entity
        user_ent_id = None
        if user and user not in ("-", "ANONYMOUS LOGON", "SYSTEM"):
            user_ent_id = get_entity_id("user", user, host)
            if user_ent_id not in entities:
                entities[user_ent_id] = {
                    "entity_id": user_ent_id,
                    "investigation_id": investigation_id,
                    "type": "user",
                    "key": user,
                    "host": host,
                    "label": f"User: {user}",
                    "first_seen": ts_start,
                    "last_seen": ts_end,
                    "attributes": {"username": user}
                }

        # 3. Process Entity (Event 1, 4688, 3, 11)
        proc_ent_id = None
        guid = ev.get("process_guid")
        pid = ev.get("pid")
        image = ev.get("image") or ""
        short_image = image.split("\\")[-1] if "\\" in image else (image.split("/")[-1] if "/" in image else image)

        if guid:
            proc_ent_id = get_entity_id("process", guid)
            guid_to_entity[guid] = proc_ent_id
            if pid:
                pid_host_to_entity[(pid, host)] = proc_ent_id
        elif pid:
            # Reused PID or Security 4688 without GUID
            proc_ent_id = get_entity_id("process", f"{pid}_{short_image}", host)
            pid_host_to_entity[(pid, host)] = proc_ent_id

        if proc_ent_id and proc_ent_id not in entities and short_image:
            entities[proc_ent_id] = {
                "entity_id": proc_ent_id,
                "investigation_id": investigation_id,
                "type": "process",
                "key": guid or f"PID:{pid}",
                "host": host,
                "label": f"{short_image} ({pid or 'N/A'})",
                "first_seen": ts_start,
                "last_seen": ts_end,
                "attributes": {
                    "image": image,
                    "command_line": ev.get("command_line", ""),
                    "pid": pid,
                    "process_guid": guid,
                    "user": user,
                    "raw_ref": raw_ref
                }
            }

        # User logged-in or running process
        if user_ent_id and proc_ent_id:
            edge_key = f"{user_ent_id}->{proc_ent_id}:executed"
            if edge_key not in edges:
                edges[edge_key] = {
                    "edge_id": f"edg_{hashlib.md5(edge_key.encode()).hexdigest()[:10]}",
                    "investigation_id": investigation_id,
                    "src_entity": user_ent_id,
                    "dst_entity": proc_ent_id,
                    "relation": "logged-in",
                    "link_strength": 0.90,
                    "is_uncertain": 0,
                    "evidence_event_ids": [eid]
                }
            else:
                if eid not in edges[edge_key]["evidence_event_ids"]:
                    edges[edge_key]["evidence_event_ids"].append(eid)

        # Parent-Child Process Relationship (Spawned)
        if code in (1, 4688) and proc_ent_id:
            parent_guid = ev.get("parent_guid")
            ppid = ev.get("ppid")
            parent_ent_id = None
            link_strength = 1.0
            is_uncertain = 0

            if parent_guid and parent_guid in guid_to_entity:
                parent_ent_id = guid_to_entity[parent_guid]
                link_strength = 0.98
            elif ppid and (ppid, host) in pid_host_to_entity:
                parent_ent_id = pid_host_to_entity[(ppid, host)]
                # Heuristic PID match without ProcessGuid carries uncertainty
                link_strength = 0.55
                is_uncertain = 1

            if parent_ent_id and parent_ent_id != proc_ent_id:
                edge_key = f"{parent_ent_id}->{proc_ent_id}:spawned"
                if edge_key not in edges:
                    edges[edge_key] = {
                        "edge_id": f"edg_{hashlib.md5(edge_key.encode()).hexdigest()[:10]}",
                        "investigation_id": investigation_id,
                        "src_entity": parent_ent_id,
                        "dst_entity": proc_ent_id,
                        "relation": "spawned",
                        "link_strength": link_strength,
                        "is_uncertain": is_uncertain,
                        "evidence_event_ids": [eid]
                    }
                else:
                    if eid not in edges[edge_key]["evidence_event_ids"]:
                        edges[edge_key]["evidence_event_ids"].append(eid)

        # Network Connection (Sysmon 3)
        dst_ip = ev.get("dst_ip")
        if code == 3 and dst_ip and proc_ent_id:
            dst_port = ev.get("dst_port")
            ip_ent_id = get_entity_id("ip", dst_ip)
            if ip_ent_id not in entities:
                entities[ip_ent_id] = {
                    "entity_id": ip_ent_id,
                    "investigation_id": investigation_id,
                    "type": "ip",
                    "key": dst_ip,
                    "host": host,
                    "label": f"IP: {dst_ip}:{dst_port}" if dst_port else f"IP: {dst_ip}",
                    "first_seen": ts_start,
                    "last_seen": ts_end,
                    "attributes": {"ip": dst_ip, "port": dst_port}
                }
            edge_key = f"{proc_ent_id}->{ip_ent_id}:connected-to"
            if edge_key not in edges:
                edges[edge_key] = {
                    "edge_id": f"edg_{hashlib.md5(edge_key.encode()).hexdigest()[:10]}",
                    "investigation_id": investigation_id,
                    "src_entity": proc_ent_id,
                    "dst_entity": ip_ent_id,
                    "relation": "connected-to",
                    "link_strength": 0.95,
                    "is_uncertain": 0,
                    "evidence_event_ids": [eid]
                }
            else:
                if eid not in edges[edge_key]["evidence_event_ids"]:
                    edges[edge_key]["evidence_event_ids"].append(eid)

        # File Creation (Sysmon 11)
        if code == 11 and proc_ent_id:
            target_filename = ev.get("image") or "dropped_file"
            file_key = target_filename.split("\\")[-1] if "\\" in target_filename else target_filename
            file_ent_id = get_entity_id("file", file_key, host)
            if file_ent_id not in entities:
                entities[file_ent_id] = {
                    "entity_id": file_ent_id,
                    "investigation_id": investigation_id,
                    "type": "file",
                    "key": target_filename,
                    "host": host,
                    "label": f"File: {file_key}",
                    "first_seen": ts_start,
                    "last_seen": ts_end,
                    "attributes": {"path": target_filename}
                }
            edge_key = f"{proc_ent_id}->{file_ent_id}:created-file"
            if edge_key not in edges:
                edges[edge_key] = {
                    "edge_id": f"edg_{hashlib.md5(edge_key.encode()).hexdigest()[:10]}",
                    "investigation_id": investigation_id,
                    "src_entity": proc_ent_id,
                    "dst_entity": file_ent_id,
                    "relation": "created-file",
                    "link_strength": 0.92,
                    "is_uncertain": 0,
                    "evidence_event_ids": [eid]
                }
            else:
                if eid not in edges[edge_key]["evidence_event_ids"]:
                    edges[edge_key]["evidence_event_ids"].append(eid)

    # Populate NetworkX Graph
    for eid, edata in entities.items():
        G.add_node(eid, **edata)

    for edg_key, edata in edges.items():
        if G.has_node(edata["src_entity"]) and G.has_node(edata["dst_entity"]):
            G.add_edge(
                edata["src_entity"],
                edata["dst_entity"],
                key=edata["edge_id"],
                **edata
            )

    return G, list(entities.values()), list(edges.values())
