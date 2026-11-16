"""Forensic Reconstruction Router — Timelines, Graphs & Conflicts."""

from typing import Optional
from fastapi import APIRouter
from database.db import get_events, get_entities, get_edges, get_findings

router = APIRouter(prefix="/api/v1/investigations/{inv_id}", tags=["Forensic Reconstruction"])


@router.get("/timeline")
def get_investigation_timeline(inv_id: str, host: Optional[str] = None):
    """
    Returns normalized chronological events with uncertainty intervals [ts_start, ts_end] and Rule 0 citations.
    """
    events = get_events(inv_id)
    if host:
        events = [e for e in events if e.get("host") == host]
    return {
        "investigation_id": inv_id,
        "total_events": len(events),
        "events": events
    }


@router.get("/graph")
def get_investigation_graph(inv_id: str):
    """
    Returns NetworkX causal provenance graph (entities and relationships) for graph visualization.
    """
    entities = get_entities(inv_id)
    edges = get_edges(inv_id)
    return {
        "investigation_id": inv_id,
        "entities_count": len(entities),
        "edges_count": len(edges),
        "entities": entities,
        "edges": edges
    }


@router.get("/conflicts")
def get_investigation_conflicts(inv_id: str):
    """
    Returns detected forensic anomalies: ORDER_CONFLICT, MISSING_PARENT, LOG_CLEARED, and SINGLE_SOURCE.
    """
    findings = get_findings(inv_id)
    flagged = [f for f in findings if f.get("flags")]
    return {
        "investigation_id": inv_id,
        "flagged_findings_count": len(flagged),
        "findings": flagged
    }
