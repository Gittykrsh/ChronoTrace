"""Evidence Ingestion & Forensic Reporting Router."""

import json
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response, PlainTextResponse
from database.db import (
    get_investigation,
    get_events,
    get_findings,
    get_entities,
    get_edges
)
from services.ingestion import run_ingestion_pipeline
from services.reporting import (
    generate_csv_timeline,
    generate_json_findings,
    generate_markdown_report
)
from api.schemas import IngestEvidenceRequest

router = APIRouter(prefix="/api/v1/investigations/{inv_id}", tags=["Evidence Ingestion & Reports"])


@router.post("/ingest")
def ingest_evidence(inv_id: str, req: IngestEvidenceRequest):
    """
    Ingests forensic log events into the 7-stage ChronoTrace processing pipeline over HTTP.
    """
    payload_bytes = json.dumps(req.events).encode("utf-8")
    summary = run_ingestion_pipeline(inv_id, {req.filename: payload_bytes})
    return summary


@router.get("/report")
def export_investigation_report(inv_id: str, format: str = Query("json", pattern="^(json|markdown|csv)$")):
    """
    Exports court-admissible forensic incident report in JSON, Markdown, or CSV.
    """
    inv = get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    events = get_events(inv_id)
    findings = get_findings(inv_id)
    entities = get_entities(inv_id)
    edges = get_edges(inv_id)

    if format == "csv":
        csv_content = generate_csv_timeline(events)
        return Response(content=csv_content, media_type="text/csv", headers={
            "Content-Disposition": f"attachment; filename=chronotrace_timeline_{inv_id}.csv"
        })
    elif format == "markdown":
        md_content = generate_markdown_report(inv, events, findings, {
            "entities": entities,
            "edges": edges
        })
        return PlainTextResponse(content=md_content)
    else:
        json_content = generate_json_findings(inv, events, findings, {
            "entities": entities,
            "edges": edges
        })
        return json.loads(json_content)
