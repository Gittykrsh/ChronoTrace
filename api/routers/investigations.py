"""Investigation Management Router."""

from fastapi import APIRouter, HTTPException, status
from database.db import (
    get_investigations,
    get_investigation,
    create_investigation,
    delete_investigation,
    get_events,
    get_findings
)
from api.schemas import CreateInvestigationRequest

router = APIRouter(prefix="/api/v1/investigations", tags=["Investigations"])


@router.get("")
def list_investigations():
    """Lists all active and archived digital forensic investigations."""
    return get_investigations()


@router.post("", status_code=status.HTTP_201_CREATED)
def create_new_investigation(req: CreateInvestigationRequest):
    """Creates a new digital forensics investigation workspace."""
    existing = get_investigation(req.id)
    if existing:
        raise HTTPException(status_code=400, detail=f"Investigation with ID '{req.id}' already exists.")
    create_investigation(req.id, req.name, req.description or "", status="Active", is_demo=False)
    return get_investigation(req.id)


@router.get("/{inv_id}")
def get_investigation_details(inv_id: str):
    """Retrieves metadata and health metrics for a specific investigation."""
    inv = get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation '{inv_id}' not found.")
    events = get_events(inv_id)
    findings = get_findings(inv_id)
    return {
        "investigation": inv,
        "total_events": len(events),
        "total_findings": len(findings),
        "hosts": sorted(list({e.get("host") for e in events if e.get("host")})),
        "sources": sorted(list({e.get("source") for e in events if e.get("source")}))
    }


@router.delete("/{inv_id}")
def delete_investigation_endpoint(inv_id: str):
    """Deletes a custom investigation and purges all its associated events, entities, edges, and findings."""
    inv = get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation '{inv_id}' not found.")
    if inv.get("is_demo") or inv_id == "inv-demo-01":
        raise HTTPException(status_code=400, detail="Cannot delete the protected baseline demonstration case ('inv-demo-01').")
    delete_investigation(inv_id)
    return {"status": "success", "message": f"Investigation '{inv_id}' and all associated evidence purged successfully."}
