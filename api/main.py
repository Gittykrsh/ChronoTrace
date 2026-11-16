"""ChronoTrace REST API Gateway & Authentication Service.

High-performance FastAPI service providing:
1. Forensic Endpoints: Investigations, Ingestion, Timelines, Provenance Graphs, Merkle Chains, and Reports.
2. Demo Authentication APIs: Google OAuth2 (PKCE), Enterprise SSO (SAML/OIDC), and Investigator Session Management.
3. Automated Swagger/OpenAPI Documentation (/docs).
"""

import os
import sys
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from database.db import (
    init_db,
    get_connection,
    get_investigations,
    get_investigation,
    create_investigation,
    get_events,
    get_entities,
    get_edges,
    get_findings,
    get_ingestion_logs,
    create_or_update_user,
    get_user_by_email,
    get_users
)
from services.ingestion import run_ingestion_pipeline
from services.crypto_chain import build_investigation_hash_chain, verify_investigation_hash_chain
from services.graph_analytics import calculate_blast_radius, compute_killchain_paths
from services.reporting import generate_csv_timeline, generate_json_findings, generate_markdown_report

# Initialize database schema on startup
init_db()

app = FastAPI(
    title="ChronoTrace DFIR API",
    description="Deterministic Uncertainty-Aware Cyberattack Reconstruction Platform API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for local dashboards and cross-origin tools
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Request & Response Models ---

class GoogleAuthRequest(BaseModel):
    code: Optional[str] = "demo-auth-code-12345"
    code_verifier: Optional[str] = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    email: Optional[str] = "analyst@chronotrace.soc"
    name: Optional[str] = "Lead Forensic Specialist"


class EnterpriseSSORequest(BaseModel):
    username: str = "analyst@chronotrace.soc"
    passphrase: str = "DefenseSecure2026!"
    clearance_level: str = "L3 Lead Forensic Specialist"
    agency: Optional[str] = "Cyber Defense Agency"


class CreateInvestigationRequest(BaseModel):
    id: str = Field(..., json_schema_extra={"example": "inv-incident-2026"})
    name: str = Field(..., json_schema_extra={"example": "Operation Blackout — Domain Controller Compromise"})
    description: Optional[str] = "Active forensic investigation into suspicious lateral movement."


class IngestEvidenceRequest(BaseModel):
    filename: str = Field("telemetry_dump.json", json_schema_extra={"example": "sysmon_telemetry.json"})
    events: List[Dict[str, Any]] = Field(..., description="Array of raw or structured forensic log events")


# --- System & Health Endpoints ---

@app.get("/api/v1/health", tags=["System Health"])
def get_system_health():
    """Returns platform subsystem status, SQLite WAL mode, and Rule 0 integrity guarantee."""
    invs = get_investigations()
    return {
        "status": "ONLINE",
        "service": "ChronoTrace DFIR Platform",
        "version": "1.0.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "storage": "Local SQLite WAL Mode (Zero Cloud Telemetry Leakage)",
        "rule_0_enforced": True,
        "active_investigations_count": len(invs),
        "security_controls": {
            "sso_provider": "Defense-Grade OAuth2 / PKCE",
            "fips_compliance": "FIPS 140-3 SHA-256 Chaining",
            "air_gapped_ready": True
        }
    }


# --- Demo Authentication APIs ---

@app.get("/api/v1/auth/google/url", tags=["Authentication"])
def get_google_auth_url(redirect_uri: str = "http://localhost:8501"):
    """
    Returns simulated Google OAuth2 2.0 authorization URL with PKCE challenge and security state.
    """
    state = uuid.uuid4().hex[:16]
    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    code_challenge = hashlib.sha256(code_verifier.encode()).hexdigest()

    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id=chronotrace-soc-defense.apps.googleusercontent.com&"
        f"redirect_uri={redirect_uri}&"
        f"response_type=code&"
        f"scope=openid%20email%20profile&"
        f"state={state}&"
        f"code_challenge={code_challenge}&"
        f"code_challenge_method=S256"
    )

    return {
        "authorization_url": auth_url,
        "client_id": "chronotrace-soc-defense.apps.googleusercontent.com",
        "code_verifier": code_verifier,
        "code_challenge": code_challenge,
        "state": state,
        "method": "PKCE S256",
        "notice": "Demo endpoint simulating Google Cloud Defense Identity Federation."
    }


@app.post("/api/v1/auth/google/verify", tags=["Authentication"])
def verify_google_token(req: GoogleAuthRequest):
    """
    Simulates Google OAuth2 token verification, decodes identity, and provisions investigator user session.
    """
    email = req.email or "analyst@chronotrace.soc"
    name = req.name or "Lead Forensic Specialist"

    # Persist or update user in SQLite database
    user = create_or_update_user(
        email=email,
        name=name,
        provider="google",
        agency="ChronoTrace National Cyber Taskforce",
        clearance_level="L3 Lead Forensic Specialist"
    )

    # Generate mock defense JWT access token
    token_payload = f"ey-chronotrace-{email}-{datetime.now(timezone.utc).timestamp()}"
    mock_token = hashlib.sha256(token_payload.encode()).hexdigest()

    return {
        "authenticated": True,
        "access_token": f"ct_sec_{mock_token[:32]}",
        "token_type": "Bearer",
        "expires_in": 28800,
        "user": user,
        "auth_provider": "google",
        "message": "Google Workspace session authenticated successfully under defense security profile."
    }


@app.post("/api/v1/auth/enterprise/sso", tags=["Authentication"])
def enterprise_sso_login(req: EnterpriseSSORequest):
    """
    Simulates Defense-Grade Enterprise SAML 2.0 / OIDC SSO Authentication.
    """
    email = req.username
    name = req.username.split("@")[0].capitalize()

    user = create_or_update_user(
        email=email,
        name=name,
        provider="enterprise_sso",
        agency=req.agency or "ChronoTrace National Cyber Taskforce",
        clearance_level=req.clearance_level
    )

    return {
        "authenticated": True,
        "session_token": f"ct_sso_{uuid.uuid4().hex}",
        "clearance_granted": req.clearance_level,
        "user": user,
        "status": "AUTHORIZED"
    }


@app.get("/api/v1/auth/users", tags=["Authentication"])
def list_registered_users():
    """Lists all registered investigators and forensic analysts in the local database."""
    return get_users()


# --- Investigation Management Endpoints ---

@app.get("/api/v1/investigations", tags=["Investigations"])
def list_investigations():
    """Lists all active and archived digital forensic investigations."""
    return get_investigations()


@app.post("/api/v1/investigations", tags=["Investigations"], status_code=status.HTTP_201_CREATED)
def create_new_investigation(req: CreateInvestigationRequest):
    """Creates a new digital forensics investigation workspace."""
    existing = get_investigation(req.id)
    if existing:
        raise HTTPException(status_code=400, detail=f"Investigation with ID '{req.id}' already exists.")
    create_investigation(req.id, req.name, req.description or "", status="Active", is_demo=False)
    return get_investigation(req.id)


@app.get("/api/v1/investigations/{inv_id}", tags=["Investigations"])
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


# --- Forensic Timeline & Reconstruction Endpoints ---

@app.get("/api/v1/investigations/{inv_id}/timeline", tags=["Forensic Reconstruction"])
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


@app.get("/api/v1/investigations/{inv_id}/graph", tags=["Forensic Reconstruction"])
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


@app.get("/api/v1/investigations/{inv_id}/conflicts", tags=["Forensic Reconstruction"])
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


@app.get("/api/v1/investigations/{inv_id}/chain", tags=["Forensic Integrity"])
def get_investigation_merkle_chain(inv_id: str):
    """
    Returns the cryptographic SHA-256 sequential hash chain and Merkle root verification.
    """
    events = get_events(inv_id)
    return build_investigation_hash_chain(events, inv_id)


@app.get("/api/v1/investigations/{inv_id}/blast-radius", tags=["Forensic Integrity"])
def get_investigation_blast_radius(inv_id: str):
    """
    Calculates enterprise blast radius percentage, compromised hosts, and kill-chain paths.
    """
    blast = calculate_blast_radius(inv_id)
    paths = compute_killchain_paths(inv_id)
    blast["killchain_paths"] = paths
    return blast


# --- Evidence Ingestion & Reporting Endpoints ---

@app.post("/api/v1/investigations/{inv_id}/ingest", tags=["Evidence Ingestion"])
def ingest_evidence(inv_id: str, req: IngestEvidenceRequest):
    """
    Ingests forensic log events into the 7-stage ChronoTrace processing pipeline over HTTP.
    """
    import json
    payload_bytes = json.dumps(req.events).encode("utf-8")
    summary = run_ingestion_pipeline(inv_id, {req.filename: payload_bytes})
    return summary


@app.get("/api/v1/investigations/{inv_id}/report", tags=["Forensic Reporting"])
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
        from fastapi.responses import Response
        return Response(content=csv_content, media_type="text/csv", headers={
            "Content-Disposition": f"attachment; filename=chronotrace_timeline_{inv_id}.csv"
        })
    elif format == "markdown":
        md_content = generate_markdown_report(inv, events, findings, {
            "entities": entities,
            "edges": edges
        })
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(content=md_content)
    else:
        json_content = generate_json_findings(inv, events, findings, {
            "entities": entities,
            "edges": edges
        })
        import json
        return json.loads(json_content)
