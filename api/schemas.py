"""Pydantic Request & Response Schemas for ChronoTrace REST API."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


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
