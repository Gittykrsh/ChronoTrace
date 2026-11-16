"""ChronoTrace REST API Gateway.

Modular FastAPI service providing:
1. Forensic Endpoints: Investigations, Ingestion, Timelines, Provenance Graphs, Merkle Chains, and Reports.
2. Demo Authentication APIs: Google OAuth2 (PKCE), Enterprise SSO (SAML/OIDC), and Investigator Session Management.
3. Automated Swagger/OpenAPI Documentation (/docs).
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database.db import init_db
import config

from api.routers import (
    health,
    auth,
    investigations,
    reconstruction,
    integrity,
    ingestion
)

# Initialize database schema on startup
init_db()

app = FastAPI(
    title="ChronoTrace DFIR API",
    description="Deterministic Uncertainty-Aware Cyberattack Reconstruction Platform API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS using configured origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount separate modular routers
app.include_router(health.router)
app.include_router(auth.router)
app.include_router(investigations.router)
app.include_router(reconstruction.router)
app.include_router(integrity.router)
app.include_router(ingestion.router)
