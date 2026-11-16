"""Centralized Configuration Manager for ChronoTrace.

Loads environment variables from .env using python-dotenv with safe fallback defaults.
"""

import os
from dotenv import load_dotenv

# Locate and load the root .env file
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(PROJECT_ROOT, ".env")
if os.path.exists(ENV_FILE):
    load_dotenv(ENV_FILE)
else:
    load_dotenv()

# Application & Environment
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
LOG_LEVEL = os.getenv("LOG_LEVEL", "info")

# Database
DATABASE_PATH = os.path.abspath(os.getenv("DATABASE_PATH", os.path.join(PROJECT_ROOT, "chronotrace.db")))
DATABASE_WAL_MODE = os.getenv("DATABASE_WAL_MODE", "true").lower() in ("true", "1", "yes")

# FastAPI Settings
API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("API_PORT", "8000"))
API_RELOAD = os.getenv("API_RELOAD", "false").lower() in ("true", "1", "yes")
CORS_ORIGINS = [orig.strip() for orig in os.getenv("CORS_ORIGINS", "*").split(",")]

# Streamlit Console
STREAMLIT_HOST = os.getenv("STREAMLIT_HOST", "127.0.0.1")
STREAMLIT_PORT = int(os.getenv("STREAMLIT_PORT", "8501"))

# Security & JWT
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "chronotrace-default-defense-key-2026")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
SESSION_EXPIRE_SECONDS = int(os.getenv("SESSION_EXPIRE_SECONDS", "28800"))

# Google OAuth2 Credentials
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "chronotrace-soc-defense.apps.googleusercontent.com")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "demo-google-oauth-client-secret")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8501")
GOOGLE_AUTH_SCOPE = os.getenv("GOOGLE_AUTH_SCOPE", "openid email profile")

# Enterprise SSO
SSO_AGENCY_NAME = os.getenv("SSO_AGENCY_NAME", "ChronoTrace National Cyber Taskforce")
SSO_DEFAULT_CLEARANCE = os.getenv("SSO_DEFAULT_CLEARANCE", "L3 Lead Forensic Specialist")
