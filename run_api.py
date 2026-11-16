"""ChronoTrace REST API Server Launcher.

Runs the FastAPI backend service on port 8000 with interactive Swagger UI at:
http://localhost:8000/docs
"""

import uvicorn
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import config

if __name__ == "__main__":
    print("=" * 70)
    print(" ChronoTrace DFIR REST API Gateway (FastAPI)")
    print(f" Swagger Documentation: http://{config.API_HOST}:{config.API_PORT}/docs")
    print(f" ReDoc Documentation:   http://{config.API_HOST}:{config.API_PORT}/redoc")
    print(f" Health Endpoint:       http://{config.API_HOST}:{config.API_PORT}/api/v1/health")
    print(f" Google Auth Demo URL:  http://{config.API_HOST}:{config.API_PORT}/api/v1/auth/google/url")
    print(f" Loaded from .env:      DATABASE={config.DATABASE_PATH}")
    print("=" * 70)
    uvicorn.run("api.main:app", host=config.API_HOST, port=config.API_PORT, reload=config.API_RELOAD, log_level=config.LOG_LEVEL)
