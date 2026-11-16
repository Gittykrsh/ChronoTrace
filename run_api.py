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

if __name__ == "__main__":
    print("=" * 70)
    print(" ChronoTrace DFIR REST API Gateway (FastAPI)")
    print(" Swagger Documentation: http://localhost:8000/docs")
    print(" ReDoc Documentation:   http://localhost:8000/redoc")
    print(" Health Endpoint:       http://localhost:8000/api/v1/health")
    print(" Google Auth Demo URL:  http://localhost:8000/api/v1/auth/google/url")
    print("=" * 70)
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=False, log_level="info")
