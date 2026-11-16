"""ChronoTrace — Uncertainty-Aware Cyberattack Reconstruction System.

Main Application Entry Point.
Directs to Welcome Portal or Investigation Overview Workspace based on authentication state.
"""

import streamlit as st
import os
import sys
import importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from database.db import init_db
from data.demo_seed import seed_demo_data

init_db()

# If not authenticated, render the Modern Welcome & Authentication portal
if not st.session_state.get("authenticated", False):
    from ui.welcome import render_welcome_portal
    render_welcome_portal()
else:
    # Authenticated: Switch directly to the primary Investigation Overview workspace
    st.switch_page("pages/1_Investigation_Overview.py")

