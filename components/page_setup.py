"""Page Setup Helper for ChronoTrace.
Applies dark theme CSS, initializes DB if needed, and loads the active investigation.
"""

import streamlit as st
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from database.db import init_db, get_investigation, get_investigations
from data.demo_seed import seed_demo_data

CSS_PATH = os.path.join(PROJECT_ROOT, "assets", "styles.css")


def setup_forensic_page(page_title: str) -> str:
    """Configures Streamlit page, injects styles, and ensures DB is seeded."""
    st.set_page_config(
        page_title=f"{page_title} — ChronoTrace",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Inject custom CSS
    if os.path.exists(CSS_PATH):
        with open(CSS_PATH, "r", encoding="utf-8") as f:
            css = f.read()
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

    # Ensure DB is initialized
    init_db()

    # Ensure demo case exists if no investigations
    invs = get_investigations()
    if not invs:
        seed_demo_data()
        invs = get_investigations()

    if "active_investigation_id" not in st.session_state or not st.session_state["active_investigation_id"]:
        st.session_state["active_investigation_id"] = invs[0]["id"]

    return st.session_state["active_investigation_id"]
