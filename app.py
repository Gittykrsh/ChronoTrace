"""ChronoTrace — Uncertainty-Aware Cyberattack Reconstruction System.

Main Application Entry Point.
Directs to Investigation Overview Workspace.
"""

import streamlit as st
import os
import sys
import importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Load the overview page module
importlib.import_module("pages.1_Investigation_Overview")
