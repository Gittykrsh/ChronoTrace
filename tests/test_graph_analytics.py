"""Unit tests for Attack Pathfinding and Blast Radius Graph Analytics."""

import pytest
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from database.db import init_db
from services.graph_analytics import calculate_blast_radius, compute_killchain_paths


def test_blast_radius_computation():
    init_db()
    # Test on inv-demo-01 which is seeded
    blast = calculate_blast_radius("inv-demo-01")
    assert "blast_radius_percentage" in blast
    assert "compromised_hosts_count" in blast
    assert "severity_rating" in blast
    assert blast["total_hosts_observed"] >= 1


def test_killchain_paths():
    init_db()
    paths = compute_killchain_paths("inv-demo-01")
    assert isinstance(paths, list)
    if paths:
        p = paths[0]
        assert "entry_entity" in p
        assert "terminal_entity" in p
        assert len(p["steps"]) >= 2
