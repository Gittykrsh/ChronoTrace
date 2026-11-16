"""Tests for safe built-in incident datasets."""

import os
import json
import pytest
from services.ingestion import run_ingestion_pipeline
from database.db import init_db, get_investigation

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_sample_events_ingestion(tmp_path):
    init_db()
    sample_path = os.path.join(PROJECT_ROOT, "data", "sample_events.json")
    assert os.path.exists(sample_path), "sample_events.json must exist in data/"

    with open(sample_path, "rb") as f:
        data = f.read()

    summary = run_ingestion_pipeline("test-inv-unit-sample", {"sample_events.json": data})
    assert summary["files_processed"] == 1
    assert summary["supported_events_normalized"] > 0
    assert summary["parsing_errors"] == 0


def test_enterprise_clean_scenario_ingestion(tmp_path):
    init_db()
    scenario_path = os.path.join(PROJECT_ROOT, "data", "enterprise_clean_scenario.json")
    assert os.path.exists(scenario_path), "enterprise_clean_scenario.json must exist in data/"

    with open(scenario_path, "rb") as f:
        data = f.read()

    summary = run_ingestion_pipeline("test-inv-unit-enterprise", {"enterprise_clean_scenario.json": data})
    assert summary["files_processed"] == 1
    assert summary["supported_events_normalized"] == 8
    assert summary["parsing_errors"] == 0
