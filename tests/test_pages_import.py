"""Test script verifying all pages and components import cleanly without runtime syntax errors."""

import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

def test_imports():
    import app
    from components import (
        render_sidebar,
        render_topbar,
        render_metric_cards,
        render_attack_activity_chart,
        render_confidence_distribution_chart,
        render_pipeline_status,
        render_timeline_gantt,
        render_event_table,
        render_event_details_drawer,
        render_provenance_graph,
        render_graph_legend,
        render_evidence_explorer,
        render_conflict_inspector
    )
    from services import (
        evaluate_event_confidence,
        detect_conflicts,
        tag_mitre_technique,
        build_provenance_graph,
        normalize_record,
        run_ingestion_pipeline,
        generate_csv_timeline,
        generate_json_findings,
        generate_markdown_report
    )
    from database import (
        init_db,
        get_investigations,
        get_events,
        get_findings,
        get_raw_events,
        get_graph_data
    )
    assert True
