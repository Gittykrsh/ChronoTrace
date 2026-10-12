"""Interactive Forensic Visualizations and Charts for ChronoTrace.

Includes:
1. Attack Activity Timeline (Plotly time-series histogram with zoom/pan/hover)
2. Event Confidence Distribution (Plotly confidence band histogram with forensic tooltip)
3. 8-Stage Investigation Pipeline Visualizer
"""

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import pandas as pd
from typing import List, Dict, Any


def render_attack_activity_chart(events: List[Dict[str, Any]]) -> None:
    """Renders interactive Plotly time-binned event activity chart."""
    if not events:
        st.info("No event records available for activity visualization.")
        return

    df = pd.DataFrame(events)
    df["datetime"] = pd.to_datetime(df["ts_start_utc"], errors="coerce")
    df = df.dropna(subset=["datetime"]).sort_values("datetime")

    # Map code labels
    code_names = {
        1: "Sysmon 1 (Process Create)",
        3: "Sysmon 3 (Network Conn)",
        11: "Sysmon 11 (File Create)",
        4624: "Sec 4624 (Logon)",
        4688: "Sec 4688 (Process Create)",
        1102: "Sec 1102 (Log Cleared)"
    }
    df["event_type"] = df["event_code"].map(lambda x: code_names.get(x, f"Event {x}"))

    fig = px.histogram(
        df,
        x="datetime",
        color="event_type",
        nbins=25,
        title="<b>Reconstructed Attack Activity Timeline</b>",
        labels={"datetime": "Timestamp (UTC)", "count": "Events Count", "event_type": "Event Class"},
        color_discrete_map={
            "Sysmon 1 (Process Create)": "#35D6E8",
            "Sysmon 3 (Network Conn)": "#8B7CFF",
            "Sysmon 11 (File Create)": "#37D99A",
            "Sec 4624 (Logon)": "#4A90E2",
            "Sec 4688 (Process Create)": "#F5B942",
            "Sec 1102 (Log Cleared)": "#FF647C"
        }
    )

    fig.update_layout(
        template="plotly_dark",
        plot_bgcolor="#121D30",
        paper_bgcolor="#121D30",
        margin=dict(l=40, r=20, t=50, b=40),
        font=dict(family="Inter, sans-serif", color="#EDF4FF"),
        xaxis=dict(
            gridcolor="rgba(148, 167, 194, 0.12)",
            showgrid=True,
            title_text="Time (UTC)"
        ),
        yaxis=dict(
            gridcolor="rgba(148, 167, 194, 0.12)",
            showgrid=True,
            title_text="Event Frequency"
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(size=10)
        ),
        hovermode="x unified"
    )

    st.plotly_chart(fig, use_container_width=True)


def render_confidence_distribution_chart(findings: List[Dict[str, Any]]) -> None:
    """Renders confidence distribution histogram grouped by standard forensic bands."""
    if not findings:
        st.info("No findings available for confidence scoring distribution.")
        return

    high = sum(1 for f in findings if f.get("confidence", 0) >= 0.80)
    mod = sum(1 for f in findings if 0.50 <= f.get("confidence", 0) < 0.80)
    low = sum(1 for f in findings if f.get("confidence", 0) < 0.50)

    categories = ["High (0.80 - 1.00)", "Moderate (0.50 - 0.79)", "Low (0.00 - 0.49)"]
    counts = [high, mod, low]
    colors = ["#37D99A", "#F5B942", "#FF647C"]

    fig = go.Figure(data=[
        go.Bar(
            x=categories,
            y=counts,
            text=counts,
            textposition="auto",
            marker=dict(color=colors, line=dict(color="rgba(255,255,255,0.15)", width=1))
        )
    ])

    fig.update_layout(
        title="<b>Event Confidence Distribution</b>",
        template="plotly_dark",
        plot_bgcolor="#121D30",
        paper_bgcolor="#121D30",
        margin=dict(l=40, r=20, t=50, b=40),
        font=dict(family="Inter, sans-serif", color="#EDF4FF"),
        xaxis=dict(gridcolor="rgba(148, 167, 194, 0.12)", title_text="Confidence Band"),
        yaxis=dict(gridcolor="rgba(148, 167, 194, 0.12)", title_text="Number of Findings")
    )

    st.plotly_chart(fig, use_container_width=True)
    st.caption(
        "ℹ️ *Note: Confidence scores are algorithmic corroboration heuristics (corroboration, source reliability, time precision, link strength), not empirical probabilities of ground truth.*"
    )


def render_pipeline_status(is_demo: bool = True) -> None:
    """Renders the 8-stage ChronoTrace processing pipeline."""
    stages = [
        ("1. Ingestion", "Completed" if is_demo else "Ready"),
        ("2. Normalization", "Completed" if is_demo else "Ready"),
        ("3. Entity Resolution", "Completed" if is_demo else "Ready"),
        ("4. Graph Builder", "Completed" if is_demo else "Ready"),
        ("5. ATT&CK Tagger", "Completed" if is_demo else "Ready"),
        ("6. Confidence/Conflict", "Completed" if is_demo else "Ready"),
        ("7. Timeline Engine", "Completed" if is_demo else "Ready"),
        ("8. Forensics UI", "Active")
    ]

    cols = st.columns(len(stages))
    for i, (name, status) in enumerate(stages):
        color = "#37D99A" if status == "Completed" else ("#35D6E8" if status == "Active" else "#94A7C2")
        badge_cls = "badge-high-conf" if status in ("Completed", "Active") else "badge-single-source"
        with cols[i]:
            st.markdown(
                f"""
                <div style="background: #121D30; border: 1px solid rgba(148,167,194,0.15); border-radius: 6px; padding: 10px 6px; text-align: center;">
                    <div style="font-size: 0.72rem; font-weight: 700; color: #EDF4FF;">{name}</div>
                    <div style="margin-top: 4px;"><span class="badge {badge_cls}" style="font-size: 0.65rem;">{status}</span></div>
                </div>
                """,
                unsafe_allow_html=True
            )
