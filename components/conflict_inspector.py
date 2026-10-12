"""Conflict and Missing-Evidence Inspector Component for ChronoTrace.

Implements Section 12 requirements:
- Deep forensic inspection for all 4 flags:
  1. ORDER_CONFLICT
  2. MISSING_PARENT
  3. LOG_CLEARED
  4. SINGLE_SOURCE
- Explains involved records, why causal order is ambiguous, what is missing, and evidence citations.
- Never fabricates a false resolution; preserves uncertainty.
"""

import streamlit as st
from typing import List, Dict, Any


def render_conflict_inspector(findings: List[Dict[str, Any]], events: List[Dict[str, Any]]) -> None:
    """Renders comprehensive Conflict & Missing Evidence Inspector."""
    events_map = {e["event_id"]: e for e in events}

    # Group findings with flags
    conflict_findings = [f for f in findings if f.get("flags_list")]

    if not conflict_findings:
        st.success("No conflicting evidence or missing-parent flags identified in the active case.")
        return

    st.markdown("### ⚠️ Conflict & Uncertainty Inspector")
    st.markdown(
        """
        *ChronoTrace surfaces missing logs, timestamp ambiguities, and uncorroborated activity.*  
        *Investigators can examine the underlying evidence without premature or artificial conflict resolution.*
        """
    )

    # Filter by specific flag
    flag_filter = st.radio(
        "Filter by Uncertainty Category:",
        ["All Flags", "ORDER_CONFLICT", "MISSING_PARENT", "LOG_CLEARED", "SINGLE_SOURCE"],
        horizontal=True,
        key="conflict_flag_filter"
    )

    filtered = conflict_findings
    if flag_filter != "All Flags":
        filtered = [f for f in filtered if flag_filter in f.get("flags_list", [])]

    st.markdown(f"**Showing {len(filtered)} flagged findings:**")

    for f in filtered:
        eid = f.get("event_id")
        ev = events_map.get(eid, {})
        flags = f.get("flags_list", [])
        raw_ref = ev.get("raw_ref", "N/A")

        # Color coding
        box_border = "#FF647C" if "LOG_CLEARED" in flags else ("#F5B942" if "ORDER_CONFLICT" in flags else ("#FF9B42" if "MISSING_PARENT" in flags else "#8B7CFF"))

        with st.container():
            st.markdown(
                f"""
                <div style="background: #17243A; border-left: 5px solid {box_border}; border-radius: 6px; padding: 14px; margin-bottom: 14px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <strong style="color: #EDF4FF; font-size: 1rem;">Finding {f['finding_id']}</strong>
                            <span style="color: #94A7C2; font-size: 0.82rem; margin-left: 8px;">(Event: {eid})</span>
                        </div>
                        <div>
                            <span class="raw-ref-pill">📄 {raw_ref}</span>
                        </div>
                    </div>
                    <div style="margin: 8px 0;">
                        {' '.join([f'<span class="badge" style="background: rgba(255,255,255,0.08); border: 1px solid {box_border}; color: {box_border};">{fl}</span>' for fl in flags])}
                    </div>
                    <div style="font-size: 0.85rem; color: #EDF4FF; margin-top: 6px;">
                        <strong>Forensic Explanation:</strong> {f.get('explanation')}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            with st.expander(f"Inspect Forensic Breakdown for {eid}", expanded=False):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("**Evidence Attributes:**")
                    st.markdown(f"- **Host:** `{ev.get('host')}`")
                    st.markdown(f"- **Source Provider:** `{ev.get('source')}` (Event `{ev.get('event_code')}`)")
                    st.markdown(f"- **Interval:** `{ev.get('ts_start_utc')}` &rarr; `{ev.get('ts_end_utc')}`")
                    st.markdown(f"- **Image:** `{ev.get('image')}`")
                    st.markdown(f"- **Command:** `{ev.get('command_line')}`")
                    st.markdown(f"- **ProcessGuid:** `{ev.get('process_guid') or 'None'}`")
                    st.markdown(f"- **ParentGuid:** `{ev.get('parent_guid') or 'None'}`")

                with c2:
                    st.markdown("**Uncertainty Impact on Confidence:**")
                    st.markdown(f"- **Overall Confidence:** `{f.get('confidence', 0):.2f}` / 1.00")
                    st.markdown(f"- **Corroboration Factor:** `{f.get('corroboration', 0):.2f}`")
                    st.markdown(f"- **Time Precision Factor:** `{f.get('time_certainty', 0):.2f}`")
                    st.markdown(f"- **Entity Link Strength:** `{f.get('link_strength', 0):.2f}`")

                    if "ORDER_CONFLICT" in flags:
                        st.warning("⚠️ ORDER_CONFLICT: Overlapping intervals establish that relative ordering is ambiguous. Do not force an artificial linear order.")
                    if "MISSING_PARENT" in flags:
                        st.warning("🧩 MISSING_PARENT: Process points to a parent process not present in logs. Possible anti-forensics or unmonitored execution.")
                    if "LOG_CLEARED" in flags:
                        st.error("🚨 LOG_CLEARED: Windows Security Event 1102 recorded. Log stream was cleared; earlier telemetry integrity is compromised.")
                    if "SINGLE_SOURCE" in flags:
                        st.info("ℹ️ SINGLE_SOURCE: Witnessed by a single telemetry channel without cross-validation.")
