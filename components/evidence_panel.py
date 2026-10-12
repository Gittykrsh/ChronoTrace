"""Dual-Pane Evidence Explorer Component for ChronoTrace.

Implements Section 9 requirements with dark-theme fidelity and reactive selection:
- Left panel: Searchable, filterable table of original records with reactive row clicking
- Right panel: Monospace structured dark inspector with syntax-highlighted JSON, key-value forensic breakdown,
  explicit distinction between authentic source evidence and normalized findings,
  and quick copy-to-clipboard actions.
"""

import streamlit as st
import json
import pandas as pd
from typing import List, Dict, Any, Optional


def render_evidence_explorer(
    raw_records: List[Dict[str, Any]],
    normalized_events: List[Dict[str, Any]],
    preselected_raw_ref: Optional[str] = None
) -> None:
    """Renders dual-pane forensic evidence explorer with dark styling and reactive row clicks."""
    if not raw_records:
        st.info("No raw evidence records found for this investigation.")
        return

    # Map normalized event by raw_ref
    norm_by_ref = {ev.get("raw_ref"): ev for ev in normalized_events}

    col_left, col_right = st.columns([5, 5])

    # Left Panel: Records Table
    with col_left:
        st.markdown(
            """
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
                <span style="font-size: 1.25rem;">📁</span>
                <span style="font-size: 1.15rem; font-weight: 700; color: #EDF4FF;">Raw Evidence Records</span>
            </div>
            """,
            unsafe_allow_html=True
        )
        
        # Search filter
        search_kw = st.text_input(
            "Search Records",
            placeholder="Search raw_ref, file, source, or record ID...",
            key="ev_search_input",
            label_visibility="collapsed"
        ).strip().lower()

        filtered_records = raw_records
        if search_kw:
            filtered_records = [
                r for r in filtered_records
                if search_kw in r.get("raw_ref", "").lower()
                or search_kw in r.get("source_file", "").lower()
                or search_kw in r.get("source", "").lower()
                or search_kw in str(r.get("event_code", ""))
            ]

        if not filtered_records:
            st.warning("No records match your search filter.")
            return

        raw_ref_options = [r["raw_ref"] for r in filtered_records]

        # Check if table selection was clicked in session_state before processing
        table_state = st.session_state.get("evidence_table_selection", {})
        if isinstance(table_state, dict):
            sel_rows = table_state.get("selection", {}).get("rows", [])
            if sel_rows and 0 <= sel_rows[0] < len(filtered_records):
                st.session_state["active_explorer_ref"] = filtered_records[sel_rows[0]]["raw_ref"]

        if preselected_raw_ref and preselected_raw_ref in raw_ref_options:
            st.session_state["active_explorer_ref"] = preselected_raw_ref
            st.session_state.pop("selected_raw_ref", None)

        if "active_explorer_ref" not in st.session_state or st.session_state["active_explorer_ref"] not in raw_ref_options:
            st.session_state["active_explorer_ref"] = raw_ref_options[0]

        selected_ref = st.session_state["active_explorer_ref"]

        # Prepare display table
        rows = []
        for r in filtered_records:
            ref = r.get("raw_ref", "")
            norm_ev = norm_by_ref.get(ref)
            norm_id = norm_ev.get("event_id", "—") if norm_ev else "Raw Only"
            rows.append({
                "Raw Reference": ref,
                "File": r.get("source_file", ""),
                "Rec #": r.get("record_number", 0),
                "Source Provider": r.get("source", ""),
                "Code": r.get("event_code", 0),
                "Normalized": norm_id
            })

        table_df = pd.DataFrame(rows)

        st.caption("Click any record row below to inspect its raw JSON and normalized schema:")

        try:
            # Interactive row selection
            table_event = st.dataframe(
                table_df,
                use_container_width=True,
                hide_index=True,
                selection_mode="single-row",
                on_select="rerun",
                key="evidence_table_selection",
                column_config={
                    "Raw Reference": st.column_config.TextColumn("Raw Reference", width="medium"),
                    "File": st.column_config.TextColumn("File", width="small"),
                    "Rec #": st.column_config.NumberColumn("Rec #", width="small"),
                    "Source Provider": st.column_config.TextColumn("Provider", width="medium"),
                    "Code": st.column_config.NumberColumn("Code", width="small"),
                    "Normalized": st.column_config.TextColumn("Event ID", width="small")
                }
            )
            if table_event and hasattr(table_event, "selection") and table_event.selection.rows:
                clicked_idx = table_event.selection.rows[0]
                if 0 <= clicked_idx < len(filtered_records):
                    st.session_state["active_explorer_ref"] = filtered_records[clicked_idx]["raw_ref"]
                    selected_ref = filtered_records[clicked_idx]["raw_ref"]
        except Exception:
            st.dataframe(table_df, use_container_width=True, hide_index=True)

    # Right Panel: Structured Evidence Inspector
    with col_right:
        st.markdown(
            """
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
                <span style="font-size: 1.25rem;">🔬</span>
                <span style="font-size: 1.15rem; font-weight: 700; color: #EDF4FF;">Structured Forensic Record Inspector</span>
            </div>
            """,
            unsafe_allow_html=True
        )

        active_record = next((r for r in raw_records if r["raw_ref"] == selected_ref), None)
        if not active_record:
            st.info("Select a record from the left panel to inspect.")
            return

        norm_ev = norm_by_ref.get(selected_ref)

        # Header card with active raw_ref pill
        st.markdown(
            f"""
            <div style="background: #121D30; border: 1px solid rgba(53,214,232,0.35); border-radius: 8px; padding: 12px 16px; margin-bottom: 12px; box-shadow: 0 4px 16px rgba(0,0,0,0.3);">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-family: 'JetBrains Mono', monospace; font-size: 1.02rem; color: #35D6E8; font-weight: 700;">
                        {active_record['raw_ref']}
                    </span>
                    <span class="badge badge-high-conf">AUTHENTIC EVIDENCE RECORD</span>
                </div>
                <div style="font-size: 0.78rem; color: #94A7C2; margin-top: 4px;">
                    Source: <strong style="color: #EDF4FF;">{active_record.get('source_file')}</strong> • Record #{active_record.get('record_number')} • Provider: {active_record.get('source')}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Tabs: Raw JSON vs Normalized Schema vs Provenance
        tab1, tab2, tab3 = st.tabs(["📄 Raw JSON", "⚖️ Normalized Schema", "🔗 Provenance Link"])

        with tab1:
            raw_content = active_record.get("raw_json", {})
            if isinstance(raw_content, str):
                try:
                    raw_content = json.loads(raw_content)
                except Exception:
                    pass

            st.caption("Immutable original log record extracted directly from source .evtx / file:")
            raw_formatted = json.dumps(raw_content, indent=2)
            st.code(raw_formatted, language="json")

        with tab2:
            if norm_ev:
                st.caption("Normalized Section 6 Schema attributes derived from this record:")
                attr_rows = []
                for k, v in norm_ev.items():
                    if k not in ("investigation_id", "flags_list"):
                        attr_rows.append({"Attribute": k, "Value": str(v) if v is not None else "—"})
                st.dataframe(pd.DataFrame(attr_rows), use_container_width=True, hide_index=True)
            else:
                st.warning("This record was not mapped to an active normalized attack event (unsupported event ID or baseline noise).")

        with tab3:
            st.markdown("**Evidence Provenance Traceability:**")
            st.markdown(f"- **Raw Reference:** `{active_record['raw_ref']}`")
            st.markdown(f"- **File on Disk:** `{active_record.get('source_file')}`")
            st.markdown(f"- **Provider Channel:** `{active_record.get('source')}`")
            if norm_ev:
                st.markdown(f"- **Normalized Event ID:** `{norm_ev.get('event_id')}`")
                st.markdown(f"- **MITRE Technique:** `{norm_ev.get('mitre_technique') or 'None'}`")
                st.markdown(f"- **Confidence Assessment:** `{norm_ev.get('confidence', 'N/A')}`")
                flags = norm_ev.get("flags_list", [])
                st.markdown(f"- **Uncertainty Flags:** `{', '.join(flags) if flags else 'None'}`")
            else:
                st.info("No active findings mapped to this raw log entry.")
