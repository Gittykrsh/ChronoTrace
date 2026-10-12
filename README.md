# ChronoTrace — Uncertainty-Aware Cyberattack Reconstruction System

![ChronoTrace Digital Forensics](assets/logo.svg)

ChronoTrace is a professional, interactive digital forensics and attack reconstruction platform designed for incident responders, threat hunters, and security analysts. It reconstructs multi-stage cyberattacks from Windows Event Logs while explicitly identifying missing evidence, timestamp ambiguities, and causal uncertainties.

---

## 1. Project Purpose & Differentiator

Traditional forensic timeline tools (e.g., Plaso, Timesketch) often present events in a rigid sequential order, masking underlying ambiguities such as clock skews, uncorroborated single-source logs, and missing parent-child relationships.

**The main differentiator of ChronoTrace is uncertainty-aware reconstruction:**
- **Evidence Traceability (Rule 0):** Every reconstructed finding points directly to an immutable log record reference (`raw_ref`).
- **Interval Timestamps:** Events are treated as time ranges `[ts_start_utc, ts_end_utc]`, preventing false ordering when timestamps overlap.
- **Four-Factor Confidence Engine:** Transparent, algorithmic corroboration scoring without black-box machine learning.
- **Uncertainty & Conflict Surfacing:** Proactively flags chronological contradictions (`ORDER_CONFLICT`), orphaned processes (`MISSING_PARENT`), audit log purges (`LOG_CLEARED`), and single-source findings (`SINGLE_SOURCE`).

---

## 2. Technology Stack

- **Language:** Python 3.10+
- **Frontend / UI:** Streamlit with custom SOC Dark Theme CSS
- **Data Wrangling:** Pandas
- **Provenance Graph:** NetworkX (Directed Graph)
- **Graph Visualization:** PyVis (Interactive Physics Canvas) & Plotly fallback
- **Interactive Visualizations:** Plotly
- **Storage:** SQLite (`PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;`)
- **EVTX Ingestion:** `python-evtx` (with XML parsing and schema validation)
- **Exports:** CSV (RFC 4180), JSON, Markdown Incident Report

---

## 3. Project Structure

```
chronotrace/
├── app.py                           # Root application entry point
├── assets/
│   ├── logo.svg                     # Vector ChronoTrace logo
│   └── styles.css                   # SOC Dark Theme Design System
├── components/
│   ├── page_setup.py                # Page config & theme loader
│   ├── sidebar.py                   # Global investigation selector & status
│   ├── topbar.py                    # Top navigation, UTC clock & filters
│   ├── metric_cards.py              # 6 Forensic KPI metric cards
│   ├── charts.py                    # Plotly activity charts & pipeline tracker
│   ├── timeline.py                  # Gantt interval timeline & event details drawer
│   ├── graph_view.py                # NetworkX + PyVis interactive provenance graph
│   ├── evidence_panel.py            # Dual-pane raw evidence explorer
│   └── conflict_inspector.py        # Dedicated 4-flag conflict inspector
├── database/
│   ├── schema.sql                   # SQLite schema for events, entities, edges, findings
│   └── db.py                        # Database access layer with raw_ref validation
├── data/
│   ├── sample_events.json           # Synthetic ground-truth attack scenario
│   └── demo_seed.py                 # Automated demonstration database seeder
├── pages/
│   ├── 1_Investigation_Overview.py  # Overview dashboard
│   ├── 2_Evidence_Ingestion.py      # EVTX/JSON upload & multi-stage pipeline
│   ├── 3_Attack_Timeline.py         # Chronological timeline & drawer
│   ├── 4_Provenance_Graph.py        # Entity resolution & graph explorer
│   ├── 5_Evidence_Explorer.py       # Dual-pane raw evidence inspector
│   └── 6_Findings_and_Reports.py    # Findings, MITRE matrix & exports
├── services/
│   ├── confidence.py                # 4-factor confidence scoring formula
│   ├── conflict_detection.py        # 4 conflict and missing evidence flags
│   ├── correlation.py               # Entity resolution & NetworkX graph builder
│   ├── ingestion.py                 # Multi-stage EVTX/JSON ingestion pipeline
│   ├── mitre_tagger.py              # Rule-based MITRE ATT&CK technique tagger
│   ├── normalization.py             # UTC normalization & Section 6 schema checks
│   └── reporting.py                 # CSV, JSON, and Markdown report generators
├── tests/
│   ├── test_schema.py               # Schema enforcement & raw_ref tests
│   ├── test_confidence.py           # Confidence scoring & time precision tests
│   ├── test_conflicts.py            # 4 conflict flags detection tests
│   └── test_normalization.py        # UTC conversion & Sysmon/Security tests
├── requirements.txt
└── README.md
```

---

## 4. Supported Event Telemetry Scope

| Provider | Event ID | Telemetry Description | Primary Entities Extracted |
| :--- | :---: | :--- | :--- |
| **Sysmon** | `1` | Process Creation | `ProcessGuid`, `Image`, `CommandLine`, `ParentProcessGuid`, `User` |
| **Sysmon** | `3` | Network Connection | `ProcessGuid`, `SourceIp`, `DestinationIp`, `DestinationPort` |
| **Sysmon** | `11` | File Creation / Drop | `ProcessGuid`, `TargetFilename`, UTC Timestamp |
| **Security** | `4624` | Successful Logon | `TargetUserName`, `LogonType`, `IpAddress` |
| **Security** | `4688` | Process Creation | `NewProcessId`, `ProcessId`, `CommandLine`, `TargetUserName` |
| **Security** | `1102` | Audit Log Cleared | Anti-Forensics / Tampering Indicator |

---

## 5. Confidence Scoring Engine

ChronoTrace implements the first-draft confidence formula:
$$\text{confidence} = w_1 \cdot \text{corroboration} + w_2 \cdot \text{source\_reliability} + w_3 \cdot \text{time\_certainty} + w_4 \cdot \text{link\_strength}$$

- **Corroboration ($0.0 - 1.0$):** Number of independent providers observing the activity.
- **Source Reliability ($0.0 - 1.0$):** Trust level of provider (Sysmon with GUIDs = 0.95; Security with reused PIDs = 0.85; Security 1102 = 1.00).
- **Time Certainty ($0.0 - 1.0$):** Precision of interval $[ts\_start, ts\_end]$ (delta $\le 1s \implies 1.0$; wide skew $\implies 0.35$).
- **Link Strength ($0.0 - 1.0$):** Confidence in entity resolution ($ProcessGuid \implies 0.98$; PID heuristic $\implies 0.55$).
- **Equal Weights:** $w_1 = w_2 = w_3 = w_4 = 0.25$ by default.

> [!NOTE]
> *A confidence score is an evidence-corroboration metric, not a mathematical claim of ground truth.*

---

## 6. Conflict and Missing-Evidence Engine

1. **`ORDER_CONFLICT`**: Time intervals overlap $[ts\_start, ts\_end]$ or independent hosts exhibit clock drift, making strict chronological ordering uncertain.
2. **`MISSING_PARENT`**: Child process exists with `ParentProcessGuid` or `ppid`, but no corresponding parent event is recorded in the ingested log stream.
3. **`LOG_CLEARED`**: Windows Security Event 1102 detected. Indicates intentional audit log clearing; marks prior telemetry as potentially tampered.
4. **`SINGLE_SOURCE`**: Event observed in only one source file/channel without cross-telemetry verification.

---

## 7. Installation & Quickstart

### Prerequisites
Python 3.10+ installed with `pip`.

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Seed Synthetic Demo Data (Optional, auto-seeded on first launch)
```bash
python data/demo_seed.py
```

### 3. Launch ChronoTrace
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

### 4. Run Automated Unit Tests
```bash
pytest tests/ -v
```

---

## 8. Export Capabilities

ChronoTrace provides full export functionality from the **Findings & Reports** workspace:
- **Timeline (CSV):** Export all normalized events, interval timestamps, and `raw_ref` citations.
- **Findings & Graph (JSON):** Export reconstructed findings, factor breakdowns, entities, and edges.
- **Incident Report (Markdown):** Complete, publication-ready Digital Forensics Incident Report formatted with Executive Summary, Methodology, Attack Kill-Chain, Conflict Analysis, and Evidence Citations.

---

## 9. Ethics and Scope

- **Rule-Based Prototype:** No machine learning, LLM hallucination, or unverified automated guessing.
- **Lab & Synthetic Safety:** Demo datasets are explicitly labelled `DEMO DATA — NOT REAL FORENSIC EVIDENCE`. Real attack testing must only be performed inside isolated virtual machines (VirtualBox/VMware).
