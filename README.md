# ChronoTrace — Uncertainty-Aware Cyberattack Reconstruction System

![ChronoTrace Digital Forensics](assets/logo.svg)

ChronoTrace is an enterprise digital forensics and attack reconstruction platform designed for incident responders, threat hunters, and forensic engineers. It reconstructs multi-stage cyberattacks from Windows Event Logs while explicitly surfacing missing evidence, timestamp ambiguities, causal contradictions, and cryptographic proof of custody.

---

## 1. Project Purpose & Core Differentiators

Traditional forensic timeline tools (e.g., Plaso, Timesketch) force events into a rigid, sequential order, masking critical ambiguities such as cross-host clock skews, uncorroborated single-source logs, and missing parent-child relationships.

**ChronoTrace eliminates black-box assumptions through deterministic mathematics:**
- **Evidence Traceability (Rule 0):** Every reconstructed finding points directly to an immutable log record reference (`raw_ref`, e.g. `sysmon.evtx#101`).
- **Interval Timestamps:** Events are treated as uncertainty intervals `[ts_start_utc, ts_end_utc]`, preventing artificial ordering when timestamps overlap.
- **Four-Factor Confidence Engine:** Transparent, deterministic arithmetic corroboration formula without black-box machine learning or hallucinating AI models.
- **Conflict & Anti-Forensics Surfacing:** Automatically flags chronological contradictions (`ORDER_CONFLICT`), orphaned processes (`MISSING_PARENT`), audit log purges (`LOG_CLEARED`), and unverified records (`SINGLE_SOURCE`).
- **Cryptographic Merkle Tree Hash Chaining:** Sequential SHA-256 block hashing that proves not a single log was modified, reordered, or deleted post-acquisition.
- **Attack Blast Radius Analytics:** Computes the mathematical percentage and breadth of compromised enterprise hosts and user identities.

---

## 2. Technology Stack

- **Language:** Python 3.10+
- **Frontend / Console:** Streamlit with Defense SOC Dark Theme CSS (`#090E1A` canvas, `#1D6FE8` primary accent)
- **REST API Gateway:** FastAPI & Uvicorn (Modular router architecture with Swagger UI at `/docs`)
- **Configuration:** Python-dotenv (`.env` & `.env.example`)
- **Causal Graph Engine:** NetworkX (Directed Acyclic Graph)
- **Interactive Visualizations:** Plotly & PyVis
- **Storage:** Local SQLite WAL mode (`PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;`)
- **EVTX Ingestion:** `python-evtx` (with XML parsing and schema validation)
- **Testing:** Pytest (22/22 unit tests passing)
- **Exports:** CSV (RFC 4180), JSON findings with provenance tree, and signed Markdown DFIR Incident Reports

---

## 3. Project Architecture

```text
chronotrace/
├── app.py                           # Root application entry point
├── config.py                        # Centralized .env configuration manager
├── run_api.py                       # Standalone FastAPI REST gateway launcher
├── .env                             # Local environment secrets & paths (git-ignored)
├── .env.example                     # Environment template for production/team
├── requirements.txt                 # Manifest with pinned production dependencies
│
├── api/                             # Modular REST API Architecture
│   ├── main.py                      # FastAPI app entry point & CORS configuration
│   ├── schemas.py                   # Pydantic request & response schemas
│   └── routers/
│       ├── auth.py                  # Google OAuth2 (PKCE) & Enterprise SSO APIs
│       ├── investigations.py        # Investigation workspace CRUD endpoints
│       ├── reconstruction.py        # Interval timeline, NetworkX graph & conflicts
│       ├── integrity.py             # Merkle tree hash chain & blast radius
│       ├── ingestion.py             # Evidence ingestion pipeline & report export
│       └── health.py                # Subsystem health & Rule 0 status
│
├── ui/                              # SOC Dark Theme & Modular UI System
│   ├── theme.py                     # High-specificity CSS & typography engine
│   ├── layout.py                    # Persistent flat sidebar & filter topbar
│   ├── components.py                # Reusable UI widgets & metric cards
│   └── welcome.py                   # Welcome portal, Google dialog & SSO modal
│
├── pages/                           # Streamlit Multi-Page Workspaces
│   ├── 1_Investigation_Overview.py  # Overview dashboard, Merkle seal & blast radius
│   ├── 2_Evidence_Ingestion.py      # EVTX/JSON uploader & safe incident presets
│   ├── 3_Attack_Timeline.py         # Chronological interval timeline & drawer
│   ├── 4_Provenance_Graph.py        # Entity resolution & causal graph explorer
│   ├── 5_Evidence_Explorer.py       # Dual-pane raw evidence inspector
│   └── 6_Findings_and_Reports.py    # Findings, MITRE matrix & exports
│
├── services/                        # Deterministic Forensic Logic Engines
│   ├── confidence.py                # 4-factor confidence scoring formula
│   ├── conflict_detection.py        # 4 conflict and anti-forensics flags
│   ├── correlation.py               # Entity resolution & NetworkX graph builder
│   ├── crypto_chain.py              # SHA-256 Merkle tree evidence hash chain
│   ├── graph_analytics.py           # Blast radius & kill-chain pathfinding
│   ├── ingestion.py                 # Multi-stage EVTX/JSON processing pipeline
│   ├── mitre_tagger.py              # Rule-based MITRE ATT&CK technique tagger
│   ├── normalization.py             # UTC normalization & interval time math
│   └── reporting.py                 # CSV, JSON, and Markdown report generators
│
├── database/                        # Persistence Layer
│   ├── schema.sql                   # SQLite schema with cascading foreign keys
│   └── db.py                        # Database access layer with WAL mode
│
├── data/                            # Verified Incident Datasets (100% Virus-Free)
│   ├── sample_events.json           # Operation Chimera (Multi-stage kill chain)
│   ├── enterprise_clean_scenario.json # Enterprise Discovery & C2 Lateral Movement
│   └── demo_seed.py                 # Automated demonstration database seeder
│
└── tests/                           # Comprehensive Automated Test Suite (22 Tests)
    ├── test_api.py                  # FastAPI health, auth & investigation tests
    ├── test_auth.py                 # User creation & session verification tests
    ├── test_confidence.py           # 4-factor confidence scoring tests
    ├── test_conflicts.py            # Conflict flags detection tests
    ├── test_crypto_chain.py         # Merkle tree & evidence tamper detection tests
    ├── test_graph_analytics.py      # Blast radius & attack path tests
    ├── test_normalization.py        # UTC conversion & Sysmon schema tests
    ├── test_pages_import.py         # Workspace syntax & import integrity tests
    ├── test_safe_datasets.py        # Safe built-in scenario ingestion tests
    └── test_schema.py               # Mandatory raw_ref Rule 0 validation tests
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
| **Security** | `1102` | Audit Log Cleared | Anti-Forensics / Log Purge Indicator |

---

## 5. Confidence Scoring Engine

ChronoTrace implements a transparent, audited 4-factor scoring formula:
$$\text{Confidence} = 0.25 \cdot \text{Corroboration} + 0.25 \cdot \text{Source Reliability} + 0.25 \cdot \text{Time Precision} + 0.25 \cdot \text{Link Strength}$$

- **Corroboration ($0.0 - 1.0$):** Number of independent providers observing the activity ($1.0$ if $\ge 2$ sources, $0.5$ if single source).
- **Source Reliability ($0.0 - 1.0$):** Trust level of telemetry provider (Sysmon with GUIDs = $0.95$; Security with reused PIDs = $0.85$; Security 1102 = $1.00$).
- **Time Precision ($0.0 - 1.0$):** Precision of interval $[ts\_start, ts\_end]$ (sub-second $\implies 1.0$; wide drift $\implies 0.35$).
- **Link Strength ($0.0 - 1.0$):** Certainty in entity resolution ($ProcessGuid \implies 0.98$; PID heuristic $\implies 0.55$).

---

## 6. Conflict and Missing-Evidence Engine

1. **`ORDER_CONFLICT`**: Time intervals overlap $[ts\_start, ts\_end]$ or independent hosts exhibit clock drift, making strict chronological ordering mathematically uncertain.
2. **`MISSING_PARENT`**: Child process exists with `ParentProcessGuid` or `ppid`, but no corresponding parent event is recorded in the ingested log stream (detects orphaned processes or deleted parent logs).
3. **`LOG_CLEARED`**: Windows Security Event 1102 detected. Indicates deliberate evidence destruction; tags prior telemetry on that host as potentially tampered.
4. **`SINGLE_SOURCE`**: Event observed in only one source file/channel without cross-telemetry verification.

---

## 7. Installation & Quickstart

### Prerequisites
Python 3.10+ installed with `pip`.

### 1. Clone Repository & Install Dependencies
```bash
git clone https://github.com/Gittykrsh/ChronoTrace.git
cd ChronoTrace
pip install -r requirements.txt
```

### 2. Configure Environment (.env)
```bash
cp .env.example .env
```
*(Optionally adjust port or database path in `.env`)*

### 3. Launch ChronoTrace Console (Streamlit)
```bash
streamlit run app.py
```
Open your browser at **`http://localhost:8501`**.

### 4. Launch REST API Gateway (FastAPI)
```bash
python run_api.py
```
Explore the interactive Swagger API documentation at **`http://localhost:8000/docs`**.

### 5. Run Automated Unit Test Suite
```bash
pytest tests/ -v
```
*Expected: 22 passed.*

---

## 8. Export Capabilities

ChronoTrace provides full export functionality from the **Findings & Reports** workspace:
- **Timeline (CSV):** Export all normalized events, interval timestamps, and `raw_ref` citations.
- **Findings & Graph (JSON):** Export reconstructed findings, factor breakdowns, entities, and edges.
- **Incident Report (Markdown):** Complete, court-admissible Digital Forensics Incident Report formatted with Executive Summary, Methodology, Attack Kill-Chain, Conflict Analysis, Merkle Root Verification, and Evidence Citations.

---

## 9. Ethics, Privacy & Scope

- **Zero Cloud Leakage:** All data is processed 100% locally in SQLite WAL mode. No sensitive corporate logs, passwords, or customer telemetry ever leave your machine.
- **Deterministic Proof:** No LLM hallucination or unverified automated guessing. Every finding maps back to exact log byte citations (`raw_ref`).
- **Lab & Synthetic Safety:** Included datasets are certified 100% virus-scanner safe with zero malicious binaries.
