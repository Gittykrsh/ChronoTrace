-- ChronoTrace SQLite Database Schema
-- Uncertainty-Aware Digital Forensics & Attack Reconstruction System

-- Investigations metadata
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL,
    is_demo INTEGER DEFAULT 0
);

-- Raw ingested evidence records (original log source)
CREATE TABLE IF NOT EXISTS raw_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_ref TEXT UNIQUE NOT NULL,
    investigation_id TEXT NOT NULL,
    source_file TEXT NOT NULL,
    record_number INTEGER NOT NULL,
    source TEXT NOT NULL,
    event_code INTEGER NOT NULL,
    raw_json TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
);

-- Normalized forensic events (Strict schema from Section 6)
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    host TEXT NOT NULL,
    source TEXT NOT NULL,
    event_code INTEGER NOT NULL,
    ts_start_utc TEXT NOT NULL,
    ts_end_utc TEXT NOT NULL,
    process_guid TEXT,
    pid INTEGER,
    ppid INTEGER,
    parent_guid TEXT,
    image TEXT,
    command_line TEXT,
    user TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    raw_ref TEXT NOT NULL,
    mitre_technique TEXT,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
    FOREIGN KEY (raw_ref) REFERENCES raw_events(raw_ref)
);

-- Provenance graph entities
CREATE TABLE IF NOT EXISTS entities (
    entity_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    type TEXT NOT NULL, -- 'process', 'user', 'host', 'ip', 'file'
    key TEXT NOT NULL,  -- e.g. ProcessGuid, Hostname, Username, IP address, FilePath
    host TEXT,
    label TEXT NOT NULL,
    first_seen TEXT,
    last_seen TEXT,
    attributes TEXT,   -- JSON string of extra properties
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
);

-- Provenance graph relationships
CREATE TABLE IF NOT EXISTS edges (
    edge_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    src_entity TEXT NOT NULL,
    dst_entity TEXT NOT NULL,
    relation TEXT NOT NULL, -- 'spawned', 'logged-in', 'connected-to', 'created-file'
    link_strength REAL DEFAULT 1.0,
    is_uncertain INTEGER DEFAULT 0,
    evidence_event_ids TEXT, -- JSON array of event_id strings
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
    FOREIGN KEY (src_entity) REFERENCES entities(entity_id),
    FOREIGN KEY (dst_entity) REFERENCES entities(entity_id)
);

-- Forensic findings and uncertainty assessments
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    confidence REAL NOT NULL,
    flags TEXT,        -- JSON array of flags: ORDER_CONFLICT, MISSING_PARENT, LOG_CLEARED, SINGLE_SOURCE
    explanation TEXT NOT NULL,
    corroboration REAL NOT NULL,
    source_reliability REAL NOT NULL,
    time_certainty REAL NOT NULL,
    link_strength REAL NOT NULL,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events(event_id)
);

-- Ingestion audit log
CREATE TABLE IF NOT EXISTS ingestion_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    file_size_bytes INTEGER,
    total_records INTEGER,
    normalized_records INTEGER,
    unsupported_records INTEGER,
    errors_count INTEGER,
    status TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    details TEXT,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
);

-- Indices for rapid querying
CREATE INDEX IF NOT EXISTS idx_events_investigation ON events(investigation_id);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_start_utc);
CREATE INDEX IF NOT EXISTS idx_events_raw_ref ON events(raw_ref);
CREATE INDEX IF NOT EXISTS idx_raw_events_ref ON raw_events(raw_ref);
CREATE INDEX IF NOT EXISTS idx_findings_investigation ON findings(investigation_id);
CREATE INDEX IF NOT EXISTS idx_edges_investigation ON edges(investigation_id);
