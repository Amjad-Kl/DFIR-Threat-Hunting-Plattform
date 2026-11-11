-- Threat Hunting Workbench - Database Schema v1
-- SQLite with FTS5 for full-text search

PRAGMA journal_mode=DELETE;
PRAGMA foreign_keys=ON;

-- ============================================================
-- CASES
-- ============================================================
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'open' CHECK(status IN ('open', 'in_progress', 'closed')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    analyst TEXT,
    classification TEXT DEFAULT 'investigation' CHECK(classification IN ('incident', 'investigation', 'exercise', 'threat_hunt')),
    time_range_start DATETIME,
    time_range_end DATETIME,
    notes TEXT
);

-- ============================================================
-- ARTIFACTS (imported source files)
-- ============================================================
CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,
    artifact_type TEXT NOT NULL CHECK(artifact_type IN ('evtx', 'registry', 'prefetch', 'amcache', 'yara_target')),
    file_size INTEGER,
    sha256 TEXT NOT NULL,
    import_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    imported_by TEXT,
    source_host TEXT,
    parsing_status TEXT DEFAULT 'pending' CHECK(parsing_status IN ('pending', 'parsing', 'done', 'error')),
    parsing_error TEXT,
    event_count INTEGER DEFAULT 0
);

-- ============================================================
-- EVENTS (normalized - the core table)
-- ============================================================
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    timestamp DATETIME NOT NULL,
    source_type TEXT NOT NULL,
    event_type TEXT DEFAULT 'other',
    severity TEXT DEFAULT 'info' CHECK(severity IN ('info', 'low', 'medium', 'high', 'critical')),
    
    source_host TEXT,
    source_user TEXT,
    source_ip TEXT,
    dest_host TEXT,
    dest_ip TEXT,
    dest_port INTEGER,
    process_name TEXT,
    process_path TEXT,
    process_pid INTEGER,
    parent_process TEXT,
    parent_pid INTEGER,
    command_line TEXT,
    file_path TEXT,
    file_hash TEXT,
    registry_key TEXT,
    registry_value TEXT,
    
    raw_data TEXT,
    channel TEXT,
    event_id INTEGER,
    
    is_suspicious BOOLEAN DEFAULT FALSE,
    is_ioc_match BOOLEAN DEFAULT FALSE,
    
    mitre_tactic TEXT,
    mitre_technique TEXT
);

-- Full-text search on events
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    command_line, process_name, process_path, file_path,
    registry_key, registry_value, raw_data,
    content='events', content_rowid='rowid'
);

-- Triggers to keep FTS in sync
CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
    INSERT INTO events_fts(rowid, command_line, process_name, process_path, file_path, registry_key, registry_value, raw_data)
    VALUES (new.rowid, new.command_line, new.process_name, new.process_path, new.file_path, new.registry_key, new.registry_value, new.raw_data);
END;

CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, command_line, process_name, process_path, file_path, registry_key, registry_value, raw_data)
    VALUES ('delete', old.rowid, old.command_line, old.process_name, old.process_path, old.file_path, old.registry_key, old.registry_value, old.raw_data);
END;

-- ============================================================
-- IOCs
-- ============================================================
CREATE TABLE IF NOT EXISTS iocs (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    ioc_type TEXT NOT NULL CHECK(ioc_type IN ('hash_md5', 'hash_sha1', 'hash_sha256', 'ip', 'domain', 'url', 'filename', 'email', 'registry_key')),
    ioc_value TEXT NOT NULL,
    description TEXT,
    source TEXT,
    confidence TEXT DEFAULT 'medium' CHECK(confidence IN ('low', 'medium', 'high')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ioc_type, ioc_value, case_id)
);

-- ============================================================
-- FINDINGS
-- ============================================================
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    event_id TEXT REFERENCES events(id) ON DELETE SET NULL,
    finding_type TEXT NOT NULL CHECK(finding_type IN ('ioc_match', 'persistence', 'suspicious_pattern', 'yara_match')),
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT DEFAULT 'medium' CHECK(severity IN ('info', 'low', 'medium', 'high', 'critical')),
    evidence TEXT,
    rule_name TEXT,
    false_positive BOOLEAN DEFAULT FALSE,
    analyst_notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- TAGS
-- ============================================================
CREATE TABLE IF NOT EXISTS tags (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('event', 'artifact', 'finding')),
    entity_id TEXT NOT NULL,
    tag_name TEXT NOT NULL,
    tag_color TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT,
    UNIQUE(entity_type, entity_id, tag_name)
);

-- ============================================================
-- AUDIT LOG
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_name TEXT,
    action TEXT NOT NULL CHECK(action IN ('import', 'analyze', 'tag', 'export', 'delete', 'create', 'update')),
    entity_type TEXT,
    entity_id TEXT,
    details TEXT
);

-- ============================================================
-- YARA RULES
-- ============================================================
CREATE TABLE IF NOT EXISTS yara_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    category TEXT,
    rule_content TEXT NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    source TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- INDICES
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_source_type ON events(source_type);
CREATE INDEX IF NOT EXISTS idx_events_process_name ON events(process_name);
CREATE INDEX IF NOT EXISTS idx_events_suspicious ON events(is_suspicious);
CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id);
CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_artifacts_case ON artifacts(case_id);
CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(ioc_type, ioc_value);
CREATE INDEX IF NOT EXISTS idx_tags_entity ON tags(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
