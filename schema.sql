-- Skema Database Lokal SQLite SKYGUARD-ID (Standar Gate Biometrik >= 98.0%)
CREATE TABLE IF NOT EXISTS personnel (
    emp_id TEXT PRIMARY KEY,
    full_name TEXT NOT NULL,
    department TEXT NOT NULL,
    clearance_level TEXT NOT NULL,
    shift_hours TEXT NOT NULL,
    embedding_128d TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attendance_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    emp_id TEXT NOT NULL,
    full_name TEXT NOT NULL,
    gate_id TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    accuracy_pct REAL NOT NULL CHECK (accuracy_pct >= 0.0 AND accuracy_pct <= 100.0),
    liveness_pct REAL NOT NULL CHECK (liveness_pct >= 0.0 AND liveness_pct <= 100.0),
    status TEXT NOT NULL,
    sha256_hash TEXT NOT NULL
);
