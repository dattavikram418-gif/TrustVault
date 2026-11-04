import sqlite3
from pathlib import Path
from .config import DATABASE_PATH

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')),
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS documents (
 id TEXT PRIMARY KEY,
 owner_id INTEGER NOT NULL REFERENCES users(id),
 filename TEXT NOT NULL,
 category TEXT NOT NULL,
 stored_name TEXT NOT NULL UNIQUE,
 size_bytes INTEGER NOT NULL,
 sha256 TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS permissions (
 document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id),
 permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
 granted_by INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(document_id,user_id)
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 actor_id INTEGER,
 actor_name TEXT NOT NULL,
 action TEXT NOT NULL,
 document_id TEXT,
 target_user_id INTEGER,
 outcome TEXT NOT NULL,
 ip_address TEXT,
 details TEXT NOT NULL,
 previous_hash TEXT NOT NULL,
 entry_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_docs_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_audit_doc ON audit_logs(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(occurred_at);
"""

def connect():
    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con

def init_db():
    with connect() as con:
        con.executescript(SCHEMA)

def rowdict(row):
    return dict(row) if row else None
