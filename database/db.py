"""
database/db.py – SQLite storage for all findings and scan sessions.
"""

import sqlite3
import json
import uuid
from datetime import datetime
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from bug_bounty_bot.config import DB_PATH


def get_connection():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_connection()
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS scan_sessions (
            id          TEXT PRIMARY KEY,
            target_name TEXT NOT NULL,
            start_url   TEXT NOT NULL,
            started_at  TEXT NOT NULL,
            finished_at TEXT,
            status      TEXT DEFAULT 'running'
        );

        CREATE TABLE IF NOT EXISTS findings (
            id              TEXT PRIMARY KEY,
            session_id      TEXT NOT NULL,
            url             TEXT NOT NULL,
            vuln_type       TEXT NOT NULL,
            severity        TEXT NOT NULL,
            title           TEXT NOT NULL,
            description     TEXT,
            evidence        TEXT,
            request_data    TEXT,
            response_data   TEXT,
            reproduction    TEXT,
            remediation     TEXT,
            cvss_score      REAL,
            status          TEXT DEFAULT 'new',
            created_at      TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
        );

        CREATE TABLE IF NOT EXISTS reports (
            id          TEXT PRIMARY KEY,
            finding_id  TEXT NOT NULL,
            draft_md    TEXT,
            reviewed    INTEGER DEFAULT 0,
            submitted   INTEGER DEFAULT 0,
            created_at  TEXT NOT NULL,
            FOREIGN KEY (finding_id) REFERENCES findings(id)
        );
    """)

    conn.commit()
    conn.close()


def new_session(target_name: str, start_url: str) -> str:
    session_id = str(uuid.uuid4())
    conn = get_connection()
    conn.execute(
        "INSERT INTO scan_sessions VALUES (?, ?, ?, ?, NULL, 'running')",
        (session_id, target_name, start_url, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
    return session_id


def close_session(session_id: str):
    conn = get_connection()
    conn.execute(
        "UPDATE scan_sessions SET finished_at=?, status='done' WHERE id=?",
        (datetime.utcnow().isoformat(), session_id)
    )
    conn.commit()
    conn.close()


def save_finding(session_id: str, finding: dict) -> str:
    finding_id = str(uuid.uuid4())
    conn = get_connection()
    conn.execute(
        """INSERT INTO findings
           (id, session_id, url, vuln_type, severity, title,
            description, evidence, request_data, response_data,
            reproduction, remediation, cvss_score, status, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            finding_id,
            session_id,
            finding.get("url", ""),
            finding.get("vuln_type", "unknown"),
            finding.get("severity", "info"),
            finding.get("title", "Untitled"),
            finding.get("description", ""),
            json.dumps(finding.get("evidence", {})),
            finding.get("request_data", ""),
            finding.get("response_data", ""),
            finding.get("reproduction", ""),
            finding.get("remediation", ""),
            finding.get("cvss_score"),
            "new",
            datetime.utcnow().isoformat(),
        )
    )
    conn.commit()
    conn.close()
    return finding_id


def get_findings_for_session(session_id: str) -> list:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM findings WHERE session_id=? ORDER BY severity",
        (session_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_findings() -> list:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM findings ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_report(finding_id: str, draft_md: str) -> str:
    report_id = str(uuid.uuid4())
    conn = get_connection()
    conn.execute(
        "INSERT INTO reports (id, finding_id, draft_md, created_at) VALUES (?,?,?,?)",
        (report_id, finding_id, draft_md, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
    return report_id


def mark_report_reviewed(report_id: str):
    conn = get_connection()
    conn.execute(
        "UPDATE reports SET reviewed=1 WHERE id=?", (report_id,)
    )
    conn.commit()
    conn.close()


def mark_report_submitted(report_id: str):
    conn = get_connection()
    conn.execute(
        "UPDATE reports SET submitted=1 WHERE id=?", (report_id,)
    )
    conn.commit()
    conn.close()
