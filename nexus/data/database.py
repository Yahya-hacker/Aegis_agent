"""
Nexus v2.0 - Database Layer
============================

SQLite-based storage for:
- Scan results
- Vulnerability findings
- Target history
- Configuration persistence
"""

import sqlite3
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass

from nexus.config import get_config

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityRecord:
    """A stored vulnerability record."""
    id: int
    target: str
    vuln_type: str
    endpoint: str
    severity: str
    title: str
    description: str
    evidence: Dict[str, Any]
    status: str  # new, confirmed, reported, fixed
    created_at: datetime
    updated_at: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "vuln_type": self.vuln_type,
            "endpoint": self.endpoint,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class Database:
    """SQLite database for persistent storage."""
    
    def __init__(self, db_path: str = None):
        config = get_config()
        self.db_path = db_path or config.data.database_url.replace("sqlite:///", "")
        
        # Ensure directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        self._init_schema()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_schema(self):
        """Initialize database schema."""
        conn = self._get_connection()
        
        conn.executescript("""
            -- Targets table
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                program TEXT,
                scope TEXT,
                notes TEXT,
                last_scanned TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Vulnerabilities table
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                status TEXT DEFAULT 'new',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(target, vuln_type, endpoint)
            );
            
            -- Scan history table
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL,
                findings_count INTEGER DEFAULT 0,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                config TEXT
            );
            
            -- Endpoints table (discovered endpoints)
            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                url TEXT NOT NULL,
                method TEXT DEFAULT 'GET',
                parameters TEXT,
                headers TEXT,
                status_code INTEGER,
                content_type TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(target, url, method)
            );
            
            -- Subdomains table
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                ip_address TEXT,
                status TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(domain, subdomain)
            );
            
            -- Credentials table (discovered credentials)
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                source TEXT,
                username TEXT,
                password TEXT,
                credential_type TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Create indexes
            CREATE INDEX IF NOT EXISTS idx_vulns_target ON vulnerabilities(target);
            CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
            CREATE INDEX IF NOT EXISTS idx_endpoints_target ON endpoints(target);
            CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain);
        """)
        
        conn.commit()
        conn.close()
        
        logger.info(f"📦 Database initialized: {self.db_path}")
    
    # ==================== Vulnerabilities ====================
    
    def save_vulnerability(
        self,
        target: str,
        vuln_type: str,
        endpoint: str,
        severity: str,
        title: str,
        description: str = "",
        evidence: Dict[str, Any] = None
    ) -> int:
        """Save a vulnerability finding."""
        conn = self._get_connection()
        
        try:
            cursor = conn.execute("""
                INSERT OR REPLACE INTO vulnerabilities 
                (target, vuln_type, endpoint, severity, title, description, evidence, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                target,
                vuln_type,
                endpoint,
                severity,
                title,
                description,
                json.dumps(evidence or {}),
            ))
            
            conn.commit()
            return cursor.lastrowid
            
        finally:
            conn.close()
    
    def get_vulnerabilities(
        self,
        target: str = None,
        severity: str = None,
        status: str = None
    ) -> List[VulnerabilityRecord]:
        """Get vulnerabilities with optional filters."""
        conn = self._get_connection()
        
        query = "SELECT * FROM vulnerabilities WHERE 1=1"
        params = []
        
        if target:
            query += " AND target = ?"
            params.append(target)
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if status:
            query += " AND status = ?"
            params.append(status)
        
        query += " ORDER BY created_at DESC"
        
        try:
            rows = conn.execute(query, params).fetchall()
            
            return [
                VulnerabilityRecord(
                    id=row["id"],
                    target=row["target"],
                    vuln_type=row["vuln_type"],
                    endpoint=row["endpoint"],
                    severity=row["severity"],
                    title=row["title"],
                    description=row["description"],
                    evidence=json.loads(row["evidence"]),
                    status=row["status"],
                    created_at=datetime.fromisoformat(row["created_at"]),
                    updated_at=datetime.fromisoformat(row["updated_at"]),
                )
                for row in rows
            ]
            
        finally:
            conn.close()
    
    def update_vulnerability_status(self, vuln_id: int, status: str):
        """Update vulnerability status."""
        conn = self._get_connection()
        
        try:
            conn.execute("""
                UPDATE vulnerabilities 
                SET status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (status, vuln_id))
            conn.commit()
            
        finally:
            conn.close()
    
    # ==================== Targets ====================
    
    def save_target(
        self,
        domain: str,
        program: str = "",
        scope: str = "",
        notes: str = ""
    ):
        """Save a target."""
        conn = self._get_connection()
        
        try:
            conn.execute("""
                INSERT OR REPLACE INTO targets (domain, program, scope, notes)
                VALUES (?, ?, ?, ?)
            """, (domain, program, scope, notes))
            conn.commit()
            
        finally:
            conn.close()
    
    def get_targets(self) -> List[Dict[str, Any]]:
        """Get all targets."""
        conn = self._get_connection()
        
        try:
            rows = conn.execute("SELECT * FROM targets ORDER BY created_at DESC").fetchall()
            return [dict(row) for row in rows]
            
        finally:
            conn.close()
    
    # ==================== Endpoints ====================
    
    def save_endpoint(
        self,
        target: str,
        url: str,
        method: str = "GET",
        parameters: List[str] = None,
        status_code: int = None
    ):
        """Save a discovered endpoint."""
        conn = self._get_connection()
        
        try:
            conn.execute("""
                INSERT OR IGNORE INTO endpoints (target, url, method, parameters, status_code)
                VALUES (?, ?, ?, ?, ?)
            """, (
                target,
                url,
                method,
                json.dumps(parameters or []),
                status_code,
            ))
            conn.commit()
            
        finally:
            conn.close()
    
    def get_endpoints(self, target: str) -> List[Dict[str, Any]]:
        """Get endpoints for a target."""
        conn = self._get_connection()
        
        try:
            rows = conn.execute(
                "SELECT * FROM endpoints WHERE target = ?",
                (target,)
            ).fetchall()
            
            return [dict(row) for row in rows]
            
        finally:
            conn.close()
    
    # ==================== Subdomains ====================
    
    def save_subdomains(self, domain: str, subdomains: List[str]):
        """Save discovered subdomains."""
        conn = self._get_connection()
        
        try:
            conn.executemany("""
                INSERT OR IGNORE INTO subdomains (domain, subdomain)
                VALUES (?, ?)
            """, [(domain, sub) for sub in subdomains])
            conn.commit()
            
        finally:
            conn.close()
    
    def get_subdomains(self, domain: str) -> List[str]:
        """Get subdomains for a domain."""
        conn = self._get_connection()
        
        try:
            rows = conn.execute(
                "SELECT subdomain FROM subdomains WHERE domain = ?",
                (domain,)
            ).fetchall()
            
            return [row["subdomain"] for row in rows]
            
        finally:
            conn.close()
    
    # ==================== Statistics ====================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        conn = self._get_connection()
        
        try:
            stats = {
                "targets": conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0],
                "vulnerabilities": conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0],
                "endpoints": conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0],
                "subdomains": conn.execute("SELECT COUNT(*) FROM subdomains").fetchone()[0],
            }
            
            # Vulnerabilities by severity
            severity_counts = conn.execute("""
                SELECT severity, COUNT(*) as count 
                FROM vulnerabilities 
                GROUP BY severity
            """).fetchall()
            
            stats["by_severity"] = {row["severity"]: row["count"] for row in severity_counts}
            
            return stats
            
        finally:
            conn.close()


# Singleton
_db: Optional[Database] = None


def get_database() -> Database:
    """Get the global database instance."""
    global _db
    if _db is None:
        _db = Database()
    return _db
