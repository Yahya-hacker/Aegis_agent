"""
Mission Database Manager for Aegis AI
Provides persistent storage for mission data to prevent duplicate work
"""

import sqlite3
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class MissionDatabase:
    """Manages SQLite database for mission tracking"""
    
    def __init__(self, db_path: str = "data/mission.db"):
        """Initialize database connection"""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True, parents=True)
        self.conn = None
        self._initialize_database()
    
    def _initialize_database(self):
        """Create database and tables if they don't exist"""
        try:
            self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self.conn.row_factory = sqlite3.Row  # Enable column access by name
            
            cursor = self.conn.cursor()
            
            # Table: subdomains
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    subdomain TEXT NOT NULL,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain, subdomain)
                )
            """)
            
            # Table: endpoints
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL UNIQUE,
                    method TEXT DEFAULT 'GET',
                    status_code INTEGER,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_scanned TIMESTAMP
                )
            """)
            
            # Table: findings
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    url TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    evidence TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    verified BOOLEAN DEFAULT 0
                )
            """)
            
            # Table: scanned_targets
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scanned_targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    result TEXT,
                    UNIQUE(target, scan_type)
                )
            """)
            
            self.conn.commit()
            logger.info(f"✅ Mission database initialized at {self.db_path}")
            
        except sqlite3.Error as e:
            logger.error(f"❌ Database initialization failed: {e}")
            raise
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")
    
    # --- SUBDOMAIN OPERATIONS ---
    
    def add_subdomain(self, domain: str, subdomain: str) -> bool:
        """Add a subdomain to the database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO subdomains (domain, subdomain) VALUES (?, ?)",
                (domain, subdomain)
            )
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            logger.error(f"Error adding subdomain: {e}")
            return False
    
    def get_subdomains(self, domain: str) -> List[str]:
        """Get all subdomains for a domain"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT subdomain FROM subdomains WHERE domain = ? ORDER BY discovered_at",
                (domain,)
            )
            return [row[0] for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error getting subdomains: {e}")
            return []
    
    # --- ENDPOINT OPERATIONS ---
    
    def add_endpoint(self, url: str, method: str = "GET", status_code: int = None) -> bool:
        """Add an endpoint to the database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """INSERT OR REPLACE INTO endpoints (url, method, status_code, discovered_at) 
                   VALUES (?, ?, ?, CURRENT_TIMESTAMP)""",
                (url, method, status_code)
            )
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error adding endpoint: {e}")
            return False
    
    def get_endpoints(self, limit: int = 100) -> List[Dict]:
        """Get all endpoints"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM endpoints ORDER BY discovered_at DESC LIMIT ?",
                (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error getting endpoints: {e}")
            return []
    
    def mark_endpoint_scanned(self, url: str) -> bool:
        """Mark an endpoint as scanned"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE endpoints SET last_scanned = CURRENT_TIMESTAMP WHERE url = ?",
                (url,)
            )
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error marking endpoint scanned: {e}")
            return False
    
    # --- FINDING OPERATIONS ---
    
    def add_finding(self, type: str, url: str, severity: str, 
                   description: str = "", evidence: str = "") -> int:
        """
        Add a finding to the database
        
        Args:
            type: Type of vulnerability (e.g., 'XSS', 'SQLi', 'IDOR')
            url: URL where vulnerability was found
            severity: Severity level (e.g., 'critical', 'high', 'medium', 'low', 'info')
            description: Description of the finding
            evidence: Evidence/proof of the vulnerability
            
        Returns:
            Finding ID or -1 on error
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """INSERT INTO findings (type, url, severity, description, evidence) 
                   VALUES (?, ?, ?, ?, ?)""",
                (type, url, severity.lower(), description, evidence)
            )
            self.conn.commit()
            logger.info(f"✅ Finding added: {type} at {url} (severity: {severity})")
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error adding finding: {e}")
            return -1
    
    def get_findings(self, severity: str = None, verified: bool = None) -> List[Dict]:
        """
        Get all findings, optionally filtered by severity and verification status
        
        Args:
            severity: Filter by severity level (optional)
            verified: Filter by verification status (optional)
            
        Returns:
            List of findings as dictionaries
        """
        try:
            cursor = self.conn.cursor()
            query = "SELECT * FROM findings WHERE 1=1"
            params = []
            
            if severity:
                query += " AND severity = ?"
                params.append(severity.lower())
            
            if verified is not None:
                query += " AND verified = ?"
                params.append(1 if verified else 0)
            
            query += " ORDER BY discovered_at DESC"
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error getting findings: {e}")
            return []
    
    def verify_finding(self, finding_id: int) -> bool:
        """Mark a finding as verified"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE findings SET verified = 1 WHERE id = ?",
                (finding_id,)
            )
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error verifying finding: {e}")
            return False
    
    # --- SCANNED TARGET OPERATIONS ---
    
    def mark_scanned(self, target: str, scan_type: str, result: str = None) -> bool:
        """
        Mark a target as scanned to avoid duplicate work
        
        Args:
            target: Target URL or domain
            scan_type: Type of scan (e.g., 'subdomain_enum', 'port_scan', 'vuln_scan')
            result: Summary of scan results (optional)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """INSERT OR REPLACE INTO scanned_targets (target, scan_type, scanned_at, result) 
                   VALUES (?, ?, CURRENT_TIMESTAMP, ?)""",
                (target, scan_type, result)
            )
            self.conn.commit()
            logger.info(f"✅ Marked as scanned: {target} ({scan_type})")
            return True
        except sqlite3.Error as e:
            logger.error(f"Error marking target scanned: {e}")
            return False
    
    def is_scanned(self, target: str, scan_type: str = None) -> bool:
        """
        Check if a target has been scanned
        
        Args:
            target: Target URL or domain
            scan_type: Type of scan to check (optional, checks all types if None)
            
        Returns:
            True if target has been scanned, False otherwise
        """
        try:
            cursor = self.conn.cursor()
            
            if scan_type:
                cursor.execute(
                    "SELECT COUNT(*) FROM scanned_targets WHERE target = ? AND scan_type = ?",
                    (target, scan_type)
                )
            else:
                cursor.execute(
                    "SELECT COUNT(*) FROM scanned_targets WHERE target = ?",
                    (target,)
                )
            
            count = cursor.fetchone()[0]
            return count > 0
        except sqlite3.Error as e:
            logger.error(f"Error checking if target scanned: {e}")
            return False
    
    def get_scanned_targets(self, scan_type: str = None) -> List[Dict]:
        """Get all scanned targets, optionally filtered by scan type"""
        try:
            cursor = self.conn.cursor()
            
            if scan_type:
                cursor.execute(
                    "SELECT * FROM scanned_targets WHERE scan_type = ? ORDER BY scanned_at DESC",
                    (scan_type,)
                )
            else:
                cursor.execute(
                    "SELECT * FROM scanned_targets ORDER BY scanned_at DESC"
                )
            
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error getting scanned targets: {e}")
            return []
    
    # --- STATISTICS ---
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        try:
            cursor = self.conn.cursor()
            
            stats = {}
            
            # Count subdomains
            cursor.execute("SELECT COUNT(*) FROM subdomains")
            stats['total_subdomains'] = cursor.fetchone()[0]
            
            # Count endpoints
            cursor.execute("SELECT COUNT(*) FROM endpoints")
            stats['total_endpoints'] = cursor.fetchone()[0]
            
            # Count findings by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count 
                FROM findings 
                GROUP BY severity
            """)
            stats['findings_by_severity'] = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Count total findings
            cursor.execute("SELECT COUNT(*) FROM findings")
            stats['total_findings'] = cursor.fetchone()[0]
            
            # Count verified findings
            cursor.execute("SELECT COUNT(*) FROM findings WHERE verified = 1")
            stats['verified_findings'] = cursor.fetchone()[0]
            
            # Count scanned targets
            cursor.execute("SELECT COUNT(DISTINCT target) FROM scanned_targets")
            stats['total_scanned_targets'] = cursor.fetchone()[0]
            
            return stats
        except sqlite3.Error as e:
            logger.error(f"Error getting statistics: {e}")
            return {}


# Singleton instance
_db_instance = None

def get_database() -> MissionDatabase:
    """Get the singleton database instance"""
    global _db_instance
    if _db_instance is None:
        _db_instance = MissionDatabase()
    return _db_instance
