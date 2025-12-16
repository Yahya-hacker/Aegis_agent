"""
Mission Database Manager for Aegis AI
Provides persistent storage for mission data to prevent duplicate work

This module uses aiosqlite for fully non-blocking async database operations,
preventing the "Brain Freeze" issue where synchronous sqlite3 would block the
entire asyncio event loop during database operations.
"""

import aiosqlite
import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class AsyncMissionDatabase:
    """
    Async SQLite database manager for mission tracking.
    
    Uses aiosqlite for non-blocking database operations that work seamlessly
    with asyncio event loops, preventing blocking of Keep-Alive signals,
    UI updates, and LLM streaming.
    """
    
    def __init__(self, db_path: str = "data/mission.db"):
        """Initialize database configuration (actual connection is async)"""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True, parents=True)
        self._db: Optional[aiosqlite.Connection] = None
        self._initialized = False
        self._lock = asyncio.Lock()
    
    async def initialize(self) -> None:
        """Initialize database connection and create tables if they don't exist"""
        if self._initialized:
            return
            
        async with self._lock:
            if self._initialized:
                return
                
            try:
                self._db = await aiosqlite.connect(str(self.db_path))
                self._db.row_factory = aiosqlite.Row
                
                # Enable WAL mode for better concurrency
                await self._db.execute("PRAGMA journal_mode=WAL")
                await self._db.execute("PRAGMA synchronous=NORMAL")
                
                # Table: subdomains
                await self._db.execute("""
                    CREATE TABLE IF NOT EXISTS subdomains (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL,
                        subdomain TEXT NOT NULL,
                        discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(domain, subdomain)
                    )
                """)
                
                # Table: endpoints
                await self._db.execute("""
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
                await self._db.execute("""
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
                await self._db.execute("""
                    CREATE TABLE IF NOT EXISTS scanned_targets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target TEXT NOT NULL,
                        scan_type TEXT NOT NULL,
                        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        result TEXT,
                        UNIQUE(target, scan_type)
                    )
                """)
                
                await self._db.commit()
                self._initialized = True
                logger.info(f"✅ Async mission database initialized at {self.db_path}")
                
            except aiosqlite.Error as e:
                logger.error(f"❌ Database initialization failed: {e}")
                raise
    
    async def _ensure_initialized(self) -> None:
        """Ensure the database is initialized before any operation"""
        if not self._initialized:
            await self.initialize()
    
    async def close(self) -> None:
        """Close database connection safely"""
        if self._db:
            try:
                await self._db.commit()
                await self._db.close()
                logger.info("Database connection closed successfully")
            except aiosqlite.Error as e:
                logger.error(f"Error closing database connection: {e}")
            finally:
                self._db = None
                self._initialized = False
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit with automatic cleanup"""
        await self.close()
        return False
    
    # --- SUBDOMAIN OPERATIONS ---
    
    async def add_subdomain(self, domain: str, subdomain: str) -> bool:
        """Add a subdomain to the database"""
        await self._ensure_initialized()
        try:
            cursor = await self._db.execute(
                "INSERT OR IGNORE INTO subdomains (domain, subdomain) VALUES (?, ?)",
                (domain, subdomain)
            )
            await self._db.commit()
            return cursor.rowcount > 0
        except aiosqlite.Error as e:
            logger.error(f"Error adding subdomain: {e}")
            return False
    
    async def get_subdomains(self, domain: str) -> List[str]:
        """Get all subdomains for a domain"""
        await self._ensure_initialized()
        try:
            cursor = await self._db.execute(
                "SELECT subdomain FROM subdomains WHERE domain = ? ORDER BY discovered_at",
                (domain,)
            )
            rows = await cursor.fetchall()
            return [row[0] for row in rows]
        except aiosqlite.Error as e:
            logger.error(f"Error getting subdomains: {e}")
            return []
    
    # --- ENDPOINT OPERATIONS ---
    
    async def add_endpoint(self, url: str, method: str = "GET", status_code: int = None) -> bool:
        """Add an endpoint to the database"""
        await self._ensure_initialized()
        try:
            await self._db.execute(
                """INSERT OR REPLACE INTO endpoints (url, method, status_code, discovered_at) 
                   VALUES (?, ?, ?, CURRENT_TIMESTAMP)""",
                (url, method, status_code)
            )
            await self._db.commit()
            return True
        except aiosqlite.Error as e:
            logger.error(f"Error adding endpoint: {e}")
            return False
    
    async def get_endpoints(self, limit: int = 100) -> List[Dict]:
        """Get all endpoints"""
        await self._ensure_initialized()
        try:
            cursor = await self._db.execute(
                "SELECT * FROM endpoints ORDER BY discovered_at DESC LIMIT ?",
                (limit,)
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
        except aiosqlite.Error as e:
            logger.error(f"Error getting endpoints: {e}")
            return []
    
    async def mark_endpoint_scanned(self, url: str) -> bool:
        """Mark an endpoint as scanned"""
        await self._ensure_initialized()
        try:
            await self._db.execute(
                "UPDATE endpoints SET last_scanned = CURRENT_TIMESTAMP WHERE url = ?",
                (url,)
            )
            await self._db.commit()
            return True
        except aiosqlite.Error as e:
            logger.error(f"Error marking endpoint scanned: {e}")
            return False
    
    # --- FINDING OPERATIONS ---
    
    async def add_finding(self, type: str, url: str, severity: str, 
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
        await self._ensure_initialized()
        try:
            cursor = await self._db.execute(
                """INSERT INTO findings (type, url, severity, description, evidence) 
                   VALUES (?, ?, ?, ?, ?)""",
                (type, url, severity.lower(), description, evidence)
            )
            await self._db.commit()
            logger.info(f"✅ Finding added: {type} at {url} (severity: {severity})")
            return cursor.lastrowid
        except aiosqlite.Error as e:
            logger.error(f"Error adding finding: {e}")
            return -1
    
    async def get_findings(self, severity: str = None, verified: bool = None) -> List[Dict]:
        """
        Get all findings, optionally filtered by severity and verification status
        
        Args:
            severity: Filter by severity level (optional)
            verified: Filter by verification status (optional)
            
        Returns:
            List of findings as dictionaries
        """
        await self._ensure_initialized()
        try:
            query = "SELECT * FROM findings WHERE 1=1"
            params = []
            
            if severity:
                query += " AND severity = ?"
                params.append(severity.lower())
            
            if verified is not None:
                query += " AND verified = ?"
                params.append(1 if verified else 0)
            
            query += " ORDER BY discovered_at DESC"
            
            cursor = await self._db.execute(query, params)
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
        except aiosqlite.Error as e:
            logger.error(f"Error getting findings: {e}")
            return []
    
    async def verify_finding(self, finding_id: int) -> bool:
        """Mark a finding as verified"""
        await self._ensure_initialized()
        try:
            await self._db.execute(
                "UPDATE findings SET verified = 1 WHERE id = ?",
                (finding_id,)
            )
            await self._db.commit()
            return True
        except aiosqlite.Error as e:
            logger.error(f"Error verifying finding: {e}")
            return False
    
    # --- SCANNED TARGET OPERATIONS ---
    
    async def mark_scanned(self, target: str, scan_type: str, result: str = None) -> bool:
        """
        Mark a target as scanned to avoid duplicate work
        
        Args:
            target: Target URL or domain
            scan_type: Type of scan (e.g., 'subdomain_enum', 'port_scan', 'vuln_scan')
            result: Summary of scan results (optional)
            
        Returns:
            True if successful, False otherwise
        """
        await self._ensure_initialized()
        try:
            await self._db.execute(
                """INSERT OR REPLACE INTO scanned_targets (target, scan_type, scanned_at, result) 
                   VALUES (?, ?, CURRENT_TIMESTAMP, ?)""",
                (target, scan_type, result)
            )
            await self._db.commit()
            logger.info(f"✅ Marked as scanned: {target} ({scan_type})")
            return True
        except aiosqlite.Error as e:
            logger.error(f"Error marking target scanned: {e}")
            return False
    
    async def is_scanned(self, target: str, scan_type: str = None) -> bool:
        """
        Check if a target has been scanned
        
        Args:
            target: Target URL or domain
            scan_type: Type of scan to check (optional, checks all types if None)
            
        Returns:
            True if target has been scanned, False otherwise
        """
        await self._ensure_initialized()
        try:
            if scan_type:
                cursor = await self._db.execute(
                    "SELECT COUNT(*) FROM scanned_targets WHERE target = ? AND scan_type = ?",
                    (target, scan_type)
                )
            else:
                cursor = await self._db.execute(
                    "SELECT COUNT(*) FROM scanned_targets WHERE target = ?",
                    (target,)
                )
            
            row = await cursor.fetchone()
            return row[0] > 0
        except aiosqlite.Error as e:
            logger.error(f"Error checking if target scanned: {e}")
            return False
    
    async def get_scanned_targets(self, scan_type: str = None) -> List[Dict]:
        """Get all scanned targets, optionally filtered by scan type"""
        await self._ensure_initialized()
        try:
            if scan_type:
                cursor = await self._db.execute(
                    "SELECT * FROM scanned_targets WHERE scan_type = ? ORDER BY scanned_at DESC",
                    (scan_type,)
                )
            else:
                cursor = await self._db.execute(
                    "SELECT * FROM scanned_targets ORDER BY scanned_at DESC"
                )
            
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
        except aiosqlite.Error as e:
            logger.error(f"Error getting scanned targets: {e}")
            return []
    
    # --- STATISTICS ---
    
    async def get_statistics(self) -> Dict:
        """Get database statistics"""
        await self._ensure_initialized()
        try:
            stats = {}
            
            # Count subdomains
            cursor = await self._db.execute("SELECT COUNT(*) FROM subdomains")
            row = await cursor.fetchone()
            stats['total_subdomains'] = row[0]
            
            # Count endpoints
            cursor = await self._db.execute("SELECT COUNT(*) FROM endpoints")
            row = await cursor.fetchone()
            stats['total_endpoints'] = row[0]
            
            # Count findings by severity
            cursor = await self._db.execute("""
                SELECT severity, COUNT(*) as count 
                FROM findings 
                GROUP BY severity
            """)
            rows = await cursor.fetchall()
            stats['findings_by_severity'] = {row[0]: row[1] for row in rows}
            
            # Count total findings
            cursor = await self._db.execute("SELECT COUNT(*) FROM findings")
            row = await cursor.fetchone()
            stats['total_findings'] = row[0]
            
            # Count verified findings
            cursor = await self._db.execute("SELECT COUNT(*) FROM findings WHERE verified = 1")
            row = await cursor.fetchone()
            stats['verified_findings'] = row[0]
            
            # Count scanned targets
            cursor = await self._db.execute("SELECT COUNT(DISTINCT target) FROM scanned_targets")
            row = await cursor.fetchone()
            stats['total_scanned_targets'] = row[0]
            
            return stats
        except aiosqlite.Error as e:
            logger.error(f"Error getting statistics: {e}")
            return {}


# Singleton instance for async database
_async_db_instance: Optional[AsyncMissionDatabase] = None
_async_db_lock = asyncio.Lock()


async def get_async_database() -> AsyncMissionDatabase:
    """Get the singleton async database instance"""
    global _async_db_instance
    if _async_db_instance is None:
        async with _async_db_lock:
            if _async_db_instance is None:
                _async_db_instance = AsyncMissionDatabase()
                await _async_db_instance.initialize()
    return _async_db_instance


# Backwards-compatible synchronous wrapper for gradual migration
class MissionDatabase:
    """
    Synchronous wrapper around AsyncMissionDatabase for backwards compatibility.
    
    This class provides synchronous methods that internally use the async database,
    allowing gradual migration of existing code. New code should use
    get_async_database() and await the async methods directly.
    
    Note: This wrapper runs async operations in the current event loop if available,
    or creates a new one. This may cause issues if called from within an existing
    async context - prefer using get_async_database() in async code.
    """
    
    def __init__(self, db_path: str = "data/mission.db"):
        """Initialize the sync wrapper"""
        self._async_db = AsyncMissionDatabase(db_path)
        self._initialized = False
    
    def _run_sync(self, coro):
        """Run an async coroutine synchronously"""
        try:
            loop = asyncio.get_running_loop()
            # We're in an async context - create a task
            # This is not ideal but maintains backwards compatibility
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        except RuntimeError:
            # No running loop - safe to use asyncio.run
            return asyncio.run(coro)
    
    def _ensure_initialized(self):
        """Ensure the database is initialized"""
        if not self._initialized:
            self._run_sync(self._async_db.initialize())
            self._initialized = True
    
    def close(self):
        """Close database connection"""
        if self._initialized:
            self._run_sync(self._async_db.close())
            self._initialized = False
    
    def __enter__(self):
        """Context manager entry"""
        self._ensure_initialized()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
        return False
    
    def add_subdomain(self, domain: str, subdomain: str) -> bool:
        """Add a subdomain to the database"""
        self._ensure_initialized()
        return self._run_sync(self._async_db.add_subdomain(domain, subdomain))
    
    def get_subdomains(self, domain: str) -> List[str]:
        """Get all subdomains for a domain"""
        self._ensure_initialized()
        return self._run_sync(self._async_db.get_subdomains(domain))
    
    def add_endpoint(self, url: str, method: str = "GET", status_code: int = None) -> bool:
        """Add an endpoint to the database"""
        self._ensure_initialized()
        return self._run_sync(self._async_db.add_endpoint(url, method, status_code))
    
    def get_endpoints(self, limit: int = 100) -> List[Dict]:
        """Get all endpoints"""
        self._ensure_initialized()
        return self._run_sync(self._async_db.get_endpoints(limit))
    
    def mark_endpoint_scanned(self, url: str) -> bool:
        """Mark an endpoint as scanned"""
        self._ensure_initialized()
        return self._run_sync(self._async_db.mark_endpoint_scanned(url))
    
    def add_finding(self, type: str, url: str, severity: str, 
                   description: str = "", evidence: str = "") -> int:
        """Add a finding to the database"""
        self._ensure_initialized()
        return self._run_sync(self._async_db.add_finding(type, url, severity, description, evidence))
    
    def get_findings(self, severity: str = None, verified: bool = None) -> List[Dict]:
        """Get all findings"""
        self._ensure_initialized()
        return self._run_sync(self._async_db.get_findings(severity, verified))
    
    def verify_finding(self, finding_id: int) -> bool:
        """Mark a finding as verified"""
        self._ensure_initialized()
        return self._run_sync(self._async_db.verify_finding(finding_id))
    
    def mark_scanned(self, target: str, scan_type: str, result: str = None) -> bool:
        """Mark a target as scanned"""
        self._ensure_initialized()
        return self._run_sync(self._async_db.mark_scanned(target, scan_type, result))
    
    def is_scanned(self, target: str, scan_type: str = None) -> bool:
        """Check if a target has been scanned"""
        self._ensure_initialized()
        return self._run_sync(self._async_db.is_scanned(target, scan_type))
    
    def get_scanned_targets(self, scan_type: str = None) -> List[Dict]:
        """Get all scanned targets"""
        self._ensure_initialized()
        return self._run_sync(self._async_db.get_scanned_targets(scan_type))
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        self._ensure_initialized()
        return self._run_sync(self._async_db.get_statistics())


# Singleton for backwards compatible sync interface
_sync_db_instance: Optional[MissionDatabase] = None


def get_database() -> MissionDatabase:
    """
    Get the singleton database instance (synchronous wrapper).
    
    For new async code, prefer using:
        db = await get_async_database()
        await db.some_method()
    """
    global _sync_db_instance
    if _sync_db_instance is None:
        _sync_db_instance = MissionDatabase()
    return _sync_db_instance
