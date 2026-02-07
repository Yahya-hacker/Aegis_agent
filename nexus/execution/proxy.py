"""
Nexus v2.0 - HTTP Proxy Layer
=============================

Request interception and modification for:
- Session management
- Request replay
- Traffic analysis
- Man-in-the-middle testing
"""

import asyncio
import aiohttp
import logging
import json
import hashlib
import time
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs

from nexus.config import get_config

logger = logging.getLogger(__name__)


@dataclass
class HTTPRequest:
    """HTTP Request representation."""
    id: str
    method: str
    url: str
    headers: Dict[str, str]
    body: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "cookies": self.cookies,
            "timestamp": self.timestamp,
        }
    
    def to_curl(self) -> str:
        """Convert to cURL command."""
        parts = [f"curl -X {self.method}"]
        
        for key, value in self.headers.items():
            parts.append(f'-H "{key}: {value}"')
        
        if self.body:
            parts.append(f"-d '{self.body}'")
        
        parts.append(f'"{self.url}"')
        
        return " \\\n  ".join(parts)
    
    @property
    def hash(self) -> str:
        """Generate unique hash for deduplication."""
        key = f"{self.method}:{self.url}:{self.body}"
        return hashlib.md5(key.encode()).hexdigest()[:12]


@dataclass
class HTTPResponse:
    """HTTP Response representation."""
    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body_length": len(self.body),
            "elapsed": self.elapsed,
        }


@dataclass
class HTTPTransaction:
    """Complete HTTP transaction (request + response)."""
    request: HTTPRequest
    response: HTTPResponse
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "request": self.request.to_dict(),
            "response": self.response.to_dict(),
        }


class ProxyClient:
    """
    HTTP client with session management.
    
    Features:
    - Cookie jar management
    - Request/response logging
    - Header manipulation
    - Rate limiting
    """
    
    def __init__(self):
        self.config = get_config()
        self._session: Optional[aiohttp.ClientSession] = None
        self._cookies: Dict[str, str] = {}
        self._default_headers: Dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        self._history: List[HTTPTransaction] = []
        self._rate_limit_delay = self.config.execution.rate_limit_delay
        self._last_request_time = 0
        
        # Request counter
        self._request_count = 0
    
    async def _ensure_session(self):
        """Ensure aiohttp session exists."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                cookie_jar=aiohttp.CookieJar(unsafe=True)  # Accept all cookies
            )
    
    async def _rate_limit(self):
        """Apply rate limiting."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._rate_limit_delay:
            await asyncio.sleep(self._rate_limit_delay - elapsed)
        self._last_request_time = time.time()
    
    def set_cookies(self, cookies: Dict[str, str]):
        """Set cookies for session."""
        self._cookies.update(cookies)
    
    def set_header(self, key: str, value: str):
        """Set a default header."""
        self._default_headers[key] = value
    
    def set_auth_token(self, token: str, header: str = "Authorization"):
        """Set authentication token."""
        if not token.startswith("Bearer ") and "bearer" in header.lower():
            token = f"Bearer {token}"
        self._default_headers[header] = token
    
    async def request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str] = None,
        body: str = "",
        json_data: Dict[str, Any] = None,
        cookies: Dict[str, str] = None,
        follow_redirects: bool = True,
    ) -> HTTPTransaction:
        """
        Make an HTTP request.
        
        Args:
            method: HTTP method
            url: Target URL
            headers: Additional headers
            body: Request body
            json_data: JSON body (alternative to body)
            cookies: Additional cookies
            follow_redirects: Follow redirects
        
        Returns:
            HTTPTransaction with request and response
        """
        await self._ensure_session()
        await self._rate_limit()
        
        self._request_count += 1
        
        # Merge headers
        final_headers = {**self._default_headers}
        if headers:
            final_headers.update(headers)
        
        # Merge cookies
        final_cookies = {**self._cookies}
        if cookies:
            final_cookies.update(cookies)
        
        # Handle JSON
        if json_data:
            body = json.dumps(json_data)
            final_headers["Content-Type"] = "application/json"
        
        # Create request record
        request = HTTPRequest(
            id=f"req_{self._request_count:06d}",
            method=method.upper(),
            url=url,
            headers=final_headers,
            body=body,
            cookies=final_cookies,
        )
        
        try:
            start_time = time.time()
            
            async with self._session.request(
                method=method,
                url=url,
                headers=final_headers,
                data=body if body else None,
                cookies=final_cookies,
                allow_redirects=follow_redirects,
                ssl=False,  # Disable SSL verification for testing
            ) as resp:
                response_body = await resp.text()
                elapsed = time.time() - start_time
                
                response = HTTPResponse(
                    status_code=resp.status,
                    headers=dict(resp.headers),
                    body=response_body,
                    elapsed=elapsed,
                )
                
        except Exception as e:
            logger.error(f"❌ Request error: {e}")
            response = HTTPResponse(
                status_code=0,
                headers={},
                body=str(e),
                elapsed=0,
            )
        
        transaction = HTTPTransaction(request=request, response=response)
        self._history.append(transaction)
        
        return transaction
    
    async def get(self, url: str, **kwargs) -> HTTPTransaction:
        """GET request."""
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> HTTPTransaction:
        """POST request."""
        return await self.request("POST", url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> HTTPTransaction:
        """PUT request."""
        return await self.request("PUT", url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> HTTPTransaction:
        """DELETE request."""
        return await self.request("DELETE", url, **kwargs)
    
    async def replay(
        self,
        transaction: HTTPTransaction,
        modifications: Dict[str, Any] = None
    ) -> HTTPTransaction:
        """
        Replay a previous request with optional modifications.
        
        Args:
            transaction: Previous transaction to replay
            modifications: Changes to make
                - headers: Dict[str, str]
                - body: str
                - url_params: Dict[str, str]
        
        Returns:
            New HTTPTransaction
        """
        mods = modifications or {}
        
        url = transaction.request.url
        headers = {**transaction.request.headers}
        body = transaction.request.body
        
        if "headers" in mods:
            headers.update(mods["headers"])
        
        if "body" in mods:
            body = mods["body"]
        
        if "url_params" in mods:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params.update({k: [v] for k, v in mods["url_params"].items()})
            new_query = urlencode(params, doseq=True)
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        
        return await self.request(
            method=transaction.request.method,
            url=url,
            headers=headers,
            body=body,
        )
    
    def get_history(self, limit: int = 100) -> List[HTTPTransaction]:
        """Get request history."""
        return self._history[-limit:]
    
    def find_in_history(
        self,
        url_pattern: str = None,
        method: str = None,
        status_code: int = None
    ) -> List[HTTPTransaction]:
        """Find transactions matching criteria."""
        results = []
        
        for txn in self._history:
            if url_pattern and url_pattern not in txn.request.url:
                continue
            if method and txn.request.method != method.upper():
                continue
            if status_code and txn.response.status_code != status_code:
                continue
            results.append(txn)
        
        return results
    
    async def close(self):
        """Close the session."""
        if self._session:
            await self._session.close()


class AuthenticatedSession:
    """
    Manages authenticated sessions for testing.
    
    Handles:
    - Login/logout
    - Token refresh
    - Session cookies
    - Multi-user testing (for IDOR)
    """
    
    def __init__(self):
        self._sessions: Dict[str, ProxyClient] = {}
        self._credentials: Dict[str, Dict[str, str]] = {}
    
    def add_user(
        self,
        user_id: str,
        credentials: Dict[str, str],
        session: ProxyClient = None
    ):
        """
        Add a user with credentials.
        
        Args:
            user_id: Unique identifier (e.g., "user1", "admin")
            credentials: Login credentials
            session: Optional existing session
        """
        self._credentials[user_id] = credentials
        self._sessions[user_id] = session or ProxyClient()
    
    async def login(
        self,
        user_id: str,
        login_url: str,
        method: str = "POST",
        credential_fields: Dict[str, str] = None
    ) -> bool:
        """
        Login a user.
        
        Args:
            user_id: User to login
            login_url: Login endpoint
            method: HTTP method
            credential_fields: Mapping of form fields to credential keys
        
        Returns:
            True if login successful
        """
        if user_id not in self._credentials:
            logger.error(f"❌ Unknown user: {user_id}")
            return False
        
        session = self._sessions[user_id]
        creds = self._credentials[user_id]
        
        # Map credentials to form fields
        field_map = credential_fields or {"username": "username", "password": "password"}
        body = {field_map.get(k, k): v for k, v in creds.items()}
        
        txn = await session.request(
            method=method,
            url=login_url,
            json_data=body,
        )
        
        success = txn.response.status_code in [200, 302]
        
        if success:
            logger.info(f"✅ Logged in as {user_id}")
        else:
            logger.warning(f"⚠️ Login failed for {user_id}: {txn.response.status_code}")
        
        return success
    
    def get_session(self, user_id: str) -> Optional[ProxyClient]:
        """Get session for a user."""
        return self._sessions.get(user_id)
    
    async def test_idor(
        self,
        endpoint: str,
        user_a: str,
        user_b: str,
        id_param: str = "id"
    ) -> Dict[str, Any]:
        """
        Test for IDOR by comparing responses between users.
        
        Args:
            endpoint: Endpoint with {id} placeholder
            user_a: First user
            user_b: Second user
            id_param: Parameter name for ID
        
        Returns:
            IDOR test result
        """
        session_a = self._sessions.get(user_a)
        session_b = self._sessions.get(user_b)
        
        if not session_a or not session_b:
            return {"error": "Sessions not found"}
        
        # Get user A's resource
        url_a = endpoint.replace("{id}", "1")  # User A's resource
        txn_a = await session_a.get(url_a)
        
        # Try to access with user B
        txn_b = await session_b.get(url_a)
        
        # Compare
        result = {
            "endpoint": endpoint,
            "user_a_status": txn_a.response.status_code,
            "user_b_status": txn_b.response.status_code,
            "vulnerable": False,
        }
        
        # If user B can access user A's resource, IDOR exists
        if txn_b.response.status_code == 200:
            if txn_a.response.body == txn_b.response.body:
                result["vulnerable"] = True
                result["severity"] = "high"
                result["description"] = f"User {user_b} can access {user_a}'s resources"
        
        return result
    
    async def close_all(self):
        """Close all sessions."""
        for session in self._sessions.values():
            await session.close()


# Singleton
_proxy_client: Optional[ProxyClient] = None
_auth_session: Optional[AuthenticatedSession] = None


def get_proxy_client() -> ProxyClient:
    """Get the global proxy client."""
    global _proxy_client
    if _proxy_client is None:
        _proxy_client = ProxyClient()
    return _proxy_client


def get_auth_session() -> AuthenticatedSession:
    """Get the global authenticated session manager."""
    global _auth_session
    if _auth_session is None:
        _auth_session = AuthenticatedSession()
    return _auth_session
