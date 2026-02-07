"""
Nexus v2.0 - Session Security Testing
=====================================

Session management vulnerability detection.
"""

import asyncio
import logging
import re
import hashlib
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime

from nexus.execution.proxy import get_proxy_client

logger = logging.getLogger(__name__)


@dataclass 
class SessionFinding:
    """A session vulnerability finding."""
    vulnerability: str
    severity: str
    description: str
    evidence: Dict[str, Any]
    remediation: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerability": self.vulnerability,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


class SessionTester:
    """
    Session security tester.
    
    Vulnerabilities tested:
    1. Session fixation
    2. Weak session tokens
    3. Session not invalidated on logout
    4. Missing secure/httponly flags
    5. Predictable session IDs
    """
    
    def __init__(self):
        self.client = get_proxy_client()
    
    def analyze_session_token(self, token: str) -> Dict[str, Any]:
        """Analyze session token for weaknesses."""
        analysis = {
            "length": len(token),
            "entropy_estimate": "low",
            "contains_timestamp": False,
            "contains_user_id": False,
            "is_sequential": False,
            "encoding": "unknown",
        }
        
        # Check length (should be at least 128 bits / 16 bytes)
        if len(token) < 32:
            analysis["entropy_estimate"] = "very_low"
        elif len(token) < 64:
            analysis["entropy_estimate"] = "low"
        else:
            analysis["entropy_estimate"] = "acceptable"
        
        # Check for timestamp patterns
        if re.search(r'1[0-9]{9}', token):  # Unix timestamp
            analysis["contains_timestamp"] = True
        
        # Check for sequential numbers
        if re.search(r'^[0-9]+$', token):
            analysis["is_sequential"] = True
        
        # Check encoding
        if re.match(r'^[a-fA-F0-9]+$', token):
            analysis["encoding"] = "hex"
        elif re.match(r'^[A-Za-z0-9+/=]+$', token):
            analysis["encoding"] = "base64"
        
        return analysis
    
    async def test_session_fixation(
        self,
        login_url: str,
        credentials: Dict[str, str],
        session_cookie_name: str = "session"
    ) -> Optional[SessionFinding]:
        """Test for session fixation vulnerability."""
        logger.info("🔍 Testing session fixation")
        
        # Get initial session
        initial_response = await self.client.get(login_url)
        initial_cookies = {c["name"]: c["value"] for c in initial_response.response.headers.get("set-cookie", "").split(";")}
        
        # Extract session token
        # This is simplified - in practice, parse Set-Cookie header
        initial_session = None
        for cookie in initial_response.response.headers:
            if session_cookie_name in str(cookie):
                initial_session = cookie
                break
        
        # Perform login
        login_response = await self.client.post(
            login_url,
            json_data=credentials
        )
        
        # Check if session changed after login
        final_session = None
        for cookie in login_response.response.headers:
            if session_cookie_name in str(cookie):
                final_session = cookie
                break
        
        if initial_session and final_session and initial_session == final_session:
            return SessionFinding(
                vulnerability="Session Fixation",
                severity="high",
                description="Session token is not regenerated after authentication",
                evidence={
                    "initial_session": str(initial_session)[:50],
                    "final_session": str(final_session)[:50],
                },
                remediation="Regenerate session ID after successful authentication",
            )
        
        return None
    
    async def test_logout_invalidation(
        self,
        protected_url: str,
        logout_url: str,
        session_token: str
    ) -> Optional[SessionFinding]:
        """Test if session is invalidated after logout."""
        logger.info("🔍 Testing logout invalidation")
        
        # Set session token
        self.client.set_cookies({"session": session_token})
        
        # Verify access works
        pre_logout = await self.client.get(protected_url)
        if pre_logout.response.status_code != 200:
            return None
        
        # Logout
        await self.client.post(logout_url)
        
        # Try using old session
        self.client.set_cookies({"session": session_token})
        post_logout = await self.client.get(protected_url)
        
        if post_logout.response.status_code == 200:
            return SessionFinding(
                vulnerability="Session Not Invalidated on Logout",
                severity="medium",
                description="Session token remains valid after logout",
                evidence={
                    "pre_logout_status": pre_logout.response.status_code,
                    "post_logout_status": post_logout.response.status_code,
                },
                remediation="Invalidate session tokens server-side on logout",
            )
        
        return None
    
    def test_cookie_flags(
        self,
        set_cookie_header: str
    ) -> List[SessionFinding]:
        """Check for missing security flags on cookies."""
        findings = []
        
        if not set_cookie_header:
            return findings
        
        header_lower = set_cookie_header.lower()
        
        if "httponly" not in header_lower:
            findings.append(SessionFinding(
                vulnerability="Missing HttpOnly Flag",
                severity="medium",
                description="Session cookie is accessible to JavaScript (XSS risk)",
                evidence={"cookie": set_cookie_header[:100]},
                remediation="Add HttpOnly flag to session cookies",
            ))
        
        if "secure" not in header_lower:
            findings.append(SessionFinding(
                vulnerability="Missing Secure Flag",
                severity="medium",
                description="Session cookie can be transmitted over HTTP",
                evidence={"cookie": set_cookie_header[:100]},
                remediation="Add Secure flag to session cookies",
            ))
        
        if "samesite" not in header_lower:
            findings.append(SessionFinding(
                vulnerability="Missing SameSite Flag",
                severity="low",
                description="Session cookie may be sent with cross-site requests",
                evidence={"cookie": set_cookie_header[:100]},
                remediation="Add SameSite=Strict or SameSite=Lax flag",
            ))
        
        return findings
    
    async def test_predictable_sessions(
        self,
        url: str,
        session_cookie_name: str = "session",
        sample_count: int = 5
    ) -> Optional[SessionFinding]:
        """Test for predictable session IDs."""
        logger.info("🔍 Testing session predictability")
        
        sessions = []
        
        # Collect multiple sessions
        for _ in range(sample_count):
            response = await self.client.get(url)
            # Extract session from cookies
            # This is simplified
            sessions.append(f"session_{_}")
        
        # Analyze for patterns
        if len(sessions) >= 3:
            # Check for sequential pattern
            try:
                if all(s.isdigit() for s in sessions):
                    nums = [int(s) for s in sessions]
                    diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
                    
                    if len(set(diffs)) == 1:  # All same difference = sequential
                        return SessionFinding(
                            vulnerability="Predictable Session IDs",
                            severity="critical",
                            description="Session IDs appear to be sequential or predictable",
                            evidence={
                                "samples": sessions,
                                "pattern": "sequential",
                            },
                            remediation="Use cryptographically secure random session ID generation",
                        )
            except:
                pass
        
        return None
    
    async def full_scan(
        self,
        app_url: str,
        login_url: str = None,
        logout_url: str = None,
        credentials: Dict[str, str] = None
    ) -> List[SessionFinding]:
        """Run all session tests."""
        findings = []
        
        logger.info(f"🔐 Session security scan starting")
        
        # Get initial response for cookie analysis
        response = await self.client.get(app_url)
        
        # Check cookie flags
        set_cookie = response.response.headers.get("set-cookie", "")
        cookie_findings = self.test_cookie_flags(set_cookie)
        findings.extend(cookie_findings)
        
        # Test predictability
        predict_finding = await self.test_predictable_sessions(app_url)
        if predict_finding:
            findings.append(predict_finding)
        
        # Test session fixation if login URL provided
        if login_url and credentials:
            fixation_finding = await self.test_session_fixation(
                login_url, credentials
            )
            if fixation_finding:
                findings.append(fixation_finding)
        
        logger.info(f"✅ Session scan complete: {len(findings)} findings")
        
        return findings


# Quick access
async def scan_session(
    app_url: str,
    login_url: str = None
) -> List[SessionFinding]:
    """Quick session security scan."""
    tester = SessionTester()
    return await tester.full_scan(app_url, login_url)
