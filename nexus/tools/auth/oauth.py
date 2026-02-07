"""
Nexus v2.0 - OAuth Security Testing
===================================

OAuth 2.0 vulnerability detection.
"""

import asyncio
import logging
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlencode

from nexus.execution.proxy import get_proxy_client

logger = logging.getLogger(__name__)


@dataclass
class OAuthFinding:
    """An OAuth vulnerability finding."""
    endpoint: str
    vulnerability: str
    severity: str
    description: str
    evidence: Dict[str, Any]
    remediation: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "vulnerability": self.vulnerability,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


class OAuthTester:
    """
    OAuth 2.0 security tester.
    
    Vulnerabilities tested:
    1. Open redirect via redirect_uri
    2. Token leakage in URL fragment
    3. Missing state parameter (CSRF)
    4. Authorization code injection
    5. Scope manipulation
    """
    
    def __init__(self):
        self.client = get_proxy_client()
    
    async def test_redirect_uri_bypass(
        self,
        auth_url: str,
        client_id: str,
        valid_redirect: str
    ) -> List[OAuthFinding]:
        """
        Test for redirect_uri validation bypass.
        
        Common bypasses:
        - Subdomain: evil.example.com
        - Path traversal: example.com/../evil.com
        - Fragment: example.com#@evil.com
        - Parameter pollution
        """
        findings = []
        logger.info(f"🔍 Testing redirect_uri bypass")
        
        parsed = urlparse(valid_redirect)
        base_domain = parsed.netloc
        
        # Generate bypass payloads
        bypass_payloads = [
            # Subdomain bypass
            f"https://evil.{base_domain}",
            f"https://{base_domain}.evil.com",
            
            # Path confusion
            f"{valid_redirect}/../../../evil.com",
            f"{valid_redirect}/../../evil.com",
            f"{valid_redirect}@evil.com",
            f"{valid_redirect}%00@evil.com",
            
            # Fragment/parameter bypass
            f"{valid_redirect}#@evil.com",
            f"{valid_redirect}?.evil.com",
            f"{valid_redirect}%23@evil.com",
            
            # URL encoding
            f"{valid_redirect}%252f%252fevil.com",
            
            # Backslash bypass
            f"{valid_redirect}\\evil.com",
            
            # Localhost bypass (for testing environments)
            "http://localhost",
            "http://127.0.0.1",
        ]
        
        for payload in bypass_payloads:
            test_url = f"{auth_url}?client_id={client_id}&redirect_uri={payload}&response_type=code"
            
            response = await self.client.get(test_url, follow_redirects=False)
            
            # Check if redirect was accepted
            if response.response.status_code in [301, 302, 303, 307, 308]:
                location = response.response.headers.get("location", "")
                
                if "evil" in location or "127.0.0.1" in location:
                    findings.append(OAuthFinding(
                        endpoint=auth_url,
                        vulnerability="Open Redirect via redirect_uri",
                        severity="high",
                        description=f"The OAuth endpoint accepts malicious redirect_uri: {payload}",
                        evidence={
                            "payload": payload,
                            "redirect_to": location,
                        },
                        remediation="Implement strict redirect_uri validation with exact string matching",
                    ))
                    logger.info(f"🎯 Redirect bypass found: {payload}")
        
        return findings
    
    async def test_missing_state(
        self,
        auth_url: str,
        client_id: str,
        redirect_uri: str
    ) -> Optional[OAuthFinding]:
        """Test if state parameter is required (CSRF protection)."""
        logger.info("🔍 Testing state parameter requirement")
        
        # Request without state
        test_url = f"{auth_url}?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code"
        
        response = await self.client.get(test_url, follow_redirects=False)
        
        # If redirect happens without state, CSRF is possible
        if response.response.status_code in [301, 302, 303, 307, 308]:
            location = response.response.headers.get("location", "")
            
            if "code=" in location and "state=" not in location:
                return OAuthFinding(
                    endpoint=auth_url,
                    vulnerability="Missing State Parameter (CSRF)",
                    severity="high",
                    description="OAuth flow does not require state parameter, enabling CSRF attacks",
                    evidence={
                        "redirect_url": location,
                    },
                    remediation="Implement and validate state parameter with unique, unpredictable values",
                )
        
        return None
    
    async def test_scope_manipulation(
        self,
        auth_url: str,
        client_id: str,
        redirect_uri: str,
        normal_scope: str = "read"
    ) -> List[OAuthFinding]:
        """Test for scope privilege escalation."""
        findings = []
        logger.info("🔍 Testing scope manipulation")
        
        elevated_scopes = [
            "admin",
            "write",
            "delete",
            "openid profile email",
            "user:read user:write user:admin",
            "*",
            "all",
        ]
        
        for scope in elevated_scopes:
            test_url = f"{auth_url}?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope={scope}"
            
            response = await self.client.get(test_url, follow_redirects=False)
            
            # Check if elevated scope was accepted
            if response.response.status_code in [200, 302]:
                if "error" not in response.response.body.lower():
                    findings.append(OAuthFinding(
                        endpoint=auth_url,
                        vulnerability="Scope Manipulation",
                        severity="high",
                        description=f"Application accepts elevated scope: {scope}",
                        evidence={
                            "scope": scope,
                            "status": response.response.status_code,
                        },
                        remediation="Validate requested scopes against allowed scopes for the client",
                    ))
        
        return findings
    
    async def test_token_in_url(
        self,
        callback_url: str
    ) -> Optional[OAuthFinding]:
        """Check if tokens are exposed in URL (response_type=token)."""
        logger.info("🔍 Testing token exposure in URL")
        
        parsed = urlparse(callback_url)
        
        # Check fragment for token
        if parsed.fragment:
            fragment_params = parse_qs(parsed.fragment)
            
            if "access_token" in fragment_params:
                return OAuthFinding(
                    endpoint=callback_url,
                    vulnerability="Token Exposure in URL Fragment",
                    severity="medium",
                    description="Access token is exposed in URL fragment, susceptible to history/referrer leakage",
                    evidence={
                        "token_present": True,
                        "fragment": parsed.fragment[:50] + "...",
                    },
                    remediation="Use response_type=code instead of token, implement PKCE",
                )
        
        # Check query for token (worse)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            
            if "access_token" in query_params:
                return OAuthFinding(
                    endpoint=callback_url,
                    vulnerability="Token Exposure in URL Query",
                    severity="high",
                    description="Access token is exposed in URL query string, logged in server logs",
                    evidence={
                        "query": parsed.query[:50] + "...",
                    },
                    remediation="Never expose tokens in query strings",
                )
        
        return None
    
    async def test_code_injection(
        self,
        token_endpoint: str,
        client_id: str,
        client_secret: str = None
    ) -> Optional[OAuthFinding]:
        """Test for authorization code injection."""
        logger.info("🔍 Testing authorization code injection")
        
        # Try to exchange a fake code
        fake_codes = [
            "test123",
            "admin",
            "' OR '1'='1",
        ]
        
        for fake_code in fake_codes:
            data = {
                "grant_type": "authorization_code",
                "code": fake_code,
                "client_id": client_id,
            }
            
            if client_secret:
                data["client_secret"] = client_secret
            
            response = await self.client.post(
                token_endpoint,
                json_data=data
            )
            
            # Check for unexpected success or info leakage
            if response.response.status_code == 200:
                return OAuthFinding(
                    endpoint=token_endpoint,
                    vulnerability="Authorization Code Injection",
                    severity="critical",
                    description="Token endpoint accepts invalid authorization codes",
                    evidence={
                        "fake_code": fake_code,
                        "response": response.response.body[:500],
                    },
                    remediation="Validate authorization codes are valid and unused",
                )
        
        return None
    
    async def full_scan(
        self,
        auth_url: str,
        token_url: str,
        client_id: str,
        redirect_uri: str,
        client_secret: str = None
    ) -> List[OAuthFinding]:
        """Run all OAuth tests."""
        findings = []
        
        logger.info(f"🔐 Full OAuth scan starting")
        
        # Run all tests
        redirect_findings = await self.test_redirect_uri_bypass(
            auth_url, client_id, redirect_uri
        )
        findings.extend(redirect_findings)
        
        state_finding = await self.test_missing_state(
            auth_url, client_id, redirect_uri
        )
        if state_finding:
            findings.append(state_finding)
        
        scope_findings = await self.test_scope_manipulation(
            auth_url, client_id, redirect_uri
        )
        findings.extend(scope_findings)
        
        code_finding = await self.test_code_injection(
            token_url, client_id, client_secret
        )
        if code_finding:
            findings.append(code_finding)
        
        logger.info(f"✅ OAuth scan complete: {len(findings)} findings")
        
        return findings


# Quick access
async def scan_oauth(
    auth_url: str,
    token_url: str,
    client_id: str,
    redirect_uri: str
) -> List[OAuthFinding]:
    """Quick OAuth security scan."""
    tester = OAuthTester()
    return await tester.full_scan(auth_url, token_url, client_id, redirect_uri)
