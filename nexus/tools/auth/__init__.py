"""
Nexus v2.0 - Auth Tools
=======================

Authentication and session security tools.
"""

from nexus.tools.auth.jwt_tool import (
    JWTAnalyzer,
    JWTFinding,
    scan_jwt,
)
from nexus.tools.auth.oauth import (
    OAuthTester,
    OAuthFinding,
    scan_oauth,
)
from nexus.tools.auth.session import (
    SessionTester,
    SessionFinding,
    scan_session,
)

__all__ = [
    # JWT
    "JWTAnalyzer",
    "JWTFinding",
    "scan_jwt",
    # OAuth
    "OAuthTester",
    "OAuthFinding",
    "scan_oauth",
    # Session
    "SessionTester",
    "SessionFinding",
    "scan_session",
]
