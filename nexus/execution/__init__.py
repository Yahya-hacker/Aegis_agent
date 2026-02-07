"""
Nexus v2.0 - Execution Layer
============================

Browser automation, OAST, and proxy components.
"""

from nexus.execution.browser import (
    BrowserAutomation,
    PageResult,
    get_browser,
)
from nexus.execution.oast import (
    OASTManager,
    InteractSHClient,
    OASTCallback,
    OASTPayload,
    get_oast_manager,
)
from nexus.execution.proxy import (
    ProxyClient,
    AuthenticatedSession,
    HTTPRequest,
    HTTPResponse,
    HTTPTransaction,
    get_proxy_client,
    get_auth_session,
)

__all__ = [
    # Browser
    "BrowserAutomation",
    "PageResult",
    "get_browser",
    # OAST
    "OASTManager",
    "InteractSHClient",
    "OASTCallback",
    "OASTPayload",
    "get_oast_manager",
    # Proxy
    "ProxyClient",
    "AuthenticatedSession",
    "HTTPRequest",
    "HTTPResponse",
    "HTTPTransaction",
    "get_proxy_client",
    "get_auth_session",
]
