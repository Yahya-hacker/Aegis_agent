"""
Target analysis and intelligence gathering
Version 8.0 - Persistent session management with proper cleanup
"""

import aiohttp
import asyncio
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse


class TargetAnalyzer:
    """
    Target analyzer with persistent aiohttp session management
    Supports async context manager protocol for clean cleanup
    """
    
    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        """
        Initialize the target analyzer
        
        Args:
            session: Existing aiohttp session to use. If None, a new one will be created.
        """
        self._session = session
        self._owns_session = session is None  # Track if we own the session
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self._session is None:
            self._session = aiohttp.ClientSession()
        return self._session
    
    async def close(self) -> None:
        """Close the session if we own it"""
        if self._session is not None and self._owns_session:
            await self._session.close()
            self._session = None
    
    async def __aenter__(self) -> 'TargetAnalyzer':
        """Async context manager support"""
        await self._get_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager support - cleanup"""
        await self.close()
        
    async def analyze_target(self, target_url: str) -> Dict[str, Any]:
        """Complete target analysis"""
        print(f"🔍 Analyzing target: {target_url}")
        
        analysis: Dict[str, Any] = {
            "target": target_url,
            "domain": urlparse(target_url).netloc,
            "technologies": [],
            "headers": {},
            "security_headers": {},
            "server_info": {},
            "accessible_endpoints": []
        }
        
        try:
            session = await self._get_session()
            
            # Analyze main target
            main_analysis = await self._analyze_url(session, target_url)
            analysis.update(main_analysis)
            
            # Check common endpoints
            common_endpoints = await self._check_common_endpoints(session, target_url)
            analysis["accessible_endpoints"] = common_endpoints
                
        except Exception as e:
            analysis["error"] = f"Analysis failed: {str(e)}"
            
        return analysis
    
    async def _analyze_url(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        """Analyze a single URL"""
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with session.get(url, timeout=timeout, ssl=False) as response:
                headers = dict(response.headers)
                
                analysis: Dict[str, Any] = {
                    "status_code": response.status,
                    "headers": headers,
                    "security_headers": self._extract_security_headers(headers),
                    "server_info": self._extract_server_info(headers),
                    "technologies": await self._detect_technologies(headers, url)
                }
                
                return analysis
                
        except Exception as e:
            return {"error": f"Failed to analyze {url}: {str(e)}"}
    
    def _extract_security_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract security-related headers"""
        security_headers: Dict[str, str] = {}
        important_headers = [
            'content-security-policy', 'x-frame-options', 'x-content-type-options',
            'strict-transport-security', 'x-xss-protection', 'referrer-policy'
        ]
        
        # Create dictionary with lowercase keys once
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header in important_headers:
            if header in headers_lower:
                security_headers[header] = headers_lower[header]
                
        return security_headers
    
    def _extract_server_info(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract server information from headers"""
        server_info: Dict[str, str] = {}
        
        # Check case-insensitively
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        if 'server' in headers_lower:
            server_info['server'] = headers_lower['server']
        if 'x-powered-by' in headers_lower:
            server_info['powered_by'] = headers_lower['x-powered-by']
        if 'x-aspnet-version' in headers_lower:
            server_info['aspnet_version'] = headers_lower['x-aspnet-version']
            
        return server_info
    
    async def _detect_technologies(self, headers: Dict[str, str], url: str) -> List[str]:
        """Detect technologies used by the target"""
        technologies: List[str] = []
        
        # Create lowercase version of headers
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Detect from headers
        server = headers_lower.get('server', '')
        powered_by = headers_lower.get('x-powered-by', '')
        
        if 'apache' in server:
            technologies.append('Apache')
        if 'nginx' in server:
            technologies.append('Nginx')
        if 'iis' in server:
            technologies.append('IIS')
        if 'php' in powered_by:
            technologies.append('PHP')
        if 'asp.net' in powered_by:
            technologies.append('ASP.NET')
            
        # Detect from URL patterns
        url_lower = url.lower()
        if '.php' in url_lower:
            technologies.append('PHP')
        if '.aspx' in url_lower:
            technologies.append('ASP.NET')
        if '.jsp' in url_lower:
            technologies.append('JSP')
            
        return list(set(technologies))  # Remove duplicates
    
    async def _check_common_endpoints(self, session: aiohttp.ClientSession, base_url: str) -> List[Dict[str, Any]]:
        """Check accessible common endpoints"""
        common_paths = [
            '/admin', '/login', '/dashboard', '/api', '/robots.txt',
            '/.git', '/backup', '/config', '/phpinfo.php', '/test'
        ]
        
        accessible: List[Dict[str, Any]] = []
        timeout = aiohttp.ClientTimeout(total=5)
        
        for path in common_paths:
            test_url = base_url.rstrip('/') + path
            try:
                async with session.get(test_url, timeout=timeout, ssl=False) as response:
                    if response.status in [200, 301, 302, 403]:
                        accessible.append({
                            "path": path,
                            "url": test_url,
                            "status": response.status
                        })
            except Exception:
                pass
                
        return accessible