"""
Target analysis and intelligence gathering
"""

import aiohttp
import asyncio
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

class TargetAnalyzer:
    def __init__(self):
        self.session = None
        
    async def analyze_target(self, target_url: str) -> Dict[str, Any]:
        """Comprehensive target analysis"""
        print(f"🔍 Analyzing target: {target_url}")
        
        analysis = {
            "target": target_url,
            "domain": urlparse(target_url).netloc,
            "technologies": [],
            "headers": {},
            "security_headers": {},
            "server_info": {},
            "accessible_endpoints": []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
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
            async with session.get(url, timeout=10, ssl=False) as response:
                headers = dict(response.headers)
                
                analysis = {
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
        security_headers = {}
        important_headers = [
            'content-security-policy', 'x-frame-options', 'x-content-type-options',
            'strict-transport-security', 'x-xss-protection', 'referrer-policy'
        ]
        
        for header in important_headers:
            if header in headers:
                security_headers[header] = headers[header]
                
        return security_headers
    
    def _extract_server_info(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract server information from headers"""
        server_info = {}
        
        if 'server' in headers:
            server_info['server'] = headers['server']
        if 'x-powered-by' in headers:
            server_info['powered_by'] = headers['x-powered-by']
        if 'x-aspnet-version' in headers:
            server_info['aspnet_version'] = headers['x-aspnet-version']
            
        return server_info
    
    async def _detect_technologies(self, headers: Dict[str, str], url: str) -> List[str]:
        """Detect technologies used by the target"""
        technologies = []
        
        # Detect from headers
        server = headers.get('server', '').lower()
        powered_by = headers.get('x-powered-by', '').lower()
        
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
        if '.php' in url:
            technologies.append('PHP')
        if '.aspx' in url:
            technologies.append('ASP.NET')
        if '.jsp' in url:
            technologies.append('JSP')
            
        return list(set(technologies))  # Remove duplicates
    
    async def _check_common_endpoints(self, session: aiohttp.ClientSession, base_url: str) -> List[str]:
        """Check for common accessible endpoints"""
        common_paths = [
            '/admin', '/login', '/dashboard', '/api', '/robots.txt',
            '/.git', '/backup', '/config', '/phpinfo.php', '/test'
        ]
        
        accessible = []
        
        for path in common_paths:
            test_url = base_url.rstrip('/') + path
            try:
                async with session.get(test_url, timeout=5, ssl=False) as response:
                    if response.status in [200, 301, 302, 403]:
                        accessible.append({
                            "path": path,
                            "url": test_url,
                            "status": response.status
                        })
            except:
                pass
                
        return accessible