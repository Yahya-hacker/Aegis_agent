"""
Analyse de cible et collecte de renseignements
Version V8 - Gestion de session persistante avec nettoyage approprié
"""

import aiohttp
import asyncio
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse


class TargetAnalyzer:
    """
    Analyseur de cible avec gestion de session aiohttp persistante
    Supporte le protocole de gestionnaire de contexte asynchrone pour un nettoyage propre
    """
    
    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        """
        Initialiser l'analyseur de cible
        
        Args:
            session: Session aiohttp existante à utiliser. Si None, une nouvelle sera créée.
        """
        self._session = session
        self._owns_session = session is None  # Suivre si nous possédons la session
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Obtenir ou créer la session aiohttp"""
        if self._session is None:
            self._session = aiohttp.ClientSession()
        return self._session
    
    async def close(self) -> None:
        """Fermer la session si nous la possédons"""
        if self._session is not None and self._owns_session:
            await self._session.close()
            self._session = None
    
    async def __aenter__(self) -> 'TargetAnalyzer':
        """Support du gestionnaire de contexte asynchrone"""
        await self._get_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Support du gestionnaire de contexte asynchrone - nettoyage"""
        await self.close()
        
    async def analyze_target(self, target_url: str) -> Dict[str, Any]:
        """Analyse complète de la cible"""
        print(f"🔍 Analyse de la cible: {target_url}")
        
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
            
            # Analyser la cible principale
            main_analysis = await self._analyze_url(session, target_url)
            analysis.update(main_analysis)
            
            # Vérifier les endpoints communs
            common_endpoints = await self._check_common_endpoints(session, target_url)
            analysis["accessible_endpoints"] = common_endpoints
                
        except Exception as e:
            analysis["error"] = f"Échec de l'analyse: {str(e)}"
            
        return analysis
    
    async def _analyze_url(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        """Analyser une seule URL"""
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
            return {"error": f"Échec de l'analyse de {url}: {str(e)}"}
    
    def _extract_security_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extraire les en-têtes liés à la sécurité"""
        security_headers: Dict[str, str] = {}
        important_headers = [
            'content-security-policy', 'x-frame-options', 'x-content-type-options',
            'strict-transport-security', 'x-xss-protection', 'referrer-policy'
        ]
        
        for header in important_headers:
            # Vérifier les deux formats de casse
            if header in headers:
                security_headers[header] = headers[header]
            elif header.lower() in {k.lower() for k in headers}:
                for k, v in headers.items():
                    if k.lower() == header.lower():
                        security_headers[header] = v
                        break
                
        return security_headers
    
    def _extract_server_info(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extraire les informations du serveur à partir des en-têtes"""
        server_info: Dict[str, str] = {}
        
        # Vérifier de manière insensible à la casse
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        if 'server' in headers_lower:
            server_info['server'] = headers_lower['server']
        if 'x-powered-by' in headers_lower:
            server_info['powered_by'] = headers_lower['x-powered-by']
        if 'x-aspnet-version' in headers_lower:
            server_info['aspnet_version'] = headers_lower['x-aspnet-version']
            
        return server_info
    
    async def _detect_technologies(self, headers: Dict[str, str], url: str) -> List[str]:
        """Détecter les technologies utilisées par la cible"""
        technologies: List[str] = []
        
        # Créer une version minuscule des en-têtes
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Détecter à partir des en-têtes
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
            
        # Détecter à partir des patterns d'URL
        url_lower = url.lower()
        if '.php' in url_lower:
            technologies.append('PHP')
        if '.aspx' in url_lower:
            technologies.append('ASP.NET')
        if '.jsp' in url_lower:
            technologies.append('JSP')
            
        return list(set(technologies))  # Supprimer les doublons
    
    async def _check_common_endpoints(self, session: aiohttp.ClientSession, base_url: str) -> List[Dict[str, Any]]:
        """Vérifier les endpoints communs accessibles"""
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