# tools/python_tools.py
import asyncio
import aiohttp
import logging
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import nmap
from typing import Dict, List, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class PythonToolManager:
    """Gère les outils avec des bibliothèques Python (Nmap, Selenium)"""
    
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            logger.error("Nmap n'est pas installé. 'nmap_scan' échouera.")
            self.nm = None
        
        # Options Selenium
        self.selenium_options = Options()
        self.selenium_options.add_argument('--headless')
        self.selenium_options.add_argument('--no-sandbox')
        self.selenium_options.add_argument('--disable-dev-shm-usage')
        self.selenium_options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')

    async def advanced_technology_detection(self, target: str) -> Dict:
        """Détection de technologies avancée (HTTP Headers + Selenium/DOM)."""
        logger.info(f"🔬 Détection de technologie pour {target}")
        tech_findings = {}
        
        # 1. Analyse des en-têtes HTTP
        try:
            async with aiohttp.ClientSession(headers={'User-Agent': 'AegisAI-Scanner'}) as session:
                async with session.get(target, ssl=False, timeout=10) as response:
                    headers = dict(response.headers)
                    if 'server' in headers:
                        tech_findings['server'] = headers['server']
                    if 'x-powered-by' in headers:
                        tech_findings['framework'] = headers['x-powered-by']
                    if 'set-cookie' in headers:
                        tech_findings['cookies'] = headers['set-cookie']
        except Exception as e:
            logger.warning(f"Analyse des en-têtes HTTP échouée: {e}")

        # 2. Analyse du DOM avec Selenium
        try:
            # Exécute Selenium dans un thread séparé pour ne pas bloquer asyncio
            loop = asyncio.get_event_loop()
            page_source = await loop.run_in_executor(None, self._get_page_source, target)
            
            page_source = page_source.lower()
            tech_patterns = {
                'wordpress': ['wp-content', 'wp-includes'],
                'react': ['react-dom', 'data-reactroot'],
                'vue': ['data-v-', 'id="app"'],
                'angular': ['ng-version'],
                'jquery': ['jquery.js', 'jquery.min.js'],
                'bootstrap': ['bootstrap.js', 'bootstrap.css']
            }
            
            detected_js = []
            for tech, patterns in tech_patterns.items():
                if any(pattern in page_source for pattern in patterns):
                    detected_js.append(tech)
            if detected_js:
                tech_findings['javascript_libs'] = detected_js
        except Exception as e:
            logger.warning(f"Analyse Selenium échouée: {e}")
        
        return {"status": "success", "data": tech_findings}

    def _get_page_source(self, target: str) -> str:
        """Fonction synchrone (pour run_in_executor) qui utilise Selenium."""
        driver = None
        try:
            # Utilise webdriver-manager pour gérer le driver
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=self.selenium_options)
            driver.get(target)
            # Attendre un peu que le JS se charge
            driver.implicitly_wait(3)
            return driver.page_source
        finally:
            if driver:
                driver.quit()

    async def nmap_scan(self, target: str, ports: str = "80,443,8080,8443,22,21,3306,5432") -> Dict:
        """Scan Nmap détaillé (librairie python)."""
        if not self.nm:
            return {"status": "error", "error": "Nmap non initialisé"}
            
        domain = urlparse(target).netloc if '://' in target else target
        logger.info(f"🔦 Exécution Nmap (bibliothèque) sur {domain} (Ports: {ports})...")
        
        try:
            # Exécute Nmap dans un thread séparé
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self.nm.scan, domain, ports, '-sV -sS -T4')
            
            findings = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    lports = self.nm[host][proto].keys()
                    for port in lports:
                        service = self.nm[host][proto][port]
                        findings.append({
                            "port": port,
                            "protocol": proto,
                            "state": service.get('state'),
                            "service_name": service.get('name', 'unknown'),
                            "product": service.get('product', ''),
                            "version": service.get('version', '')
                        })
            return {"status": "success", "data": findings}
        except Exception as e:
            logger.error(f"❌ Scan Nmap échoué: {e}")
            return {"status": "error", "error": str(e)}