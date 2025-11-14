# tools/python_tools.py
# --- VERSION ENHANCED - With Stealth & OOB Detection ---

import asyncio
import aiohttp
import logging
import random
import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
import nmap
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from utils.helpers import AegisHelpers

logger = logging.getLogger(__name__)

class PythonToolManager:
    """Gère les outils avec des bibliothèques Python (Nmap, Selenium) + Stealth & OOB"""
    
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            logger.error("Nmap n'est pas installé. 'nmap_scan' échouera.")
            self.nm = None
        
        # Options Selenium with stealth
        self.selenium_options = Options()
        self.selenium_options.add_argument('--headless')
        self.selenium_options.add_argument('--no-sandbox')
        self.selenium_options.add_argument('--disable-dev-shm-usage')
        # Use random User-Agent for Selenium
        self.selenium_options.add_argument(f'user-agent={AegisHelpers.get_random_user_agent()}')
        
        # TASK 2: OOB detection storage
        self.oob_payloads = {}  # {payload_id: {url: str, created_at: timestamp}}

    def _get_selenium_driver(self):
        """Initialise et retourne un driver Selenium."""
        service = Service(ChromeDriverManager().install())
        return webdriver.Chrome(service=service, options=self.selenium_options)

    async def advanced_technology_detection(self, target: str) -> Dict:
        """Advanced technology detection with stealth features + session injection"""
        logger.info(f"🔬 Détection de technologie pour {target}")
        
        # TASK 4: Apply jitter before request
        await AegisHelpers.apply_jitter()
        
        tech_findings = {}
        try:
            # TASK 4: Use stealth headers and random proxy
            headers = AegisHelpers.get_stealth_headers()
            proxy = AegisHelpers.get_random_proxy()
            
            # TASK 1: Inject session data
            headers, cookies = self._inject_session_data(headers)
            
            connector = None
            if proxy:
                logger.info(f"🔒 Using proxy: {proxy}")
                connector = aiohttp.TCPConnector()
            
            async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
                kwargs = {'ssl': False, 'timeout': 10, 'cookies': cookies}
                if proxy:
                    kwargs['proxy'] = proxy
                
                async with session.get(target, **kwargs) as response:
                    headers = dict(response.headers)
                    if 'server' in headers: tech_findings['server'] = headers['server']
                    if 'x-powered-by' in headers: tech_findings['framework'] = headers['x-powered-by']
                    if 'set-cookie' in headers: tech_findings['cookies'] = headers['set-cookie']
        except Exception as e:
            logger.warning(f"Analyse des en-têtes HTTP échouée: {e}")
        
        try:
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
        driver = None
        try:
            driver = self._get_selenium_driver()
            driver.get(target)
            driver.implicitly_wait(3)
            return driver.page_source
        finally:
            if driver:
                driver.quit()

    async def nmap_scan(self, target: str, ports: str = "80,443,8080,8443,22,21,3306,5432") -> Dict:
        # ... (Pas de changement ici, fonction existante) ...
        if not self.nm:
            return {"status": "error", "error": "Nmap non initialisé"}
        domain = urlparse(target).netloc if '://' in target else target
        logger.info(f"🔦 Exécution Nmap (bibliothèque) sur {domain} (Ports: {ports})...")
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self.nm.scan, domain, ports, '-sV -sS -T4')
            findings = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    lports = self.nm[host][proto].keys()
                    for port in lports:
                        service = self.nm[host][proto][port]
                        findings.append({"port": port, "protocol": proto, "state": service.get('state'), "service_name": service.get('name', 'unknown'), "product": service.get('product', ''), "version": service.get('version', '')})
            return {"status": "success", "data": findings}
        except Exception as e:
            logger.error(f"❌ Scan Nmap échoué: {e}")
            return {"status": "error", "error": str(e)}

    # --- NOUVELLES FONCTIONS SOPHISTIQUÉES ---
    
    def _inject_session_data(self, headers: Dict, cookies: Dict = None) -> tuple:
        """
        TASK 1: Inject session cookies and headers into requests
        
        Args:
            headers: Base headers dictionary
            cookies: Optional cookies dictionary to update
            
        Returns:
            Tuple of (updated_headers, cookies_dict)
        """
        session_data = self._load_session_data()
        
        if not session_data:
            return headers, cookies or {}
        
        logger.info("🔐 Injecting authenticated session data into request")
        
        # Merge session headers
        if 'headers' in session_data:
            headers.update(session_data['headers'])
        
        # Prepare cookies
        cookie_dict = cookies or {}
        if 'cookies' in session_data:
            for cookie in session_data['cookies']:
                cookie_dict[cookie['name']] = cookie['value']
        
        return headers, cookie_dict

    async def fetch_url(self, target_url: str) -> Dict:
        """
        Récupère une URL spécifique avec stealth features + session injection
        """
        logger.info(f"🔗 Fetching URL: {target_url}")
        
        # TASK 4: Apply jitter before request
        await AegisHelpers.apply_jitter()
        
        try:
            # TASK 4: Use stealth headers and random proxy
            headers = AegisHelpers.get_stealth_headers()
            proxy = AegisHelpers.get_random_proxy()
            
            # TASK 1: Inject session data
            headers, cookies = self._inject_session_data(headers)
            
            connector = None
            if proxy:
                logger.info(f"🔒 Using proxy: {proxy}")
                connector = aiohttp.TCPConnector()
            
            async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
                kwargs = {'ssl': False, 'timeout': 10, 'cookies': cookies}
                if proxy:
                    kwargs['proxy'] = proxy
                
                async with session.get(target_url, **kwargs) as response:
                    content = await response.text()
                    return {
                        "status": "success",
                        "data": {
                            "url": target_url,
                            "status_code": response.status,
                            "content_length": len(content),
                            "content_preview": content[:200]
                        }
                    }
        except Exception as e:
            logger.warning(f"Échec du fetch de l'URL {target_url}: {e}")
            return {"status": "error", "error": str(e)}

    async def discover_interactables(self, target_url: str) -> Dict:
        """
        Utilise Selenium pour trouver tous les éléments interactifs (formulaires, champs, boutons).
        C'est "l'œil" de l'IA pour l'analyse de la logique métier.
        """
        logger.info(f"👀 Découverte des interactions sur {target_url} avec Selenium...")
        try:
            loop = asyncio.get_event_loop()
            interactables = await loop.run_in_executor(None, self._discover_interactables_sync, target_url)
            return {"status": "success", "data": interactables}
        except Exception as e:
            logger.error(f"❌ Découverte Selenium échouée: {e}")
            return {"status": "error", "error": str(e)}

    def _discover_interactables_sync(self, target_url: str) -> Dict:
        """Fonction Selenium synchrone pour la découverte."""
        driver = None
        try:
            driver = self._get_selenium_driver()
            driver.get(target_url)
            driver.implicitly_wait(2)
            
            forms = []
            for form in driver.find_elements(By.TAG_NAME, "form"):
                form_data = {
                    "id": form.get_attribute("id"),
                    "action": form.get_attribute("action"),
                    "method": form.get_attribute("method"),
                    "inputs": []
                }
                for inp in form.find_elements(By.TAG_NAME, "input"):
                    form_data["inputs"].append({
                        "name": inp.get_attribute("name"),
                        "type": inp.get_attribute("type"),
                        "id": inp.get_attribute("id")
                    })
                forms.append(form_data)
            
            links = []
            for link in driver.find_elements(By.TAG_NAME, "a"):
                href = link.get_attribute("href")
                if href and href.startswith("http"):
                    links.append(href)
            
            return {"forms": forms, "links": list(set(links[:20]))} # Limite à 20 liens
        finally:
            if driver:
                driver.quit()

    async def test_form_payload(self, target_url: str, form_identifier: str, input_payloads: Dict[str, str]) -> Dict:
        """
        Utilise Selenium pour soumettre un formulaire avec des payloads spécifiques.
        L'IA doit fournir les payloads (ex: {'username': '<script>alert(1)</script>'})
        """
        logger.info(f"💉 Test de payload sur formulaire {form_identifier} à {target_url}...")
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, self._test_form_payload_sync, target_url, form_identifier, input_payloads)
            return {"status": "success", "data": result}
        except Exception as e:
            logger.error(f"❌ Test de formulaire Selenium échoué: {e}")
            return {"status": "error", "error": str(e)}

    def _test_form_payload_sync(self, target_url: str, form_identifier: str, input_payloads: Dict[str, str]) -> Dict:
        """Fonction Selenium synchrone pour le test de formulaire."""
        driver = None
        try:
            driver = self._get_selenium_driver()
            driver.get(target_url)
            driver.implicitly_wait(2)
            
            # Trouver le formulaire (par ID ou XPath)
            if form_identifier.startswith("//"):
                form = driver.find_element(By.XPATH, form_identifier)
            else:
                form = driver.find_element(By.ID, form_identifier)
            
            if not form:
                return {"submitted": False, "error": "Formulaire non trouvé"}

            # Remplir les champs
            for name, payload in input_payloads.items():
                try:
                    input_field = form.find_element(By.NAME, name)
                    input_field.send_keys(payload)
                except Exception:
                    logger.warning(f"Champ '{name}' non trouvé dans le formulaire {form_identifier}")
            
            form.submit()
            
            # Vérifier s'il y a une alerte (pour XSS)
            try:
                alert = driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                return {"submitted": True, "result": "alert_popped", "alert_text": alert_text}
            except Exception:
                # Pas d'alerte, c'est normal pour SQLi
                pass

            # Renvoyer l'URL et un aperçu de la page après soumission
            return {
                "submitted": True,
                "result": "form_submitted",
                "final_url": driver.current_url,
                "final_page_preview": driver.page_source[:200]
            }
        finally:
            if driver:
                driver.quit()
    
    # --- TASK 2: OUT-OF-BAND (OOB) DETECTION FOR BLIND VULNERABILITIES ---
    
    async def generate_oob_payload(self, payload_type: str = "http") -> Dict:
        """
        TASK 2: Generate an out-of-band payload for detecting blind vulnerabilities
        
        This simulates interactsh-like functionality for detecting:
        - Blind RCE
        - Blind SSRF
        - Blind XXE
        - DNS exfiltration
        
        Args:
            payload_type: Type of OOB payload (http, dns, etc.)
        
        Returns:
            Dictionary with payload ID and URL to inject
        """
        import time
        import uuid
        
        logger.info(f"👁️ Generating OOB payload (type: {payload_type})...")
        
        # Generate unique identifier
        payload_id = str(uuid.uuid4())[:8]
        timestamp = int(time.time())
        
        # In production, this would use interactsh or similar service
        # For now, we simulate with a placeholder that could be replaced with real service
        # You would integrate with: https://github.com/projectdiscovery/interactsh
        
        # Simulated interactsh-like URL (in production, use real interactsh API)
        unique_subdomain = f"{payload_id}-{timestamp}"
        oob_url = f"http://{unique_subdomain}.oast.fun"  # oast.fun is a real interactsh instance
        
        # Store the payload for later checking
        self.oob_payloads[payload_id] = {
            "url": oob_url,
            "created_at": timestamp,
            "type": payload_type,
            "interactions": []
        }
        
        # Generate different payload formats based on type
        payloads = {
            "http": oob_url,
            "dns": unique_subdomain + ".oast.fun",
            "curl": f"curl {oob_url}",
            "wget": f"wget {oob_url}",
            "nslookup": f"nslookup {unique_subdomain}.oast.fun",
            "ping": f"ping -c 1 {unique_subdomain}.oast.fun"
        }
        
        logger.info(f"✅ OOB payload generated: {payload_id}")
        
        return {
            "status": "success",
            "data": {
                "payload_id": payload_id,
                "url": oob_url,
                "payloads": payloads,
                "note": "Inject these payloads and use check_oob_interactions() to verify callbacks"
            }
        }
    
    async def check_oob_interactions(self, payload_id: str) -> Dict:
        """
        TASK 2: Check if there were any interactions with the OOB payload
        
        This would query the interactsh service to check for callbacks
        
        Args:
            payload_id: The ID returned from generate_oob_payload()
        
        Returns:
            Dictionary with interaction details
        """
        logger.info(f"🔍 Checking OOB interactions for payload: {payload_id}")
        
        if payload_id not in self.oob_payloads:
            return {
                "status": "error",
                "error": f"Payload ID {payload_id} not found. Generate a payload first."
            }
        
        payload_info = self.oob_payloads[payload_id]
        
        # In production, this would query the interactsh API
        # Example: https://github.com/projectdiscovery/interactsh#using-interactsh-client
        # 
        # For now, we simulate the check
        # In real implementation, you would:
        # 1. Use interactsh-client Python library
        # 2. Or make HTTP requests to interactsh server API
        # 3. Poll for DNS/HTTP interactions
        
        try:
            # Simulated check (in production, use real interactsh client)
            # import interactsh_client
            # client = interactsh_client.Client()
            # interactions = client.poll(payload_id)
            
            # For now, return simulated response
            logger.info(f"⚠️ OOB check is simulated. Integrate real interactsh for production use.")
            
            return {
                "status": "success",
                "data": {
                    "payload_id": payload_id,
                    "url": payload_info["url"],
                    "interactions_found": 0,  # Would be populated by real interactsh
                    "interactions": [],  # Would contain HTTP/DNS logs
                    "note": "This is a simulated check. Integrate interactsh library for real OOB detection.",
                    "integration_guide": "Install: pip install interactsh && use interactsh-client Python API"
                }
            }
            
        except Exception as e:
            logger.error(f"❌ Error checking OOB interactions: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    # --- TASK 1: AUTHENTICATED SESSION MANAGEMENT ---
    
    async def manage_session(self, action: str, credentials: Dict[str, str] = None) -> Dict:
        """
        TASK 1: Manage authenticated sessions for scanning authenticated areas
        
        This tool allows the agent to:
        - Login to a web application using Selenium
        - Save cookies and headers to data/session.json
        - Logout and clear session data
        
        Args:
            action: 'login' or 'logout'
            credentials: Dictionary with login credentials
                - 'url': Login page URL
                - 'username_field': CSS selector for username field
                - 'password_field': CSS selector for password field
                - 'username': Username to login with
                - 'password': Password to login with
                - 'submit_button': CSS selector for submit button (optional)
                
        Returns:
            Dictionary with status and session data
        """
        from pathlib import Path
        import json
        
        session_file = Path("data/session.json")
        session_file.parent.mkdir(exist_ok=True, parents=True)
        
        if action == "logout":
            # Clear session file
            if session_file.exists():
                session_file.unlink()
                logger.info("🚪 Session cleared successfully")
                return {
                    "status": "success",
                    "data": {"message": "Session cleared"}
                }
            else:
                return {
                    "status": "success",
                    "data": {"message": "No active session to clear"}
                }
        
        elif action == "login":
            if not credentials:
                return {
                    "status": "error",
                    "error": "Credentials required for login action"
                }
            
            required_fields = ['url', 'username_field', 'password_field', 'username', 'password']
            missing = [f for f in required_fields if f not in credentials]
            if missing:
                return {
                    "status": "error",
                    "error": f"Missing required credentials: {', '.join(missing)}"
                }
            
            logger.info(f"🔐 Attempting login to {credentials['url']}...")
            
            try:
                loop = asyncio.get_event_loop()
                session_data = await loop.run_in_executor(
                    None, self._perform_login, credentials
                )
                
                # Save session data to file
                with open(session_file, 'w') as f:
                    json.dump(session_data, f, indent=2)
                
                logger.info(f"✅ Login successful, session saved to {session_file}")
                
                return {
                    "status": "success",
                    "data": {
                        "message": "Login successful, session saved",
                        "cookies_count": len(session_data.get('cookies', [])),
                        "session_file": str(session_file)
                    }
                }
                
            except Exception as e:
                logger.error(f"❌ Login failed: {e}")
                return {
                    "status": "error",
                    "error": f"Login failed: {str(e)}"
                }
        
        else:
            return {
                "status": "error",
                "error": f"Unknown action: {action}. Use 'login' or 'logout'"
            }
    
    def _perform_login(self, credentials: Dict[str, str]) -> Dict:
        """Perform login using Selenium and capture session data"""
        driver = None
        try:
            driver = self._get_selenium_driver()
            driver.get(credentials['url'])
            driver.implicitly_wait(3)
            
            # Find and fill username field
            username_field = driver.find_element(By.CSS_SELECTOR, credentials['username_field'])
            username_field.clear()
            username_field.send_keys(credentials['username'])
            
            # Find and fill password field
            password_field = driver.find_element(By.CSS_SELECTOR, credentials['password_field'])
            password_field.clear()
            password_field.send_keys(credentials['password'])
            
            # Submit the form
            if 'submit_button' in credentials:
                submit_button = driver.find_element(By.CSS_SELECTOR, credentials['submit_button'])
                submit_button.click()
            else:
                # Try to submit via form or press Enter
                password_field.submit()
            
            # Wait for page to load after login
            driver.implicitly_wait(5)
            
            # Capture cookies
            cookies = driver.get_cookies()
            
            # Capture current URL (to detect redirects)
            current_url = driver.current_url
            
            # Build session data
            session_data = {
                "cookies": cookies,
                "headers": {
                    "User-Agent": driver.execute_script("return navigator.userAgent;"),
                    "Referer": current_url
                },
                "login_url": credentials['url'],
                "current_url": current_url,
                "timestamp": asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else 0
            }
            
            return session_data
            
        finally:
            if driver:
                driver.quit()
    
    def _load_session_data(self) -> Dict:
        """Load session data from file if it exists"""
        from pathlib import Path
        import json
        
        session_file = Path("data/session.json")
        if session_file.exists():
            try:
                with open(session_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load session data: {e}")
        
        return None
