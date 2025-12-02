# tools/python_tools.py
# --- VERSION ENHANCED - With Stealth, OOB Detection & Self-Healing Chrome ---
"""
Python-based security tools for Aegis AI.

Provides browser automation, network scanning, session management,
and advanced security testing capabilities using Selenium, Nmap, and aiohttp.

Features:
    - Stealth HTTP requests with random User-Agents and proxies
    - OOB (Out-of-Band) detection for blind vulnerabilities
    - Multi-session management for privilege escalation testing
    - JavaScript sandbox execution for client-side bypass
    - Self-healing Chrome binary detection
"""

import asyncio
import aiohttp
import logging
import random
import os
import shutil
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
import nmap
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
from utils.helpers import AegisHelpers

logger = logging.getLogger(__name__)

# Standard Chrome binary paths on Linux systems
CHROME_BINARY_PATHS = [
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
    "/usr/local/bin/google-chrome",
]


def find_chrome_binary() -> Optional[str]:
    """
    Find Chrome binary in standard Linux paths.
    
    Searches common installation locations for Chrome/Chromium browser.
    This implements the self-healing infrastructure pattern for browser detection.
    
    Returns:
        Optional[str]: Path to Chrome binary if found, None otherwise.
    """
    for path in CHROME_BINARY_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            logger.info(f"🔧 Found Chrome binary at: {path}")
            return path
    
    # Try using 'which' command as fallback
    for browser in ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]:
        binary_path = shutil.which(browser)
        if binary_path:
            logger.info(f"🔧 Found Chrome binary via which: {binary_path}")
            return binary_path
    
    logger.warning("⚠️ Chrome binary not found in standard paths")
    return None


class PythonToolManager:
    """
    Manages security tools using Python libraries (Nmap, Selenium) with stealth features.
    
    Provides browser automation, network scanning, and session management
    with built-in stealth capabilities like random User-Agents, proxy rotation,
    and request jittering.
    
    Attributes:
        nm: Nmap PortScanner instance for network scanning.
        selenium_options: Chrome options configured for headless stealth operation.
        oob_payloads: Storage for Out-of-Band detection payloads.
        sessions: Multi-session storage for privilege escalation testing.
    """
    
    def __init__(self):
        """Initialize the PythonToolManager with Nmap and Selenium configuration."""
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            logger.error("❌ Nmap is not installed. Methods using nmap (nmap_scan, advanced_port_scan) will fail.")
            self.nm = None
        
        # Options Selenium with stealth
        self.selenium_options = Options()
        self.selenium_options.add_argument('--headless')
        self.selenium_options.add_argument('--no-sandbox')
        self.selenium_options.add_argument('--disable-dev-shm-usage')
        # Use random User-Agent for Selenium
        self.selenium_options.add_argument(f'user-agent={AegisHelpers.get_random_user_agent()}')
        
        # Set Chrome binary path if found
        chrome_binary = find_chrome_binary()
        if chrome_binary:
            self.selenium_options.binary_location = chrome_binary
        
        # OOB detection storage
        self.oob_payloads: Dict[str, Dict] = {}
        
        # Multi-session storage for privilege escalation testing
        self.sessions: Dict[str, Dict] = {}
        
        logger.info("🔧 PythonToolManager initialized")

    def _get_selenium_driver(self):
        """
        Initialize and return a Selenium Chrome WebDriver.
        
        Implements self-healing: if WebDriver fails to find Chrome binary,
        searches standard Linux paths before falling back to default.
        
        Returns:
            webdriver.Chrome: Configured Chrome WebDriver instance.
            
        Raises:
            Exception: If Chrome binary cannot be found or WebDriver fails to initialize.
        """
        try:
            # FORCE SYSTEM DRIVER as per manual repair instructions
            # This ensures compatibility with the installed chromium version
            system_driver = '/usr/bin/chromedriver'
            if os.path.exists(system_driver):
                logger.info(f"🔧 Forcing system chromedriver at: {system_driver}")
                service = Service(system_driver)
            else:
                # Fallback if not found (though it should be there)
                logger.warning(f"⚠️ System driver not found at {system_driver}, falling back to discovery")
                discovered_driver = shutil.which("chromedriver")
                if discovered_driver:
                    service = Service(discovered_driver)
                else:
                    logger.info("🔧 System chromedriver not found, using webdriver_manager")
                    service = Service(ChromeDriverManager().install())
                
            return webdriver.Chrome(service=service, options=self.selenium_options)
        except Exception as e:
            error_msg = str(e).lower()
            # Check if error is related to Chrome binary
            if 'chrome' in error_msg or 'binary' in error_msg or 'executable' in error_msg:
                logger.warning(f"⚠️ WebDriver init failed: {e}")
                logger.info("🔧 Searching for Chrome binary in standard paths...")
                
                chrome_binary = find_chrome_binary()
                if chrome_binary:
                    self.selenium_options.binary_location = chrome_binary
                    logger.info(f"🔧 Retrying with Chrome binary: {chrome_binary}")
                    
                    # Retry with system driver or manager
                    system_driver = shutil.which("chromedriver")
                    if system_driver:
                        service = Service(system_driver)
                    else:
                        service = Service(ChromeDriverManager().install())
                        
                    return webdriver.Chrome(service=service, options=self.selenium_options)
                else:
                    raise RuntimeError(
                        "Chrome binary not found. Please install Chrome/Chromium: "
                        "apt install chromium-browser or apt install google-chrome-stable"
                    )
            raise

    async def advanced_technology_detection(self, target: str) -> Dict:
        """Advanced technology detection with stealth features + session injection"""
        logger.info(f"🔬 Technology detection for {target}")
        
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
            logger.warning(f"HTTP header analysis failed: {e}")
        
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
            logger.warning(f"Selenium analysis failed: {e}")
        
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

    async def nmap_scan(self, target: str, ports: str = "80,443,8080,8443,22,21,3306,5432", arguments: str = "-sV -sS -T4") -> Dict:
        # ... (No change here, existing function) ...
        if not self.nm:
            return {"status": "error", "error": "Nmap not initialized"}
        domain = urlparse(target).netloc if '://' in target else target
        logger.info(f"🔦 Executing Nmap (library) on {domain} (Ports: {ports}) Args: {arguments}...")
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self.nm.scan, domain, ports, arguments)
            findings = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    lports = self.nm[host][proto].keys()
                    for port in lports:
                        service = self.nm[host][proto][port]
                        findings.append({"port": port, "protocol": proto, "state": service.get('state'), "service_name": service.get('name', 'unknown'), "product": service.get('product', ''), "version": service.get('version', '')})
            return {"status": "success", "data": findings}
        except Exception as e:
            logger.error(f"❌ Nmap scan failed: {e}")
            return {"status": "error", "error": str(e)}

    # --- NEW SOPHISTICATED FUNCTIONS ---
    
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
        Fetches a specific URL with stealth features + session injection
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
    
    # --- MULTI-SESSION MANAGEMENT FOR PRIVILEGE ESCALATION TESTING ---
    
    async def manage_multi_session(self, action: str, session_name: str, credentials: Dict[str, str] = None) -> Dict:
        """
        Manage multiple named sessions for privilege escalation testing
        
        This allows the agent to maintain separate sessions for:
        - Session_Admin: High-privilege user session
        - Session_User: Low-privilege user session
        
        Args:
            action: 'login', 'logout', 'list'
            session_name: Name of the session (e.g., 'Session_Admin', 'Session_User')
            credentials: Dictionary with login credentials (same format as manage_session)
                
        Returns:
            Dictionary with status and session data
        """
        from pathlib import Path
        import json
        
        if action == "list":
            # List all active sessions
            return {
                "status": "success",
                "data": {
                    "sessions": list(self.sessions.keys()),
                    "count": len(self.sessions)
                }
            }
        
        if action == "logout":
            # Clear specific session
            if session_name in self.sessions:
                del self.sessions[session_name]
                logger.info(f"🚪 Session '{session_name}' cleared successfully")
                
                # Also clear from file
                session_file = Path(f"data/session_{session_name}.json")
                if session_file.exists():
                    session_file.unlink()
                
                return {
                    "status": "success",
                    "data": {"message": f"Session '{session_name}' cleared"}
                }
            else:
                return {
                    "status": "success",
                    "data": {"message": f"No active session named '{session_name}'"}
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
            
            logger.info(f"🔐 Attempting login for session '{session_name}' to {credentials['url']}...")
            
            try:
                loop = asyncio.get_event_loop()
                session_data = await loop.run_in_executor(
                    None, self._perform_login, credentials
                )
                
                # Store session data in memory
                self.sessions[session_name] = session_data
                
                # Also save to file for persistence
                session_file = Path(f"data/session_{session_name}.json")
                session_file.parent.mkdir(exist_ok=True, parents=True)
                with open(session_file, 'w') as f:
                    json.dump(session_data, f, indent=2)
                
                logger.info(f"✅ Login successful for '{session_name}', session saved")
                
                return {
                    "status": "success",
                    "data": {
                        "message": f"Login successful for session '{session_name}'",
                        "session_name": session_name,
                        "cookies_count": len(session_data.get('cookies', [])),
                        "session_file": str(session_file)
                    }
                }
                
            except Exception as e:
                logger.error(f"❌ Login failed for '{session_name}': {e}")
                return {
                    "status": "error",
                    "error": f"Login failed: {str(e)}"
                }
        
        else:
            return {
                "status": "error",
                "error": f"Unknown action: {action}. Use 'login', 'logout', or 'list'"
            }
    
    async def replay_request_with_session(
        self,
        original_request: Dict[str, Any],
        session_name: str
    ) -> Dict:
        """
        Replay a captured request using a different session's cookies
        
        This is used for privilege escalation testing - replay an admin
        request with a low-privilege user's cookies to check for authorization bypass.
        
        Args:
            original_request: Dictionary with request details:
                - method: HTTP method (GET, POST, etc.)
                - url: Target URL
                - headers: Optional headers dict
                - data: Optional POST data
            session_name: Name of session to use (e.g., 'Session_User')
                
        Returns:
            Dictionary with status and response details
        """
        if session_name not in self.sessions:
            # Try to load from file
            from pathlib import Path
            import json
            
            session_file = Path(f"data/session_{session_name}.json")
            if session_file.exists():
                try:
                    with open(session_file, 'r') as f:
                        self.sessions[session_name] = json.load(f)
                except Exception as e:
                    return {
                        "status": "error",
                        "error": f"Session '{session_name}' not found and could not load from file: {e}"
                    }
            else:
                return {
                    "status": "error",
                    "error": f"Session '{session_name}' not found. Login first using manage_multi_session."
                }
        
        session_data = self.sessions[session_name]
        
        # Extract request details
        method = original_request.get('method', 'GET').upper()
        url = original_request.get('url')
        headers = original_request.get('headers', {})
        data = original_request.get('data', {})
        
        if not url:
            return {
                "status": "error",
                "error": "URL is required in original_request"
            }
        
        logger.info(f"🔄 Replaying {method} request to {url} with session '{session_name}'")
        
        # Inject session cookies and headers
        cookies = {}
        if 'cookies' in session_data:
            for cookie in session_data['cookies']:
                cookies[cookie['name']] = cookie['value']
        
        # Merge session headers
        if 'headers' in session_data:
            headers.update(session_data['headers'])
        
        try:
            # Apply jitter for stealth
            await AegisHelpers.apply_jitter()
            
            async with aiohttp.ClientSession(headers=headers) as session:
                kwargs = {
                    'ssl': False,
                    'timeout': aiohttp.ClientTimeout(total=10),
                    'cookies': cookies
                }
                
                # Execute request
                if method == 'GET':
                    async with session.get(url, **kwargs) as response:
                        status_code = response.status
                        response_text = await response.text()
                        response_headers = dict(response.headers)
                elif method == 'POST':
                    kwargs['data'] = data
                    async with session.post(url, **kwargs) as response:
                        status_code = response.status
                        response_text = await response.text()
                        response_headers = dict(response.headers)
                else:
                    return {
                        "status": "error",
                        "error": f"Unsupported HTTP method: {method}"
                    }
                
                logger.info(f"✅ Request replayed: Status {status_code}")
                
                # Analyze response to detect privilege escalation
                is_success = 200 <= status_code < 300
                
                return {
                    "status": "success",
                    "data": {
                        "session_name": session_name,
                        "method": method,
                        "url": url,
                        "status_code": status_code,
                        "response_preview": response_text[:500],
                        "response_headers": response_headers,
                        "is_successful": is_success,
                        "privilege_escalation_detected": is_success,  # If low-priv session succeeded, it's likely priv esc
                        "note": "If this succeeded with low-privilege session, it indicates privilege escalation vulnerability"
                    }
                }
                
        except Exception as e:
            logger.error(f"❌ Error replaying request: {e}")
            return {
                "status": "error",
                "error": f"Failed to replay request: {str(e)}"
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
    
    def execute_extracted_js(self, js_code: str, arguments: list = None, function_name: str = "targetFunction") -> Optional[str]:
        """
        The "Mirror" JS Sandbox - Execute JavaScript extracted from target's source code.
        
        Takes a cryptographic function found in the target's .js bundle,
        wraps it in a runner, and executes it locally in Node.js to generate valid tokens.
        
        Args:
            js_code: JavaScript code containing the function to execute
            arguments: List of arguments to pass to the function
            function_name: Name of the function to call (default: "targetFunction")
        
        Returns:
            Output from the JavaScript execution, or None if failed
        
        Example:
            >>> js_code = '''
            ... function generateToken(user, timestamp) {
            ...     return btoa(user + ':' + timestamp + ':secret');
            ... }
            ... '''
            >>> result = tool.execute_extracted_js(js_code, ['admin', '1234567890'], 'generateToken')
        """
        import subprocess
        import json
        
        if arguments is None:
            arguments = []
        
        logger.info(f"[Mirror] Executing extracted JS function '{function_name}' with {len(arguments)} arguments")
        
        # Escape arguments for JSON
        args_json = json.dumps(arguments)
        
        # Encode JS code to Base64 to prevent syntax errors with backticks/quotes
        import base64
        js_code_b64 = base64.b64encode(js_code.encode('utf-8')).decode('utf-8')

        # Create a secure sandbox wrapper using Node.js vm module
        # This prevents access to process, fs, and require
        # We decode the Base64 code inside the wrapper to avoid string escaping issues
        wrapper = f"""
const vm = require('vm');

// Decode the target code from Base64
const codeBuffer = Buffer.from('{js_code_b64}', 'base64');
const targetCode = codeBuffer.toString('utf-8');

const wrappedCode = `
${{targetCode}}

// Aegis wrapper to call the function
try {{
    const result = {function_name}(...{args_json});
    JSON.stringify({{ success: true, result: result }});
}} catch (error) {{
    JSON.stringify({{ success: false, error: error.message }});
}}
`;

try {{
    // Create a secure context without access to sensitive globals
    const context = vm.createContext({{
        console: {{ log: () => {{}} }}, // Disable console logs inside sandbox
        btoa: (str) => Buffer.from(str).toString('base64'),
        atob: (str) => Buffer.from(str, 'base64').toString('binary'),
        JSON: JSON
    }});

    // Execute code in sandbox with timeout
    const result = vm.runInContext(wrappedCode, context, {{ timeout: 1000 }});
    console.log(result);
}} catch (e) {{
    console.log(JSON.stringify({{ success: false, error: 'Sandbox Error: ' + e.message }}));
}}
"""
        
        try:
            # Secure execution with timeout
            result = subprocess.run(
                ["node", "-e", wrapper],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Parse the output
                output = result.stdout.strip()
                try:
                    parsed = json.loads(output)
                    if parsed.get("success"):
                        logger.info(f"[Mirror] JS execution successful: {parsed.get('result')}")
                        return str(parsed.get("result"))
                    else:
                        logger.warning(f"[Mirror] JS execution error: {parsed.get('error')}")
                        return None
                except json.JSONDecodeError:
                    # If not JSON, return raw output
                    logger.info(f"[Mirror] JS execution output: {output}")
                    return output
            else:
                logger.error(f"[Mirror] JS execution failed: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error("[Mirror] JS execution timed out (5s limit)")
            return None
        except FileNotFoundError:
            logger.error("[Mirror] Node.js not found. Please install Node.js to use this feature.")
            return None
        except Exception as e:
            logger.error(f"[Mirror] JS execution error: {e}")
            return None
    
    async def extract_and_execute_js_function(
        self, 
        target_url: str, 
        function_pattern: str,
        arguments: list = None
    ) -> Optional[str]:
        """
        Advanced Mirror feature: Extract a JS function from a webpage and execute it.
        
        Args:
            target_url: URL to fetch JavaScript from
            function_pattern: Regex pattern to extract the function (e.g., r'function generateToken.*?}')
            arguments: Arguments to pass to the extracted function
        
        Returns:
            Result of function execution
        """
        import re
        
        logger.info(f"[Mirror] Fetching and extracting JS from {target_url}")
        
        try:
            # Fetch the page
            headers = AegisHelpers.get_stealth_headers()
            
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(target_url, ssl=False, timeout=10) as response:
                    content = await response.text()
            
            # Extract the function using regex
            match = re.search(function_pattern, content, re.DOTALL)
            
            if match:
                js_code = match.group(0)
                logger.info(f"[Mirror] Extracted function: {js_code[:100]}...")
                
                # Try to determine function name
                func_name_match = re.search(r'function\s+(\w+)', js_code)
                if func_name_match:
                    function_name = func_name_match.group(1)
                else:
                    # Anonymous function, wrap it
                    function_name = "extractedFunction"
                    js_code = f"const {function_name} = {js_code};"
                
                # Execute the extracted function
                return self.execute_extracted_js(js_code, arguments, function_name)
            else:
                logger.warning(f"[Mirror] Could not find function matching pattern: {function_pattern}")
                return None
                
        except Exception as e:
            logger.error(f"[Mirror] Error extracting/executing JS: {e}")
            return None
