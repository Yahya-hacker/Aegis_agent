# tools/python_tools.py
# --- VERSION MODIFIÉE ---

import asyncio
import aiohttp
import logging
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By # <-- AJOUTÉ
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

    def _get_selenium_driver(self):
        """Initialise et retourne un driver Selenium."""
        service = Service(ChromeDriverManager().install())
        return webdriver.Chrome(service=service, options=self.selenium_options)

    async def advanced_technology_detection(self, target: str) -> Dict:
        # ... (Pas de changement ici, fonction existante) ...
        logger.info(f"🔬 Détection de technologie pour {target}")
        tech_findings = {}
        try:
            async with aiohttp.ClientSession(headers={'User-Agent': 'AegisAI-Scanner'}) as session:
                async with session.get(target, ssl=False, timeout=10) as response:
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
            tech_patterns = {'wordpress': ['wp-content', 'wp-includes'],'react': ['react-dom', 'data-reactroot'],'vue': ['data-v-', 'id="app"'],'angular': ['ng-version'],'jquery': ['jquery.js', 'jquery.min.js'],'bootstrap': ['bootstrap.js', 'bootstrap.css']}
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

    async def fetch_url(self, target_url: str) -> Dict:
        """
        Récupère une URL spécifique (pour tester les IDOR, les chemins, etc.).
        """
        logger.info(f"🔗 Fetching URL: {target_url}")
        try:
            async with aiohttp.ClientSession(headers={'User-Agent': 'AegisAI-Scanner'}) as session:
                async with session.get(target_url, ssl=False, timeout=10) as response:
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
