# agents/scanner.py
# --- VERSION MODIFIÉE ---

import logging
from typing import Dict, List, Any
from urllib.parse import urlparse
from tools.tool_manager import RealToolManager
from tools.python_tools import PythonToolManager

logger = logging.getLogger(__name__)

class AegisScanner:
    """Exécute les actions granulaires décidées par le cerveau IA."""
    
    def __init__(self, ai_core):
        self.ai_core = ai_core
        self.real_tools = RealToolManager()
        self.python_tools = PythonToolManager()

    async def execute_action(self, action: Dict) -> Dict:
        """Orchestrateur qui exécute l'action demandée par l'IA."""
        tool = action.get("tool")
        args = action.get("args", {})
        
        logger.info(f"Tentative d'exécution de l'action : {tool} avec args {args}")
        
        try:
            # Outils de Reconnaissance
            if tool == "subdomain_enumeration":
                domain = args.get("domain")
                if not domain: return {"status": "error", "error": "Domaine manquant"}
                return await self.real_tools.subdomain_enumeration(domain)

            elif tool == "port_scanning":
                target = args.get("target")
                if not target: return {"status": "error", "error": "Cible manquante"}
                return await self.real_tools.port_scanning(target)

            elif tool == "nmap_scan":
                target = args.get("target")
                ports = args.get("ports", "80,443,8080,8443")
                if not target: return {"status": "error", "error": "Cible manquante"}
                return await self.python_tools.nmap_scan(target, ports)

            elif tool == "url_discovery":
                domain = args.get("domain")
                if not domain: return {"status": "error", "error": "Domaine manquant"}
                return await self.real_tools.url_discovery(domain)

            elif tool == "tech_detection":
                target = args.get("target")
                if not target: return {"status": "error", "error": "Cible manquante"}
                if '://' not in target: target = f"http://{target}"
                return await self.python_tools.advanced_technology_detection(target)
            
            # Outils d'Attaque et d'Analyse Logique (NOUVEAU)
            elif tool == "vulnerability_scan":
                target_url = args.get("target")
                if not target_url: return {"status": "error", "error": "Cible URL manquante"}
                if '://' not in target_url: target_url = f"http://{target_url}"
                return await self.real_tools.vulnerability_scan(target_url)

            elif tool == "run_sqlmap":
                target_url = args.get("target")
                if not target_url: return {"status": "error", "error": "Cible URL manquante"}
                return await self.real_tools.run_sqlmap(target_url)

            elif tool == "discover_interactables":
                target_url = args.get("target")
                if not target_url: return {"status": "error", "error": "Cible URL manquante"}
                if '://' not in target_url: target_url = f"http://{target_url}"
                return await self.python_tools.discover_interactables(target_url)

            elif tool == "test_form_payload":
                target_url = args.get("target")
                form_id = args.get("form_identifier") # ex: "login-form" ou "//form[1]"
                payloads = args.get("input_payloads") # ex: {"user": "admin", "pass": "' or 1=1--"}
                if not all([target_url, form_id, payloads]):
                    return {"status": "error", "error": "Arguments manquants pour test_form_payload"}
                if '://' not in target_url: target_url = f"http://{target_url}"
                return await self.python_tools.test_form_payload(target_url, form_id, payloads)
                
            elif tool == "fetch_url":
                target_url = args.get("target")
                if not target_url: return {"status": "error", "error": "Cible URL manquante"}
                return await self.python_tools.fetch_url(target_url)

            else:
                logger.warning(f"Outil inconnu demandé par l'IA : {tool}")
                return {"status": "error", "error": f"Outil inconnu : {tool}"}
                
        except Exception as e:
            logger.error(f"Erreur fatale en exécutant {tool}: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
