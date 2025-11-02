# tools/tool_manager.py
# --- VERSION MODIFIÉE ---

import asyncio
import json
import subprocess
import logging
import re  # <-- AJOUTÉ
from pathlib import Path
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class RealToolManager:
    """Manages REAL security tool execution via subprocess"""
    
    def __init__(self):
        self.tool_paths = self._discover_tool_paths()
        logger.info(f"Outils CLI découverts : {list(self.tool_paths.keys())}")
    
    def _discover_tool_paths(self) -> Dict[str, str]:
        """Trouve le chemin d'installation des outils."""
        # AJOUT DE 'sqlmap' À LA LISTE
        tools = ["subfinder", "nuclei", "naabu", "httpx", "amass", "waybackurls", "gau", "sqlmap"]
        paths = {}
        
        for tool in tools:
            try:
                result = subprocess.run(f"which {tool}", shell=True, capture_output=True, text=True, check=True)
                if result.returncode == 0:
                    paths[tool] = result.stdout.strip()
            except Exception:
                logger.warning(f"⚠️ Outil {tool} non trouvé dans le PATH.")
        
        return paths
    
    async def _execute(self, tool_name: str, args: List[str], timeout: int = 600) -> Dict[str, Any]:
        """Wrapper d'exécution asynchrone générique."""
        if tool_name not in self.tool_paths:
            return {"status": "error", "error": f"Outil {tool_name} non trouvé"}
        
        cmd = [self.tool_paths[tool_name]] + args
        logger.info(f"Exécution : {' '.join(cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            
            if process.returncode != 0:
                logger.error(f"Erreur de {tool_name}: {stderr.decode()}")
                return {"status": "error", "error": stderr.decode()}

            return {"status": "success", "stdout": stdout.decode(), "stderr": stderr.decode()}
            
        except asyncio.TimeoutError:
            logger.error(f"Outil {tool_name} a dépassé le timeout de {timeout}s")
            return {"status": "error", "error": "Timeout"}
        except Exception as e:
            logger.error(f"Échec d'exécution de {tool_name}: {e}")
            return {"status": "error", "error": str(e)}

    # --- MÉTHODES D'OUTILS SPÉCIFIQUES ---

    async def subdomain_enumeration(self, domain: str) -> Dict:
        """Trouve les sous-domaines avec Subfinder."""
        result = await self._execute("subfinder", ["-d", domain, "-silent"])
        if result["status"] == "error": return result
        
        subdomains = [s for s in result["stdout"].strip().split('\n') if s.strip()]
        return {"status": "success", "data": subdomains}
        
    async def vulnerability_scan(self, target_url: str) -> Dict:
        """Scan une URL avec Nuclei et parse la sortie JSONL."""
        output_dir = Path("data/sessions")
        output_dir.mkdir(exist_ok=True, parents=True)
        safe_name = re.sub(r'[^a-zA-Z0-9]', '_', target_url)
        output_file = output_dir / f"nuclei_{safe_name}.jsonl"

        args = ["-u", target_url, "-severity", "low,medium,high,critical", "-jsonl", "-o", str(output_file)]
        result = await self._execute("nuclei", args)
        if result["status"] == "error": return result
        
        findings = []
        if output_file.exists():
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            output_file.unlink() # Nettoyer
            
        return {"status": "success", "data": findings}

    async def port_scanning(self, target: str) -> Dict:
        """Scan les ports avec Naabu et parse la sortie JSON."""
        result = await self._execute("naabu", ["-host", target, "-silent", "-json"])
        if result["status"] == "error": return result
        
        open_ports = []
        if result["stdout"].strip():
            for line in result["stdout"].strip().split('\n'):
                try:
                    open_ports.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return {"status": "success", "data": open_ports}

    async def url_discovery(self, domain: str) -> Dict:
        """Découvre les URLs avec GAU et Waybackurls."""
        urls = set()
        
        gau_result = await self._execute("gau", [domain])
        if gau_result["status"] == "success":
            urls.update(gau_result["stdout"].strip().split('\n'))
        
        wb_result = await self._execute("waybackurls", [domain])
        if wb_result["status"] == "success":
            urls.update(wb_result["stdout"].strip().split('\n'))
            
        return {"status": "success", "data": [u for u in urls if u.strip()]}

    # --- NOUVELLE FONCTION SQLMAP ---
    async def run_sqlmap(self, target_url: str) -> Dict:
        """Exécute sqlmap sur une URL."""
        logger.info(f"🔬 Lancement de SQLmap sur : {target_url}")
        
        # Commande SQLMap : --batch (non-interactif), --level=3, --risk=2
        args = ["-u", target_url, "--batch", "--level=3", "--risk=2"]
        result = await self._execute("sqlmap", args)
        
        if result["status"] == "error":
            return result
        
        # Parsing basique de la sortie
        stdout = result["stdout"]
        if "is vulnerable" in stdout or "identified the following injection point" in stdout:
            return {"status": "success", "data": {"vulnerable": True, "output": stdout}}
        else:
            return {"status": "success", "data": {"vulnerable": False, "output": stdout}}
