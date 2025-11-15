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
    """Manages REAL security tool execution via subprocess with rate limiting"""
    
    def __init__(self):
        self.tool_paths = self._discover_tool_paths()
        logger.info(f"Outils CLI découverts : {list(self.tool_paths.keys())}")
        
        # Rate limiting configuration
        self.last_request_time = {}  # Track last request time per tool
        self.min_delay_between_requests = 2.0  # Minimum seconds between requests
        self.max_concurrent_requests = 3  # Maximum concurrent tool executions
        self.active_processes = 0  # Track active processes
    
    def _load_session_data(self) -> Dict:
        """TASK 1: Load session data from file if it exists"""
        session_file = Path("data/session.json")
        if session_file.exists():
            try:
                with open(session_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load session data: {e}")
        
        return None
    
    def _build_cookie_header(self, session_data: Dict) -> str:
        """TASK 1: Build cookie header from session data"""
        if not session_data or 'cookies' not in session_data:
            return ""
        
        cookie_pairs = []
        for cookie in session_data['cookies']:
            cookie_pairs.append(f"{cookie['name']}={cookie['value']}")
        
        return "; ".join(cookie_pairs)
    
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
        """Wrapper d'exécution asynchrone générique avec rate limiting"""
        if tool_name not in self.tool_paths:
            return {"status": "error", "error": f"Outil {tool_name} non trouvé"}
        
        # Rate limiting: enforce delay between requests
        import time
        current_time = time.time()
        if tool_name in self.last_request_time:
            time_since_last = current_time - self.last_request_time[tool_name]
            if time_since_last < self.min_delay_between_requests:
                wait_time = self.min_delay_between_requests - time_since_last
                logger.info(f"⏱️ Rate limiting: waiting {wait_time:.1f}s before executing {tool_name}")
                await asyncio.sleep(wait_time)
        
        # Check concurrent request limit
        while self.active_processes >= self.max_concurrent_requests:
            logger.warning(f"⚠️ Max concurrent requests ({self.max_concurrent_requests}) reached, waiting...")
            await asyncio.sleep(1)
        
        self.last_request_time[tool_name] = time.time()
        self.active_processes += 1
        
        try:
            cmd = [self.tool_paths[tool_name]] + args
            logger.info(f"Exécution : {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                # Kill the process if it times out
                try:
                    process.kill()
                    await process.wait()
                except:
                    pass
                logger.error(f"Outil {tool_name} a dépassé le timeout de {timeout}s")
                return {"status": "error", "error": f"Timeout after {timeout}s"}
            
            if process.returncode != 0:
                logger.error(f"Erreur de {tool_name}: {stderr.decode()}")
                return {"status": "error", "error": stderr.decode()}

            return {"status": "success", "stdout": stdout.decode(), "stderr": stderr.decode()}
            
        except Exception as e:
            logger.error(f"Échec d'exécution de {tool_name}: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
        finally:
            self.active_processes -= 1

    # --- MÉTHODES D'OUTILS SPÉCIFIQUES ---

    async def subdomain_enumeration(self, domain: str) -> Dict:
        """Trouve les sous-domaines avec Subfinder."""
        result = await self._execute("subfinder", ["-d", domain, "-silent"])
        if result["status"] == "error": return result
        
        subdomains = [s for s in result["stdout"].strip().split('\n') if s.strip()]
        return {"status": "success", "data": subdomains}
        
    async def vulnerability_scan(self, target_url: str) -> Dict:
        """Scan une URL avec Nuclei et parse la sortie JSONL (with session injection)"""
        output_dir = Path("data/sessions")
        output_dir.mkdir(exist_ok=True, parents=True)
        safe_name = re.sub(r'[^a-zA-Z0-9]', '_', target_url)
        output_file = output_dir / f"nuclei_{safe_name}.jsonl"

        args = ["-u", target_url, "-severity", "low,medium,high,critical", "-jsonl", "-o", str(output_file)]
        
        # TASK 1: Inject session cookies if available
        session_data = self._load_session_data()
        if session_data:
            cookie_header = self._build_cookie_header(session_data)
            if cookie_header:
                logger.info("🔐 Injecting session cookies into Nuclei scan")
                args.extend(["-H", f"Cookie: {cookie_header}"])
        
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
        """Exécute sqlmap sur une URL (with session injection)"""
        logger.info(f"🔬 Lancement de SQLmap sur : {target_url}")
        
        # Commande SQLMap : --batch (non-interactif), --level=3, --risk=2
        args = ["-u", target_url, "--batch", "--level=3", "--risk=2"]
        
        # TASK 1: Inject session cookies if available
        session_data = self._load_session_data()
        if session_data:
            cookie_header = self._build_cookie_header(session_data)
            if cookie_header:
                logger.info("🔐 Injecting session cookies into SQLmap")
                args.extend(["--cookie", cookie_header])
        
        result = await self._execute("sqlmap", args)
        
        if result["status"] == "error":
            return result
        
        # Parsing basique de la sortie
        stdout = result["stdout"]
        if "is vulnerable" in stdout or "identified the following injection point" in stdout:
            return {"status": "success", "data": {"vulnerable": True, "output": stdout}}
        else:
            return {"status": "success", "data": {"vulnerable": False, "output": stdout}}
