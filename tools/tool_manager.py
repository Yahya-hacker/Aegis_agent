# tools/tool_manager.py
# --- VERSION ENHANCED - God Mode Tool Configuration ---
"""
Real Tool Manager for Aegis AI.

Manages execution of security tools (Nuclei, Nmap, SQLMap, etc.) via subprocess
with rate limiting, session management, and "God Mode" aggressive configurations.

Features:
    - Session cookie injection for authenticated scanning
    - Rate limiting and concurrent request management
    - Aggressive "God Mode" scan configurations
    - Async subprocess execution with timeout handling
"""

import asyncio
import json
import subprocess
import logging
import re
from pathlib import Path
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class RealToolManager:
    """
    Manages REAL security tool execution via subprocess with rate limiting.
    
    Implements "God Mode" aggressive scan configurations for comprehensive
    security testing while respecting rate limits and resource constraints.
    
    Attributes:
        tool_paths: Dictionary mapping tool names to their binary paths.
        last_request_time: Tracks last request time per tool for rate limiting.
        min_delay_between_requests: Minimum seconds between requests to same tool.
        max_concurrent_requests: Maximum number of concurrent tool executions.
        active_processes: Counter for currently running processes.
        high_impact_mode: When True, uses maximum aggression settings.
    """
    
    def __init__(self, high_impact_mode: bool = False):
        """
        Initialize the RealToolManager.
        
        Args:
            high_impact_mode: If True, enables maximum aggression scan settings.
        """
        self.tool_paths = self._discover_tool_paths()
        logger.info(f"🔧 Discovered CLI tools: {list(self.tool_paths.keys())}")
        
        # Rate limiting configuration
        self.last_request_time: Dict[str, float] = {}
        self.min_delay_between_requests = 2.0
        self.max_concurrent_requests = 3
        self.active_processes = 0
        
        # God Mode configuration
        self.high_impact_mode = high_impact_mode
    
    def _load_session_data(self) -> Dict:
        """
        Load session data from file if it exists.
        
        Returns:
            Dict: Session data containing cookies and headers, or empty dict.
        """
        session_file = Path("data/session.json")
        if session_file.exists():
            try:
                with open(session_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"⚠️ Failed to load session data: {e}")
        
        return {}
    
    def _build_cookie_header(self, session_data: Dict) -> str:
        """
        Build cookie header from session data.
        
        Args:
            session_data: Session data dictionary with cookies.
            
        Returns:
            str: Cookie header string in format "name1=value1; name2=value2".
        """
        if not session_data or 'cookies' not in session_data:
            return ""
        
        cookie_pairs = []
        for cookie in session_data['cookies']:
            cookie_pairs.append(f"{cookie['name']}={cookie['value']}")
        
        return "; ".join(cookie_pairs)
    
    def _discover_tool_paths(self) -> Dict[str, str]:
        """
        Find the installation path of security tools.
        
        Searches PATH for common security tools and records their locations.
        
        Returns:
            Dict[str, str]: Dictionary mapping tool names to binary paths.
        """
        tools = ["subfinder", "nuclei", "naabu", "httpx", "amass", "waybackurls", "gau", "sqlmap", "nmap"]
        paths = {}
        
        for tool in tools:
            try:
                # Use shell=False with list arguments for security
                result = subprocess.run(
                    ["which", tool],
                    capture_output=True,
                    text=True,
                    check=True
                )
                if result.returncode == 0:
                    paths[tool] = result.stdout.strip()
            except Exception:
                logger.warning(f"⚠️ Tool {tool} not found in PATH")
        
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
        """
        Find subdomains using Subfinder passive sources.
        
        Args:
            domain: Target domain to enumerate subdomains for.
            
        Returns:
            Dict: Dictionary with status and list of discovered subdomains.
        """
        result = await self._execute("subfinder", ["-d", domain, "-silent"])
        if result["status"] == "error":
            return result
        
        subdomains = [s for s in result["stdout"].strip().split('\n') if s.strip()]
        return {"status": "success", "data": subdomains}
        
    async def vulnerability_scan(self, target_url: str) -> Dict:
        """
        Scan a URL with Nuclei using God Mode aggressive configuration.
        
        God Mode settings:
            - Increased batch size (-bs 10)
            - High concurrency (-c 50)
            - Elevated rate limit (-rate-limit 150)
            - DAST templates enabled (-dast)
            - All template types (-t)
        
        Warning:
            The default rate limit of 150 req/sec is aggressive and may:
            - Trigger WAF/IDS defensive measures
            - Overwhelm underpowered target systems
            - Be inappropriate for production environments
            
            Consider lowering the rate for sensitive targets.
        
        Args:
            target_url: Target URL to scan for vulnerabilities.
            
        Returns:
            Dict: Dictionary with status and list of discovered vulnerabilities.
        """
        output_dir = Path("data/sessions")
        output_dir.mkdir(exist_ok=True, parents=True)
        safe_name = re.sub(r'[^a-zA-Z0-9]', '_', target_url)
        output_file = output_dir / f"nuclei_{safe_name}.jsonl"

        # GOD MODE: Aggressive Nuclei configuration
        # WARNING: High rate limit (150 req/sec) may trigger defensive measures
        args = [
            "-u", target_url,
            "-severity", "low,medium,high,critical",
            "-jsonl",
            "-o", str(output_file),
            # God Mode settings
            "-bs", "10",       # Batch size
            "-c", "50",        # Concurrency
            "-rate-limit", "150",  # Rate limit (aggressive - may trigger WAF)
        ]
        
        logger.warning("⚠️ Using aggressive rate limit (150 req/sec) - may trigger defensive measures")
        
        # Add DAST if high impact mode
        if self.high_impact_mode:
            args.extend(["-dast"])
            logger.info("🛡️ God Mode: DAST scanning enabled")
        
        # Inject session cookies if available
        session_data = self._load_session_data()
        if session_data:
            cookie_header = self._build_cookie_header(session_data)
            if cookie_header:
                logger.info("🔐 Injecting session cookies into Nuclei scan")
                args.extend(["-H", f"Cookie: {cookie_header}"])
        
        result = await self._execute("nuclei", args)
        if result["status"] == "error":
            return result
        
        findings = []
        if output_file.exists():
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            output_file.unlink()  # Cleanup
            
        return {"status": "success", "data": findings}

    async def port_scanning(self, target: str) -> Dict:
        """
        Scan ports with Naabu and parse JSON output.
        
        Args:
            target: Target host or IP to scan.
            
        Returns:
            Dict: Dictionary with status and list of open ports.
        """
        result = await self._execute("naabu", ["-host", target, "-silent", "-json"])
        if result["status"] == "error":
            return result
        
        open_ports = []
        if result["stdout"].strip():
            for line in result["stdout"].strip().split('\n'):
                try:
                    open_ports.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return {"status": "success", "data": open_ports}
    
    async def nmap_scan(self, target: str, ports: str = None) -> Dict:
        """
        Perform comprehensive Nmap scan with God Mode configuration.
        
        God Mode settings:
            - SYN scan (-sS)
            - Service version detection (-sV)
            - Full port range (-p-)
            - Aggressive timing (-T4)
            - High minimum rate (--min-rate 1000)
        
        Args:
            target: Target host or IP to scan.
            ports: Optional comma-separated port list. If None, scans all ports.
            
        Returns:
            Dict: Dictionary with status and list of discovered services.
        """
        if "nmap" not in self.tool_paths:
            return {"status": "error", "error": "Nmap not found in PATH"}
        
        # GOD MODE: Aggressive Nmap configuration
        args = [
            target,
            "-sS",              # SYN scan
            "-sV",              # Service version detection
            "-T4",              # Aggressive timing
            "--min-rate", "1000",  # Fast rate
            "-oX", "-",         # XML output to stdout
        ]
        
        # Use provided ports or full range
        if ports:
            args.extend(["-p", ports])
        else:
            args.extend(["-p-"])  # Full port scan
        
        logger.info(f"🔧 Nmap God Mode scan: {target}")
        result = await self._execute("nmap", args, timeout=900)  # 15 min timeout
        
        if result["status"] == "error":
            return result
        
        # Parse basic output (XML parsing would be more robust)
        return {"status": "success", "data": {"output": result["stdout"]}}

    async def url_discovery(self, domain: str) -> Dict:
        """
        Discover URLs and endpoints using GAU and Waybackurls.
        
        Args:
            domain: Target domain to discover URLs for.
            
        Returns:
            Dict: Dictionary with status and list of discovered URLs.
        """
        urls = set()
        
        gau_result = await self._execute("gau", [domain])
        if gau_result["status"] == "success":
            urls.update(gau_result["stdout"].strip().split('\n'))
        
        wb_result = await self._execute("waybackurls", [domain])
        if wb_result["status"] == "success":
            urls.update(wb_result["stdout"].strip().split('\n'))
            
        return {"status": "success", "data": [u for u in urls if u.strip()]}

    async def run_sqlmap(self, target_url: str, high_impact: bool = False) -> Dict:
        """
        Execute SQLMap SQL injection testing with configurable aggression.
        
        Standard mode uses level=3, risk=2.
        High Impact mode uses level=5, risk=3 for maximum detection.
        
        Args:
            target_url: Target URL with parameter to test.
            high_impact: If True, uses maximum aggression (level=5, risk=3).
            
        Returns:
            Dict: Dictionary with status and vulnerability detection results.
        """
        logger.info(f"🛡️ Launching SQLMap on: {target_url}")
        
        # Determine aggression level
        use_high_impact = high_impact or self.high_impact_mode
        
        if use_high_impact:
            # GOD MODE: Maximum SQLMap aggression
            args = [
                "-u", target_url,
                "--batch",
                "--random-agent",
                "--level=5",
                "--risk=3"
            ]
            logger.info("🛡️ God Mode: SQLMap level=5, risk=3")
        else:
            # Standard mode
            args = ["-u", target_url, "--batch", "--level=3", "--risk=2"]
        
        # Inject session cookies if available
        session_data = self._load_session_data()
        if session_data:
            cookie_header = self._build_cookie_header(session_data)
            if cookie_header:
                logger.info("🔐 Injecting session cookies into SQLMap")
                args.extend(["--cookie", cookie_header])
        
        result = await self._execute("sqlmap", args)
        
        if result["status"] == "error":
            return result
        
        # Parse output for vulnerability indicators
        stdout = result["stdout"]
        if "is vulnerable" in stdout or "identified the following injection point" in stdout:
            return {"status": "success", "data": {"vulnerable": True, "output": stdout}}
        else:
            return {"status": "success", "data": {"vulnerable": False, "output": stdout}}
