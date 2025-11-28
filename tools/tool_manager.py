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
    
    Implements adaptive intensity modes for comprehensive security testing:
    - stealth: Low and slow, evades detection
    - normal: Balanced approach
    - aggressive: Maximum speed and coverage (God Mode)
    
    Attributes:
        tool_paths: Dictionary mapping tool names to their binary paths.
        last_request_time: Tracks last request time per tool for rate limiting.
        min_delay_between_requests: Minimum seconds between requests to same tool.
        max_concurrent_requests: Maximum number of concurrent tool executions.
        active_processes: Counter for currently running processes.
        high_impact_mode: When True, uses maximum aggression settings.
    """
    
    # Intensity configurations for each tool
    INTENSITY_CONFIGS = {
        "nmap": {
            "stealth": ["-sS", "-T2", "-f"],  # Fragmented packets, slow timing
            "normal": ["-sS", "-T3"],          # SYN scan, normal timing
            "aggressive": ["-sS", "-T4", "-A", "-p-"],  # Aggressive, all ports, OS detection
        },
        "nuclei": {
            "stealth": ["-rl", "10", "-c", "5"],  # Rate limit 10, concurrency 5
            "normal": ["-rl", "50", "-c", "25"],   # Rate limit 50, concurrency 25
            "aggressive": ["-rl", "150", "-c", "50", "-dast"],  # Max rate, DAST enabled
        },
        "sqlmap": {
            "stealth": ["--level=1", "--risk=1"],  # Minimal testing
            "normal": ["--level=3", "--risk=2"],   # Balanced testing
            "aggressive": ["--level=5", "--risk=3"],  # Maximum testing
        },
    }
    
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
    
    def get_intensity_args(self, tool_name: str, intensity: str = 'normal') -> List[str]:
        """
        Get intensity-specific command arguments for a tool.
        
        Args:
            tool_name: Name of the tool (nmap, nuclei, sqlmap)
            intensity: Intensity level ('stealth', 'normal', 'aggressive')
            
        Returns:
            List of command-line arguments for the specified intensity
        """
        if tool_name not in self.INTENSITY_CONFIGS:
            logger.warning(f"No intensity config for {tool_name}, using empty args")
            return []
        
        tool_config = self.INTENSITY_CONFIGS[tool_name]
        
        # Validate requested intensity exists, fallback to 'normal' only if it exists
        if intensity not in tool_config:
            logger.warning(f"Invalid intensity '{intensity}' for {tool_name}")
            if 'normal' in tool_config:
                intensity = 'normal'
                logger.warning(f"Falling back to 'normal' intensity")
            else:
                # Return first available intensity as fallback
                available = list(tool_config.keys())
                if available:
                    intensity = available[0]
                    logger.warning(f"Falling back to '{intensity}' intensity")
                else:
                    return []
        
        return tool_config[intensity].copy()
    
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
        
    async def vulnerability_scan(self, target_url: str, intensity: str = 'normal') -> Dict:
        """
        Scan a URL with Nuclei using adaptive intensity configuration.
        
        Intensity modes:
            - stealth: Low rate (10 req/sec), low concurrency (5) - evades detection
            - normal: Balanced rate (50 req/sec), moderate concurrency (25)
            - aggressive: High rate (150 req/sec), high concurrency (50), DAST enabled
        
        Warning:
            Aggressive mode may trigger WAF/IDS defensive measures.
            Use stealth mode for sensitive targets.
        
        Args:
            target_url: Target URL to scan for vulnerabilities.
            intensity: Scan intensity ('stealth', 'normal', 'aggressive'). Default: 'normal'
            
        Returns:
            Dict: Dictionary with status and list of discovered vulnerabilities.
        """
        output_dir = Path("data/sessions")
        output_dir.mkdir(exist_ok=True, parents=True)
        safe_name = re.sub(r'[^a-zA-Z0-9]', '_', target_url)
        output_file = output_dir / f"nuclei_{safe_name}.jsonl"

        # Get intensity-specific arguments
        intensity_args = self.get_intensity_args("nuclei", intensity)
        
        # Base Nuclei arguments
        args = [
            "-u", target_url,
            "-severity", "low,medium,high,critical",
            "-jsonl",
            "-o", str(output_file),
            "-bs", "10",  # Batch size
        ]
        
        # Add intensity-specific args
        args.extend(intensity_args)
        
        if intensity == 'aggressive' or self.high_impact_mode:
            logger.warning("⚠️ Using aggressive mode - may trigger defensive measures")
        elif intensity == 'stealth':
            logger.info("🕵️ Stealth mode: Low rate, minimal footprint")
        else:
            logger.info("🔧 Normal mode: Balanced scanning")
        
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
    
    async def nmap_scan(self, target: str, ports: str = None, intensity: str = 'normal') -> Dict:
        """
        Perform Nmap scan with adaptive intensity configuration.
        
        Intensity modes:
            - stealth: SYN scan, slow timing (-T2), fragmented packets (-f)
            - normal: SYN scan, normal timing (-T3)
            - aggressive: SYN scan, aggressive timing (-T4), OS detection (-A), all ports (-p-)
        
        Args:
            target: Target host or IP to scan.
            ports: Optional comma-separated port list. If None and aggressive, scans all ports.
            intensity: Scan intensity ('stealth', 'normal', 'aggressive'). Default: 'normal'
            
        Returns:
            Dict: Dictionary with status and list of discovered services.
        """
        if "nmap" not in self.tool_paths:
            return {"status": "error", "error": "Nmap not found in PATH"}
        
        # Get intensity-specific arguments
        intensity_args = self.get_intensity_args("nmap", intensity)
        
        # Base arguments
        args = [target]
        
        # Add intensity-specific args
        args.extend(intensity_args)
        
        # Add service version detection for normal and aggressive
        if intensity != 'stealth':
            args.append("-sV")
        
        # XML output
        args.extend(["-oX", "-"])
        
        # Use provided ports or auto-determine based on intensity
        if ports:
            args.extend(["-p", ports])
        elif intensity == 'aggressive':
            # Full port scan only in aggressive mode (already included in INTENSITY_CONFIGS)
            pass
        else:
            # Default ports for stealth and normal
            args.extend(["-p", "80,443,8080,8443,22,21,25,53,110,143,3306,5432"])
        
        if intensity == 'stealth':
            logger.info(f"🕵️ Nmap Stealth scan: {target} (fragmented, slow)")
        elif intensity == 'aggressive':
            logger.warning(f"⚠️ Nmap Aggressive scan: {target} (full ports, OS detection)")
        else:
            logger.info(f"🔧 Nmap Normal scan: {target}")
        
        # Timeout varies by intensity
        timeout = 1800 if intensity == 'aggressive' else (600 if intensity == 'normal' else 900)
        result = await self._execute("nmap", args, timeout=timeout)
        
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

    async def run_sqlmap(self, target_url: str, intensity: str = 'normal', high_impact: bool = False) -> Dict:
        """
        Execute SQLMap SQL injection testing with adaptive intensity.
        
        Intensity modes:
            - stealth: level=1, risk=1 - Minimal testing, low detection risk
            - normal: level=3, risk=2 - Balanced testing
            - aggressive: level=5, risk=3 - Maximum detection, may cause issues
        
        Args:
            target_url: Target URL with parameter to test.
            intensity: Test intensity ('stealth', 'normal', 'aggressive'). Default: 'normal'
            high_impact: Deprecated. Use intensity='aggressive' instead.
            
        Returns:
            Dict: Dictionary with status and vulnerability detection results.
        """
        logger.info(f"🛡️ Launching SQLMap on: {target_url}")
        
        # Handle legacy high_impact parameter
        if high_impact or self.high_impact_mode:
            intensity = 'aggressive'
        
        # Get intensity-specific arguments
        intensity_args = self.get_intensity_args("sqlmap", intensity)
        
        # Base SQLMap arguments
        args = [
            "-u", target_url,
            "--batch",
            "--random-agent",
        ]
        
        # Add intensity-specific args
        args.extend(intensity_args)
        
        if intensity == 'stealth':
            logger.info("🕵️ SQLMap Stealth mode: level=1, risk=1")
        elif intensity == 'aggressive':
            logger.warning("⚠️ SQLMap Aggressive mode: level=5, risk=3 - may cause issues")
        else:
            logger.info("🔧 SQLMap Normal mode: level=3, risk=2")
        
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
