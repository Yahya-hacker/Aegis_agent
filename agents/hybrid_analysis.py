#!/usr/bin/env python3
"""
AEGIS OMEGA PROTOCOL - Hybrid Analysis Module
==============================================

Implements the Code-to-Payload Loop:
- Detects .git folders and open source components during web scanning
- Auto-clones repositories for source code analysis
- Uses Code LLM (Qwen) to identify exact vulnerable code lines
- Generates targeted payloads specific to discovered vulnerabilities

This bridges reverse_engine and pwn_exploiter to the Web Scanner for
comprehensive hybrid analysis (reading code + attacking).
"""

import asyncio
import logging
import json
import re
import os
import tempfile
import shutil
import subprocess
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class VulnerableCodeLocation:
    """Represents a vulnerable code location identified by LLM analysis"""
    file_path: str
    line_number: int
    code_snippet: str
    vulnerability_type: str
    severity: str  # critical, high, medium, low
    confidence: float  # 0.0-1.0
    explanation: str
    cwe_id: Optional[str] = None
    payload_suggestions: List[str] = field(default_factory=list)


@dataclass
class SourceCodeAnalysis:
    """Result of source code analysis"""
    repo_url: str
    local_path: str
    vulnerabilities: List[VulnerableCodeLocation]
    technologies: List[str]
    entry_points: List[str]  # API endpoints, routes, etc.
    security_findings: Dict[str, Any]
    analysis_timestamp: datetime = field(default_factory=datetime.now)


class HybridAnalysisEngine:
    """
    Hybrid Analysis Engine for Code-to-Payload Loop.
    
    When scanning a web app, if Aegis finds a .git folder or open source component,
    this engine:
    1. Auto-clones the repository
    2. Passes code to the Code LLM (Qwen)
    3. Identifies exact lines of vulnerable code
    4. Generates payloads specific to those vulnerabilities
    """
    
    # Configurable limits
    MAX_SOURCE_FILES = 50  # Maximum source files to analyze per repo
    MAX_FINDINGS_PER_FILE = 5  # Maximum pattern findings per file for LLM analysis
    MAX_FILES_FOR_LLM = 10  # Maximum files to send to LLM
    GIT_CLONE_TIMEOUT = 60  # Seconds timeout for git clone
    GIT_RECONSTRUCT_TIMEOUT = 120  # Seconds timeout for git reconstruction
    
    # Common open source component indicators
    OPENSOURCE_INDICATORS = {
        ".git": "git_repository",
        ".gitignore": "git_repository",
        "package.json": "nodejs",
        "composer.json": "php_composer",
        "requirements.txt": "python",
        "Gemfile": "ruby",
        "pom.xml": "java_maven",
        "build.gradle": "java_gradle",
        "Cargo.toml": "rust",
        "go.mod": "golang",
        "setup.py": "python",
        "pyproject.toml": "python",
    }
    
    # Common vulnerable patterns to look for in code
    VULNERABLE_PATTERNS = {
        "sql_injection": [
            r"execute\s*\(\s*['\"].*\+.*['\"]",  # String concatenation in SQL
            r"query\s*\(\s*['\"].*\%.*['\"]",     # String formatting in SQL
            r"cursor\.execute\s*\(.*\+",          # Python SQL injection
            r"\$_(GET|POST|REQUEST)\[.*\]\s*\.\s*",  # PHP SQL injection
            r"\.query\(\s*[`'\"].*\$\{",          # JS template literal injection
        ],
        "command_injection": [
            r"exec\s*\(.*\$_(GET|POST|REQUEST)",   # PHP command injection
            r"system\s*\(.*\+",                    # Command with concatenation
            r"subprocess\.(run|call|Popen)\(.*\+",  # Python subprocess
            r"child_process\.exec\(.*\+",          # Node.js command injection
            r"os\.system\(.*\+",                   # Python os.system
        ],
        "path_traversal": [
            r"open\s*\(.*\+.*\)",                  # File open with concatenation
            r"file_get_contents\s*\(.*\$",         # PHP file read
            r"include\s*\(.*\$_(GET|POST)",        # PHP include injection
            r"readFile\s*\(.*\+",                  # Node.js file read
        ],
        "xss": [
            r"innerHTML\s*=\s*.*\+",               # DOM XSS
            r"document\.write\s*\(.*\+",           # document.write XSS
            r"echo\s+\$_(GET|POST|REQUEST)",       # PHP reflected XSS
            r"\.html\(.*\$",                       # jQuery XSS
        ],
        "deserialization": [
            r"pickle\.loads?\s*\(",                # Python pickle
            r"unserialize\s*\(",                   # PHP unserialize
            r"ObjectInputStream",                  # Java deserialization
            r"yaml\.load\s*\(",                    # Python YAML unsafe load
        ],
    }
    
    # File extensions to analyze
    ANALYZABLE_EXTENSIONS = {
        ".py", ".php", ".js", ".ts", ".jsx", ".tsx", ".java", ".rb", 
        ".go", ".rs", ".c", ".cpp", ".h", ".cs", ".asp", ".aspx",
        ".jsp", ".vue", ".svelte"
    }
    
    def __init__(self, ai_core=None, work_dir: str = "/tmp/aegis_hybrid"):
        """
        Initialize the Hybrid Analysis Engine.
        
        Args:
            ai_core: EnhancedAegisAI instance for LLM access
            work_dir: Directory for cloned repositories
        """
        self.ai_core = ai_core
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        self.analysis_cache: Dict[str, SourceCodeAnalysis] = {}
        self._analysis_counter = 0
        
        # Robustness: Import timeout and circuit breaker utilities
        try:
            from utils.robustness import (
                get_timeout_manager,
                get_circuit_breaker,
                get_bottleneck_detector
            )
            self._timeout_mgr = get_timeout_manager()
            self._circuit = get_circuit_breaker("hybrid_analysis")
            self._bottleneck = get_bottleneck_detector()
        except ImportError:
            self._timeout_mgr = None
            self._circuit = None
            self._bottleneck = None
        
        logger.info("🔬 Hybrid Analysis Engine initialized")
    
    async def detect_source_exposure(
        self,
        target_url: str,
        session: Optional[aiohttp.ClientSession] = None
    ) -> Dict[str, Any]:
        """
        Detect if target has exposed source code or open source components.
        
        Args:
            target_url: Base URL of the target
            session: Optional aiohttp session
            
        Returns:
            Dictionary with detection results
        """
        logger.info(f"🔍 Scanning for source code exposure: {target_url}")
        
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        detections = {
            "git_exposed": False,
            "git_config_content": None,
            "open_source_files": [],
            "potential_repo_url": None,
            "technologies": [],
        }
        
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            # Check for .git directory exposure
            git_paths = [
                "/.git/",
                "/.git/config",
                "/.git/HEAD",
                "/.git/index",
                "/.git/logs/HEAD",
            ]
            
            for path in git_paths:
                try:
                    async with session.get(
                        urljoin(base_url, path),
                        timeout=aiohttp.ClientTimeout(total=10),
                        allow_redirects=False,
                        ssl=False
                    ) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            
                            if path == "/.git/config":
                                detections["git_exposed"] = True
                                detections["git_config_content"] = content
                                
                                # Extract remote URL from config
                                remote_match = re.search(
                                    r'url\s*=\s*(https?://[^\s]+|git@[^\s]+)',
                                    content
                                )
                                if remote_match:
                                    repo_url = remote_match.group(1)
                                    # Convert SSH URL to HTTPS
                                    if repo_url.startswith("git@"):
                                        repo_url = repo_url.replace(
                                            "git@github.com:",
                                            "https://github.com/"
                                        ).rstrip(".git")
                                    detections["potential_repo_url"] = repo_url
                                
                                logger.info(f"✅ .git/config exposed at {target_url}")
                                
                            elif path == "/.git/HEAD":
                                detections["git_exposed"] = True
                                logger.info(f"✅ .git/HEAD exposed at {target_url}")
                                
                except Exception as e:
                    logger.debug(f"Error checking {path}: {e}")
            
            # Check for common open source files
            for filename, tech in self.OPENSOURCE_INDICATORS.items():
                if filename.startswith(".git"):
                    continue  # Already checked
                    
                try:
                    async with session.get(
                        urljoin(base_url, f"/{filename}"),
                        timeout=aiohttp.ClientTimeout(total=10),
                        allow_redirects=False,
                        ssl=False
                    ) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            
                            # Verify it's not a 404 page with 200 status
                            if "<!DOCTYPE" not in content[:100].lower():
                                detections["open_source_files"].append({
                                    "file": filename,
                                    "technology": tech,
                                    "content_preview": content[:500]
                                })
                                
                                if tech not in detections["technologies"]:
                                    detections["technologies"].append(tech)
                                    
                                logger.info(f"✅ Found {filename} ({tech})")
                                
                except Exception as e:
                    logger.debug(f"Error checking {filename}: {e}")
            
        finally:
            if close_session:
                await session.close()
        
        return detections
    
    async def clone_repository(
        self,
        repo_url: str,
        depth: int = 1
    ) -> Optional[str]:
        """
        Clone a repository for analysis.
        
        Args:
            repo_url: URL of the repository to clone
            depth: Git clone depth (shallow clone)
            
        Returns:
            Local path to cloned repository, or None if failed
        """
        logger.info(f"📥 Cloning repository: {repo_url}")
        
        # Generate unique directory name
        self._analysis_counter += 1
        repo_name = urlparse(repo_url).path.strip("/").replace("/", "_")
        local_path = self.work_dir / f"{repo_name}_{self._analysis_counter}"
        
        try:
            # Clean URL (remove .git suffix if present for https URLs)
            clean_url = repo_url
            if clean_url.endswith(".git"):
                clean_url = clean_url[:-4]
            if not clean_url.startswith(("http://", "https://", "git@")):
                clean_url = f"https://{clean_url}"
            
            # Clone with depth limit
            cmd = [
                "git", "clone",
                "--depth", str(depth),
                "--single-branch",
                clean_url,
                str(local_path)
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.GIT_CLONE_TIMEOUT
            )
            
            if process.returncode == 0:
                logger.info(f"✅ Repository cloned to {local_path}")
                return str(local_path)
            else:
                error = stderr.decode('utf-8', errors='replace')
                logger.warning(f"Failed to clone repository: {error}")
                return None
                
        except asyncio.TimeoutError:
            logger.error("Repository clone timed out")
            return None
        except Exception as e:
            logger.error(f"Error cloning repository: {e}")
            return None
    
    async def reconstruct_from_git(
        self,
        target_url: str
    ) -> Optional[str]:
        """
        Reconstruct source code from exposed .git directory.
        
        Uses git-dumper or similar technique to recover source code
        when .git is exposed but directory listing is disabled.
        
        Args:
            target_url: URL with exposed .git
            
        Returns:
            Local path to reconstructed repository, or None if failed
        """
        logger.info(f"🔧 Attempting to reconstruct from .git: {target_url}")
        
        # Generate unique directory name
        self._analysis_counter += 1
        parsed = urlparse(target_url)
        repo_name = parsed.netloc.replace(".", "_")
        local_path = self.work_dir / f"{repo_name}_reconstructed_{self._analysis_counter}"
        
        try:
            # Check if git-dumper is available
            git_dumper = shutil.which("git-dumper")
            
            if git_dumper:
                # Use git-dumper
                cmd = [git_dumper, target_url.rstrip("/") + "/.git", str(local_path)]
            else:
                # Fallback: Manual reconstruction
                logger.info("git-dumper not found, using manual reconstruction")
                return await self._manual_git_reconstruction(target_url, local_path)
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=120  # 2 minute timeout
            )
            
            if process.returncode == 0 and local_path.exists():
                logger.info(f"✅ Repository reconstructed to {local_path}")
                return str(local_path)
            else:
                logger.warning(f"Failed to reconstruct repository")
                return None
                
        except Exception as e:
            logger.error(f"Error reconstructing from .git: {e}")
            return None
    
    async def _manual_git_reconstruction(
        self,
        target_url: str,
        local_path: Path
    ) -> Optional[str]:
        """
        Manually reconstruct git repository by downloading objects.
        
        Args:
            target_url: URL with exposed .git
            local_path: Local path to save reconstructed repo
            
        Returns:
            Local path if successful, None otherwise
        """
        local_path.mkdir(parents=True, exist_ok=True)
        git_dir = local_path / ".git"
        git_dir.mkdir(exist_ok=True)
        
        base_url = target_url.rstrip("/") + "/.git"
        
        async with aiohttp.ClientSession() as session:
            try:
                # Download essential git files
                essential_files = [
                    "HEAD",
                    "config",
                    "index",
                    "packed-refs",
                    "objects/info/packs",
                ]
                
                for file_path in essential_files:
                    try:
                        async with session.get(
                            f"{base_url}/{file_path}",
                            timeout=aiohttp.ClientTimeout(total=10),
                            ssl=False
                        ) as resp:
                            if resp.status == 200:
                                content = await resp.read()
                                file_local = git_dir / file_path
                                file_local.parent.mkdir(parents=True, exist_ok=True)
                                file_local.write_bytes(content)
                    except Exception:
                        pass
                
                # Try to checkout HEAD
                cmd = ["git", "-C", str(local_path), "checkout", "-f"]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
                
                # Check if we got any source files
                source_files = list(local_path.glob("**/*.*"))
                if source_files:
                    logger.info(f"✅ Recovered {len(source_files)} files")
                    return str(local_path)
                else:
                    logger.warning("No source files recovered")
                    return None
                    
            except Exception as e:
                logger.error(f"Manual reconstruction failed: {e}")
                return None
    
    async def analyze_source_code(
        self,
        local_path: str,
        target_context: Optional[Dict[str, Any]] = None
    ) -> SourceCodeAnalysis:
        """
        Analyze source code for vulnerabilities using Code LLM.
        
        Args:
            local_path: Path to the source code directory
            target_context: Optional context about the target
            
        Returns:
            SourceCodeAnalysis with identified vulnerabilities
        """
        logger.info(f"🔬 Analyzing source code: {local_path}")
        
        path = Path(local_path)
        if not path.exists():
            raise ValueError(f"Path does not exist: {local_path}")
        
        vulnerabilities = []
        technologies = []
        entry_points = []
        security_findings = {}
        
        # Step 1: Identify technologies
        for filename, tech in self.OPENSOURCE_INDICATORS.items():
            if (path / filename).exists():
                technologies.append(tech)
        
        # Step 2: Collect source files for analysis
        source_files = []
        for ext in self.ANALYZABLE_EXTENSIONS:
            source_files.extend(path.glob(f"**/*{ext}"))
        
        # Limit to first 50 files to avoid token limits
        source_files = source_files[:50]
        
        logger.info(f"📁 Found {len(source_files)} source files to analyze")
        
        # Step 3: Quick pattern-based scan
        pattern_findings = await self._pattern_based_scan(source_files)
        
        # Step 4: LLM-based deep analysis for files with pattern matches
        if self.ai_core and pattern_findings:
            llm_findings = await self._llm_code_analysis(
                pattern_findings,
                target_context
            )
            vulnerabilities.extend(llm_findings)
        else:
            # Convert pattern findings to VulnerableCodeLocation
            for finding in pattern_findings:
                vulnerabilities.append(VulnerableCodeLocation(
                    file_path=finding["file"],
                    line_number=finding["line"],
                    code_snippet=finding["snippet"],
                    vulnerability_type=finding["vuln_type"],
                    severity=finding.get("severity", "medium"),
                    confidence=finding.get("confidence", 0.6),
                    explanation=f"Pattern match for {finding['vuln_type']}",
                    payload_suggestions=[]
                ))
        
        # Step 5: Identify entry points (routes, endpoints)
        entry_points = await self._extract_entry_points(source_files, technologies)
        
        analysis = SourceCodeAnalysis(
            repo_url=local_path,
            local_path=local_path,
            vulnerabilities=vulnerabilities,
            technologies=technologies,
            entry_points=entry_points,
            security_findings=security_findings
        )
        
        # Cache the analysis
        self.analysis_cache[local_path] = analysis
        
        logger.info(f"✅ Analysis complete: {len(vulnerabilities)} vulnerabilities, "
                   f"{len(entry_points)} entry points")
        
        return analysis
    
    async def _pattern_based_scan(
        self,
        source_files: List[Path]
    ) -> List[Dict[str, Any]]:
        """
        Quick pattern-based vulnerability scan.
        
        Args:
            source_files: List of source file paths
            
        Returns:
            List of pattern match findings
        """
        findings = []
        
        for file_path in source_files:
            try:
                content = file_path.read_text(errors='ignore')
                lines = content.split('\n')
                
                for vuln_type, patterns in self.VULNERABLE_PATTERNS.items():
                    for pattern in patterns:
                        try:
                            regex = re.compile(pattern, re.IGNORECASE)
                            
                            for line_num, line in enumerate(lines, 1):
                                if regex.search(line):
                                    # Get context (5 lines before and after)
                                    start = max(0, line_num - 6)
                                    end = min(len(lines), line_num + 5)
                                    snippet = '\n'.join(lines[start:end])
                                    
                                    findings.append({
                                        "file": str(file_path),
                                        "line": line_num,
                                        "snippet": snippet,
                                        "vuln_type": vuln_type,
                                        "pattern": pattern,
                                        "severity": self._get_severity(vuln_type),
                                        "confidence": 0.6
                                    })
                                    
                        except re.error:
                            continue
                            
            except Exception as e:
                logger.debug(f"Error scanning {file_path}: {e}")
        
        return findings
    
    def _get_severity(self, vuln_type: str) -> str:
        """Get severity for vulnerability type"""
        severity_map = {
            "sql_injection": "critical",
            "command_injection": "critical",
            "deserialization": "critical",
            "path_traversal": "high",
            "xss": "medium",
        }
        return severity_map.get(vuln_type, "medium")
    
    async def _llm_code_analysis(
        self,
        pattern_findings: List[Dict[str, Any]],
        target_context: Optional[Dict[str, Any]]
    ) -> List[VulnerableCodeLocation]:
        """
        Use LLM to analyze code snippets and generate targeted payloads.
        
        Args:
            pattern_findings: Findings from pattern scan
            target_context: Context about the target
            
        Returns:
            List of VulnerableCodeLocation with LLM analysis
        """
        vulnerabilities = []
        
        if not self.ai_core or not self.ai_core.is_initialized:
            logger.warning("AI core not available for LLM analysis")
            return vulnerabilities
        
        # Group findings by file for efficiency
        findings_by_file = {}
        for finding in pattern_findings:
            file_path = finding["file"]
            if file_path not in findings_by_file:
                findings_by_file[file_path] = []
            findings_by_file[file_path].append(finding)
        
        # Analyze each file's findings
        for file_path, file_findings in list(findings_by_file.items())[:10]:  # Limit to 10 files
            analysis_prompt = f"""You are a security code reviewer. Analyze these potential vulnerabilities found in source code.

FILE: {file_path}
TARGET CONTEXT: {json.dumps(target_context or {}, indent=2)}

POTENTIAL VULNERABILITIES:
"""
            for i, finding in enumerate(file_findings[:5], 1):  # Limit to 5 findings per file
                analysis_prompt += f"""
--- Finding {i} ---
Type: {finding['vuln_type']}
Line: {finding['line']}
Code Snippet:
```
{finding['snippet']}
```
"""
            
            analysis_prompt += """
For EACH finding, provide:
1. Is this a REAL vulnerability or a false positive? Explain why.
2. What is the exact vulnerable line and function?
3. How can it be exploited? Provide specific steps.
4. Generate 2-3 SPECIFIC payloads that would work for this exact code.

Respond in JSON format:
{
    "findings": [
        {
            "finding_index": 1,
            "is_vulnerable": true|false,
            "vulnerability_type": "type",
            "severity": "critical|high|medium|low",
            "confidence": 0.0-1.0,
            "vulnerable_line": 42,
            "explanation": "Why this is/isn't vulnerable",
            "cwe_id": "CWE-89",
            "exploitation_steps": ["step1", "step2"],
            "payloads": [
                {"payload": "actual payload", "description": "what it does"}
            ]
        }
    ]
}
"""
            
            try:
                response = await self.ai_core.call_code_specialist(
                    prompt=analysis_prompt,
                    context="Source code security analysis for payload generation",
                    temperature=0.4
                )
                
                content = response.get("content", "")
                
                # Parse JSON response
                from agents.enhanced_ai_core import parse_json_robust
                result = await parse_json_robust(
                    content,
                    self.ai_core.orchestrator,
                    "Code vulnerability analysis"
                )
                
                if result and "findings" in result:
                    for finding_result in result["findings"]:
                        if finding_result.get("is_vulnerable", False):
                            idx = finding_result.get("finding_index", 1) - 1
                            if 0 <= idx < len(file_findings):
                                original = file_findings[idx]
                                
                                payloads = [
                                    p.get("payload", "")
                                    for p in finding_result.get("payloads", [])
                                ]
                                
                                vulnerabilities.append(VulnerableCodeLocation(
                                    file_path=file_path,
                                    line_number=finding_result.get(
                                        "vulnerable_line",
                                        original.get("line", 0)
                                    ),
                                    code_snippet=original.get("snippet", ""),
                                    vulnerability_type=finding_result.get(
                                        "vulnerability_type",
                                        original.get("vuln_type", "unknown")
                                    ),
                                    severity=finding_result.get("severity", "medium"),
                                    confidence=finding_result.get("confidence", 0.7),
                                    explanation=finding_result.get("explanation", ""),
                                    cwe_id=finding_result.get("cwe_id"),
                                    payload_suggestions=payloads
                                ))
                                
            except Exception as e:
                logger.error(f"LLM analysis failed for {file_path}: {e}")
        
        return vulnerabilities
    
    async def _extract_entry_points(
        self,
        source_files: List[Path],
        technologies: List[str]
    ) -> List[str]:
        """
        Extract API endpoints and routes from source code.
        
        Args:
            source_files: List of source file paths
            technologies: Detected technologies
            
        Returns:
            List of entry point strings (routes, endpoints)
        """
        entry_points = []
        
        # Patterns for common frameworks
        route_patterns = {
            "python": [
                r'@app\.route\([\'"]([^\'"]+)[\'"]',     # Flask
                r'@router\.(get|post|put|delete)\([\'"]([^\'"]+)[\'"]',  # FastAPI
                r'path\([\'"]([^\'"]+)[\'"]',            # Django
            ],
            "nodejs": [
                r'app\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]',  # Express
                r'router\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]',
            ],
            "php": [
                r'Route::(get|post|put|delete)\([\'"]([^\'"]+)[\'"]',  # Laravel
            ],
            "java": [
                r'@(Get|Post|Put|Delete)Mapping\([\'"]([^\'"]+)[\'"]',  # Spring
                r'@Path\([\'"]([^\'"]+)[\'"]',           # JAX-RS
            ],
        }
        
        for file_path in source_files:
            try:
                content = file_path.read_text(errors='ignore')
                
                for tech_patterns in route_patterns.values():
                    for pattern in tech_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if isinstance(match, tuple):
                                # Route with method
                                route = match[-1]  # Last group is the route
                            else:
                                route = match
                            
                            if route and route not in entry_points:
                                entry_points.append(route)
                                
            except Exception as e:
                logger.debug(f"Error extracting entry points from {file_path}: {e}")
        
        return entry_points[:100]  # Limit to 100 entry points
    
    async def generate_targeted_payloads(
        self,
        vulnerability: VulnerableCodeLocation,
        target_url: str
    ) -> List[Dict[str, Any]]:
        """
        Generate targeted payloads for a specific vulnerability.
        
        Args:
            vulnerability: The vulnerability to generate payloads for
            target_url: The target URL
            
        Returns:
            List of payload dictionaries with test information
        """
        payloads = []
        
        # Start with LLM-generated payloads
        for payload in vulnerability.payload_suggestions:
            payloads.append({
                "payload": payload,
                "source": "llm_generated",
                "vulnerability_type": vulnerability.vulnerability_type,
                "target_line": vulnerability.line_number,
                "confidence": vulnerability.confidence
            })
        
        # Generate additional payloads if AI core available
        if self.ai_core and self.ai_core.is_initialized:
            payload_prompt = f"""Generate 5 specific attack payloads for this vulnerability:

VULNERABILITY TYPE: {vulnerability.vulnerability_type}
SEVERITY: {vulnerability.severity}
CWE: {vulnerability.cwe_id or 'Unknown'}

VULNERABLE CODE:
```
{vulnerability.code_snippet}
```

EXPLANATION:
{vulnerability.explanation}

TARGET URL: {target_url}

Generate payloads that:
1. Are specifically crafted for this exact code pattern
2. Would bypass common WAF rules
3. Include both detection and exploitation variants
4. Are safe for authorized testing

Respond with JSON:
{{
    "payloads": [
        {{
            "payload": "the actual payload string",
            "purpose": "what this payload tests/does",
            "expected_behavior": "what happens if vulnerable",
            "waf_evasion": "any WAF bypass techniques used"
        }}
    ]
}}
"""
            
            try:
                response = await self.ai_core.call_code_specialist(
                    prompt=payload_prompt,
                    context="Targeted payload generation from source code analysis",
                    temperature=0.6
                )
                
                from agents.enhanced_ai_core import parse_json_robust
                result = await parse_json_robust(
                    response.get("content", ""),
                    self.ai_core.orchestrator,
                    "Payload generation"
                )
                
                if result and "payloads" in result:
                    for p in result["payloads"]:
                        payloads.append({
                            "payload": p.get("payload", ""),
                            "source": "llm_targeted",
                            "purpose": p.get("purpose", ""),
                            "expected_behavior": p.get("expected_behavior", ""),
                            "waf_evasion": p.get("waf_evasion", ""),
                            "vulnerability_type": vulnerability.vulnerability_type,
                            "confidence": 0.8
                        })
                        
            except Exception as e:
                logger.error(f"Failed to generate additional payloads: {e}")
        
        return payloads
    
    async def full_hybrid_analysis(
        self,
        target_url: str,
        session: Optional[aiohttp.ClientSession] = None
    ) -> Dict[str, Any]:
        """
        Perform full hybrid analysis workflow.
        
        1. Detect source code exposure
        2. Clone/reconstruct repository
        3. Analyze code for vulnerabilities
        4. Generate targeted payloads
        
        Args:
            target_url: Target URL to analyze
            session: Optional aiohttp session
            
        Returns:
            Complete hybrid analysis results
        """
        logger.info(f"🚀 Starting full hybrid analysis for {target_url}")
        
        results = {
            "target_url": target_url,
            "source_exposure": None,
            "repository_cloned": False,
            "local_path": None,
            "analysis": None,
            "vulnerabilities": [],
            "targeted_payloads": [],
            "entry_points": [],
            "recommendations": []
        }
        
        # Step 1: Detect source exposure
        detection = await self.detect_source_exposure(target_url, session)
        results["source_exposure"] = detection
        
        local_path = None
        
        # Step 2: Get source code
        if detection.get("potential_repo_url"):
            # Clone from remote repository
            local_path = await self.clone_repository(detection["potential_repo_url"])
            
        elif detection.get("git_exposed"):
            # Reconstruct from exposed .git
            local_path = await self.reconstruct_from_git(target_url)
        
        if local_path:
            results["repository_cloned"] = True
            results["local_path"] = local_path
            
            # Step 3: Analyze source code
            try:
                analysis = await self.analyze_source_code(
                    local_path,
                    {"target_url": target_url, "detection": detection}
                )
                results["analysis"] = {
                    "technologies": analysis.technologies,
                    "entry_points": analysis.entry_points,
                    "vulnerabilities_count": len(analysis.vulnerabilities)
                }
                results["entry_points"] = analysis.entry_points
                
                # Step 4: Generate targeted payloads for each vulnerability
                for vuln in analysis.vulnerabilities:
                    vuln_dict = {
                        "file": vuln.file_path,
                        "line": vuln.line_number,
                        "type": vuln.vulnerability_type,
                        "severity": vuln.severity,
                        "confidence": vuln.confidence,
                        "explanation": vuln.explanation,
                        "cwe_id": vuln.cwe_id
                    }
                    results["vulnerabilities"].append(vuln_dict)
                    
                    # Generate payloads
                    payloads = await self.generate_targeted_payloads(vuln, target_url)
                    for payload in payloads:
                        payload["vulnerability"] = vuln_dict
                        results["targeted_payloads"].append(payload)
                
                # Add recommendations
                if results["vulnerabilities"]:
                    results["recommendations"].append(
                        "Test discovered entry points with generated payloads"
                    )
                    results["recommendations"].append(
                        "Focus on high/critical severity vulnerabilities first"
                    )
                    
            except Exception as e:
                logger.error(f"Analysis failed: {e}")
                results["error"] = str(e)
        else:
            results["recommendations"].append(
                "No source code exposure detected - continue with black-box testing"
            )
        
        logger.info(f"✅ Hybrid analysis complete: {len(results['vulnerabilities'])} vulnerabilities, "
                   f"{len(results['targeted_payloads'])} payloads generated")
        
        return results
    
    def cleanup(self, local_path: Optional[str] = None):
        """
        Clean up cloned repositories.
        
        Args:
            local_path: Specific path to clean, or None to clean all
        """
        if local_path:
            path = Path(local_path)
            if path.exists() and str(path).startswith(str(self.work_dir)):
                shutil.rmtree(path, ignore_errors=True)
                logger.info(f"🗑️ Cleaned up: {local_path}")
        else:
            # Clean all
            for child in self.work_dir.iterdir():
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
            logger.info("🗑️ Cleaned up all temporary repositories")


# Singleton instance
_hybrid_analysis_engine: Optional[HybridAnalysisEngine] = None


def get_hybrid_analysis_engine(ai_core=None) -> HybridAnalysisEngine:
    """Get or create the global hybrid analysis engine instance"""
    global _hybrid_analysis_engine
    if _hybrid_analysis_engine is None:
        _hybrid_analysis_engine = HybridAnalysisEngine(ai_core=ai_core)
    elif ai_core is not None and _hybrid_analysis_engine.ai_core is None:
        _hybrid_analysis_engine.ai_core = ai_core
    return _hybrid_analysis_engine
