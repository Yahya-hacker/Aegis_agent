"""
CTF Mode for Aegis Agent
Specialized mode for Capture The Flag competitions across all domains
Version 1.0 - Full-Spectrum CTF Operations
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class CTFDomain(Enum):
    """CTF challenge domains"""
    WEB = "web"
    CRYPTO = "crypto"
    BINARY = "binary"
    REVERSE = "reverse"
    FORENSICS = "forensics"
    NETWORK = "network"
    PWN = "pwn"
    MISC = "misc"
    OSINT = "osint"
    STEGANOGRAPHY = "steganography"


@dataclass
class CTFChallenge:
    """Represents a CTF challenge"""
    challenge_id: str
    name: str
    domain: CTFDomain
    description: str
    points: int
    difficulty: str  # easy, medium, hard
    files: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    hints: List[str] = field(default_factory=list)
    flag_format: Optional[str] = None
    status: str = "pending"  # pending, in_progress, solved, failed
    attempts: int = 0
    start_time: Optional[float] = None
    solve_time: Optional[float] = None
    flag: Optional[str] = None
    solution_path: List[str] = field(default_factory=list)


class CTFMode:
    """
    CTF Mode - Specialized agent mode for CTF competitions.
    
    Features:
    - Multi-domain challenge detection and classification
    - Concurrent challenge solving
    - Domain-specific tool selection
    - Automated flag discovery and validation
    - Progress tracking and strategy adaptation
    """
    
    def __init__(self, ai_core, tools_loader, parallel_engine):
        """
        Initialize CTF mode.
        
        Args:
            ai_core: EnhancedAegisAI instance
            tools_loader: DynamicToolLoader instance
            parallel_engine: ParallelExecutionEngine instance
        """
        self.ai_core = ai_core
        self.tools_loader = tools_loader
        self.parallel_engine = parallel_engine
        self.challenges: Dict[str, CTFChallenge] = {}
        self.active = False
        
        # Domain-specific tool mappings
        self.domain_tools = self._initialize_domain_tools()
        
        # CTF-specific configuration
        self.max_concurrent_challenges = 3
        self.flag_patterns = [
            r'flag\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'[A-Z0-9]{32}',  # MD5-like
            r'picoCTF\{[^}]+\}',
            r'HTB\{[^}]+\}',
        ]
        
        logger.info("✅ CTF Mode initialized")
    
    def _initialize_domain_tools(self) -> Dict[CTFDomain, List[str]]:
        """Initialize domain-specific tool mappings"""
        return {
            CTFDomain.WEB: [
                "genesis_fuzzer",
                "application_spider",
                "visual_recon",
                "sqlmap",
                "nuclei",
                "burpsuite",
                "ffuf",
                "gobuster"
            ],
            CTFDomain.CRYPTO: [
                "ciphey",
                "hashid",
                "john",
                "hashcat",
                "openssl",
                "rsatool",
                "xortool"
            ],
            CTFDomain.BINARY: [
                "checksec",
                "strings",
                "objdump",
                "radare2",
                "ghidra",
                "ida",
                "binary_ninja"
            ],
            CTFDomain.REVERSE: [
                "radare2",
                "ghidra",
                "ida",
                "gdb",
                "ltrace",
                "strace",
                "angr"
            ],
            CTFDomain.FORENSICS: [
                "exiftool",
                "binwalk",
                "steghide",
                "volatility",
                "foremost",
                "autopsy",
                "strings"
            ],
            CTFDomain.NETWORK: [
                "tshark",
                "tcpdump",
                "wireshark",
                "nmap",
                "masscan",
                "scapy"
            ],
            CTFDomain.PWN: [
                "checksec",
                "pwntools",
                "ropper",
                "rop-gadget",
                "gdb",
                "one_gadget"
            ],
            CTFDomain.STEGANOGRAPHY: [
                "steghide",
                "stegsolve",
                "zsteg",
                "exiftool",
                "binwalk",
                "outguess"
            ],
            CTFDomain.OSINT: [
                "subfinder",
                "amass",
                "theHarvester",
                "sherlock",
                "maltego"
            ]
        }
    
    async def activate(self, ctf_name: str = "CTF Competition"):
        """Activate CTF mode"""
        self.active = True
        logger.info(f"🎯 CTF Mode activated for: {ctf_name}")
        
        # Set domain context for LLM optimization
        if hasattr(self.ai_core, 'blackboard'):
            self.ai_core.blackboard.set_domain_context("CTF")
        
        print(f"\n{'='*60}")
        print(f"🎯 AEGIS CTF MODE ACTIVATED")
        print(f"{'='*60}")
        print(f"Competition: {ctf_name}")
        print(f"Max Concurrent: {self.max_concurrent_challenges} challenges")
        print(f"Supported Domains: {', '.join([d.value for d in CTFDomain])}")
        print(f"{'='*60}\n")
    
    async def register_challenge(
        self,
        name: str,
        domain: str,
        description: str,
        points: int = 100,
        difficulty: str = "medium",
        files: Optional[List[str]] = None,
        urls: Optional[List[str]] = None,
        flag_format: Optional[str] = None
    ) -> str:
        """
        Register a CTF challenge.
        
        Args:
            name: Challenge name
            domain: Challenge domain (web, crypto, binary, etc.)
            description: Challenge description
            points: Point value
            difficulty: Difficulty level
            files: List of file paths
            urls: List of URLs
            flag_format: Expected flag format regex
            
        Returns:
            Challenge ID
        """
        challenge_id = f"ctf_{len(self.challenges)}_{name.replace(' ', '_')}"
        
        try:
            domain_enum = CTFDomain(domain.lower())
        except ValueError:
            logger.warning(f"Unknown domain '{domain}', using MISC")
            domain_enum = CTFDomain.MISC
        
        challenge = CTFChallenge(
            challenge_id=challenge_id,
            name=name,
            domain=domain_enum,
            description=description,
            points=points,
            difficulty=difficulty,
            files=files or [],
            urls=urls or [],
            flag_format=flag_format
        )
        
        self.challenges[challenge_id] = challenge
        
        logger.info(f"📝 Challenge registered: {name} ({domain_enum.value}, {points} pts)")
        
        return challenge_id
    
    async def auto_detect_challenges(self, directory: Path) -> List[str]:
        """
        Auto-detect CTF challenges from a directory.
        
        Args:
            directory: Path to directory containing challenges
            
        Returns:
            List of registered challenge IDs
        """
        logger.info(f"🔍 Auto-detecting challenges in: {directory}")
        
        challenge_ids = []
        
        if not directory.exists():
            logger.error(f"Directory not found: {directory}")
            return []
        
        # Look for challenge directories
        for item in directory.iterdir():
            if item.is_dir():
                # Try to detect challenge type from files
                domain = await self._detect_domain(item)
                
                challenge_id = await self.register_challenge(
                    name=item.name,
                    domain=domain.value,
                    description=f"Auto-detected challenge from {item.name}",
                    files=[str(f) for f in item.glob("*") if f.is_file()]
                )
                
                challenge_ids.append(challenge_id)
        
        logger.info(f"✅ Auto-detected {len(challenge_ids)} challenges")
        
        return challenge_ids
    
    async def _detect_domain(self, challenge_dir: Path) -> CTFDomain:
        """Detect challenge domain from files"""
        files = list(challenge_dir.glob("*"))
        
        # Check for binary files
        for f in files:
            if f.is_file():
                # Check file extension
                ext = f.suffix.lower()
                
                if ext in ['.exe', '.elf', '.bin', '.o']:
                    return CTFDomain.BINARY
                elif ext in ['.pcap', '.pcapng', '.cap']:
                    return CTFDomain.NETWORK
                elif ext in ['.jpg', '.png', '.gif', '.bmp']:
                    return CTFDomain.STEGANOGRAPHY
                elif ext in ['.zip', '.tar', '.gz', '.img', '.dd']:
                    return CTFDomain.FORENSICS
                elif ext in ['.py', '.c', '.cpp', '.js']:
                    return CTFDomain.REVERSE
        
        # Default to MISC
        return CTFDomain.MISC
    
    async def solve_all_challenges(self) -> Dict[str, Any]:
        """
        Solve all registered challenges in parallel.
        
        Returns:
            Results summary
        """
        logger.info(f"🚀 Starting to solve {len(self.challenges)} challenges")
        
        # Submit all challenges to parallel engine
        for challenge_id, challenge in self.challenges.items():
            await self.parallel_engine.submit_task(
                task_id=challenge_id,
                name=f"Solve: {challenge.name}",
                coroutine=self._solve_challenge(challenge),
                timeout=1800.0  # 30 minutes per challenge
            )
        
        # Execute with concurrent limit
        results = await self.parallel_engine.execute_all()
        
        # Compile CTF-specific results
        solved = [c for c in self.challenges.values() if c.status == "solved"]
        failed = [c for c in self.challenges.values() if c.status == "failed"]
        
        total_points = sum(c.points for c in solved)
        
        summary = {
            "total_challenges": len(self.challenges),
            "solved": len(solved),
            "failed": len(failed),
            "total_points": total_points,
            "success_rate": f"{(len(solved) / len(self.challenges) * 100):.1f}%",
            "solved_challenges": [
                {
                    "name": c.name,
                    "domain": c.domain.value,
                    "points": c.points,
                    "flag": c.flag,
                    "solve_time": f"{c.solve_time:.2f}s" if c.solve_time else "N/A"
                }
                for c in solved
            ],
            "failed_challenges": [
                {
                    "name": c.name,
                    "domain": c.domain.value,
                    "points": c.points,
                    "attempts": c.attempts
                }
                for c in failed
            ]
        }
        
        logger.info(f"🏆 CTF Results: {len(solved)}/{len(self.challenges)} solved, {total_points} points")
        
        return summary
    
    async def _solve_challenge(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """
        Solve a single CTF challenge.
        
        Args:
            challenge: Challenge to solve
            
        Returns:
            Solution result
        """
        logger.info(f"🎯 Solving: {challenge.name} ({challenge.domain.value})")
        
        challenge.status = "in_progress"
        challenge.start_time = asyncio.get_event_loop().time()
        
        try:
            # Get domain-specific strategy
            strategy = await self._get_domain_strategy(challenge)
            
            # Execute strategy
            result = await self._execute_strategy(challenge, strategy)
            
            if result.get("success") and result.get("flag"):
                challenge.status = "solved"
                challenge.flag = result["flag"]
                challenge.solve_time = asyncio.get_event_loop().time() - challenge.start_time
                challenge.solution_path = result.get("solution_path", [])
                
                logger.info(f"✅ SOLVED: {challenge.name} - Flag: {challenge.flag}")
                
                return {
                    "success": True,
                    "challenge": challenge.name,
                    "flag": challenge.flag,
                    "solve_time": challenge.solve_time
                }
            else:
                challenge.status = "failed"
                logger.warning(f"❌ Failed to solve: {challenge.name}")
                
                return {
                    "success": False,
                    "challenge": challenge.name,
                    "error": result.get("error", "No flag found")
                }
        
        except Exception as e:
            challenge.status = "failed"
            logger.error(f"❌ Error solving {challenge.name}: {e}", exc_info=True)
            
            return {
                "success": False,
                "challenge": challenge.name,
                "error": str(e)
            }
    
    async def _get_domain_strategy(self, challenge: CTFChallenge) -> List[str]:
        """Get solving strategy for challenge domain"""
        
        # Get recommended tools for domain
        recommended_tools = self.domain_tools.get(challenge.domain, [])
        
        # Use AI to create custom strategy
        strategy_prompt = f"""You are a CTF expert solving a {challenge.domain.value} challenge.

Challenge: {challenge.name}
Description: {challenge.description}
Difficulty: {challenge.difficulty}
Files: {', '.join(challenge.files) if challenge.files else 'None'}
URLs: {', '.join(challenge.urls) if challenge.urls else 'None'}

Recommended tools: {', '.join(recommended_tools)}

Create a step-by-step strategy to solve this challenge.
Return a JSON list of steps, each with:
- "action": description of the action
- "tool": tool to use (from recommended list)
- "args": arguments for the tool

Format: {{"steps": [...]}}
"""
        
        try:
            response = await self.ai_core.llm_orchestrator.query_llm(
                prompt=strategy_prompt,
                role="strategic",
                temperature=0.5
            )
            
            # Parse strategy from response
            import json
            strategy_data = json.loads(response)
            return strategy_data.get("steps", [])
            
        except Exception as e:
            logger.error(f"Failed to generate strategy: {e}")
            
            # Return default strategy based on domain
            return self._get_default_strategy(challenge)
    
    def _get_default_strategy(self, challenge: CTFChallenge) -> List[Dict[str, Any]]:
        """Get default strategy for a domain"""
        
        strategies = {
            CTFDomain.WEB: [
                {"action": "Spider website", "tool": "application_spider"},
                {"action": "Find vulnerabilities", "tool": "genesis_fuzzer"},
                {"action": "Test SQL injection", "tool": "sqlmap"}
            ],
            CTFDomain.CRYPTO: [
                {"action": "Identify cipher", "tool": "ciphey"},
                {"action": "Crack hash", "tool": "hashcat"}
            ],
            CTFDomain.BINARY: [
                {"action": "Check protections", "tool": "checksec"},
                {"action": "Extract strings", "tool": "strings"},
                {"action": "Disassemble", "tool": "radare2"}
            ],
            CTFDomain.FORENSICS: [
                {"action": "Extract metadata", "tool": "exiftool"},
                {"action": "Extract embedded files", "tool": "binwalk"},
                {"action": "Find hidden data", "tool": "foremost"}
            ],
            CTFDomain.NETWORK: [
                {"action": "Analyze PCAP", "tool": "tshark"},
                {"action": "Follow TCP streams", "tool": "wireshark"}
            ]
        }
        
        return strategies.get(challenge.domain, [
            {"action": "Analyze with AI", "tool": "ai_analysis"}
        ])
    
    async def _execute_strategy(
        self,
        challenge: CTFChallenge,
        strategy: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Execute a solving strategy"""
        
        solution_path = []
        findings = []
        
        for step in strategy:
            challenge.attempts += 1
            
            logger.info(f"📍 Step {len(solution_path) + 1}: {step.get('action')}")
            solution_path.append(step.get('action'))
            
            # Execute tool
            tool_name = step.get('tool')
            
            if tool_name == "ai_analysis":
                # Use AI for analysis
                result = await self._ai_analysis(challenge, findings)
            else:
                # Execute actual tool
                result = await self._execute_tool(tool_name, challenge, step.get('args', {}))
            
            findings.append(result)
            
            # Check if we found a flag
            flag = self._extract_flag(result)
            if flag:
                return {
                    "success": True,
                    "flag": flag,
                    "solution_path": solution_path,
                    "findings": findings
                }
        
        # No flag found
        return {
            "success": False,
            "error": "No flag found after executing all steps",
            "solution_path": solution_path,
            "findings": findings
        }
    
    async def _execute_tool(
        self,
        tool_name: str,
        challenge: CTFChallenge,
        args: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a specific tool for challenge solving"""
        
        try:
            # Map to actual tool execution
            # This would integrate with the actual tool manager
            logger.info(f"🔧 Executing tool: {tool_name}")
            
            # Placeholder - actual implementation would call the real tool
            return {
                "tool": tool_name,
                "output": f"Tool {tool_name} executed",
                "success": True
            }
            
        except Exception as e:
            logger.error(f"Tool execution failed: {e}")
            return {
                "tool": tool_name,
                "error": str(e),
                "success": False
            }
    
    async def _ai_analysis(
        self,
        challenge: CTFChallenge,
        previous_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Use AI to analyze challenge and previous findings"""
        
        analysis_prompt = f"""Analyze this CTF challenge and suggest the next step.

Challenge: {challenge.name}
Domain: {challenge.domain.value}
Description: {challenge.description}

Previous findings:
{json.dumps(previous_findings, indent=2)}

What should we try next? Provide specific, actionable suggestions.
"""
        
        try:
            response = await self.ai_core.llm_orchestrator.query_llm(
                prompt=analysis_prompt,
                role="reasoning",
                temperature=0.7
            )
            
            return {
                "analysis": response,
                "success": True
            }
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return {
                "error": str(e),
                "success": False
            }
    
    def _extract_flag(self, result: Dict[str, Any]) -> Optional[str]:
        """Extract flag from tool result"""
        import re
        
        # Convert result to string
        result_str = str(result)
        
        # Try each flag pattern
        for pattern in self.flag_patterns:
            match = re.search(pattern, result_str, re.IGNORECASE)
            if match:
                return match.group(0)
        
        return None
    
    def get_challenge_status(self, challenge_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific challenge"""
        if challenge_id not in self.challenges:
            return None
        
        challenge = self.challenges[challenge_id]
        
        return {
            "id": challenge.challenge_id,
            "name": challenge.name,
            "domain": challenge.domain.value,
            "status": challenge.status,
            "points": challenge.points,
            "attempts": challenge.attempts,
            "flag": challenge.flag if challenge.status == "solved" else None,
            "solve_time": f"{challenge.solve_time:.2f}s" if challenge.solve_time else None
        }
    
    def get_scoreboard(self) -> Dict[str, Any]:
        """Get current CTF scoreboard"""
        solved = [c for c in self.challenges.values() if c.status == "solved"]
        total_points = sum(c.points for c in solved)
        
        by_domain = {}
        for c in solved:
            domain = c.domain.value
            if domain not in by_domain:
                by_domain[domain] = {"count": 0, "points": 0}
            by_domain[domain]["count"] += 1
            by_domain[domain]["points"] += c.points
        
        return {
            "total_challenges": len(self.challenges),
            "solved_challenges": len(solved),
            "total_points": total_points,
            "by_domain": by_domain,
            "solved_list": [
                {
                    "name": c.name,
                    "domain": c.domain.value,
                    "points": c.points,
                    "flag": c.flag
                }
                for c in sorted(solved, key=lambda x: x.solve_time or 0)
            ]
        }


# Import for json serialization
import json
