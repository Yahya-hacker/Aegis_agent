"""
CTF Mode Manager for Aegis AI v9.1
===================================

This module provides comprehensive CTF (Capture The Flag) support with
specialized tools, strategies, and domain-specific capabilities.

CTF Domains Supported:
- Web Exploitation
- Cryptography  
- Binary Exploitation (Pwn)
- Reverse Engineering
- Forensics
- Steganography
- Network Analysis
- OSINT
- Miscellaneous

Features:
- Automatic challenge type detection
- Domain-specific tool selection
- Flag pattern recognition
- Hint analysis
- Solution verification
"""

import asyncio
import logging
import re
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class CTFDomain(Enum):
    """CTF challenge domains"""
    WEB = "web"
    CRYPTO = "crypto"
    PWN = "pwn"
    REVERSING = "reversing"
    FORENSICS = "forensics"
    STEGO = "stego"
    NETWORK = "network"
    OSINT = "osint"
    MISC = "misc"


@dataclass
class CTFChallenge:
    """Represents a CTF challenge"""
    id: str
    name: str
    domain: CTFDomain
    description: str = ""
    points: int = 0
    files: List[str] = field(default_factory=list)
    hints: List[str] = field(default_factory=list)
    url: Optional[str] = None
    flag_format: Optional[str] = None
    status: str = "unsolved"
    started_at: Optional[str] = None
    solved_at: Optional[str] = None
    flag: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    attempted_tools: List[str] = field(default_factory=list)


@dataclass
class FlagCandidate:
    """A potential flag found during solving"""
    value: str
    source: str  # Where it was found
    confidence: float  # 0.0 to 1.0
    verified: bool = False


class CTFModeManager:
    """
    Manages CTF mode operations with specialized strategies.
    
    Features:
    - Challenge type auto-detection
    - Domain-specific tool recommendations
    - Flag extraction and verification
    - Progress tracking
    """
    
    # Flag patterns for common CTF formats
    FLAG_PATTERNS = [
        r'flag\{[^}]+\}',
        r'FLAG\{[^}]+\}',
        r'ctf\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'picoCTF\{[^}]+\}',
        r'HTB\{[^}]+\}',
        r'DUCTF\{[^}]+\}',
        r'[A-Za-z]+CTF\{[^}]+\}',
        r'[a-f0-9]{32}',  # MD5-like
        r'[a-f0-9]{64}',  # SHA256-like
    ]
    
    # Domain-specific tools
    DOMAIN_TOOLS = {
        CTFDomain.WEB: [
            'crawl_and_map_application',
            'vulnerability_scan',
            'run_sqlmap',
            'discover_interactables',
            'test_form_payload',
            'fuzz_endpoint',
        ],
        CTFDomain.CRYPTO: [
            'solve_crypto',
            'crack_hash',
        ],
        CTFDomain.PWN: [
            'check_binary_protections',
            'find_rop_gadgets',
            'analyze_binary',
            'disassemble_function',
        ],
        CTFDomain.REVERSING: [
            'analyze_binary',
            'disassemble_function',
        ],
        CTFDomain.FORENSICS: [
            'analyze_file_artifacts',
            'extract_embedded',
            'extract_steghide',
        ],
        CTFDomain.STEGO: [
            'analyze_file_artifacts',
            'extract_steghide',
            'extract_embedded',
        ],
        CTFDomain.NETWORK: [
            'analyze_pcap',
            'follow_tcp_stream',
        ],
        CTFDomain.OSINT: [
            'fetch_url',
            'crawl_and_map_application',
        ],
        CTFDomain.MISC: [
            'solve_crypto',
            'analyze_file_artifacts',
            'fetch_url',
        ],
    }
    
    # Keywords for domain detection
    DOMAIN_KEYWORDS = {
        CTFDomain.WEB: ['web', 'http', 'https', 'javascript', 'xss', 'sql', 'injection', 'cookie', 'session', 'php', 'html'],
        CTFDomain.CRYPTO: ['crypto', 'cipher', 'encrypt', 'decrypt', 'rsa', 'aes', 'hash', 'base64', 'encoding', 'xor'],
        CTFDomain.PWN: ['pwn', 'buffer', 'overflow', 'exploit', 'shellcode', 'rop', 'binary', 'stack', 'heap'],
        CTFDomain.REVERSING: ['reverse', 'crackme', 'keygen', 'malware', 'obfuscate', 'debug', 'assembly'],
        CTFDomain.FORENSICS: ['forensic', 'memory', 'disk', 'carving', 'deleted', 'timeline', 'evidence'],
        CTFDomain.STEGO: ['stego', 'hidden', 'image', 'audio', 'lsb', 'embedded', 'secret'],
        CTFDomain.NETWORK: ['network', 'pcap', 'packet', 'traffic', 'wireshark', 'tcp', 'udp', 'dns'],
        CTFDomain.OSINT: ['osint', 'recon', 'social', 'geolocation', 'metadata', 'dox'],
    }
    
    # File extension to domain mapping
    FILE_EXTENSIONS = {
        CTFDomain.PWN: ['.elf', '.bin', '.exe', '.out'],
        CTFDomain.REVERSING: ['.elf', '.exe', '.apk', '.jar', '.dll', '.so'],
        CTFDomain.FORENSICS: ['.mem', '.img', '.dd', '.raw', '.E01'],
        CTFDomain.STEGO: ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.wav', '.mp3'],
        CTFDomain.NETWORK: ['.pcap', '.pcapng', '.cap'],
        CTFDomain.CRYPTO: ['.enc', '.encrypted', '.cipher'],
    }
    
    def __init__(self, scanner=None, ai_core=None):
        """
        Initialize the CTF Mode Manager.
        
        Args:
            scanner: AegisScanner instance for tool execution
            ai_core: AI core for intelligent analysis
        """
        self.scanner = scanner
        self.ai_core = ai_core
        
        # Challenge management
        self.challenges: Dict[str, CTFChallenge] = {}
        self.active_challenge: Optional[str] = None
        
        # Flag tracking
        self.found_flags: List[FlagCandidate] = []
        self.submitted_flags: Set[str] = set()
        
        # CTF metadata
        self.ctf_name: Optional[str] = None
        self.flag_format: Optional[str] = None
        self.team_name: Optional[str] = None
        
        # Statistics
        self.challenges_solved = 0
        self.total_points = 0
        
        logger.info("🏁 CTF Mode Manager initialized")
    
    def set_ctf_config(
        self,
        ctf_name: str,
        flag_format: Optional[str] = None,
        team_name: Optional[str] = None
    ) -> None:
        """Configure CTF-specific settings"""
        self.ctf_name = ctf_name
        self.flag_format = flag_format
        self.team_name = team_name
        
        if flag_format:
            # Add custom flag pattern
            self.FLAG_PATTERNS.insert(0, flag_format.replace('{flag}', r'[^}]+'))
        
        logger.info(f"🏁 CTF configured: {ctf_name}")
    
    async def add_challenge(
        self,
        challenge_id: str,
        name: str,
        description: str = "",
        domain: Optional[CTFDomain] = None,
        points: int = 0,
        files: Optional[List[str]] = None,
        hints: Optional[List[str]] = None,
        url: Optional[str] = None
    ) -> CTFChallenge:
        """
        Add a CTF challenge.
        
        Args:
            challenge_id: Unique identifier
            name: Challenge name
            description: Challenge description
            domain: Challenge domain (auto-detected if None)
            points: Point value
            files: Associated files
            hints: Available hints
            url: Challenge URL (for web challenges)
            
        Returns:
            The created challenge
        """
        # Auto-detect domain if not specified
        if domain is None:
            domain = await self._detect_domain(name, description, files or [], url)
        
        challenge = CTFChallenge(
            id=challenge_id,
            name=name,
            domain=domain,
            description=description,
            points=points,
            files=files or [],
            hints=hints or [],
            url=url,
            flag_format=self.flag_format
        )
        
        self.challenges[challenge_id] = challenge
        logger.info(f"🎯 Challenge added: {name} ({domain.value})")
        
        return challenge
    
    async def _detect_domain(
        self,
        name: str,
        description: str,
        files: List[str],
        url: Optional[str]
    ) -> CTFDomain:
        """Auto-detect challenge domain from available information"""
        text = f"{name} {description}".lower()
        
        # Check URL first
        if url:
            return CTFDomain.WEB
        
        # Check file extensions
        for file_path in files:
            ext = Path(file_path).suffix.lower()
            for domain, extensions in self.FILE_EXTENSIONS.items():
                if ext in extensions:
                    return domain
        
        # Check keywords
        scores = {domain: 0 for domain in CTFDomain}
        for domain, keywords in self.DOMAIN_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text:
                    scores[domain] += 1
        
        # Return highest scoring domain
        if max(scores.values()) > 0:
            return max(scores.items(), key=lambda x: x[1])[0]
        
        return CTFDomain.MISC
    
    async def start_challenge(self, challenge_id: str) -> Dict[str, Any]:
        """
        Start working on a challenge.
        
        Returns recommended tools and initial analysis.
        """
        if challenge_id not in self.challenges:
            return {'status': 'error', 'error': 'Challenge not found'}
        
        challenge = self.challenges[challenge_id]
        challenge.status = 'in_progress'
        challenge.started_at = datetime.now().isoformat()
        self.active_challenge = challenge_id
        
        logger.info(f"🚀 Starting challenge: {challenge.name}")
        
        # Get recommended tools
        recommended_tools = self.DOMAIN_TOOLS.get(challenge.domain, [])
        
        # Build initial strategy
        strategy = await self._build_strategy(challenge)
        
        return {
            'status': 'started',
            'challenge': {
                'id': challenge.id,
                'name': challenge.name,
                'domain': challenge.domain.value,
                'points': challenge.points
            },
            'recommended_tools': recommended_tools,
            'strategy': strategy,
            'hints_available': len(challenge.hints)
        }
    
    async def _build_strategy(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """Build an initial strategy for the challenge"""
        domain = challenge.domain
        
        strategies = {
            CTFDomain.WEB: {
                'steps': [
                    'Explore the web application manually',
                    'Run directory brute-force',
                    'Check for common vulnerabilities (SQLi, XSS, SSTI)',
                    'Analyze JavaScript for hints',
                    'Check cookies and session handling'
                ],
                'priority_tools': ['crawl_and_map_application', 'vulnerability_scan', 'run_sqlmap']
            },
            CTFDomain.CRYPTO: {
                'steps': [
                    'Identify the cipher/encoding type',
                    'Check for known cipher patterns',
                    'Attempt frequency analysis',
                    'Try common keys and passwords',
                    'Look for mathematical weaknesses'
                ],
                'priority_tools': ['solve_crypto', 'crack_hash']
            },
            CTFDomain.PWN: {
                'steps': [
                    'Check binary protections',
                    'Analyze vulnerable functions',
                    'Find buffer overflow points',
                    'Look for ROP gadgets',
                    'Build exploit payload'
                ],
                'priority_tools': ['check_binary_protections', 'find_rop_gadgets', 'analyze_binary']
            },
            CTFDomain.REVERSING: {
                'steps': [
                    'Static analysis with strings/objdump',
                    'Identify main function logic',
                    'Look for anti-debugging tricks',
                    'Dynamic analysis with debugger',
                    'Understand key validation'
                ],
                'priority_tools': ['analyze_binary', 'disassemble_function']
            },
            CTFDomain.FORENSICS: {
                'steps': [
                    'Extract file metadata',
                    'Check for embedded files',
                    'Analyze file headers',
                    'Look for deleted data',
                    'Timeline analysis'
                ],
                'priority_tools': ['analyze_file_artifacts', 'extract_embedded']
            },
            CTFDomain.STEGO: {
                'steps': [
                    'Check file metadata and headers',
                    'Extract LSB data from images',
                    'Try common steganography passwords',
                    'Analyze audio spectrograms',
                    'Check for appended data'
                ],
                'priority_tools': ['analyze_file_artifacts', 'extract_steghide']
            },
            CTFDomain.NETWORK: {
                'steps': [
                    'Overview of packet capture',
                    'Follow TCP streams',
                    'Extract transferred files',
                    'Look for credentials',
                    'Analyze protocol specifics'
                ],
                'priority_tools': ['analyze_pcap', 'follow_tcp_stream']
            },
        }
        
        return strategies.get(domain, {
            'steps': ['Analyze the challenge description', 'Identify relevant tools', 'Experiment and iterate'],
            'priority_tools': self.DOMAIN_TOOLS.get(domain, [])
        })
    
    async def analyze_for_flags(
        self,
        content: str,
        source: str = "unknown"
    ) -> List[FlagCandidate]:
        """
        Analyze content for potential flags.
        
        Args:
            content: Text content to analyze
            source: Where this content came from
            
        Returns:
            List of potential flags found
        """
        candidates = []
        
        for pattern in self.FLAG_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                # Skip if already submitted
                if match in self.submitted_flags:
                    continue
                
                confidence = self._calculate_flag_confidence(match)
                
                candidate = FlagCandidate(
                    value=match,
                    source=source,
                    confidence=confidence
                )
                candidates.append(candidate)
                self.found_flags.append(candidate)
                
                logger.info(f"🚩 Potential flag found: {match[:20]}... (confidence: {confidence:.0%})")
        
        return candidates
    
    def _calculate_flag_confidence(self, flag: str) -> float:
        """Calculate confidence score for a potential flag"""
        confidence = 0.5
        
        # Check against custom flag format
        if self.flag_format:
            prefix = self.flag_format.split('{')[0]
            if flag.startswith(prefix):
                confidence += 0.3
        
        # Check common flag patterns
        if re.match(r'^[A-Za-z]+\{.*\}$', flag):
            confidence += 0.2
        
        # Length checks
        if 10 <= len(flag) <= 100:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    async def submit_flag(
        self,
        flag: str,
        challenge_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Submit a flag (in a real CTF, this would hit the scoreboard).
        
        Args:
            flag: The flag to submit
            challenge_id: Challenge this flag is for
            
        Returns:
            Submission result
        """
        challenge_id = challenge_id or self.active_challenge
        
        if challenge_id and challenge_id in self.challenges:
            challenge = self.challenges[challenge_id]
            challenge.flag = flag
            challenge.status = 'solved'
            challenge.solved_at = datetime.now().isoformat()
            
            self.challenges_solved += 1
            self.total_points += challenge.points
            
            logger.info(f"🏆 Challenge solved: {challenge.name} (+{challenge.points} pts)")
        
        self.submitted_flags.add(flag)
        
        return {
            'status': 'submitted',
            'flag': flag,
            'challenge_id': challenge_id,
            'total_solved': self.challenges_solved,
            'total_points': self.total_points
        }
    
    def get_recommended_tools(
        self,
        challenge_id: Optional[str] = None
    ) -> List[str]:
        """Get recommended tools for a challenge"""
        challenge_id = challenge_id or self.active_challenge
        
        if not challenge_id or challenge_id not in self.challenges:
            return []
        
        challenge = self.challenges[challenge_id]
        return self.DOMAIN_TOOLS.get(challenge.domain, [])
    
    def get_ctf_stats(self) -> Dict[str, Any]:
        """Get CTF progress statistics"""
        return {
            'ctf_name': self.ctf_name,
            'team_name': self.team_name,
            'challenges_total': len(self.challenges),
            'challenges_solved': self.challenges_solved,
            'challenges_in_progress': sum(
                1 for c in self.challenges.values()
                if c.status == 'in_progress'
            ),
            'total_points': self.total_points,
            'flags_found': len(self.found_flags),
            'flags_submitted': len(self.submitted_flags),
            'by_domain': {
                domain.value: {
                    'total': sum(
                        1 for c in self.challenges.values()
                        if c.domain == domain
                    ),
                    'solved': sum(
                        1 for c in self.challenges.values()
                        if c.domain == domain and c.status == 'solved'
                    )
                }
                for domain in CTFDomain
            }
        }
    
    def export_writeup(self, challenge_id: str) -> str:
        """Generate a writeup for a solved challenge"""
        if challenge_id not in self.challenges:
            return "Challenge not found"
        
        challenge = self.challenges[challenge_id]
        
        writeup = f"""# {challenge.name}

**Category:** {challenge.domain.value}  
**Points:** {challenge.points}  
**Status:** {challenge.status}  

## Description

{challenge.description}

## Solution

### Files Analyzed
{chr(10).join(f"- {f}" for f in challenge.files) if challenge.files else "No files provided"}

### Tools Used
{chr(10).join(f"- {t}" for t in challenge.attempted_tools) if challenge.attempted_tools else "No specific tools recorded"}

### Notes
{chr(10).join(f"- {n}" for n in challenge.notes) if challenge.notes else "No notes recorded"}

### Flag
`{challenge.flag or "Not yet solved"}`

---
*Solved at: {challenge.solved_at or "N/A"}*
"""
        return writeup


# Global instance
_ctf_manager: Optional[CTFModeManager] = None


def get_ctf_manager(scanner=None, ai_core=None) -> CTFModeManager:
    """Get the global CTF Mode Manager instance"""
    global _ctf_manager
    if _ctf_manager is None:
        _ctf_manager = CTFModeManager(scanner=scanner, ai_core=ai_core)
    elif scanner is not None and _ctf_manager.scanner is None:
        _ctf_manager.scanner = scanner
    elif ai_core is not None and _ctf_manager.ai_core is None:
        _ctf_manager.ai_core = ai_core
    return _ctf_manager
