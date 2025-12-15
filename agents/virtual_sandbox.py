#!/usr/bin/env python3
"""
AEGIS OMEGA PROTOCOL - Virtual Sandbox Safety Module
======================================================

Implements safety mechanisms for command execution:
- Pre-Compute: Predict expected HTTP responses before execution
- Atomic Verification: Halt on >20% deviation from prediction
- Dependency Lock: Prevent tool installation mid-mission
- Honeypot Detection: Identify suspicious response patterns

This module ensures the agent doesn't execute "blind" commands.
"""

import asyncio
import logging
import re
import hashlib
import difflib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class VerificationStatus(Enum):
    """Status of response verification"""
    PASSED = "passed"
    WARNING = "warning"
    FAILED = "failed"
    HONEYPOT_SUSPECTED = "honeypot_suspected"


@dataclass
class ResponsePrediction:
    """Prediction for an expected response"""
    expected_status_code: int
    expected_content_patterns: List[str]
    expected_headers: Dict[str, str]
    expected_content_type: Optional[str] = None
    expected_response_time_ms: Optional[int] = None
    anti_patterns: List[str] = field(default_factory=list)  # Patterns that shouldn't appear
    confidence: float = 0.7
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationResult:
    """Result of response verification against prediction"""
    status: VerificationStatus
    deviation_score: float  # 0.0 (exact match) to 1.0 (completely different)
    matches: List[str]      # What matched
    mismatches: List[str]   # What didn't match
    honeypot_indicators: List[str]
    should_halt: bool
    reasoning: str
    timestamp: datetime = field(default_factory=datetime.now)


class VirtualSandbox:
    """
    Virtual Sandbox for safe command execution.
    
    Three core safety mechanisms:
    
    1. PRE-COMPUTE: Predict expected HTTP response or CLI output before execution
    2. ATOMIC VERIFICATION: If actual response deviates >20% from prediction, HALT
    3. DEPENDENCY LOCK: DO NOT install tools mid-mission, use fallbacks
    
    This prevents:
    - Executing against honeypots
    - Triggering WAF traps
    - Running commands with unexpected effects
    """
    
    # Maximum allowed deviation before halting
    DEVIATION_THRESHOLD = 0.20
    
    # Warning threshold (below halt threshold)
    WARNING_THRESHOLD = 0.10
    
    # Honeypot indicators that suggest a trap
    HONEYPOT_INDICATORS = {
        # Too-good responses
        "admin:admin",
        "root:root",
        "test:test",
        "password:password",
        "immediate success",
        "all access granted",
        
        # Suspicious patterns
        "honeypot",
        "canary",
        "trap",
        "decoy",
        "fake_database",
        "fake_admin",
        "test_environment",
        
        # Unusual success patterns
        "you_found_it",
        "congratulations",
        "flag{",
        "CTF{",
    }
    
    # Common response patterns by tool type
    EXPECTED_PATTERNS = {
        "http_request": {
            "success_codes": [200, 201, 204, 301, 302, 304],
            "client_error_codes": [400, 401, 403, 404, 405, 429],
            "server_error_codes": [500, 502, 503, 504],
            "content_patterns": {
                "html": ["<html", "<!DOCTYPE", "<head>", "<body>"],
                "json": ["{", "[", '"'],
                "xml": ["<?xml", "<", ">"]
            }
        },
        "sql_injection_test": {
            "success_indicators": [
                "error", "syntax", "sql", "mysql", "postgres", 
                "oracle", "sqlite", "odbc", "database"
            ],
            "blind_indicators": ["sleep", "delay", "timeout"],
            "anti_patterns": ["too easy", "dummy data"]
        },
        "xss_test": {
            "success_indicators": ["<script>", "alert(", "onerror", "onload"],
            "reflection_patterns": ["reflected", "payload"]
        }
    }
    
    # Blocked installation commands
    BLOCKED_INSTALL_PATTERNS = [
        r"pip\s+install",
        r"npm\s+install",
        r"apt\s+install",
        r"apt-get\s+install",
        r"yum\s+install",
        r"brew\s+install",
        r"gem\s+install",
        r"cargo\s+install",
        r"go\s+install",
        r"curl.*\|\s*sh",
        r"wget.*\|\s*sh",
        r"curl.*\|\s*bash",
        r"wget.*\|\s*bash",
    ]
    
    def __init__(self, deviation_threshold: float = 0.20):
        """
        Initialize the Virtual Sandbox.
        
        Args:
            deviation_threshold: Maximum allowed deviation (default: 20%)
        """
        self.deviation_threshold = deviation_threshold
        self.prediction_history: List[Tuple[ResponsePrediction, Any, VerificationResult]] = []
        self._locked_tools: set = set()
    
    def predict_response(self, action: Dict[str, Any], 
                         context: Optional[Dict[str, Any]] = None) -> ResponsePrediction:
        """
        Pre-compute the expected response for an action.
        
        Args:
            action: The action to predict (tool + args)
            context: Optional context (previous responses, target info)
            
        Returns:
            ResponsePrediction with expected outcomes
        """
        tool = action.get("tool", "")
        args = action.get("args", {})
        
        # Default prediction
        prediction = ResponsePrediction(
            expected_status_code=200,
            expected_content_patterns=[],
            expected_headers={},
            anti_patterns=list(self.HONEYPOT_INDICATORS)
        )
        
        # HTTP request predictions
        if tool in ["http_request", "get_request", "post_request"]:
            url = args.get("url", "")
            method = args.get("method", "GET").upper()
            
            prediction.expected_status_code = 200
            
            # Predict content type based on URL
            if ".json" in url or "/api/" in url:
                prediction.expected_content_type = "application/json"
                prediction.expected_content_patterns = ["{", '"']
            elif ".xml" in url:
                prediction.expected_content_type = "application/xml"
                prediction.expected_content_patterns = ["<?xml", "<"]
            else:
                prediction.expected_content_type = "text/html"
                prediction.expected_content_patterns = ["<", ">"]
            
            # POST should return 200 or 201
            if method == "POST":
                prediction.expected_status_code = 200  # or 201
        
        # SQL injection test predictions
        elif tool == "sql_injection_test":
            # Expect error messages or timing differences, not immediate success
            prediction.expected_content_patterns = [
                "error", "syntax", "mysql", "sql"
            ]
            prediction.anti_patterns.extend([
                "admin access granted",
                "password: admin",
                "all data retrieved"
            ])
        
        # XSS test predictions
        elif tool == "xss_test":
            payload = args.get("payload", "")
            if payload:
                # Expect payload to be reflected or sanitized
                prediction.expected_content_patterns = [payload[:20]]
        
        # Directory scan predictions
        elif tool in ["directory_scan", "directory_bruteforce"]:
            # Expect mix of 200s, 404s, 403s
            prediction.expected_status_code = 404  # Most paths don't exist
            prediction.expected_content_patterns = ["not found", "404"]
        
        # Use context for smarter predictions
        if context:
            previous_response = context.get("last_response", {})
            
            # If we've seen 403 before, expect similar treatment
            if previous_response.get("status_code") == 403:
                prediction.expected_status_code = 403
                prediction.expected_content_patterns.append("forbidden")
            
            # If rate limited, expect continued rate limiting
            if previous_response.get("status_code") == 429:
                prediction.expected_status_code = 429
                prediction.expected_content_patterns.append("rate limit")
        
        logger.info(f"🔮 Pre-computed: Expecting {prediction.expected_status_code}, "
                   f"patterns: {prediction.expected_content_patterns[:3]}")
        
        return prediction
    
    def verify_response(self, prediction: ResponsePrediction, 
                        actual_response: Dict[str, Any]) -> VerificationResult:
        """
        Verify actual response against prediction (Atomic Verification).
        
        If deviation > 20%, HALT and re-evaluate.
        
        Args:
            prediction: The expected response
            actual_response: The actual response received
            
        Returns:
            VerificationResult with deviation analysis
        """
        matches = []
        mismatches = []
        honeypot_indicators = []
        deviation_scores = []
        
        # 1. Status code verification
        actual_status = actual_response.get("status_code", 0)
        if actual_status == prediction.expected_status_code:
            matches.append(f"Status code: {actual_status}")
            deviation_scores.append(0.0)
        else:
            mismatches.append(f"Status code: expected {prediction.expected_status_code}, got {actual_status}")
            
            # Calculate status code deviation
            if actual_status // 100 == prediction.expected_status_code // 100:
                deviation_scores.append(0.1)  # Same category (2xx, 4xx, etc.)
            else:
                deviation_scores.append(0.5)  # Different category
        
        # 2. Content pattern verification
        actual_body = str(actual_response.get("body", "")).lower()
        
        for pattern in prediction.expected_content_patterns:
            if pattern.lower() in actual_body:
                matches.append(f"Pattern found: {pattern[:30]}")
                deviation_scores.append(0.0)
            else:
                mismatches.append(f"Pattern missing: {pattern[:30]}")
                deviation_scores.append(0.2)
        
        # 3. Anti-pattern verification (things that shouldn't appear)
        for anti_pattern in prediction.anti_patterns:
            if anti_pattern.lower() in actual_body:
                honeypot_indicators.append(f"Suspicious pattern: {anti_pattern}")
                deviation_scores.append(0.4)  # High deviation for anti-patterns
        
        # 4. Content type verification
        if prediction.expected_content_type:
            actual_content_type = actual_response.get("headers", {}).get("content-type", "")
            if prediction.expected_content_type in actual_content_type:
                matches.append(f"Content-Type: {prediction.expected_content_type}")
                deviation_scores.append(0.0)
            else:
                mismatches.append(f"Content-Type: expected {prediction.expected_content_type}")
                deviation_scores.append(0.15)
        
        # 5. Check for honeypot indicators
        for indicator in self.HONEYPOT_INDICATORS:
            if indicator.lower() in actual_body:
                honeypot_indicators.append(indicator)
        
        # Calculate overall deviation
        if deviation_scores:
            overall_deviation = sum(deviation_scores) / len(deviation_scores)
        else:
            overall_deviation = 0.0
        
        # Boost deviation if honeypot indicators found
        if honeypot_indicators:
            overall_deviation = min(1.0, overall_deviation + 0.3 * len(honeypot_indicators))
        
        # Determine status
        if honeypot_indicators:
            status = VerificationStatus.HONEYPOT_SUSPECTED
            should_halt = True
            reasoning = f"HONEYPOT WARNING: Suspicious patterns detected: {honeypot_indicators}"
        elif overall_deviation > self.deviation_threshold:
            status = VerificationStatus.FAILED
            should_halt = True
            reasoning = f"DEVIATION EXCEEDED: {overall_deviation:.0%} > {self.deviation_threshold:.0%} threshold"
        elif overall_deviation > self.WARNING_THRESHOLD:
            status = VerificationStatus.WARNING
            should_halt = False
            reasoning = f"WARNING: Minor deviation detected ({overall_deviation:.0%})"
        else:
            status = VerificationStatus.PASSED
            should_halt = False
            reasoning = f"VERIFIED: Response matches prediction ({overall_deviation:.0%} deviation)"
        
        result = VerificationResult(
            status=status,
            deviation_score=overall_deviation,
            matches=matches,
            mismatches=mismatches,
            honeypot_indicators=honeypot_indicators,
            should_halt=should_halt,
            reasoning=reasoning
        )
        
        # Store in history
        self.prediction_history.append((prediction, actual_response, result))
        
        # Log result
        status_emoji = {
            VerificationStatus.PASSED: "✅",
            VerificationStatus.WARNING: "⚠️",
            VerificationStatus.FAILED: "❌",
            VerificationStatus.HONEYPOT_SUSPECTED: "🍯"
        }
        
        logger.info(f"{status_emoji[status]} Verification: {reasoning}")
        
        return result
    
    def check_dependency_lock(self, command: str) -> Tuple[bool, str]:
        """
        Check if a command violates the dependency lock.
        
        Mid-mission tool installation is blocked.
        
        Args:
            command: The command to check
            
        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        command_lower = command.lower()
        
        for pattern in self.BLOCKED_INSTALL_PATTERNS:
            if re.search(pattern, command_lower):
                return False, (
                    f"DEPENDENCY LOCK: Installation commands blocked mid-mission. "
                    f"Pattern matched: {pattern}. "
                    f"Use raw Python implementation or logic-based alternative."
                )
        
        return True, "Command allowed"
    
    def get_fallback_implementation(self, tool: str) -> Optional[Dict[str, Any]]:
        """
        Get a fallback implementation when a tool is unavailable.
        
        Returns raw Python/socket-based alternatives.
        
        Args:
            tool: Tool that's unavailable
            
        Returns:
            Fallback implementation or None
        """
        fallbacks = {
            "nmap": {
                "type": "python",
                "description": "Use socket-based port scanning",
                "code": """
import socket

def scan_port(host, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False
"""
            },
            "sqlmap": {
                "type": "python",
                "description": "Use requests-based SQLi testing",
                "code": """
import requests

def test_sqli(url, param):
    payloads = ["'", "' OR '1'='1", "' OR 1=1--"]
    for payload in payloads:
        try:
            resp = requests.get(url, params={param: payload}, timeout=10)
            if any(err in resp.text.lower() for err in ['sql', 'error', 'syntax']):
                return True
        except:
            pass
    return False
"""
            },
            "nikto": {
                "type": "python",
                "description": "Use requests-based vulnerability scanning",
                "code": """
import requests

def scan_common_vulns(url):
    paths = ['/.git/config', '/.env', '/wp-config.php', '/admin/', '/backup/']
    findings = []
    for path in paths:
        try:
            resp = requests.get(url + path, timeout=5)
            if resp.status_code == 200:
                findings.append(path)
        except:
            pass
    return findings
"""
            }
        }
        
        return fallbacks.get(tool)
    
    def calculate_content_similarity(self, content1: str, content2: str) -> float:
        """
        Calculate similarity between two content strings.
        
        Args:
            content1: First content string
            content2: Second content string
            
        Returns:
            Similarity score (0.0-1.0)
        """
        if not content1 or not content2:
            return 0.0 if content1 != content2 else 1.0
        
        # Use sequence matcher for similarity
        ratio = difflib.SequenceMatcher(None, content1[:1000], content2[:1000]).ratio()
        return ratio
    
    def get_verification_summary(self) -> Dict[str, Any]:
        """Get summary of all verifications"""
        if not self.prediction_history:
            return {"total": 0, "passed": 0, "failed": 0, "honeypots": 0}
        
        passed = len([r for _, _, r in self.prediction_history if r.status == VerificationStatus.PASSED])
        failed = len([r for _, _, r in self.prediction_history if r.status == VerificationStatus.FAILED])
        warnings = len([r for _, _, r in self.prediction_history if r.status == VerificationStatus.WARNING])
        honeypots = len([r for _, _, r in self.prediction_history if r.status == VerificationStatus.HONEYPOT_SUSPECTED])
        
        avg_deviation = sum(r.deviation_score for _, _, r in self.prediction_history) / len(self.prediction_history)
        
        return {
            "total": len(self.prediction_history),
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "honeypots_detected": honeypots,
            "average_deviation": avg_deviation,
            "halt_count": len([r for _, _, r in self.prediction_history if r.should_halt])
        }


# Global instance
_virtual_sandbox: Optional[VirtualSandbox] = None


def get_virtual_sandbox() -> VirtualSandbox:
    """Get the global virtual sandbox instance"""
    global _virtual_sandbox
    if _virtual_sandbox is None:
        _virtual_sandbox = VirtualSandbox()
    return _virtual_sandbox
