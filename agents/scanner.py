# agents/scanner.py
# --- VERSION 8.0 - Full-Spectrum CTF & Red Team Operations ---

import asyncio
import json
import logging
import os
import re
import tempfile
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from pathlib import Path
from tools.tool_manager import RealToolManager
from tools.python_tools import PythonToolManager
from tools.visual_recon import get_visual_recon_tool
from tools.tool_installer import get_tool_installer
from utils.database_manager import get_database
from utils.impact_quantifier import get_impact_quantifier
from agents.enhanced_ai_core import parse_json_robust

# Import CTF capability modules
from tools.capabilities import (
    get_crypto_engine,
    get_reverse_engine,
    get_forensics_lab,
    get_pwn_exploiter,
    get_network_sentry,
)

logger = logging.getLogger(__name__)

class AegisScanner:
    """
    Executes granular actions decided by the AI brain.
    
    v8.0 adds full-spectrum CTF and Red Team capabilities:
    - Cryptography (crypto_engine)
    - Reverse Engineering (reverse_engine)
    - Digital Forensics (forensics_lab)
    - Binary Exploitation (pwn_exploiter)
    - Network Analysis (network_sentry)
    """
    
    # Configuration constants
    MAX_SELF_CORRECTION_RECURSION = 1  # Allow one recursive healing attempt
    MAX_SUMMARY_OUTPUT_LENGTH = 2000   # Threshold for smart summarization
    
    def __init__(self, ai_core):
        self.ai_core = ai_core
        self.real_tools = RealToolManager()
        self.python_tools = PythonToolManager()
        self.visual_recon = get_visual_recon_tool()
        self.db = get_database()  # Mission database
        self.som_mappings = {}  # Store SoM mappings {url: element_mapping}
        self.impact_quantifier = get_impact_quantifier(ai_core)  # RAG-based impact assessment
        self.tool_installer = get_tool_installer()  # Self-healing tool installer
        
        # Initialize CTF capability engines
        self.crypto_engine = get_crypto_engine()
        self.reverse_engine = get_reverse_engine()
        self.forensics_lab = get_forensics_lab()
        self.pwn_exploiter = get_pwn_exploiter()
        self.network_sentry = get_network_sentry()
        
        logger.info("🛡️ AegisScanner v8.0 initialized with CTF capabilities")
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain name format"""
        import re
        # Simple domain validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, domain)) and len(domain) <= 253
    
    def _validate_target(self, target: str) -> bool:
        """Validate target (domain or IP)"""
        import re
        # Check if it's a valid domain
        if self._validate_domain(target):
            return True
        # Check if it's a valid IP
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, target):
            parts = target.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        # Check if it's a URL
        if target.startswith(('http://', 'https://')):
            return True
        return False
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL format"""
        from urllib.parse import urlparse
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _summarize_output(self, tool_name: str, output: str, target: str = "") -> Dict[str, Any]:
        """
        Smart Summarization: Avoid flooding the LLM context window with massive outputs.
        
        If output exceeds MAX_SUMMARY_OUTPUT_LENGTH chars:
        1. Extract key information (open ports, vulnerabilities, etc.)
        2. Save full output to data/evidence/ for reference
        3. Return only the summary to the LLM
        
        Args:
            tool_name: Name of the tool that produced the output
            output: Raw output string from the tool
            target: Target that was scanned (for file naming)
            
        Returns:
            Dict with 'summary' (for LLM) and 'evidence_file' (path to full output)
        """
        # If output is small enough, return as-is
        if len(output) <= self.MAX_SUMMARY_OUTPUT_LENGTH:
            return {
                "summary": output,
                "evidence_file": None,
                "was_summarized": False
            }
        
        logger.info(f"📊 Output too large ({len(output)} chars), summarizing...")
        
        # Save full output to evidence file
        evidence_file = self._save_evidence(tool_name, output, target)
        
        # Extract summary based on tool type
        summary = self._extract_summary(tool_name, output)
        
        return {
            "summary": summary,
            "evidence_file": evidence_file,
            "was_summarized": True,
            "original_length": len(output)
        }
    
    def _save_evidence(self, tool_name: str, output: str, target: str = "") -> str:
        """
        Save full tool output to evidence file.
        
        Args:
            tool_name: Name of the tool
            output: Full output to save
            target: Target identifier for file naming
            
        Returns:
            Path to the saved evidence file
        """
        import time
        
        # Create evidence directory
        evidence_dir = Path("data/evidence")
        evidence_dir.mkdir(exist_ok=True, parents=True)
        
        # Generate safe filename
        safe_target = re.sub(r'[^a-zA-Z0-9]', '_', target)[:50] if target else "unknown"
        timestamp = int(time.time())
        filename = f"{tool_name}_{safe_target}_{timestamp}.txt"
        filepath = evidence_dir / filename
        
        # Save output
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"# Tool: {tool_name}\n")
                f.write(f"# Target: {target}\n")
                f.write(f"# Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Output Length: {len(output)} chars\n")
                f.write("=" * 60 + "\n\n")
                f.write(output)
            
            logger.info(f"💾 Full output saved to: {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Failed to save evidence: {e}")
            return ""
    
    def _extract_summary(self, tool_name: str, output: str) -> str:
        """
        Extract key information from tool output based on tool type.
        
        Uses regex patterns to extract:
        - Open ports from nmap/naabu
        - Vulnerabilities from nuclei
        - SQL injection points from sqlmap
        - Interesting strings from reverse engineering
        
        Args:
            tool_name: Name of the tool
            output: Full output string
            
        Returns:
            Summarized output (max ~1500 chars)
        """
        summary_parts = [f"📋 SUMMARY ({tool_name}) - Full output saved to evidence file\n"]
        
        if tool_name in ["nmap_scan", "nmap", "port_scanning"]:
            # Extract open ports from nmap output
            open_ports = []
            
            # Pattern for nmap output: "PORT     STATE SERVICE"
            port_pattern = r'(\d+)/(\w+)\s+(open|filtered)\s+(\S+)'
            matches = re.findall(port_pattern, output)
            
            if matches:
                summary_parts.append("\n🔓 OPEN PORTS:")
                for port, protocol, state, service in matches[:20]:  # Limit to 20 ports
                    summary_parts.append(f"  • {port}/{protocol} ({state}) - {service}")
                
                if len(matches) > 20:
                    summary_parts.append(f"  ... and {len(matches) - 20} more ports")
            else:
                # Try XML format
                xml_ports = re.findall(r'<port protocol="(\w+)" portid="(\d+)".*?state="(\w+)".*?name="([^"]*)"', output)
                if xml_ports:
                    summary_parts.append("\n🔓 OPEN PORTS:")
                    for protocol, port, state, service in xml_ports[:20]:
                        summary_parts.append(f"  • {port}/{protocol} ({state}) - {service}")
        
        elif tool_name in ["vulnerability_scan", "nuclei"]:
            # Extract vulnerabilities
            summary_parts.append("\n⚠️ VULNERABILITIES FOUND:")
            
            # Pattern for nuclei JSONL output indicators
            vuln_pattern = r'"template-id":\s*"([^"]+)".*?"severity":\s*"([^"]+)"'
            matches = re.findall(vuln_pattern, output)
            
            if matches:
                severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
                matches = sorted(matches, key=lambda x: severity_order.get(x[1].lower(), 5))
                
                for template_id, severity in matches[:15]:
                    emoji = "🔴" if severity.lower() in ["critical", "high"] else "🟡" if severity.lower() == "medium" else "🟢"
                    summary_parts.append(f"  {emoji} [{severity.upper()}] {template_id}")
                
                if len(matches) > 15:
                    summary_parts.append(f"  ... and {len(matches) - 15} more findings")
            else:
                summary_parts.append("  No specific vulnerabilities extracted")
        
        elif tool_name in ["run_sqlmap", "sqlmap"]:
            # Extract SQL injection info
            if "is vulnerable" in output.lower():
                summary_parts.append("\n💉 SQL INJECTION CONFIRMED!")
                
                # Extract injection type
                inj_types = re.findall(r'Type:\s*([^\n]+)', output)
                if inj_types:
                    summary_parts.append("\nInjection Types:")
                    for inj_type in inj_types[:5]:
                        summary_parts.append(f"  • {inj_type.strip()}")
                
                # Extract payload examples
                payloads = re.findall(r'Payload:\s*([^\n]+)', output)
                if payloads:
                    summary_parts.append("\nPayload Examples:")
                    for payload in payloads[:3]:
                        summary_parts.append(f"  • {payload.strip()[:100]}")
            else:
                summary_parts.append("\n❌ No SQL injection detected")
        
        elif tool_name in ["analyze_binary", "reverse_engine"]:
            # Extract interesting strings and functions
            summary_parts.append("\n🔍 BINARY ANALYSIS:")
            
            # Count strings
            strings_match = re.search(r'"total_count":\s*(\d+)', output)
            if strings_match:
                summary_parts.append(f"  Total strings: {strings_match.group(1)}")
            
            # Extract interesting strings
            interesting = re.findall(r'"interesting_strings":\s*\[([^\]]+)\]', output)
            if interesting:
                summary_parts.append("\n  Interesting strings found (flags, passwords, URLs, etc.)")
            
            # Extract entry point
            entry = re.search(r'"entry_point":\s*"([^"]+)"', output)
            if entry:
                summary_parts.append(f"  Entry point: {entry.group(1)}")
        
        elif tool_name in ["check_binary_protections", "pwn"]:
            # Extract security protections
            summary_parts.append("\n🛡️ BINARY PROTECTIONS:")
            
            protections = {
                'NX': re.search(r'"nx":\s*(true|false|null)', output),
                'Canary': re.search(r'"canary":\s*(true|false|null)', output),
                'PIE': re.search(r'"pie":\s*(true|false|null)', output),
                'RELRO': re.search(r'"relro":\s*"?([^",}]+)', output),
            }
            
            for prot, match in protections.items():
                if match:
                    value = match.group(1)
                    emoji = "✅" if value == "true" or value == "full" else "❌" if value == "false" or value == "none" else "⚠️"
                    summary_parts.append(f"  {emoji} {prot}: {value}")
        
        else:
            # Generic summary - first and last 500 chars
            summary_parts.append("\n📄 OUTPUT EXCERPT:")
            summary_parts.append(output[:500])
            summary_parts.append("\n... [truncated] ...\n")
            summary_parts.append(output[-500:])
        
        summary = "\n".join(summary_parts)
        
        # Ensure summary doesn't exceed limit
        if len(summary) > 1500:
            summary = summary[:1500] + "\n... [summary truncated]"
        
        return summary
    
    async def _self_correct_and_retry(self, tool: str, original_args: Dict, error_message: str, recursion_depth: int = 0) -> Optional[Dict]:
        """
        Self-Correction Loop: Use Coder LLM to suggest fixes for failed commands
        
        Supports recursive healing - if initial correction fails, can ask the Coder LLM
        to fix its own fix (up to MAX_SELF_CORRECTION_RECURSION recursions).
        
        Args:
            tool: The tool that failed
            original_args: Original arguments that caused the failure
            error_message: The error message from the failure
            recursion_depth: Current recursion level
            
        Returns:
            Corrected arguments dict or None if correction fails
        """
        if recursion_depth > self.MAX_SELF_CORRECTION_RECURSION:
            logger.warning(f"❌ Max recursion depth ({self.MAX_SELF_CORRECTION_RECURSION}) reached for self-correction")
            return None
        
        recursion_label = f" (recursion {recursion_depth})" if recursion_depth > 0 else ""
        logger.info(f"🔧 Self-Correction{recursion_label}: Attempting to fix failed {tool} command...")
        
        correction_prompt = f"""A security testing tool failed with an error. Analyze the error and suggest a fixed command.

FAILED TOOL: {tool}
ORIGINAL ARGUMENTS: {original_args}
ERROR MESSAGE: {error_message}

Your task:
1. Analyze why the command failed
2. Suggest corrected or alternative arguments that might work
3. Consider common issues like syntax errors, timeouts, invalid formats, missing parameters

Respond with JSON ONLY containing the corrected arguments:
{{
  "corrected_args": {{"param": "value"}},
  "reasoning": "Brief explanation of what was wrong and how you fixed it"
}}

If you cannot suggest a fix, respond with:
{{
  "corrected_args": null,
  "reasoning": "Explanation of why this cannot be fixed"
}}
"""
        
        try:
            # Call the Coder LLM for error correction
            response = await self.ai_core.orchestrator.call_llm(
                'coder',
                [
                    {"role": "system", "content": "You are an expert in debugging security tools and command syntax."},
                    {"role": "user", "content": correction_prompt}
                ],
                temperature=0.6,
                max_tokens=512
            )
            
            content = response.get('content', '')
            
            # Use robust JSON parser from enhanced_ai_core instead of brittle regex+json.loads
            correction = await parse_json_robust(
                content,
                orchestrator=self.ai_core.orchestrator,
                context="Self-correction of tool arguments"
            )
            
            if correction:
                corrected_args = correction.get('corrected_args')
                reasoning = correction.get('reasoning', 'No reasoning provided')
                
                logger.info(f"💡 Correction reasoning: {reasoning}")
                
                if corrected_args is not None:
                    logger.info(f"✅ Corrected arguments: {corrected_args}")
                    return corrected_args
                else:
                    logger.warning(f"❌ Coder LLM could not suggest a fix")
                    return None
            
            # If JSON parsing failed, attempt recursive healing (ask LLM to fix its own response)
            if recursion_depth < self.MAX_SELF_CORRECTION_RECURSION:
                logger.warning(f"⚠️ Could not parse correction JSON, attempting recursive healing...")
                
                # Sanitize the content before including in error - remove potential secrets/credentials
                sanitized_content = self._sanitize_content_for_logging(content[:300])
                recursive_error = f"Previous correction attempt returned invalid JSON format. Response preview: {sanitized_content}"
                
                return await self._self_correct_and_retry(
                    tool, 
                    original_args, 
                    recursive_error,
                    recursion_depth + 1
                )
            
            logger.warning("Could not parse correction JSON after recursive attempts")
            return None
            
        except Exception as e:
            logger.error(f"Error during self-correction: {e}", exc_info=True)
            return None
    
    def _sanitize_content_for_logging(self, content: str) -> str:
        """
        Sanitize content before logging to remove potential sensitive information.
        
        Args:
            content: Raw content string
            
        Returns:
            Sanitized content safe for logging
        """
        # Common patterns that might contain sensitive data
        sensitive_patterns = [
            (r'password["\s:=]+["\']?[\w\S]+["\']?', 'password=***'),
            (r'api[_-]?key["\s:=]+["\']?[\w\S]+["\']?', 'api_key=***'),
            (r'secret["\s:=]+["\']?[\w\S]+["\']?', 'secret=***'),
            (r'token["\s:=]+["\']?[\w\S]+["\']?', 'token=***'),
            (r'bearer\s+[\w\-\.]+', 'bearer ***'),
        ]
        
        sanitized = content
        for pattern, replacement in sensitive_patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        
        return sanitized

    async def execute_action(self, action: Dict) -> Dict:
        """
        Orchestrateur qui exécute l'action demandée par l'IA avec validation, error handling,
        and self-correction capabilities (TASK 3)
        
        Args:
            action: Dictionary containing tool name and arguments
            
        Returns:
            Dictionary with status and results
        """
        # Input validation
        if not isinstance(action, dict):
            return {"status": "error", "error": "Invalid action format: must be a dictionary"}
        
        tool = action.get("tool")
        args = action.get("args", {})
        
        # Validate tool name
        if not tool or not isinstance(tool, str):
            return {"status": "error", "error": "Missing or invalid tool name"}
        
        # Validate args
        if not isinstance(args, dict):
            return {"status": "error", "error": "Invalid args format: must be a dictionary"}
        
        logger.info(f"Executing action: {tool} with args {args}")
        
        # TASK 3: Self-correction wrapper - try once, then retry with corrected args if it fails
        max_attempts = 2
        current_args = args.copy()
        last_error = None
        
        for attempt in range(max_attempts):
            try:
                # Execute the tool with current args
                result = await self._execute_tool_internal(tool, current_args)
                
                # If successful, return immediately
                if result.get("status") == "success":
                    return result
                
                # If error, prepare for potential retry
                last_error = result.get("error", "Unknown error")
                
                # If this was the first attempt and we got an error, try self-correction
                if attempt == 0:
                    logger.warning(f"⚠️ Tool {tool} failed on first attempt: {last_error}")
                    logger.info(f"🔧 Attempting self-correction...")
                    
                    corrected_args = await self._self_correct_and_retry(tool, current_args, last_error)
                    
                    if corrected_args is not None:
                        logger.info(f"🔄 Retrying {tool} with corrected arguments...")
                        current_args = corrected_args
                        continue  # Retry with corrected args
                    else:
                        # Cannot correct, return the error
                        logger.warning(f"❌ Self-correction failed, returning original error")
                        return result
                else:
                    # Second attempt failed, return the error
                    return result
                    
            except Exception as e:
                last_error = str(e)
                logger.error(f"❌ Exception in {tool} (attempt {attempt + 1}/{max_attempts}): {e}", exc_info=True)
                
                # Try self-correction on first attempt
                if attempt == 0:
                    logger.info(f"🔧 Attempting self-correction after exception...")
                    corrected_args = await self._self_correct_and_retry(tool, current_args, last_error)
                    
                    if corrected_args is not None:
                        logger.info(f"🔄 Retrying {tool} with corrected arguments...")
                        current_args = corrected_args
                        continue
                    else:
                        # Cannot correct, return error
                        return {"status": "error", "error": str(e)}
                else:
                    # Second attempt exception, return error
                    return {"status": "error", "error": str(e)}
        
        # Should not reach here, but just in case
        return {"status": "error", "error": last_error or "Unknown error after retries"}
    
    async def _execute_tool_internal(self, tool: str, args: Dict) -> Dict:
        """
        Internal method that executes the actual tool logic
        Separated to allow retry logic in execute_action
        
        Args:
            tool: Tool name
            args: Tool arguments
            
        Returns:
            Result dictionary
        """
        try:
            # Outils de Reconnaissance
            if tool == "subdomain_enumeration":
                domain = args.get("domain")
                if not domain: 
                    return {"status": "error", "error": "Domaine manquant"}
                if not self._validate_domain(domain):
                    return {"status": "error", "error": f"Invalid domain format: {domain}"}
                
                # TASK 2: Execute and record in database
                result = await self.real_tools.subdomain_enumeration(domain)
                if result.get("status") == "success":
                    # Record scan in database
                    data = result.get("data", [])
                    scan_result = f"Found {len(data)} subdomains" if isinstance(data, list) else "Completed"
                    self.db.mark_scanned(domain, "subdomain_enumeration", scan_result)
                return result

            elif tool == "port_scanning":
                target = args.get("target")
                if not target: 
                    return {"status": "error", "error": "Cible manquante"}
                if not self._validate_target(target):
                    return {"status": "error", "error": f"Invalid target format: {target}"}
                
                # TASK 2: Execute and record in database
                result = await self.real_tools.port_scanning(target)
                if result.get("status") == "success":
                    data = result.get("data", [])
                    scan_result = f"Found {len(data)} open ports" if isinstance(data, list) else "Completed"
                    self.db.mark_scanned(target, "port_scanning", scan_result)
                return result

            elif tool == "nmap_scan":
                target = args.get("target")
                ports = args.get("ports", "80,443,8080,8443")
                intensity = args.get("intensity", "normal")
                if not target: return {"status": "error", "error": "Cible manquante"}
                
                # TASK 2: Execute and record in database (use real_tools for intensity support)
                result = await self.real_tools.nmap_scan(target, ports, intensity=intensity)
                if result.get("status") == "success":
                    data = result.get("data", {})
                    
                    # TASK 5: Smart Summarization - avoid flooding LLM context
                    if isinstance(data, dict) and "output" in data:
                        raw_output = data["output"]
                        summarized = self._summarize_output("nmap_scan", raw_output, target)
                        
                        # Replace raw output with summary for LLM
                        data["output"] = summarized["summary"]
                        data["evidence_file"] = summarized.get("evidence_file")
                        data["was_summarized"] = summarized.get("was_summarized", False)
                        result["data"] = data
                    
                    scan_result = f"Scanned with intensity={intensity}"
                    self.db.mark_scanned(target, "nmap_scan", scan_result)
                return result

            elif tool == "url_discovery":
                domain = args.get("domain")
                if not domain: return {"status": "error", "error": "Domaine manquant"}
                
                # TASK 2: Execute and record in database
                result = await self.real_tools.url_discovery(domain)
                if result.get("status") == "success":
                    data = result.get("data", [])
                    scan_result = f"Found {len(data)} URLs" if isinstance(data, list) else "Completed"
                    self.db.mark_scanned(domain, "url_discovery", scan_result)
                return result

            elif tool == "tech_detection":
                target = args.get("target")
                if not target: 
                    return {"status": "error", "error": "Cible manquante"}
                if not self._validate_target(target):
                    return {"status": "error", "error": f"Invalid target format: {target}"}
                if '://' not in target: 
                    target = f"http://{target}"
                if not self._validate_url(target):
                    return {"status": "error", "error": f"Invalid URL format: {target}"}
                
                # TASK 2: Execute and record in database
                result = await self.python_tools.advanced_technology_detection(target)
                if result.get("status") == "success":
                    self.db.mark_scanned(target, "tech_detection", "Technology detection completed")
                return result
            
            # Outils d'Attaque et d'Analyse Logique (NOUVEAU)
            elif tool == "vulnerability_scan":
                target_url = args.get("target")
                intensity = args.get("intensity", "normal")
                if not target_url: 
                    return {"status": "error", "error": "Cible URL manquante"}
                if '://' not in target_url: 
                    target_url = f"http://{target_url}"
                if not self._validate_url(target_url):
                    return {"status": "error", "error": f"Invalid URL format: {target_url}"}
                
                # TASK 2: Execute, record scan and findings in database
                result = await self.real_tools.vulnerability_scan(target_url, intensity=intensity)
                if result.get("status") == "success":
                    data = result.get("data", [])
                    scan_result = f"Found {len(data)} vulnerabilities (intensity={intensity})" if isinstance(data, list) else "Completed"
                    self.db.mark_scanned(target_url, "vulnerability_scan", scan_result)
                    
                    # TASK 3: Verify each finding before adding to database
                    if isinstance(data, list):
                        verified_count = 0
                        rejected_count = 0
                        for finding in data:
                            if isinstance(finding, dict):
                                # Deep Think verification
                                verified_finding = await self.ai_core.verify_finding_with_reasoning(finding, target_url)
                                
                                if verified_finding is not None:
                                    # Finding passed verification - add to database
                                    finding_type = verified_finding.get('template-id', 'unknown')
                                    severity = verified_finding.get('info', {}).get('severity', 'info')
                                    description = verified_finding.get('info', {}).get('name', '')
                                    evidence = verified_finding.get('matched-at', '')
                                    self.db.add_finding(finding_type, target_url, severity, description, evidence)
                                    verified_count += 1
                                else:
                                    # Finding rejected as hallucination
                                    rejected_count += 1
                                    logger.info(f"🚫 Rejected hallucinated finding: {finding.get('template-id', 'unknown')}")
                        
                        logger.info(f"✅ Verification complete: {verified_count} accepted, {rejected_count} rejected")
                return result

            elif tool == "run_sqlmap":
                target_url = args.get("target")
                intensity = args.get("intensity", "normal")
                if not target_url: return {"status": "error", "error": "Cible URL manquante"}
                
                # TASK 2: Execute and record findings
                result = await self.real_tools.run_sqlmap(target_url, intensity=intensity)
                if result.get("status") == "success":
                    data = result.get("data", {})
                    vulnerable = data.get("vulnerable", False)
                    scan_result = "SQL Injection found" if vulnerable else "No SQL Injection"
                    self.db.mark_scanned(target_url, "run_sqlmap", scan_result)
                    
                    # TASK 5: Smart Summarization for large SQLMap output
                    if "output" in data:
                        raw_output = data["output"]
                        summarized = self._summarize_output("run_sqlmap", raw_output, target_url)
                        data["output"] = summarized["summary"]
                        data["evidence_file"] = summarized.get("evidence_file")
                        data["was_summarized"] = summarized.get("was_summarized", False)
                        result["data"] = data
                    
                    # TASK 3: Verify finding before recording if vulnerable
                    if vulnerable:
                        # Construct finding dict for verification
                        finding = {
                            "type": "SQL Injection",
                            "severity": "high",
                            "description": "SQL Injection vulnerability detected by SQLmap",
                            "evidence": data.get("output", "")[:500],
                            "tool": "sqlmap"
                        }
                        
                        # Deep Think verification
                        verified_finding = await self.ai_core.verify_finding_with_reasoning(finding, target_url)
                        
                        if verified_finding is not None:
                            # Finding passed verification
                            self.db.add_finding(
                                "SQL Injection",
                                target_url,
                                "high",
                                "SQL Injection vulnerability detected by SQLmap",
                                data.get("output", "")[:500]
                            )
                            logger.info("✅ SQL Injection finding verified and recorded")
                        else:
                            logger.info("🚫 SQL Injection finding rejected as hallucination")
                return result

            elif tool == "discover_interactables":
                target_url = args.get("target")
                if not target_url: return {"status": "error", "error": "Cible URL manquante"}
                if '://' not in target_url: target_url = f"http://{target_url}"
                return await self.python_tools.discover_interactables(target_url)

            elif tool == "test_form_payload":
                target_url = args.get("target")
                form_id = args.get("form_identifier") # ex: "login-form" ou "//form[1]"
                payloads = args.get("input_payloads") # ex: {"user": "admin", "pass": "' or 1=1--"}
                if not all([target_url, form_id, payloads]):
                    return {"status": "error", "error": "Arguments manquants pour test_form_payload"}
                if '://' not in target_url: target_url = f"http://{target_url}"
                return await self.python_tools.test_form_payload(target_url, form_id, payloads)
                
            elif tool == "fetch_url":
                target_url = args.get("target")
                if not target_url: return {"status": "error", "error": "Cible URL manquante"}
                return await self.python_tools.fetch_url(target_url)
            
            # Session Management Tool (TASK 1)
            elif tool == "manage_session":
                action = args.get("action")
                credentials = args.get("credentials", {})
                if not action:
                    return {"status": "error", "error": "Action manquante (login/logout)"}
                return await self.python_tools.manage_session(action, credentials)
            
            # Multi-Session Management for Privilege Escalation Testing
            elif tool == "manage_multi_session":
                action = args.get("action")
                session_name = args.get("session_name")
                credentials = args.get("credentials", {})
                
                if not action:
                    return {"status": "error", "error": "Action manquante (login/logout/list)"}
                if not session_name and action != "list":
                    return {"status": "error", "error": "Session name manquant (e.g., 'Session_Admin', 'Session_User')"}
                
                return await self.python_tools.manage_multi_session(action, session_name, credentials)
            
            elif tool == "replay_request_with_session":
                original_request = args.get("request")
                session_name = args.get("session_name")
                
                if not original_request:
                    return {"status": "error", "error": "Original request data manquant"}
                if not session_name:
                    return {"status": "error", "error": "Session name manquant"}
                
                return await self.python_tools.replay_request_with_session(original_request, session_name)
            
            # Database Tools (TASK 2)
            elif tool == "db_add_finding":
                finding_type = args.get("type")
                url = args.get("url")
                severity = args.get("severity")
                description = args.get("description", "")
                evidence = args.get("evidence", "")
                
                if not all([finding_type, url, severity]):
                    return {"status": "error", "error": "Arguments manquants (type, url, severity requis)"}
                
                finding_id = self.db.add_finding(finding_type, url, severity, description, evidence)
                if finding_id > 0:
                    return {"status": "success", "data": {"finding_id": finding_id, "message": "Finding added"}}
                else:
                    return {"status": "error", "error": "Failed to add finding"}
            
            elif tool == "db_get_findings":
                severity = args.get("severity")
                verified = args.get("verified")
                findings = self.db.get_findings(severity=severity, verified=verified)
                return {"status": "success", "data": findings}
            
            elif tool == "db_is_scanned":
                target = args.get("target")
                scan_type = args.get("scan_type")
                if not target:
                    return {"status": "error", "error": "Target manquant"}
                
                is_scanned = self.db.is_scanned(target, scan_type)
                return {"status": "success", "data": {"target": target, "scan_type": scan_type, "is_scanned": is_scanned}}
            
            elif tool == "db_mark_scanned":
                target = args.get("target")
                scan_type = args.get("scan_type")
                result = args.get("result", "")
                
                if not all([target, scan_type]):
                    return {"status": "error", "error": "Arguments manquants (target, scan_type requis)"}
                
                success = self.db.mark_scanned(target, scan_type, result)
                if success:
                    return {"status": "success", "data": {"message": "Target marked as scanned"}}
                else:
                    return {"status": "error", "error": "Failed to mark target as scanned"}
            
            elif tool == "db_get_statistics":
                stats = self.db.get_statistics()
                return {"status": "success", "data": stats}
            
            # Visual Reconnaissance Tools (SoM - Set-of-Mark)
            elif tool == "capture_screenshot_som":
                target_url = args.get("url")
                full_page = args.get("full_page", False)
                
                if not target_url:
                    return {"status": "error", "error": "URL manquante"}
                
                if '://' not in target_url:
                    target_url = f"http://{target_url}"
                
                if not self._validate_url(target_url):
                    return {"status": "error", "error": f"Invalid URL format: {target_url}"}
                
                # Capture screenshot with SoM
                result = await self.visual_recon.capture_with_som(target_url, full_page=full_page)
                
                if result.get("status") == "success":
                    # Store the element mapping for later use
                    self.som_mappings[target_url] = result.get("element_mapping", {})
                    logger.info(f"📍 Stored SoM mapping for {target_url} with {len(self.som_mappings[target_url])} elements")
                
                return result
            
            elif tool == "click_element_by_id":
                target_url = args.get("url")
                element_id = args.get("element_id")
                
                if not target_url:
                    return {"status": "error", "error": "URL manquante"}
                
                if element_id is None:
                    return {"status": "error", "error": "element_id manquant"}
                
                if '://' not in target_url:
                    target_url = f"http://{target_url}"
                
                if not self._validate_url(target_url):
                    return {"status": "error", "error": f"Invalid URL format: {target_url}"}
                
                # Get the element mapping for this URL
                element_mapping = self.som_mappings.get(target_url)
                
                if not element_mapping:
                    return {
                        "status": "error",
                        "error": f"No SoM mapping found for {target_url}. Run capture_screenshot_som first."
                    }
                
                # Convert element_id to int if it's a string
                try:
                    element_id = int(element_id)
                except (ValueError, TypeError):
                    return {"status": "error", "error": f"Invalid element_id: {element_id}. Must be an integer."}
                
                # Click the element
                result = await self.visual_recon.click_element(target_url, element_id, element_mapping)
                
                # If click was successful and URL didn't change (SPA navigation),
                # automatically re-capture to update the SoM mapping
                if result.get("status") == "success" and not result.get("url_changed", True):
                    logger.info("🔄 SPA navigation detected (URL unchanged), re-capturing screenshot with SoM...")
                    
                    # Use the new_url from the result (should be same as target_url for SPA)
                    current_url = result.get("new_url", target_url)
                    
                    # Re-capture screenshot with SoM to get fresh element mapping
                    recapture_result = await self.visual_recon.capture_with_som(current_url, full_page=False)
                    
                    if recapture_result.get("status") == "success":
                        # Update the SoM mapping with fresh data
                        fresh_mapping = recapture_result.get("element_mapping", {})
                        self.som_mappings[current_url] = fresh_mapping
                        
                        # Add re-capture info to the result
                        result["spa_recapture"] = {
                            "status": "success",
                            "new_element_count": len(fresh_mapping),
                            "screenshot_path": recapture_result.get("screenshot_path")
                        }
                        logger.info(f"✅ SoM re-captured: {len(fresh_mapping)} elements indexed")
                    else:
                        # Re-capture failed, log but don't fail the click operation
                        logger.warning(f"⚠️ Failed to re-capture SoM after SPA navigation: {recapture_result.get('error')}")
                        result["spa_recapture"] = {
                            "status": "error",
                            "error": recapture_result.get("error")
                        }
                
                return result
            
            elif tool == "visual_screenshot":
                target_url = args.get("url")
                full_page = args.get("full_page", False)
                
                if not target_url:
                    return {"status": "error", "error": "URL manquante"}
                
                if '://' not in target_url:
                    target_url = f"http://{target_url}"
                
                if not self._validate_url(target_url):
                    return {"status": "error", "error": f"Invalid URL format: {target_url}"}
                
                # Capture regular screenshot (without SoM)
                result = await self.visual_recon.capture_screenshot(target_url, full_page=full_page)
                return result
            
            # Impact Quantifier / RAG Tools
            elif tool == "ingest_documentation":
                doc_url = args.get("url")
                doc_type = args.get("type", "api")
                
                if not doc_url:
                    return {"status": "error", "error": "Documentation URL manquante"}
                
                return await self.impact_quantifier.ingest_documentation(doc_url, doc_type)
            
            elif tool == "assess_impact":
                finding = args.get("finding")
                context = args.get("context", "")
                
                if not finding:
                    return {"status": "error", "error": "Finding data manquant"}
                
                return await self.impact_quantifier.assess_impact(finding, context)
            
            elif tool == "rag_statistics":
                stats = self.impact_quantifier.get_statistics()
                return {"status": "success", "data": stats}
            
            # =================================================================
            # CTF & ADVANCED OPERATIONS TOOLS (v8.0)
            # =================================================================
            
            # --- CRYPTOGRAPHY TOOLS ---
            elif tool == "solve_crypto":
                text_or_file = args.get("text_or_file")
                if not text_or_file:
                    return {"status": "error", "error": "text_or_file argument required"}
                
                return await self._execute_with_fallback(
                    "solve_crypto",
                    lambda: self.crypto_engine.solve_crypto(text_or_file),
                    text_or_file
                )
            
            elif tool == "crack_hash":
                hash_value = args.get("hash_value")
                hash_type = args.get("hash_type")
                wordlist = args.get("wordlist", "/usr/share/wordlists/rockyou.txt")
                
                if not hash_value:
                    return {"status": "error", "error": "hash_value argument required"}
                
                return await self._execute_with_fallback(
                    "crack_hash",
                    lambda: self.crypto_engine.crack_hash(hash_value, hash_type, wordlist),
                    hash_value
                )
            
            # --- REVERSE ENGINEERING TOOLS ---
            elif tool == "analyze_binary":
                filepath = args.get("filepath")
                if not filepath:
                    return {"status": "error", "error": "filepath argument required"}
                
                # Validate file exists
                if not Path(filepath).exists():
                    return {"status": "error", "error": f"File not found: {filepath}"}
                
                return await self._execute_with_fallback(
                    "analyze_binary",
                    lambda: self.reverse_engine.analyze_binary(filepath),
                    filepath
                )
            
            elif tool == "disassemble_function":
                filepath = args.get("filepath")
                function_name = args.get("function_name", "main")
                
                if not filepath:
                    return {"status": "error", "error": "filepath argument required"}
                
                if not Path(filepath).exists():
                    return {"status": "error", "error": f"File not found: {filepath}"}
                
                return await self._execute_with_fallback(
                    "disassemble_function",
                    lambda: self.reverse_engine.disassemble_function(filepath, function_name),
                    filepath
                )
            
            # --- FORENSICS TOOLS ---
            elif tool == "analyze_file_artifacts":
                filepath = args.get("filepath")
                if not filepath:
                    return {"status": "error", "error": "filepath argument required"}
                
                if not Path(filepath).exists():
                    return {"status": "error", "error": f"File not found: {filepath}"}
                
                return await self._execute_with_fallback(
                    "analyze_file_artifacts",
                    lambda: self.forensics_lab.analyze_file_artifacts(filepath),
                    filepath
                )
            
            elif tool == "extract_embedded":
                filepath = args.get("filepath")
                output_dir = args.get("output_dir")
                
                if not filepath:
                    return {"status": "error", "error": "filepath argument required"}
                
                if not Path(filepath).exists():
                    return {"status": "error", "error": f"File not found: {filepath}"}
                
                return await self._execute_with_fallback(
                    "extract_embedded",
                    lambda: self.forensics_lab.extract_embedded(filepath, output_dir),
                    filepath
                )
            
            elif tool == "extract_steghide":
                filepath = args.get("filepath")
                password = args.get("password", "")
                output_file = args.get("output_file")
                
                if not filepath:
                    return {"status": "error", "error": "filepath argument required"}
                
                if not Path(filepath).exists():
                    return {"status": "error", "error": f"File not found: {filepath}"}
                
                return await self._execute_with_fallback(
                    "extract_steghide",
                    lambda: self.forensics_lab.extract_steghide(filepath, password, output_file),
                    filepath
                )
            
            # --- BINARY EXPLOITATION (PWN) TOOLS ---
            elif tool == "check_binary_protections":
                filepath = args.get("filepath")
                if not filepath:
                    return {"status": "error", "error": "filepath argument required"}
                
                if not Path(filepath).exists():
                    return {"status": "error", "error": f"File not found: {filepath}"}
                
                return await self._execute_with_fallback(
                    "check_binary_protections",
                    lambda: self.pwn_exploiter.check_binary_protections(filepath),
                    filepath
                )
            
            elif tool == "find_rop_gadgets":
                filepath = args.get("filepath")
                max_gadgets = args.get("max_gadgets", 50)
                
                if not filepath:
                    return {"status": "error", "error": "filepath argument required"}
                
                if not Path(filepath).exists():
                    return {"status": "error", "error": f"File not found: {filepath}"}
                
                return await self._execute_with_fallback(
                    "find_rop_gadgets",
                    lambda: self.pwn_exploiter.find_rop_gadgets(filepath, max_gadgets),
                    filepath
                )
            
            # --- NETWORK ANALYSIS TOOLS ---
            elif tool == "analyze_pcap":
                filepath = args.get("filepath")
                if not filepath:
                    return {"status": "error", "error": "filepath argument required"}
                
                if not Path(filepath).exists():
                    return {"status": "error", "error": f"File not found: {filepath}"}
                
                return await self._execute_with_fallback(
                    "analyze_pcap",
                    lambda: self.network_sentry.analyze_pcap(filepath),
                    filepath
                )
            
            elif tool == "follow_tcp_stream":
                filepath = args.get("filepath")
                stream_number = args.get("stream_number", 0)
                
                if not filepath:
                    return {"status": "error", "error": "filepath argument required"}
                
                if not Path(filepath).exists():
                    return {"status": "error", "error": f"File not found: {filepath}"}
                
                return await self._execute_with_fallback(
                    "follow_tcp_stream",
                    lambda: self.network_sentry.follow_tcp_stream(filepath, stream_number),
                    filepath
                )

            else:
                logger.warning(f"Outil inconnu demandé par l'IA : {tool}")
                return {"status": "error", "error": f"Outil inconnu : {tool}"}
                
        except Exception as e:
            logger.error(f"Erreur fatale en exécutant {tool}: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
    
    async def _execute_with_fallback(
        self,
        tool_name: str,
        execute_func,
        input_data: str
    ) -> Dict[str, Any]:
        """
        Execute a tool with fallback mechanism.
        
        If the tool fails (e.g., missing dependency), this method:
        1. Attempts to install the missing tool (if self-healing enabled)
        2. Falls back to asking the Coder LLM to write a custom Python script
        
        Args:
            tool_name: Name of the tool being executed
            execute_func: Async function to execute
            input_data: Input data for potential fallback script
            
        Returns:
            Tool execution result or fallback result
        """
        try:
            # Try to execute the tool
            result = await execute_func()
            
            # Check if result indicates missing tool
            if result.get("status") == "error" and "tool_missing" in result:
                missing_tool = result.get("tool_missing")
                logger.warning(f"⚠️ Tool '{missing_tool}' is missing, attempting recovery...")
                
                # Try self-healing installation
                install_result = await self.tool_installer.ensure_tool_available(missing_tool)
                
                if install_result.get("status") == "success":
                    logger.info(f"✅ Tool '{missing_tool}' installed, retrying...")
                    return await execute_func()
                else:
                    # Fall back to Coder LLM
                    logger.info(f"🔧 Falling back to Coder LLM for custom solution...")
                    return await self._fallback_to_coder_llm(tool_name, input_data, result.get("error", "Tool unavailable"))
            
            return result
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"❌ Tool execution failed: {error_msg}")
            
            # Check if it's a tool-not-found type error
            if "not found" in error_msg.lower() or "not installed" in error_msg.lower():
                logger.info(f"🔧 Falling back to Coder LLM for custom solution...")
                return await self._fallback_to_coder_llm(tool_name, input_data, error_msg)
            
            return {"status": "error", "error": error_msg}
    
    async def _fallback_to_coder_llm(
        self,
        tool_name: str,
        input_data: str,
        error_message: str
    ) -> Dict[str, Any]:
        """
        Fall back to Coder LLM to write a custom Python script.
        
        When a specialized tool is unavailable, ask the Coder LLM to
        write equivalent Python code to accomplish the task.
        
        Args:
            tool_name: Name of the failed tool
            input_data: Input that was provided to the tool
            error_message: Error message from the failed attempt
            
        Returns:
            Result from running the generated script, or error if fallback fails
        """
        logger.info(f"🤖 Coder LLM fallback for '{tool_name}'...")
        
        # Map tool names to descriptions for the prompt
        tool_descriptions = {
            "solve_crypto": "analyze and decode/decrypt the given text (try base64, hex, rot13, common ciphers)",
            "crack_hash": "identify the hash type and attempt common passwords",
            "analyze_binary": "extract strings and basic info from a binary file",
            "analyze_file_artifacts": "extract metadata and look for embedded data",
            "check_binary_protections": "check ELF binary protections (NX, canary, PIE, RELRO)",
            "analyze_pcap": "parse and extract useful information from network capture",
        }
        
        task_description = tool_descriptions.get(tool_name, f"accomplish what '{tool_name}' would do")
        
        fallback_prompt = f"""A security tool failed with error: {error_message}

I need you to write a Python script to {task_description}.

Input data: {input_data[:500]}{'...' if len(input_data) > 500 else ''}

Requirements:
1. Write a complete, runnable Python script
2. Use only standard library or commonly available packages
3. Output results in a structured format (dict or JSON)
4. Handle errors gracefully
5. The script should print the results to stdout as JSON

Respond with ONLY the Python code, no explanation:
```python
# Your code here
```"""

        try:
            # Call the Coder LLM
            response = await self.ai_core.orchestrator.call_llm(
                'coder',
                [
                    {"role": "system", "content": "You are an expert Python security programmer. Write clean, efficient code."},
                    {"role": "user", "content": fallback_prompt}
                ],
                temperature=0.7,
                max_tokens=2048
            )
            
            content = response.get('content', '')
            
            # Extract Python code from response
            code_match = re.search(r'```python\s*(.*?)\s*```', content, re.DOTALL)
            
            if code_match:
                python_code = code_match.group(1)
                logger.info(f"📝 Generated fallback script ({len(python_code)} chars)")
                
                # Execute the generated code safely
                exec_result = await self._execute_fallback_script(python_code, input_data)
                
                return {
                    "status": "success" if exec_result.get("success") else "partial",
                    "data": exec_result.get("output"),
                    "fallback_used": True,
                    "original_tool": tool_name,
                    "message": f"Used Coder LLM fallback for {tool_name}"
                }
            else:
                return {
                    "status": "error",
                    "error": "Failed to generate fallback script",
                    "fallback_attempted": True
                }
                
        except Exception as e:
            logger.error(f"❌ Fallback failed: {e}")
            return {
                "status": "error",
                "error": f"Original error: {error_message}. Fallback also failed: {str(e)}",
                "fallback_attempted": True
            }
    
    async def _execute_fallback_script(
        self,
        python_code: str,
        input_data: str
    ) -> Dict[str, Any]:
        """
        Execute a generated Python script safely.
        
        Args:
            python_code: The Python code to execute
            input_data: Input data to pass to the script
            
        Returns:
            Dictionary with execution results
        """
        try:
            # Write the script to a temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                # Inject input data as a variable
                full_script = f'''
import json
import sys

# Input data from tool
INPUT_DATA = """{input_data.replace('"', '\\"')}"""

{python_code}
'''
                f.write(full_script)
                script_path = f.name
            
            try:
                # Execute the script with a timeout
                process = await asyncio.create_subprocess_exec(
                    'python', script_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=60  # 1 minute timeout
                )
                
                output = stdout.decode('utf-8', errors='replace')
                errors = stderr.decode('utf-8', errors='replace')
                
                # Try to parse output as JSON
                try:
                    parsed_output = json.loads(output.strip())
                except (json.JSONDecodeError, ValueError):
                    parsed_output = {"raw_output": output}
                
                return {
                    "success": process.returncode == 0,
                    "output": parsed_output,
                    "errors": errors if errors else None
                }
                
            finally:
                # Clean up
                if os.path.exists(script_path):
                    os.unlink(script_path)
                    
        except asyncio.TimeoutError:
            return {"success": False, "output": None, "errors": "Script execution timed out"}
        except Exception as e:
            return {"success": False, "output": None, "errors": str(e)}
