"""
Output parsers for security tools - Enhanced with robust error handling
"""

import re
import json
from typing import Dict, List, Any

class ToolOutputParsers:
    @staticmethod
    def _safe_json_parse(text: str, fallback_key: str = "raw_output") -> Dict[str, Any]:
        """
        TASK 3: Safely parse JSON with fallback to structured text extraction
        
        Args:
            text: Text that might contain JSON
            fallback_key: Key to use if JSON parsing fails
            
        Returns:
            Dictionary with parsed data or structured fallback
        """
        # Try direct JSON parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        
        # Try to extract JSON from markdown code blocks
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
        
        # Try to find any JSON-like structure
        json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass
        
        # Fallback: return as structured text
        return {
            fallback_key: text[:1000] if len(text) > 1000 else text,
            "parse_status": "fallback",
            "note": "Could not parse as JSON, returning raw text"
        }
    
    @staticmethod
    def _extract_structured_info(text: str) -> Dict[str, Any]:
        """
        Extract structured information from unstructured text using regex
        
        Returns:
            Dictionary with extracted data
        """
        info = {}
        
        # Look for common patterns
        patterns = {
            "urls": r'https?://[^\s<>"{}|\\^`\[\]]+',
            "ip_addresses": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            "ports": r'\b(?:port|PORT)[:\s]+(\d+)\b',
            "vulnerabilities": r'(?:vulnerability|vuln|CVE)[:\s]+([^\n]+)',
            "severity": r'(?:severity|SEVERITY)[:\s]+(\w+)',
        }
        
        for key, pattern in patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                info[key] = list(set(matches))[:10]  # Limit to 10 unique matches
        
        return info
    
    @staticmethod
    def parse_sqlmap_output(stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse SQLMap output for vulnerabilities with robust error handling"""
        try:
            vulnerabilities = []
            
            # Look for SQL injection patterns
            injection_patterns = [
                r"Type: (.+?) Title: (.+?) Payload: (.+?)",
                r"parameter '(.+?)' is vulnerable",
                r"injection point: (.+?) parameter: (.+?)"
            ]
            
            lines = stdout.split('\n')
            for i, line in enumerate(lines):
                if "sql injection" in line.lower():
                    vuln = {
                        "type": "SQL Injection",
                        "technique": "Unknown",
                        "parameter": "Unknown",
                        "confidence": "High" if "confirmed" in line.lower() else "Medium"
                    }
                    
                    # Look for more details in surrounding lines
                    for j in range(max(0, i-3), min(len(lines), i+4)):
                        if "Type:" in lines[j]:
                            vuln["technique"] = lines[j].split("Type:")[1].strip()
                        if "Parameter:" in lines[j]:
                            vuln["parameter"] = lines[j].split("Parameter:")[1].strip()
                    
                    vulnerabilities.append(vuln)
            
            # Extract additional structured info
            structured_info = ToolOutputParsers._extract_structured_info(stdout)
            
            return {
                "vulnerabilities_found": vulnerabilities,
                "summary": f"Found {len(vulnerabilities)} SQL injection points",
                "raw_output_preview": stdout[:500] + "..." if len(stdout) > 500 else stdout,
                "additional_info": structured_info
            }
        except Exception as e:
            # Fallback to safe parsing
            return ToolOutputParsers._safe_json_parse(stdout, "sqlmap_output")
    
    @staticmethod
    def parse_dirsearch_output(stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse Dirsearch output for discovered paths with robust error handling"""
        try:
            discovered_paths = []
            
            # Look for discovered paths (status codes 200, 301, 302, etc.)
            pattern = r"\[\d{2}:\d{2}:\d{2}\] (\d{3}) - (\d+)B - (.+)"
            
            for line in stdout.split('\n'):
                match = re.search(pattern, line)
                if match:
                    status_code, size, path = match.groups()
                    if status_code in ['200', '301', '302', '403']:
                        discovered_paths.append({
                            "path": path.strip(),
                            "status_code": int(status_code),
                            "size": int(size)
                        })
            
            return {
                "discovered_paths": discovered_paths,
                "total_found": len(discovered_paths),
                "interesting_paths": [p for p in discovered_paths if p["status_code"] in [200, 301, 302]]
            }
        except Exception as e:
            # Fallback to safe parsing
            return ToolOutputParsers._safe_json_parse(stdout, "dirsearch_output")
    
    @staticmethod
    def parse_nuclei_output(stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse Nuclei output for vulnerabilities with robust error handling"""
        try:
            vulnerabilities = []
            
            # Nuclei JSON lines format
            for line in stdout.split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)
                        vuln = {
                            "type": data.get("template-id", "Unknown"),
                            "severity": data.get("info", {}).get("severity", "Unknown"),
                            "url": data.get("host", "Unknown"),
                            "description": data.get("info", {}).get("description", "No description"),
                            "reference": data.get("info", {}).get("reference", [])
                        }
                        vulnerabilities.append(vuln)
                    except json.JSONDecodeError:
                        # Try to parse non-JSON lines
                        if "[" in line and "]" in line and "http" in line:
                            parts = line.split()
                            for part in parts:
                                if part.startswith('http'):
                                    vulnerabilities.append({
                                        "type": "Unknown",
                                        "severity": "Unknown", 
                                        "url": part,
                                        "description": "Found by Nuclei",
                                        "reference": []
                                    })
            
            # Extract additional structured info from stderr too
            structured_info = ToolOutputParsers._extract_structured_info(stderr)
            
            return {
                "vulnerabilities_found": vulnerabilities,
                "summary": f"Found {len(vulnerabilities)} potential vulnerabilities",
                "additional_info": structured_info
            }
        except Exception as e:
            # Fallback to safe parsing
            return ToolOutputParsers._safe_json_parse(stdout, "nuclei_output")
    
    @staticmethod
    def parse_nikto_output(stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse Nikto output for server misconfigurations with robust error handling"""
        try:
            findings = []
            
            # Nikto findings typically start with "+"
            for line in stdout.split('\n'):
                if line.strip().startswith('+'):
                    finding = {
                        "type": "Server Misconfiguration",
                        "description": line.strip()[1:].strip(),  # Remove the "+"
                        "severity": "Medium"  # Nikto findings are typically informational to medium
                    }
                    findings.append(finding)
            
            return {
                "findings": findings,
                "summary": f"Found {len(findings)} server misconfigurations"
            }
        except Exception as e:
            # Fallback to safe parsing
            return ToolOutputParsers._safe_json_parse(stdout, "nikto_output")
    
    @staticmethod
    def parse_scan_result(stdout: str, stderr: str, tool_name: str = "generic") -> Dict[str, Any]:
        """
        TASK 3: Generic parser that ALWAYS returns a structured dictionary
        This is the fallback for any tool output that needs parsing
        
        Args:
            stdout: Standard output from tool
            stderr: Standard error from tool
            tool_name: Name of the tool for context
            
        Returns:
            Always returns a structured dictionary, never fails
        """
        try:
            # Try tool-specific parser first
            if tool_name.lower() == "sqlmap":
                return ToolOutputParsers.parse_sqlmap_output(stdout, stderr)
            elif tool_name.lower() == "dirsearch":
                return ToolOutputParsers.parse_dirsearch_output(stdout, stderr)
            elif tool_name.lower() == "nuclei":
                return ToolOutputParsers.parse_nuclei_output(stdout, stderr)
            elif tool_name.lower() == "nikto":
                return ToolOutputParsers.parse_nikto_output(stdout, stderr)
            
            # Generic parsing
            structured_info = ToolOutputParsers._extract_structured_info(stdout)
            
            return {
                "tool": tool_name,
                "status": "parsed",
                "output_preview": stdout[:500] if len(stdout) > 500 else stdout,
                "stderr_preview": stderr[:200] if stderr and len(stderr) > 200 else stderr,
                "extracted_data": structured_info,
                "raw_available": True
            }
            
        except Exception as e:
            # Ultimate fallback - this should NEVER fail
            return {
                "tool": tool_name,
                "status": "error_parsing",
                "error": str(e),
                "raw_output": stdout[:1000] if stdout else "",
                "raw_stderr": stderr[:500] if stderr else "",
                "note": "Parser encountered an error, returning raw output"
            }