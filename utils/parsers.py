"""
Output parsers for security tools
"""

import re
import json
from typing import Dict, List, Any

class ToolOutputParsers:
    @staticmethod
    def parse_sqlmap_output(stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse SQLMap output for vulnerabilities"""
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
        
        return {
            "vulnerabilities_found": vulnerabilities,
            "summary": f"Found {len(vulnerabilities)} SQL injection points",
            "raw_output_preview": stdout[:500] + "..." if len(stdout) > 500 else stdout
        }

    @staticmethod
    def parse_dirsearch_output(stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse Dirsearch output for discovered paths"""
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

    @staticmethod
    def parse_nuclei_output(stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse Nuclei output for vulnerabilities"""
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
        
        return {
            "vulnerabilities_found": vulnerabilities,
            "summary": f"Found {len(vulnerabilities)} potential vulnerabilities"
        }

    @staticmethod
    def parse_nikto_output(stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse Nikto output for server misconfigurations"""
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