"""
Network Analysis (Sentry) Module for Aegis v8.0

Provides network traffic analysis capabilities including:
- PCAP file analysis
- Credential extraction
- HTTP stream reconstruction
- Suspicious flow detection

Tools wrapped: tshark (Wireshark CLI), tcpdump
"""

import asyncio
import logging
import subprocess
import shutil
from typing import Dict, Any, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)


class NetworkSentry:
    """
    Network traffic analysis engine for CTF and penetration testing.
    
    Wraps tshark and tcpdump with self-healing capabilities.
    """
    
    # Dependency mapping: command -> package name
    DEPENDENCIES = {
        "tshark": "tshark",
        "tcpdump": "tcpdump",
        "capinfos": "wireshark-common",
    }
    
    def __init__(self):
        """Initialize the network sentry."""
        self.tool_paths: Dict[str, Optional[str]] = {}
        self._discover_tools()
        logger.info("📡 NetworkSentry initialized")
    
    def _discover_tools(self) -> None:
        """Discover available network analysis tools."""
        for tool in self.DEPENDENCIES.keys():
            path = shutil.which(tool)
            self.tool_paths[tool] = path
            if path:
                logger.debug(f"✅ Found {tool}: {path}")
            else:
                logger.debug(f"⚠️ Tool {tool} not found")
    
    def check_dependency(self, tool_name: str) -> bool:
        """
        Check if a specific tool is available.
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            True if the tool is available, False otherwise
        """
        if tool_name not in self.tool_paths:
            self._discover_tools()
        return self.tool_paths.get(tool_name) is not None
    
    def get_missing_dependencies(self) -> List[str]:
        """
        Get list of missing tools.
        
        Returns:
            List of tool names that are not installed
        """
        return [tool for tool, path in self.tool_paths.items() if path is None]
    
    async def analyze_pcap(
        self,
        filepath: str,
        timeout: int = 180
    ) -> Dict[str, Any]:
        """
        Comprehensive PCAP file analysis.
        
        Extracts:
        - Capture statistics
        - Protocol hierarchy
        - Potential credentials
        - HTTP streams
        - Suspicious flows
        - DNS queries
        
        Args:
            filepath: Path to the PCAP file
            timeout: Maximum time for analysis
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"📡 Analyzing PCAP: {filepath}")
        
        # Validate file exists
        path = Path(filepath)
        if not path.exists():
            return {"status": "error", "error": f"File not found: {filepath}"}
        
        if not path.is_file():
            return {"status": "error", "error": f"Not a file: {filepath}"}
        
        # Check file extension
        if not path.suffix.lower() in ['.pcap', '.pcapng', '.cap']:
            logger.warning(f"Unusual file extension for PCAP: {path.suffix}")
        
        results = {
            "status": "success",
            "filepath": str(path.absolute()),
            "filename": path.name,
            "size": path.stat().st_size,
            "statistics": {},
            "protocols": [],
            "credentials": [],
            "http_streams": [],
            "dns_queries": [],
            "suspicious_flows": [],
            "endpoints": [],
            "tools_used": [],
        }
        
        # Step 1: Get capture statistics
        stats_result = await self._get_capture_stats(filepath, timeout)
        if stats_result.get("status") == "success":
            results["statistics"] = stats_result.get("data", {})
            results["tools_used"].append("capinfos")
        
        # Step 2: Get protocol hierarchy
        proto_result = await self._get_protocol_hierarchy(filepath, timeout)
        if proto_result.get("status") == "success":
            results["protocols"] = proto_result.get("data", [])
            results["tools_used"].append("tshark")
        
        # Step 3: Extract potential credentials
        creds_result = await self._extract_credentials(filepath, timeout)
        if creds_result.get("status") == "success":
            results["credentials"] = creds_result.get("data", [])
        
        # Step 4: Extract HTTP streams
        http_result = await self._extract_http_streams(filepath, timeout)
        if http_result.get("status") == "success":
            results["http_streams"] = http_result.get("data", [])
        
        # Step 5: Extract DNS queries
        dns_result = await self._extract_dns_queries(filepath, timeout)
        if dns_result.get("status") == "success":
            results["dns_queries"] = dns_result.get("data", [])
        
        # Step 6: Get conversation endpoints
        endpoints_result = await self._get_endpoints(filepath, timeout)
        if endpoints_result.get("status") == "success":
            results["endpoints"] = endpoints_result.get("data", [])
        
        # Step 7: Identify suspicious flows
        results["suspicious_flows"] = self._identify_suspicious_flows(results)
        
        return results
    
    async def _get_capture_stats(
        self,
        filepath: str,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """Get capture file statistics."""
        if not self.check_dependency("capinfos"):
            # Fallback to tshark
            if self.check_dependency("tshark"):
                return await self._get_stats_tshark(filepath, timeout)
            return {"status": "skipped", "error": "No stats tool available"}
        
        try:
            cmd = ["capinfos", "-A", filepath]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode('utf-8', errors='replace')
            
            # Parse capinfos output
            stats = {}
            for line in output.strip().split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    stats[key.strip()] = value.strip()
            
            return {
                "status": "success",
                "data": stats
            }
            
        except asyncio.TimeoutError:
            return {"status": "error", "error": "Statistics collection timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _get_stats_tshark(
        self,
        filepath: str,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """Get basic stats using tshark."""
        try:
            # Get packet count
            cmd = ["tshark", "-r", filepath, "-T", "fields", "-e", "frame.number"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            packet_count = len(stdout.decode('utf-8', errors='replace').strip().split('\n'))
            
            return {
                "status": "success",
                "data": {
                    "packet_count": packet_count
                }
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _get_protocol_hierarchy(
        self,
        filepath: str,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """Get protocol hierarchy from PCAP."""
        if not self.check_dependency("tshark"):
            return {"status": "skipped", "error": "tshark not available"}
        
        try:
            cmd = ["tshark", "-r", filepath, "-q", "-z", "io,phs"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode('utf-8', errors='replace')
            
            # Parse protocol hierarchy
            protocols = []
            for line in output.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith('=') and 'Protocol' not in line:
                    # Parse lines like "  eth:ip:tcp:http"
                    parts = line.split()
                    if parts:
                        protocols.append({
                            "protocol": parts[0],
                            "frames": parts[1] if len(parts) > 1 else None,
                            "bytes": parts[2] if len(parts) > 2 else None,
                        })
            
            return {
                "status": "success",
                "data": protocols
            }
            
        except asyncio.TimeoutError:
            return {"status": "error", "error": "Protocol analysis timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _extract_credentials(
        self,
        filepath: str,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """Extract potential credentials from PCAP."""
        if not self.check_dependency("tshark"):
            return {"status": "skipped", "error": "tshark not available"}
        
        credentials = []
        
        try:
            # Look for HTTP Basic Auth
            cmd = [
                "tshark", "-r", filepath, "-Y", "http.authbasic",
                "-T", "fields", "-e", "http.authbasic"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode('utf-8', errors='replace').strip()
            if output:
                for line in output.split('\n'):
                    if line.strip():
                        credentials.append({
                            "type": "HTTP Basic Auth",
                            "value": line.strip()
                        })
            
            # Look for FTP credentials
            cmd = [
                "tshark", "-r", filepath, "-Y", "ftp.request.command == USER || ftp.request.command == PASS",
                "-T", "fields", "-e", "ftp.request.command", "-e", "ftp.request.arg"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode('utf-8', errors='replace').strip()
            if output:
                for line in output.split('\n'):
                    parts = line.strip().split('\t')
                    if len(parts) >= 2:
                        credentials.append({
                            "type": f"FTP {parts[0]}",
                            "value": parts[1]
                        })
            
            # Look for SMTP auth
            cmd = [
                "tshark", "-r", filepath, "-Y", "smtp.auth.username || smtp.auth.password",
                "-T", "fields", "-e", "smtp.auth.username", "-e", "smtp.auth.password"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode('utf-8', errors='replace').strip()
            if output:
                for line in output.split('\n'):
                    if line.strip():
                        credentials.append({
                            "type": "SMTP Auth",
                            "value": line.strip()
                        })
            
            return {
                "status": "success",
                "data": credentials
            }
            
        except asyncio.TimeoutError:
            return {"status": "error", "error": "Credential extraction timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _extract_http_streams(
        self,
        filepath: str,
        timeout: int = 60,
        max_streams: int = 20
    ) -> Dict[str, Any]:
        """Extract HTTP request/response info."""
        if not self.check_dependency("tshark"):
            return {"status": "skipped", "error": "tshark not available"}
        
        try:
            cmd = [
                "tshark", "-r", filepath, "-Y", "http",
                "-T", "fields",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "http.request.method", "-e", "http.request.uri",
                "-e", "http.host", "-e", "http.response.code",
                "-E", "header=n", "-E", "separator=|"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode('utf-8', errors='replace').strip()
            
            streams = []
            for line in output.split('\n')[:max_streams]:
                if line.strip():
                    parts = line.split('|')
                    if len(parts) >= 4:
                        streams.append({
                            "src_ip": parts[0],
                            "dst_ip": parts[1],
                            "method": parts[2],
                            "uri": parts[3],
                            "host": parts[4] if len(parts) > 4 else None,
                            "response_code": parts[5] if len(parts) > 5 else None,
                        })
            
            return {
                "status": "success",
                "data": streams
            }
            
        except asyncio.TimeoutError:
            return {"status": "error", "error": "HTTP extraction timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _extract_dns_queries(
        self,
        filepath: str,
        timeout: int = 60,
        max_queries: int = 50
    ) -> Dict[str, Any]:
        """Extract DNS queries from PCAP."""
        if not self.check_dependency("tshark"):
            return {"status": "skipped", "error": "tshark not available"}
        
        try:
            cmd = [
                "tshark", "-r", filepath, "-Y", "dns.flags.response == 0",
                "-T", "fields", "-e", "dns.qry.name",
                "-E", "header=n"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode('utf-8', errors='replace').strip()
            
            # Get unique queries
            queries = list(set([q.strip() for q in output.split('\n') if q.strip()]))
            
            return {
                "status": "success",
                "data": queries[:max_queries]
            }
            
        except asyncio.TimeoutError:
            return {"status": "error", "error": "DNS extraction timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _get_endpoints(
        self,
        filepath: str,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """Get communication endpoints."""
        if not self.check_dependency("tshark"):
            return {"status": "skipped", "error": "tshark not available"}
        
        try:
            cmd = ["tshark", "-r", filepath, "-q", "-z", "endpoints,ip"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode('utf-8', errors='replace')
            
            # Parse endpoint list
            endpoints = []
            for line in output.strip().split('\n'):
                line = line.strip()
                # Skip header lines
                if not line or line.startswith('=') or 'Address' in line:
                    continue
                
                parts = line.split()
                if parts and '.' in parts[0]:  # IP address
                    endpoints.append({
                        "ip": parts[0],
                        "packets": parts[1] if len(parts) > 1 else None,
                        "bytes": parts[2] if len(parts) > 2 else None,
                    })
            
            return {
                "status": "success",
                "data": endpoints
            }
            
        except asyncio.TimeoutError:
            return {"status": "error", "error": "Endpoint extraction timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def _identify_suspicious_flows(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify suspicious network flows."""
        suspicious = []
        
        # Check for credentials in clear text
        if results.get("credentials"):
            suspicious.append({
                "type": "clear_text_credentials",
                "description": f"Found {len(results['credentials'])} potential credentials in clear text",
                "severity": "high"
            })
        
        # Check for suspicious DNS queries
        dns_queries = results.get("dns_queries", [])
        suspicious_domains = []
        for query in dns_queries:
            # Check for base64-like subdomains (potential exfiltration)
            parts = query.split('.')
            for part in parts:
                if len(part) > 30 and part.isalnum():
                    suspicious_domains.append(query)
                    break
            # Check for known malicious TLDs or patterns
            if any(tld in query.lower() for tld in ['.tk', '.xyz', '.top', '.pw']):
                suspicious_domains.append(query)
        
        if suspicious_domains:
            suspicious.append({
                "type": "suspicious_dns",
                "description": f"Found {len(suspicious_domains)} suspicious DNS queries",
                "severity": "medium",
                "domains": suspicious_domains[:10]
            })
        
        # Check HTTP for interesting paths
        http_streams = results.get("http_streams", [])
        interesting_paths = []
        sensitive_patterns = ['/admin', '/login', '/api', '/config', '/.git', '/.env', '/backup']
        for stream in http_streams:
            uri = stream.get("uri", "")
            if any(pattern in uri.lower() for pattern in sensitive_patterns):
                interesting_paths.append(uri)
        
        if interesting_paths:
            suspicious.append({
                "type": "sensitive_paths",
                "description": f"Found {len(interesting_paths)} requests to sensitive paths",
                "severity": "low",
                "paths": interesting_paths[:10]
            })
        
        return suspicious
    
    async def follow_tcp_stream(
        self,
        filepath: str,
        stream_number: int = 0,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """
        Follow a specific TCP stream.
        
        Args:
            filepath: Path to PCAP file
            stream_number: TCP stream number to follow
            timeout: Maximum time for extraction
            
        Returns:
            Dictionary with stream content
        """
        if not self.check_dependency("tshark"):
            return {"status": "error", "error": "tshark not available"}
        
        try:
            cmd = [
                "tshark", "-r", filepath,
                "-q", "-z", f"follow,tcp,ascii,{stream_number}"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode('utf-8', errors='replace')
            
            return {
                "status": "success",
                "data": {
                    "stream_number": stream_number,
                    "content": output
                }
            }
            
        except asyncio.TimeoutError:
            return {"status": "error", "error": "Stream extraction timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}


# Singleton instance
_network_sentry_instance = None


def get_network_sentry() -> NetworkSentry:
    """Get singleton network sentry instance."""
    global _network_sentry_instance
    if _network_sentry_instance is None:
        _network_sentry_instance = NetworkSentry()
    return _network_sentry_instance
