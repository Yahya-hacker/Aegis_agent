"""
Nexus v2.0 - Port Scanning
==========================

Tools: nmap, masscan, rustscan
"""

import asyncio
import logging
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from nexus.execution.e2b_sandbox import execute_in_sandbox

logger = logging.getLogger(__name__)


@dataclass
class Port:
    """Information about a discovered port."""
    port: int
    protocol: str
    state: str
    service: str = ""
    version: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "version": self.version,
        }


@dataclass
class Host:
    """Information about a scanned host."""
    ip: str
    hostname: str = ""
    state: str = "up"
    ports: List[Port] = field(default_factory=list)
    os_guess: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "state": self.state,
            "ports": [p.to_dict() for p in self.ports],
            "os_guess": self.os_guess,
        }


@dataclass
class ScanResult:
    """Result of port scan."""
    target: str
    hosts: List[Host]
    scan_type: str
    duration: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "hosts": [h.to_dict() for h in self.hosts],
            "scan_type": self.scan_type,
            "duration": self.duration,
            "total_open_ports": sum(len(h.ports) for h in self.hosts),
        }


async def run_nmap(
    target: str,
    ports: str = "1-1000",
    scan_type: str = "-sV",
    timeout: int = 600
) -> ScanResult:
    """
    Run nmap scan.
    
    Args:
        target: Target IP/hostname
        ports: Port range
        scan_type: Nmap scan type (-sS, -sV, -sC, etc.)
        timeout: Scan timeout
    
    Returns:
        ScanResult with discovered hosts/ports
    """
    logger.info(f"🔍 Running nmap on {target}")
    
    args = {
        "target": target,
        "p": ports,
        "oX": "-",  # XML output to stdout
    }
    
    # Add scan type flags
    if "-sV" in scan_type:
        args["sV"] = True
    if "-sC" in scan_type:
        args["sC"] = True
    if "-sS" in scan_type:
        args["sS"] = True
    
    result = await execute_in_sandbox({
        "tool": "nmap",
        "args": args
    })
    
    if result.get("status") != "success":
        return ScanResult(target=target, hosts=[], scan_type=scan_type, duration=0)
    
    # Parse nmap output
    output = result.get("stdout", "")
    hosts = parse_nmap_output(output)
    
    return ScanResult(
        target=target,
        hosts=hosts,
        scan_type=scan_type,
        duration=result.get("duration", 0),
    )


def parse_nmap_output(output: str) -> List[Host]:
    """Parse nmap output (text format)."""
    hosts = []
    current_host = None
    
    lines = output.split("\n")
    
    for line in lines:
        # Match host line
        host_match = re.match(r"Nmap scan report for (.+?)(?:\s+\((.+)\))?$", line)
        if host_match:
            if current_host:
                hosts.append(current_host)
            
            hostname = host_match.group(1)
            ip = host_match.group(2) or hostname
            current_host = Host(ip=ip, hostname=hostname)
            continue
        
        # Match port line
        port_match = re.match(
            r"(\d+)/(\w+)\s+(\w+)\s+(.+?)(?:\s+(.+))?$",
            line.strip()
        )
        if port_match and current_host:
            port = Port(
                port=int(port_match.group(1)),
                protocol=port_match.group(2),
                state=port_match.group(3),
                service=port_match.group(4),
                version=port_match.group(5) or "",
            )
            current_host.ports.append(port)
    
    if current_host:
        hosts.append(current_host)
    
    return hosts


async def quick_scan(target: str) -> ScanResult:
    """Quick scan of common ports."""
    common_ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
    return await run_nmap(target, ports=common_ports, scan_type="-sV")


async def full_scan(target: str) -> ScanResult:
    """Full port scan (1-65535)."""
    return await run_nmap(target, ports="1-65535", scan_type="-sS")


async def service_scan(target: str, ports: str) -> ScanResult:
    """Detailed service version scan."""
    return await run_nmap(target, ports=ports, scan_type="-sV -sC")


async def scan_network(cidr: str, ports: str = "80,443") -> List[ScanResult]:
    """Scan a network range."""
    results = []
    result = await run_nmap(cidr, ports=ports, scan_type="-sn")  # Ping scan first
    
    # Then scan each live host
    for host in result.hosts:
        if host.state == "up":
            host_result = await quick_scan(host.ip)
            results.append(host_result)
    
    return results


async def identify_web_servers(target: str) -> List[Dict[str, Any]]:
    """Find web servers on common ports."""
    web_ports = "80,443,8080,8443,8000,8888,3000,5000,9000"
    result = await run_nmap(target, ports=web_ports, scan_type="-sV")
    
    web_servers = []
    for host in result.hosts:
        for port in host.ports:
            if port.state == "open" and any(
                svc in port.service.lower() 
                for svc in ["http", "https", "ssl", "nginx", "apache", "tomcat"]
            ):
                proto = "https" if port.port in [443, 8443] or "ssl" in port.service.lower() else "http"
                web_servers.append({
                    "url": f"{proto}://{host.ip}:{port.port}",
                    "service": port.service,
                    "version": port.version,
                })
    
    return web_servers
