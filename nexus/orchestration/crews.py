"""
Nexus v2.0 - Multi-Agent Crews
==============================

Specialized agent crews for different phases:
- ReconCrew: Subdomain, port scan, crawl, param discovery
- ExploitCrew: IDOR, XSS, SQLi, SSRF testing
- ReportCrew: Finding validation, report generation
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable, Awaitable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

from nexus.config import get_config

logger = logging.getLogger(__name__)


class CrewRole(str, Enum):
    """Roles for crew members."""
    RECON_LEAD = "recon_lead"
    SUBDOMAIN_HUNTER = "subdomain_hunter"
    PORT_SCANNER = "port_scanner"
    CRAWLER = "crawler"
    PARAM_FINDER = "param_finder"
    
    EXPLOIT_LEAD = "exploit_lead"
    IDOR_TESTER = "idor_tester"
    XSS_SPECIALIST = "xss_specialist"
    SQLI_EXPERT = "sqli_expert"
    SSRF_HUNTER = "ssrf_hunter"
    AUTH_BREAKER = "auth_breaker"
    
    REPORT_LEAD = "report_lead"
    VALIDATOR = "validator"
    WRITER = "writer"


@dataclass
class CrewMember:
    """Individual agent in a crew."""
    role: CrewRole
    name: str
    description: str
    tools: List[str]
    model_type: str = "reasoning"
    
    async def execute(self, task: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a task."""
        from nexus.intelligence.litellm_client import get_json_completion
        
        system_prompt = f"""You are {self.name}, a specialist in {self.description}.

Your available tools: {', '.join(self.tools)}

Context:
- Target: {context.get('target', 'unknown')}
- Phase: {context.get('phase', 'unknown')}
- Confidence: {context.get('confidence', 0):.0%}

Analyze the task and determine the best action.
Respond in JSON format:
{{
  "reasoning": "Your analysis...",
  "action": {{
    "tool": "tool_name",
    "args": {{"arg": "value"}}
  }},
  "priority": "high/medium/low"
}}"""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Task: {task.get('description', 'Analyze target')}"}
        ]
        
        response = await get_json_completion(
            model_type=self.model_type,
            messages=messages
        )
        
        return response or {"error": "No response from agent"}


@dataclass
class Crew(ABC):
    """Base class for agent crews."""
    name: str
    members: List[CrewMember] = field(default_factory=list)
    
    @abstractmethod
    async def execute_mission(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the crew's mission."""
        pass
    
    async def broadcast(self, message: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Broadcast a message to all crew members."""
        tasks = [
            member.execute({"description": message}, context)
            for member in self.members
        ]
        return await asyncio.gather(*tasks)


class ReconCrew(Crew):
    """Reconnaissance specialist crew."""
    
    def __init__(self):
        super().__init__(
            name="ReconCrew",
            members=[
                CrewMember(
                    role=CrewRole.SUBDOMAIN_HUNTER,
                    name="SubdomainHunter",
                    description="subdomain enumeration and discovery",
                    tools=["subfinder", "amass", "assetfinder"],
                ),
                CrewMember(
                    role=CrewRole.PORT_SCANNER,
                    name="PortScanner",
                    description="port scanning and service identification",
                    tools=["nmap", "masscan", "rustscan"],
                ),
                CrewMember(
                    role=CrewRole.CRAWLER,
                    name="WebCrawler",
                    description="web crawling and endpoint discovery",
                    tools=["katana", "gospider", "hakrawler"],
                ),
                CrewMember(
                    role=CrewRole.PARAM_FINDER,
                    name="ParamFinder",
                    description="parameter discovery and analysis",
                    tools=["arjun", "paramspider", "gau"],
                ),
            ]
        )
    
    async def execute_mission(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Run full reconnaissance on target."""
        logger.info(f"🔍 ReconCrew starting mission on {target}")
        
        results = {
            "subdomains": [],
            "ports": [],
            "endpoints": [],
            "parameters": [],
        }
        
        # Phase 1: Subdomain enumeration
        subdomain_member = self.members[0]
        subdomain_result = await subdomain_member.execute(
            {"description": f"Find all subdomains of {target}"},
            {**context, "target": target}
        )
        if subdomain_result.get("action"):
            results["subdomains_action"] = subdomain_result["action"]
        
        # Phase 2: Port scanning (parallel with subdomain)
        port_member = self.members[1]
        port_result = await port_member.execute(
            {"description": f"Scan ports on {target}"},
            {**context, "target": target}
        )
        if port_result.get("action"):
            results["ports_action"] = port_result["action"]
        
        # Phase 3: Crawling
        crawler_member = self.members[2]
        crawl_result = await crawler_member.execute(
            {"description": f"Crawl and discover endpoints on {target}"},
            {**context, "target": target}
        )
        if crawl_result.get("action"):
            results["crawl_action"] = crawl_result["action"]
        
        # Phase 4: Parameter discovery
        param_member = self.members[3]
        param_result = await param_member.execute(
            {"description": f"Find parameters and entry points on {target}"},
            {**context, "target": target}
        )
        if param_result.get("action"):
            results["param_action"] = param_result["action"]
        
        return results


class ExploitCrew(Crew):
    """Exploitation specialist crew."""
    
    def __init__(self):
        super().__init__(
            name="ExploitCrew",
            members=[
                CrewMember(
                    role=CrewRole.IDOR_TESTER,
                    name="IDORHunter",
                    description="Insecure Direct Object Reference testing",
                    tools=["idor_scan", "autorize", "match_replace"],
                    model_type="reasoning",
                ),
                CrewMember(
                    role=CrewRole.XSS_SPECIALIST,
                    name="XSSMaster",
                    description="Cross-Site Scripting vulnerability testing",
                    tools=["dalfox", "xsstrike", "kxss"],
                    model_type="code",
                ),
                CrewMember(
                    role=CrewRole.SQLI_EXPERT,
                    name="SQLiExpert",
                    description="SQL Injection testing and exploitation",
                    tools=["sqlmap", "ghauri", "nosqli"],
                    model_type="code",
                ),
                CrewMember(
                    role=CrewRole.SSRF_HUNTER,
                    name="SSRFHunter",
                    description="Server-Side Request Forgery testing",
                    tools=["ssrfmap", "gopherus", "oast_probe"],
                    model_type="reasoning",
                ),
                CrewMember(
                    role=CrewRole.AUTH_BREAKER,
                    name="AuthBreaker",
                    description="Authentication and authorization bypass",
                    tools=["jwt_tool", "oauth_tester", "session_hijack"],
                    model_type="reasoning",
                ),
            ]
        )
    
    async def execute_mission(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Run exploitation testing on target."""
        logger.info(f"💀 ExploitCrew starting mission on {target}")
        
        # Get endpoints from context
        endpoints = context.get("endpoints", [target])
        
        results = {
            "vulnerabilities": [],
            "actions_taken": [],
        }
        
        # Test each endpoint with appropriate crew member
        for endpoint in endpoints[:10]:  # Limit for safety
            # IDOR testing (highest priority)
            idor_result = await self.members[0].execute(
                {"description": f"Test for IDOR vulnerabilities on {endpoint}"},
                {**context, "target": endpoint}
            )
            if idor_result.get("action"):
                results["actions_taken"].append({
                    "type": "idor",
                    "endpoint": endpoint,
                    "action": idor_result["action"]
                })
            
            # XSS testing
            xss_result = await self.members[1].execute(
                {"description": f"Test for XSS vulnerabilities on {endpoint}"},
                {**context, "target": endpoint}
            )
            if xss_result.get("action"):
                results["actions_taken"].append({
                    "type": "xss",
                    "endpoint": endpoint,
                    "action": xss_result["action"]
                })
        
        return results


class ReportCrew(Crew):
    """Report generation and validation crew."""
    
    def __init__(self):
        super().__init__(
            name="ReportCrew",
            members=[
                CrewMember(
                    role=CrewRole.VALIDATOR,
                    name="FindingValidator",
                    description="validating and confirming vulnerabilities",
                    tools=["curl", "http_request", "replay"],
                    model_type="reasoning",
                ),
                CrewMember(
                    role=CrewRole.WRITER,
                    name="ReportWriter",
                    description="writing professional security reports",
                    tools=["report_generator", "screenshot", "poc_creator"],
                    model_type="strategic",
                ),
            ]
        )
    
    async def execute_mission(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate report for findings."""
        logger.info(f"📝 ReportCrew generating report for {target}")
        
        findings = context.get("vulnerabilities", [])
        
        # Validate each finding
        validated = []
        for finding in findings:
            result = await self.members[0].execute(
                {"description": f"Validate vulnerability: {finding}"},
                {**context, "finding": finding}
            )
            if result.get("action"):
                validated.append({
                    "finding": finding,
                    "validation": result
                })
        
        # Generate report
        report_result = await self.members[1].execute(
            {"description": f"Generate professional bug bounty report for {len(validated)} findings"},
            {**context, "validated_findings": validated}
        )
        
        return {
            "validated_count": len(validated),
            "report": report_result
        }


# ============================================================================
# CREW MANAGER
# ============================================================================

class CrewManager:
    """Manages all agent crews."""
    
    def __init__(self):
        self.recon = ReconCrew()
        self.exploit = ExploitCrew()
        self.report = ReportCrew()
        
        self._crews = {
            "recon": self.recon,
            "exploit": self.exploit,
            "report": self.report,
        }
    
    def get_crew(self, name: str) -> Optional[Crew]:
        """Get a crew by name."""
        return self._crews.get(name)
    
    async def run_full_mission(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run a complete bounty mission with all crews."""
        context = context or {}
        context["target"] = target
        
        logger.info(f"🚀 Starting full bounty mission on {target}")
        
        # Phase 1: Recon
        context["phase"] = "recon"
        recon_results = await self.recon.execute_mission(target, context)
        context["recon"] = recon_results
        
        # Phase 2: Exploit (if recon succeeded)
        context["phase"] = "exploit"
        context["confidence"] = 0.5  # After recon
        exploit_results = await self.exploit.execute_mission(target, context)
        context["exploit"] = exploit_results
        
        # Phase 3: Report
        context["phase"] = "report"
        context["vulnerabilities"] = exploit_results.get("vulnerabilities", [])
        report_results = await self.report.execute_mission(target, context)
        
        return {
            "target": target,
            "recon": recon_results,
            "exploit": exploit_results,
            "report": report_results,
        }


# Singleton
_crew_manager: Optional[CrewManager] = None


def get_crew_manager() -> CrewManager:
    """Get the global crew manager."""
    global _crew_manager
    if _crew_manager is None:
        _crew_manager = CrewManager()
    return _crew_manager
