"""
Nexus v2.0 - Attack Chain Planner
=================================

LLM-powered attack chain planning.
Analyzes recon data and plans multi-step attack paths.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from nexus.config import get_config
from nexus.intelligence.litellm_client import get_json_completion

logger = logging.getLogger(__name__)


class AttackPhase(str, Enum):
    """Phases of an attack."""
    RECON = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFIL = "data_exfiltration"
    PERSISTENCE = "persistence"


class VulnCategory(str, Enum):
    """Vulnerability categories."""
    INJECTION = "injection"  # SQLi, XSS, Command, SSTI
    BROKEN_AUTH = "broken_auth"  # Session, JWT, OAuth
    BROKEN_ACCESS = "broken_access"  # IDOR, privilege escalation
    SECURITY_MISCONFIG = "security_misconfig"  # CORS, headers
    EXPOSURE = "exposure"  # Info leak, sensitive data
    SSRF = "ssrf"
    LOGIC_FLAW = "logic_flaw"


@dataclass
class AttackNode:
    """A single step in an attack chain."""
    id: str
    name: str
    category: VulnCategory
    phase: AttackPhase
    target: str
    technique: str
    prerequisites: List[str] = field(default_factory=list)
    confidence: float = 0.5
    impact: str = "medium"
    tools: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "phase": self.phase.value,
            "target": self.target,
            "technique": self.technique,
            "prerequisites": self.prerequisites,
            "confidence": self.confidence,
            "impact": self.impact,
            "tools": self.tools,
        }


@dataclass
class AttackChain:
    """A complete attack chain (series of steps)."""
    id: str
    name: str
    nodes: List[AttackNode]
    overall_confidence: float = 0.5
    estimated_impact: str = "medium"
    complexity: str = "medium"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "nodes": [n.to_dict() for n in self.nodes],
            "overall_confidence": self.overall_confidence,
            "estimated_impact": self.estimated_impact,
            "complexity": self.complexity,
        }


class AttackPlanner:
    """
    Plans attack chains based on reconnaissance data.
    Uses LLM to generate intelligent attack strategies.
    """
    
    def __init__(self):
        self.config = get_config()
        self._chains: List[AttackChain] = []
    
    async def analyze_target(
        self,
        target: str,
        recon_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze target and generate attack surface map.
        
        Args:
            target: Target domain/IP
            recon_data: Reconnaissance results
        
        Returns:
            Attack surface analysis
        """
        prompt = f"""Analyze this target and reconnaissance data to identify the attack surface.

TARGET: {target}

RECONNAISSANCE DATA:
- Subdomains: {recon_data.get('subdomains', [])}
- Open Ports: {recon_data.get('ports', [])}
- Technologies: {recon_data.get('technologies', [])}
- Endpoints: {recon_data.get('endpoints', [])}
- Parameters: {recon_data.get('parameters', [])}

Provide a detailed attack surface analysis in JSON:
{{
  "attack_surface": {{
    "web_applications": ["list of web apps/endpoints"],
    "api_endpoints": ["list of API endpoints"],
    "authentication_points": ["login pages, OAuth, etc"],
    "file_upload_points": ["endpoints accepting files"],
    "user_input_points": ["forms, search, etc"],
    "data_exposure_risks": ["potential info leaks"],
    "third_party_integrations": ["external services"]
  }},
  "priority_targets": [
    {{"target": "endpoint", "reason": "why it's high value", "vuln_potential": "likely vulns"}}
  ],
  "recommended_attack_vectors": [
    "IDOR on /api/users/*",
    "SQLi on search parameter",
    "SSRF via webhook URL"
  ]
}}"""

        result = await get_json_completion(
            model_type="strategic",
            messages=[{"role": "user", "content": prompt}]
        )
        
        return result or {}
    
    async def plan_attack_chains(
        self,
        target: str,
        attack_surface: Dict[str, Any],
        constraints: Dict[str, Any] = None
    ) -> List[AttackChain]:
        """
        Generate attack chains based on attack surface.
        
        Args:
            target: Target domain
            attack_surface: Analysis from analyze_target
            constraints: Rules (no destructive attacks, etc)
        
        Returns:
            List of attack chains sorted by expected impact
        """
        constraints = constraints or {"no_destructive": True, "stealth_mode": True}
        
        prompt = f"""Based on this attack surface, plan detailed attack chains.

TARGET: {target}

ATTACK SURFACE:
{attack_surface}

CONSTRAINTS: {constraints}

Generate 3-5 attack chains from most impactful to least.
Each chain should be a realistic path to a vulnerability.

Respond in JSON:
{{
  "chains": [
    {{
      "id": "chain_1",
      "name": "IDOR to Account Takeover",
      "complexity": "low/medium/high",
      "estimated_impact": "critical/high/medium/low",
      "confidence": 0.7,
      "steps": [
        {{
          "step": 1,
          "name": "Identify user ID parameter",
          "technique": "Parameter analysis",
          "tool": "burp_intruder",
          "target": "/api/users/123",
          "prerequisites": []
        }},
        {{
          "step": 2,
          "name": "Test IDOR",
          "technique": "Replace user ID with another",
          "tool": "idor_scanner",
          "target": "/api/users/124",
          "prerequisites": ["step_1"]
        }}
      ]
    }}
  ]
}}"""

        result = await get_json_completion(
            model_type="strategic",
            messages=[{"role": "user", "content": prompt}]
        )
        
        if not result:
            return []
        
        chains = []
        for chain_data in result.get("chains", []):
            nodes = []
            for step in chain_data.get("steps", []):
                node = AttackNode(
                    id=f"{chain_data['id']}_step_{step.get('step', 0)}",
                    name=step.get("name", ""),
                    category=self._infer_category(step.get("technique", "")),
                    phase=AttackPhase.EXPLOITATION,
                    target=step.get("target", ""),
                    technique=step.get("technique", ""),
                    prerequisites=step.get("prerequisites", []),
                    tools=[step.get("tool", "")],
                )
                nodes.append(node)
            
            chain = AttackChain(
                id=chain_data.get("id", ""),
                name=chain_data.get("name", ""),
                nodes=nodes,
                overall_confidence=chain_data.get("confidence", 0.5),
                estimated_impact=chain_data.get("estimated_impact", "medium"),
                complexity=chain_data.get("complexity", "medium"),
            )
            chains.append(chain)
        
        self._chains = chains
        return chains
    
    def _infer_category(self, technique: str) -> VulnCategory:
        """Infer vulnerability category from technique."""
        technique_lower = technique.lower()
        
        if any(x in technique_lower for x in ["idor", "access", "privilege"]):
            return VulnCategory.BROKEN_ACCESS
        elif any(x in technique_lower for x in ["sql", "xss", "inject", "command"]):
            return VulnCategory.INJECTION
        elif any(x in technique_lower for x in ["auth", "session", "jwt", "oauth"]):
            return VulnCategory.BROKEN_AUTH
        elif any(x in technique_lower for x in ["ssrf", "server-side"]):
            return VulnCategory.SSRF
        elif any(x in technique_lower for x in ["logic", "business", "workflow"]):
            return VulnCategory.LOGIC_FLAW
        else:
            return VulnCategory.EXPOSURE
    
    async def get_next_action(
        self,
        current_state: Dict[str, Any],
        completed_steps: List[str]
    ) -> Optional[AttackNode]:
        """
        Get the next action to take based on current state.
        
        Args:
            current_state: Current mission state
            completed_steps: List of completed step IDs
        
        Returns:
            Next attack node to execute
        """
        for chain in self._chains:
            for node in chain.nodes:
                if node.id in completed_steps:
                    continue
                
                # Check prerequisites
                prereqs_met = all(p in completed_steps for p in node.prerequisites)
                if prereqs_met:
                    return node
        
        return None
    
    def get_chains(self) -> List[Dict[str, Any]]:
        """Get all planned attack chains."""
        return [c.to_dict() for c in self._chains]


# Singleton
_planner: Optional[AttackPlanner] = None


def get_attack_planner() -> AttackPlanner:
    """Get the global attack planner."""
    global _planner
    if _planner is None:
        _planner = AttackPlanner()
    return _planner
