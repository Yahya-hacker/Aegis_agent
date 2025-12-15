#!/usr/bin/env python3
"""
AEGIS OMEGA PROTOCOL - Adversarial Swarm Protocol
==================================================

Implements the internal debate mechanism with sub-personas:
- RED (Attacker): Proposes aggressive exploit strategies
- BLUE (Defender): Analyzes defenses, WAF signatures, rate limits
- JUDGE (Strategist): Synthesizes optimal stealth path

This module ensures actions are evaluated from multiple perspectives
before execution, improving success rates and reducing detection.
"""

import asyncio
import logging
import json
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class SwarmPersona(Enum):
    """Sub-personas in the adversarial swarm"""
    RED = "red"      # Attacker perspective
    BLUE = "blue"    # Defender perspective
    JUDGE = "judge"  # Strategic synthesis


@dataclass
class SwarmArgument:
    """An argument from a swarm persona"""
    persona: SwarmPersona
    content: str
    risk_assessment: Optional[float] = None  # 0-10 scale
    confidence: float = 0.8
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DebateResult:
    """Result of an adversarial debate"""
    original_action: Dict[str, Any]
    red_argument: SwarmArgument
    blue_argument: SwarmArgument
    judge_decision: SwarmArgument
    final_action: Dict[str, Any]
    risk_score: float
    approved: bool
    reasoning: str
    modifications: List[str] = field(default_factory=list)
    debate_id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


class AdversarialSwarm:
    """
    Adversarial Swarm Protocol implementation.
    
    Before executing any tool with risk_score > threshold, simulates 
    a debate between internal sub-personas:
    
    - RED (Attacker): Proposes aggressive exploits
    - BLUE (Defender): Identifies detection risks
    - JUDGE (Strategist): Synthesizes stealth approach
    
    Output format: [DEBATE] RED: ..., BLUE: ..., JUDGE: Executing stealth variant B.
    """
    
    # Default risk threshold for triggering debate
    RISK_THRESHOLD = 5.0
    
    # Tool risk scores (tools above threshold trigger debate)
    TOOL_RISK_SCORES = {
        # High risk (exploitation)
        "sql_injection_test": 8,
        "xss_test": 7,
        "command_injection": 9,
        "file_upload_exploit": 8,
        "deserialization_attack": 9,
        "ssrf_test": 7,
        "lfi_test": 7,
        "rfi_test": 8,
        "xxe_test": 7,
        "template_injection": 8,
        
        # Medium risk (intrusive scanning)
        "directory_bruteforce": 6,
        "parameter_fuzzing": 6,
        "authentication_bypass": 7,
        "session_hijacking": 8,
        "brute_force_login": 7,
        
        # Low risk (reconnaissance)
        "http_request": 2,
        "find_forms": 3,
        "technology_fingerprint": 3,
        "port_scan": 4,
        "dns_lookup": 2,
        "whois_lookup": 1,
        "screenshot_capture": 2,
        "robots_txt": 1,
        "sitemap": 1
    }
    
    # WAF signatures that BLUE should check
    WAF_SIGNATURES = {
        "cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
        "akamai": ["akamai", "x-akamai"],
        "aws_waf": ["x-amz-cf", "awselb"],
        "imperva": ["incap_ses", "visid_incap"],
        "f5": ["f5avraaaaaaa", "bigipserver"],
        "modsecurity": ["mod_security", "modsec"],
        "sucuri": ["x-sucuri-id"],
        "wordfence": ["wordfence"],
    }
    
    # Rate limit indicators
    RATE_LIMIT_INDICATORS = [
        "429", "too many requests", "rate limit", 
        "slow down", "request limit", "throttl"
    ]
    
    # Honeypot indicators
    HONEYPOT_INDICATORS = [
        "hidden", "trap", "honeypot", "canary",
        "decoy", "fake", "bait"
    ]
    
    def __init__(self, ai_core=None, risk_threshold: float = 5.0):
        """
        Initialize the Adversarial Swarm.
        
        Args:
            ai_core: Optional AI core for LLM-based reasoning
            risk_threshold: Risk score threshold for triggering debate
        """
        self.ai_core = ai_core
        self.risk_threshold = risk_threshold
        self.debate_history: List[DebateResult] = []
        self._debate_counter = 0
        
        # Context from previous scans (for BLUE analysis)
        self.detected_waf: Optional[str] = None
        self.rate_limit_observed: bool = False
        self.last_response_headers: Dict[str, str] = {}
    
    def get_tool_risk(self, tool_name: str) -> float:
        """
        Get the risk score for a tool.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Risk score (0-10)
        """
        return self.TOOL_RISK_SCORES.get(tool_name, 5.0)
    
    async def should_debate(self, action: Dict[str, Any]) -> bool:
        """
        Determine if an action requires debate.
        
        Args:
            action: The proposed action
            
        Returns:
            True if debate is required
        """
        tool = action.get("tool", "")
        risk = self.get_tool_risk(tool)
        return risk > self.risk_threshold
    
    async def conduct_debate(self, action: Dict[str, Any], 
                             context: Optional[Dict[str, Any]] = None) -> DebateResult:
        """
        Conduct an adversarial debate on a proposed action.
        
        Args:
            action: The proposed action (tool + args)
            context: Additional context (target info, previous responses)
            
        Returns:
            DebateResult with final decision
        """
        self._debate_counter += 1
        debate_id = f"debate_{self._debate_counter}"
        
        tool = action.get("tool", "unknown")
        args = action.get("args", {})
        risk_score = self.get_tool_risk(tool)
        
        logger.info(f"\n{'='*80}")
        logger.info(f"🎭 ADVERSARIAL SWARM DEBATE - {debate_id}")
        logger.info(f"Tool: {tool} | Risk Score: {risk_score}/10")
        logger.info(f"{'='*80}")
        
        # Generate arguments from each persona
        if self.ai_core:
            red_arg, blue_arg, judge_arg = await self._llm_debate(action, context)
        else:
            red_arg, blue_arg, judge_arg = await self._heuristic_debate(action, context)
        
        # Log the debate
        logger.info(f"\n🔴 RED (Attacker): {red_arg.content[:200]}...")
        logger.info(f"\n🔵 BLUE (Defender): {blue_arg.content[:200]}...")
        logger.info(f"\n⚖️ JUDGE (Strategist): {judge_arg.content[:200]}...")
        
        # Parse judge decision for modifications
        final_action, modifications = self._apply_judge_decision(action, judge_arg)
        
        # Determine if action is approved
        approved = "reject" not in judge_arg.content.lower() and "abort" not in judge_arg.content.lower()
        
        result = DebateResult(
            original_action=action,
            red_argument=red_arg,
            blue_argument=blue_arg,
            judge_decision=judge_arg,
            final_action=final_action,
            risk_score=risk_score,
            approved=approved,
            reasoning=judge_arg.content,
            modifications=modifications,
            debate_id=debate_id
        )
        
        self.debate_history.append(result)
        
        # Format output as specified
        debate_output = (
            f"[DEBATE] RED: {red_arg.content[:100]}... | "
            f"BLUE: {blue_arg.content[:100]}... | "
            f"JUDGE: {judge_arg.content[:150]}"
        )
        logger.info(f"\n📋 {debate_output}")
        logger.info(f"{'='*80}\n")
        
        return result
    
    async def _heuristic_debate(self, action: Dict[str, Any],
                                 context: Optional[Dict[str, Any]]) -> Tuple[SwarmArgument, SwarmArgument, SwarmArgument]:
        """
        Generate debate arguments using heuristics (no LLM).
        
        Args:
            action: Proposed action
            context: Additional context
            
        Returns:
            Tuple of (red, blue, judge) arguments
        """
        tool = action.get("tool", "unknown")
        args = action.get("args", {})
        target = args.get("url", args.get("target", "unknown"))
        
        # RED: Aggressive attack proposal
        red_attacks = {
            "sql_injection_test": "Use time-based blind SQLi with SLEEP(5) to confirm vulnerability. If successful, escalate to UNION-based extraction.",
            "xss_test": "Inject polyglot payload that bypasses common filters: jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert())/",
            "directory_bruteforce": "Use aggressive wordlist with common backup files (.bak, .old, .sql) and max threads.",
            "authentication_bypass": "Try SQL injection in login, default credentials, and JWT token manipulation.",
        }
        
        red_content = red_attacks.get(
            tool, 
            f"Execute {tool} with maximum aggression. Use all available payloads and don't throttle requests."
        )
        
        red_arg = SwarmArgument(
            persona=SwarmPersona.RED,
            content=red_content,
            risk_assessment=8.0,
            confidence=0.8
        )
        
        # BLUE: Defense analysis
        blue_warnings = []
        
        # Check for WAF
        if self.detected_waf:
            blue_warnings.append(f"⚠️ {self.detected_waf.upper()} WAF detected - aggressive scanning will trigger blocks")
        
        # Check headers for WAF signatures
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            if context:
                headers = context.get("headers", {})
                for sig in signatures:
                    if any(sig.lower() in str(v).lower() for v in headers.values()):
                        blue_warnings.append(f"⚠️ {waf_name.upper()} signatures detected in headers")
                        break
        
        # Check for rate limiting
        if self.rate_limit_observed:
            blue_warnings.append("⚠️ Rate limiting observed - slow down requests")
        
        # Tool-specific warnings
        tool_warnings = {
            "sql_injection_test": "SQLi payloads trigger most WAF rules. Use encoding/obfuscation.",
            "xss_test": "XSS detection is common. Avoid obvious <script> tags.",
            "directory_bruteforce": "High request volume will trigger rate limits and logging.",
            "authentication_bypass": "Failed logins are typically logged and may lock accounts.",
        }
        
        if tool in tool_warnings:
            blue_warnings.append(tool_warnings[tool])
        
        if not blue_warnings:
            blue_warnings.append("No immediate defense concerns detected, but proceed with caution.")
        
        blue_content = " ".join(blue_warnings)
        
        blue_arg = SwarmArgument(
            persona=SwarmPersona.BLUE,
            content=blue_content,
            risk_assessment=5.0,
            confidence=0.7
        )
        
        # JUDGE: Strategic synthesis
        judge_mods = []
        
        # Apply mitigations based on BLUE's warnings
        if "WAF" in blue_content:
            judge_mods.append("Use URL encoding and case variation to bypass WAF")
            judge_mods.append("Add random delays between requests (1-3 seconds)")
        
        if "rate limit" in blue_content.lower():
            judge_mods.append("Reduce request rate to 1 request per 2 seconds")
            judge_mods.append("Rotate User-Agent headers")
        
        if "logging" in blue_content.lower():
            judge_mods.append("Minimize footprint - use targeted payloads only")
        
        if not judge_mods:
            judge_mods.append("Proceed with stealth variant - single targeted request")
        
        judge_content = f"Execute stealth variant. Modifications: {'; '.join(judge_mods)}"
        
        judge_arg = SwarmArgument(
            persona=SwarmPersona.JUDGE,
            content=judge_content,
            risk_assessment=4.0,
            confidence=0.85
        )
        
        return red_arg, blue_arg, judge_arg
    
    async def _llm_debate(self, action: Dict[str, Any],
                          context: Optional[Dict[str, Any]]) -> Tuple[SwarmArgument, SwarmArgument, SwarmArgument]:
        """
        Generate debate arguments using LLM.
        
        Args:
            action: Proposed action
            context: Additional context
            
        Returns:
            Tuple of (red, blue, judge) arguments
        """
        tool = action.get("tool", "unknown")
        args = action.get("args", {})
        
        debate_prompt = f"""You are simulating an ADVERSARIAL SWARM PROTOCOL debate for a security testing action.

ACTION TO EVALUATE:
Tool: {tool}
Arguments: {json.dumps(args, indent=2)}
Context: {json.dumps(context or {}, indent=2) if context else "No additional context"}

WAF/Defense Status:
- Detected WAF: {self.detected_waf or "None detected"}
- Rate Limiting Observed: {self.rate_limit_observed}

Generate responses from THREE personas:

1. RED (Attacker): Propose the most aggressive, effective exploit approach.
   - What payload/technique maximizes impact?
   - How to escalate if initial attack succeeds?

2. BLUE (Defender): Analyze defense mechanisms that would catch RED's approach.
   - What WAF rules would trigger?
   - What rate limits or detection mechanisms exist?
   - What logging would capture this attack?

3. JUDGE (Strategist): Synthesize a path that achieves RED's goal while bypassing BLUE's constraints.
   - What modifications make the attack stealthier?
   - What's the minimal footprint approach?

Respond in JSON format:
{{
    "red": {{
        "content": "Aggressive attack proposal...",
        "risk_assessment": 8.5
    }},
    "blue": {{
        "content": "Defense analysis and warnings...",
        "risk_assessment": 5.0
    }},
    "judge": {{
        "content": "Stealth variant decision: Execute with modifications...",
        "risk_assessment": 4.0,
        "modifications": ["mod1", "mod2"]
    }}
}}
"""
        
        try:
            response = await self.ai_core.orchestrator.route_request(
                prompt=debate_prompt,
                task_type="reasoning",
                context={"phase": "SWARM_DEBATE", "tool": tool}
            )
            
            # Parse response
            from agents.enhanced_ai_core import parse_json_robust
            result = await parse_json_robust(response, self.ai_core.orchestrator, "swarm debate")
            
            if result:
                red_arg = SwarmArgument(
                    persona=SwarmPersona.RED,
                    content=result.get("red", {}).get("content", "Attack proposal"),
                    risk_assessment=result.get("red", {}).get("risk_assessment", 8.0),
                    confidence=0.8
                )
                
                blue_arg = SwarmArgument(
                    persona=SwarmPersona.BLUE,
                    content=result.get("blue", {}).get("content", "Defense analysis"),
                    risk_assessment=result.get("blue", {}).get("risk_assessment", 5.0),
                    confidence=0.7
                )
                
                judge_arg = SwarmArgument(
                    persona=SwarmPersona.JUDGE,
                    content=result.get("judge", {}).get("content", "Execute stealth variant"),
                    risk_assessment=result.get("judge", {}).get("risk_assessment", 4.0),
                    confidence=0.85,
                    metadata={"modifications": result.get("judge", {}).get("modifications", [])}
                )
                
                return red_arg, blue_arg, judge_arg
        
        except Exception as e:
            logger.error(f"LLM debate failed: {e}, falling back to heuristics")
        
        # Fallback to heuristic debate
        return await self._heuristic_debate(action, context)
    
    def _apply_judge_decision(self, original_action: Dict[str, Any],
                               judge_arg: SwarmArgument) -> Tuple[Dict[str, Any], List[str]]:
        """
        Apply judge's modifications to the original action.
        
        Args:
            original_action: The original proposed action
            judge_arg: The judge's argument with modifications
            
        Returns:
            Tuple of (modified_action, list_of_modifications)
        """
        modified_action = original_action.copy()
        modifications = []
        
        # Get modifications from judge metadata
        judge_mods = judge_arg.metadata.get("modifications", [])
        
        # Apply common modifications based on content
        content_lower = judge_arg.content.lower()
        args = modified_action.get("args", {})
        
        if "delay" in content_lower or "slow" in content_lower:
            args["delay"] = args.get("delay", 2.0)  # Add 2 second delay
            modifications.append("Added 2-second delay between requests")
        
        if "encoding" in content_lower or "obfuscat" in content_lower:
            args["use_encoding"] = True
            modifications.append("Enabled payload encoding/obfuscation")
        
        if "single" in content_lower or "targeted" in content_lower:
            args["max_attempts"] = 1
            modifications.append("Limited to single targeted attempt")
        
        if "user-agent" in content_lower or "rotate" in content_lower:
            args["rotate_headers"] = True
            modifications.append("Enabled header rotation")
        
        modified_action["args"] = args
        modifications.extend(judge_mods)
        
        return modified_action, modifications
    
    def update_context(self, headers: Dict[str, str] = None, 
                       rate_limited: bool = False) -> None:
        """
        Update swarm context with new information.
        
        Args:
            headers: HTTP response headers (for WAF detection)
            rate_limited: Whether rate limiting was observed
        """
        if headers:
            self.last_response_headers = headers
            
            # Detect WAF from headers
            for waf_name, signatures in self.WAF_SIGNATURES.items():
                for sig in signatures:
                    if any(sig.lower() in str(v).lower() for v in headers.values()):
                        self.detected_waf = waf_name
                        logger.info(f"🛡️ Detected WAF: {waf_name}")
                        break
        
        if rate_limited:
            self.rate_limit_observed = True
            logger.info("⏱️ Rate limiting detected - swarm will adapt")
    
    def get_debate_summary(self) -> Dict[str, Any]:
        """Get summary of all debates conducted"""
        return {
            "total_debates": len(self.debate_history),
            "approved_actions": len([d for d in self.debate_history if d.approved]),
            "rejected_actions": len([d for d in self.debate_history if not d.approved]),
            "average_risk_score": (
                sum(d.risk_score for d in self.debate_history) / len(self.debate_history)
                if self.debate_history else 0
            ),
            "detected_waf": self.detected_waf,
            "rate_limit_observed": self.rate_limit_observed
        }


# Global instance
_adversarial_swarm: Optional[AdversarialSwarm] = None


def get_adversarial_swarm(ai_core=None) -> AdversarialSwarm:
    """Get the global adversarial swarm instance"""
    global _adversarial_swarm
    if _adversarial_swarm is None:
        _adversarial_swarm = AdversarialSwarm(ai_core=ai_core)
    return _adversarial_swarm
