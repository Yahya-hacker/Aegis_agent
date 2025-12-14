#!/usr/bin/env python3
"""
SOTA Agent Integration Module
==============================

Integrates all SOTA components into the main agent workflow:
- KTV Loop (KNOW-THINK-TEST-VALIDATE)
- Discovery/Validation Agents
- Asset Deduplication
- Policy Parser and Target Scoring
"""

import asyncio
import logging
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime

# Import SOTA components
from agents.ktv_loop import KTVLoop, Fact
from agents.discovery_validation_agents import DiscoveryValidationOrchestrator
from utils.asset_deduplication import get_asset_deduplicator
from utils.policy_parser import get_policy_parser, get_target_scorer

logger = logging.getLogger(__name__)


class SOTAAgent:
    """
    State-of-the-Art Agent that integrates all advanced components.
    
    This agent implements the complete SOTA workflow:
    1. Parse policies and determine scope
    2. Discover and deduplicate assets
    3. Score and prioritize targets
    4. Execute KTV loop for systematic testing
    5. Use Discovery/Validation separation
    6. Maintain persistent state
    """
    
    def __init__(self, ai_core, scanner):
        """
        Initialize SOTA Agent.
        
        Args:
            ai_core: Enhanced AI core
            scanner: Scanner for executing actions
        """
        self.ai_core = ai_core
        self.scanner = scanner
        
        # Initialize components
        self.ktv_loop = KTVLoop(ai_core, scanner)
        self.discovery_validation = DiscoveryValidationOrchestrator(ai_core, scanner)
        self.asset_deduplicator = get_asset_deduplicator()
        self.policy_parser = get_policy_parser()
        self.target_scorer = get_target_scorer(ai_core)
        
        # State management
        self.state_path = Path("data/agent_state.json")
        self.state = self._load_state()
        
        logger.info("🚀 SOTA Agent initialized with all advanced components")
    
    def _load_state(self) -> Dict[str, Any]:
        """Load persistent state"""
        if self.state_path.exists():
            try:
                with open(self.state_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading state: {e}")
        
        return {
            "current_phase": "IDLE",
            "iteration": 0,
            "facts_count": 0,
            "hypotheses_count": 0,
            "tested_hypotheses": 0,
            "confirmed_vulnerabilities": 0,
            "discovery_findings": 0,
            "validated_findings": 0,
            "assets_total": 0,
            "assets_clustered": 0,
            "target_scores": [],
            "mission_history": []
        }
    
    def _save_state(self):
        """Save persistent state"""
        try:
            self.state_path.parent.mkdir(exist_ok=True)
            with open(self.state_path, 'w') as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving state: {e}")
    
    async def execute_mission(self, target: str, rules: str, max_iterations: int = 10) -> Dict[str, Any]:
        """
        Execute a complete penetration testing mission using SOTA methodology.
        
        Args:
            target: Target URL or domain
            rules: Mission rules and policies
            max_iterations: Maximum KTV loop iterations
            
        Returns:
            Mission results
        """
        logger.info(f"🎯 Starting SOTA mission: {target}")
        print("\n" + "="*80)
        print(f"🎯 SOTA PENTEST MISSION - {target}")
        print("="*80)
        
        mission_start = datetime.now()
        
        # Phase 0: Policy Parsing and Scope Definition
        print("\n📜 Phase 0: Policy Parsing and Scope Definition")
        print("-" * 80)
        
        parsed_rules = self.policy_parser.parse_policy(rules)
        logger.info(f"✓ Parsed {len(parsed_rules)} policy rules")
        
        # Check if target is in scope
        in_scope, reason = self.policy_parser.is_in_scope(target)
        if not in_scope:
            logger.warning(f"❌ Target {target} is out of scope: {reason}")
            return {
                "status": "out_of_scope",
                "reason": reason,
                "target": target
            }
        
        logger.info(f"✓ Target {target} is in scope")
        
        # Get rate limits
        rate_limits = self.policy_parser.get_rate_limits()
        logger.info(f"✓ Rate limits: {rate_limits}")
        
        # Phase 1: Reconnaissance and Asset Discovery
        print("\n🔍 Phase 1: Reconnaissance and Asset Discovery")
        print("-" * 80)
        
        # Perform initial reconnaissance
        recon_data = await self._perform_reconnaissance(target)
        
        # Add asset to deduplicator
        asset = self.asset_deduplicator.add_asset(
            url=target,
            content=recon_data.get("html_content"),
            screenshot_path=recon_data.get("screenshot_path"),
            metadata=recon_data
        )
        
        # Update state
        self.state["assets_total"] = len(self.asset_deduplicator.assets)
        self.state["assets_clustered"] = len(self.asset_deduplicator.clusters)
        self._save_state()
        
        # Get deduplication report
        dedup_report = self.asset_deduplicator.get_cluster_report()
        logger.info(f"✓ Asset deduplication: {dedup_report['efficiency_gain']:.1%} efficiency gain")
        
        # Phase 2: Target Scoring and Prioritization
        print("\n🎯 Phase 2: Target Scoring and Prioritization")
        print("-" * 80)
        
        scored_target = await self.target_scorer.score_target(target, recon_data)
        logger.info(f"✓ Target score: {scored_target.score:.1f}/100")
        
        # Update state
        self.state["target_scores"].append({
            "url": target,
            "score": scored_target.score,
            "in_scope": scored_target.in_scope,
            "timestamp": datetime.now().isoformat()
        })
        self._save_state()
        
        # Initialize KTV loop with reconnaissance facts
        print("\n📚 Initializing KNOW phase with reconnaissance data")
        print("-" * 80)
        
        await self._populate_initial_facts(recon_data)
        
        # Phase 3: Discovery Agent Scan
        print("\n🔍 Phase 3: Discovery Agent - Vulnerability Scanning")
        print("-" * 80)
        
        context = {
            "target": target,
            "rules": rules,
            "score": scored_target.score,
            "in_scope": scored_target.in_scope
        }
        
        discovery_results = await self.discovery_validation.scan_and_validate(target, context)
        
        # Update state
        self.state["discovery_findings"] = discovery_results["potential_findings"]
        self.state["validated_findings"] = discovery_results["validated_findings"]
        self._save_state()
        
        logger.info(f"✓ Discovery: {discovery_results['potential_findings']} findings")
        logger.info(f"✓ Validation: {discovery_results['validated_findings']} vulnerabilities confirmed")
        
        # Phase 4: KTV Loop Execution
        print("\n🔄 Phase 4: KNOW-THINK-TEST-VALIDATE Loop")
        print("-" * 80)
        
        ktv_results = await self.ktv_loop.execute_loop(context, max_iterations)
        
        # Update state
        ktv_state = self.ktv_loop.get_state_summary()
        self.state.update({
            "current_phase": ktv_state["current_phase"],
            "iteration": ktv_state["iteration"],
            "facts_count": ktv_state["facts_count"],
            "hypotheses_count": ktv_state["active_hypotheses"],
            "tested_hypotheses": ktv_state["tested_hypotheses"],
            "confirmed_vulnerabilities": ktv_state["confirmed_hypotheses"]
        })
        self._save_state()
        
        # Phase 5: Asset Extrapolation
        print("\n📋 Phase 5: Finding Extrapolation to Similar Assets")
        print("-" * 80)
        
        extrapolated_findings = []
        
        for vuln in discovery_results["vulnerabilities"]:
            # Extrapolate to similar assets
            extrapolations = self.asset_deduplicator.extrapolate_finding(asset, vuln)
            extrapolated_findings.extend(extrapolations)
            logger.info(f"✓ Extrapolated {len(extrapolations)} findings to similar assets")
        
        # Compile final results
        mission_end = datetime.now()
        duration = (mission_end - mission_start).total_seconds()
        
        results = {
            "status": "complete",
            "target": target,
            "duration_seconds": duration,
            "reconnaissance": recon_data,
            "asset_deduplication": dedup_report,
            "target_score": scored_target.score,
            "discovery_validation": discovery_results,
            "ktv_loop": ktv_results,
            "extrapolated_findings": len(extrapolated_findings),
            "total_vulnerabilities": discovery_results["validated_findings"] + ktv_results["total_hypotheses_tested"],
            "efficiency_metrics": {
                "assets_scanned": 1,
                "assets_represented": len(self.asset_deduplicator.get_assets_to_test()),
                "deduplication_efficiency": dedup_report["efficiency_gain"],
                "ktv_iterations": ktv_results["iterations"],
                "discovery_validation_rate": (
                    discovery_results["validated_findings"] / max(discovery_results["potential_findings"], 1)
                )
            }
        }
        
        # Add to mission history
        self.state["mission_history"].append({
            "target": target,
            "timestamp": mission_end.isoformat(),
            "vulnerabilities": results["total_vulnerabilities"],
            "duration": duration
        })
        self._save_state()
        
        # Print summary
        print("\n" + "="*80)
        print("✅ MISSION COMPLETE")
        print("="*80)
        print(f"Target: {target}")
        print(f"Duration: {duration:.1f}s")
        print(f"Validated Vulnerabilities: {discovery_results['validated_findings']}")
        print(f"KTV Confirmed: {ktv_results.get('total_hypotheses_tested', 0)}")
        print(f"Extrapolated Findings: {len(extrapolated_findings)}")
        print(f"Deduplication Efficiency: {dedup_report['efficiency_gain']:.1%}")
        print("="*80 + "\n")
        
        return results
    
    async def _perform_reconnaissance(self, target: str) -> Dict[str, Any]:
        """Perform initial reconnaissance"""
        logger.info(f"🔍 Performing reconnaissance on {target}")
        
        recon_data = {
            "target": target,
            "html_content": None,
            "screenshot_path": None,
            "technology_stack": [],
            "security_headers": {},
            "forms": [],
            "http_response": {}
        }
        
        try:
            # HTTP request
            http_action = {
                "tool": "http_request",
                "args": {"url": target, "method": "GET"}
            }
            
            http_result = await self.scanner.execute_action(http_action)
            
            if http_result.get("status") == "success":
                recon_data["html_content"] = http_result.get("body", "")
                recon_data["http_response"] = http_result
                recon_data["security_headers"] = http_result.get("headers", {})
            
            # Try to capture screenshot (for visual deduplication)
            try:
                screenshot_action = {
                    "tool": "capture_screenshot",
                    "args": {"url": target}
                }
                
                screenshot_result = await self.scanner.execute_action(screenshot_action)
                
                if screenshot_result.get("status") == "success":
                    recon_data["screenshot_path"] = screenshot_result.get("path")
            except Exception as e:
                logger.warning(f"Screenshot capture failed: {e}")
            
            # Form discovery
            try:
                form_action = {
                    "tool": "find_forms",
                    "args": {"url": target}
                }
                
                form_result = await self.scanner.execute_action(form_action)
                
                if form_result.get("status") == "success":
                    recon_data["forms"] = form_result.get("forms", [])
            except Exception as e:
                logger.warning(f"Form discovery failed: {e}")
        
        except Exception as e:
            logger.error(f"Reconnaissance error: {e}", exc_info=True)
        
        return recon_data
    
    async def _populate_initial_facts(self, recon_data: Dict[str, Any]) -> None:
        """Populate KTV loop with initial facts from reconnaissance"""
        
        # Fact: Target URL
        self.ktv_loop.add_fact(
            description=f"Target is {recon_data['target']}",
            source="reconnaissance",
            category="target_info"
        )
        
        # Fact: HTTP response
        if recon_data.get("http_response"):
            status_code = recon_data["http_response"].get("status_code")
            if status_code:
                self.ktv_loop.add_fact(
                    description=f"Target returns HTTP {status_code}",
                    source="http_request",
                    category="http_info"
                )
        
        # Fact: Forms discovered
        if recon_data.get("forms"):
            form_count = len(recon_data["forms"])
            self.ktv_loop.add_fact(
                description=f"Target has {form_count} form(s)",
                source="form_discovery",
                category="attack_surface"
            )
        
        # Fact: Security headers
        if recon_data.get("security_headers"):
            headers = recon_data["security_headers"]
            
            # Check for important security headers
            if "strict-transport-security" not in headers:
                self.ktv_loop.add_fact(
                    description="HSTS header is missing",
                    source="security_headers",
                    category="security_config",
                    confidence=1.0
                )
            
            if "content-security-policy" not in headers:
                self.ktv_loop.add_fact(
                    description="CSP header is missing",
                    source="security_headers",
                    category="security_config",
                    confidence=1.0
                )
        
        logger.info(f"✓ Populated {len(self.ktv_loop.state.facts)} initial facts")
    
    def get_current_state(self) -> Dict[str, Any]:
        """Get current agent state for UI display"""
        return self.state.copy()
    
    async def handle_command(self, command: str) -> Dict[str, Any]:
        """
        Handle commands from UI or CLI.
        
        Args:
            command: Command string
            
        Returns:
            Command result
        """
        logger.info(f"📨 Received command: {command}")
        
        # Parse command
        parts = command.strip().split()
        
        if not parts:
            return {"status": "error", "message": "Empty command"}
        
        cmd = parts[0].lower()
        
        if cmd == "scan" and len(parts) >= 2:
            target = parts[1]
            rules = " ".join(parts[2:]) if len(parts) > 2 else "Standard penetration testing"
            
            result = await self.execute_mission(target, rules)
            return {"status": "success", "result": result}
        
        elif cmd == "stop":
            logger.info("Stopping agent...")
            return {"status": "success", "message": "Agent stopped"}
        
        elif cmd == "pause":
            self.state["current_phase"] = "PAUSED"
            self._save_state()
            return {"status": "success", "message": "Agent paused"}
        
        elif cmd == "resume":
            self.state["current_phase"] = "IDLE"
            self._save_state()
            return {"status": "success", "message": "Agent resumed"}
        
        elif cmd == "status":
            return {"status": "success", "state": self.get_current_state()}
        
        else:
            return {"status": "error", "message": f"Unknown command: {cmd}"}


def get_sota_agent(ai_core, scanner) -> SOTAAgent:
    """
    Get SOTA Agent instance.
    
    Args:
        ai_core: Enhanced AI core
        scanner: Scanner instance
        
    Returns:
        SOTAAgent instance
    """
    return SOTAAgent(ai_core, scanner)
